package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	_ "github.com/mattn/go-sqlite3"
)

var (
	db     *sql.DB
	dbPath = "/data/yossarian.db"

	// LDAP configuration
	ldapServer       string
	ldapBindDN       string
	ldapBindPassword string
	ldapSearchBase   string
	ldapSyncInterval int
	dcCACertPath     string
)

type LookupResponse struct {
	USN string `json:"usn"`
}

func initDB() error {
	var err error
	db, err = sql.Open("sqlite3", dbPath)
	if err != nil {
		return err
	}

	createTableSQL := `
	CREATE TABLE IF NOT EXISTS ad_accounts (
		account TEXT PRIMARY KEY,
		usn TEXT NOT NULL
	);
	CREATE TABLE IF NOT EXISTS sensitive_terms (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		term TEXT NOT NULL UNIQUE,
		replacement TEXT DEFAULT '[SENSITIVE]',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE TABLE IF NOT EXISTS org_settings (
		key TEXT PRIMARY KEY,
		value TEXT,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_by TEXT
	);
	CREATE TABLE IF NOT EXISTS batch_jobs (
		job_id TEXT PRIMARY KEY,
		username TEXT NOT NULL,
		status TEXT NOT NULL DEFAULT 'queued',
		total_files INTEGER DEFAULT 0,
		processed_files INTEGER DEFAULT 0,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		started_at DATETIME,
		completed_at DATETIME,
		input_path TEXT,
		output_path TEXT,
		error_message TEXT
	);
	CREATE INDEX IF NOT EXISTS idx_batch_jobs_username ON batch_jobs(username);
	CREATE INDEX IF NOT EXISTS idx_batch_jobs_status ON batch_jobs(status);
	CREATE TABLE IF NOT EXISTS api_keys (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		key_hash TEXT NOT NULL UNIQUE,
		key_prefix TEXT NOT NULL,
		name TEXT NOT NULL,
		username TEXT NOT NULL,
		scopes TEXT DEFAULT 'read,write',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		expires_at DATETIME,
		last_used_at DATETIME,
		is_active INTEGER DEFAULT 1
	);
	CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
	CREATE INDEX IF NOT EXISTS idx_api_keys_username ON api_keys(username);`

	_, err = db.Exec(createTableSQL)
	if err != nil {
		return err
	}

	// Insert default org settings
	defaultSettings := `
	INSERT OR IGNORE INTO org_settings (key, value) VALUES 
		('disclaimer_enabled', 'false'),
		('disclaimer_text', ''),
		('docs_enabled', 'false'),
		('docs_title', 'Documentation'),
		('docs_url', '');`

	_, err = db.Exec(defaultSettings)
	return err
}

func connectLDAP() (*ldap.Conn, error) {
	// Load DC CA certificate if available
	var tlsConfig *tls.Config
	if dcCACertPath != "" {
		if _, err := os.Stat(dcCACertPath); err == nil {
			caCert, err := ioutil.ReadFile(dcCACertPath)
			if err == nil {
				caCertPool := x509.NewCertPool()
				if caCertPool.AppendCertsFromPEM(caCert) {
					tlsConfig = &tls.Config{
						RootCAs: caCertPool,
					}
				}
			}
		}
	}

	// Connect to LDAP server
	var conn *ldap.Conn
	var err error

	if tlsConfig != nil {
		conn, err = ldap.DialURL(ldapServer, ldap.DialWithTLSConfig(tlsConfig))
	} else {
		conn, err = ldap.DialURL(ldapServer)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to connect to LDAP: %v", err)
	}

	// Bind with service account
	err = conn.Bind(ldapBindDN, ldapBindPassword)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to bind to LDAP: %v", err)
	}

	return conn, nil
}

func syncLDAPAccounts() error {
	if ldapServer == "" || ldapBindDN == "" || ldapBindPassword == "" {
		log.Printf("LDAP configuration incomplete, skipping sync")
		return nil
	}

	// Clear existing accounts before full sync
	log.Printf("Clearing existing AD accounts before sync...")
	result, err := db.Exec("DELETE FROM ad_accounts")
	if err != nil {
		return fmt.Errorf("failed to clear existing accounts: %v", err)
	}

	if rowsAffected, err := result.RowsAffected(); err == nil {
		log.Printf("Cleared %d existing accounts", rowsAffected)
	}

	conn, err := connectLDAP()
	if err != nil {
		return fmt.Errorf("LDAP connection failed: %v", err)
	}
	defer conn.Close()

	// ---------------------------
	// USER ACCOUNT SEARCH (Paged)
	// ---------------------------
	userSearchRequest := ldap.NewSearchRequest(
		ldapSearchBase,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(&(objectClass=user)(!(objectClass=computer))(sAMAccountName=*))",
		[]string{"sAMAccountName", "uSNCreated"},
		nil,
	)

	userPagingControl := ldap.NewControlPaging(1000) // match AD's MaxPageSize
	userSearchRequest.Controls = []ldap.Control{userPagingControl}

	allUserEntries := []*ldap.Entry{}
	pageCount := 0

	for {
		userSearchResult, err := conn.Search(userSearchRequest)
		if err != nil {
			return fmt.Errorf("user search failed: %v", err)
		}

		pageCount++
		log.Printf("User search page %d: got %d entries, total so far: %d",
			pageCount, len(userSearchResult.Entries),
			len(allUserEntries)+len(userSearchResult.Entries))

		allUserEntries = append(allUserEntries, userSearchResult.Entries...)

		pagingResult := ldap.FindControl(userSearchResult.Controls, ldap.ControlTypePaging)
		if pagingResult == nil {
			break
		}
		pagingControl := pagingResult.(*ldap.ControlPaging)

		if len(pagingControl.Cookie) == 0 {
			break // no more pages
		}

		// update same control's cookie
		userPagingControl.SetCookie(pagingControl.Cookie)
	}

	// final empty-cookie request to end paging
	userPagingControl.SetCookie([]byte{})
	_, _ = conn.Search(userSearchRequest)

	// ------------------------------
	// COMPUTER ACCOUNT SEARCH (Paged)
	// ------------------------------
	computerSearchRequest := ldap.NewSearchRequest(
		ldapSearchBase,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(&(objectClass=computer)(sAMAccountName=*))",
		[]string{"sAMAccountName", "uSNCreated"},
		nil,
	)

	computerPagingControl := ldap.NewControlPaging(1000)
	computerSearchRequest.Controls = []ldap.Control{computerPagingControl}

	allComputerEntries := []*ldap.Entry{}
	pageCount = 0

	for {
		computerSearchResult, err := conn.Search(computerSearchRequest)
		if err != nil {
			return fmt.Errorf("computer search failed: %v", err)
		}

		pageCount++
		log.Printf("Computer search page %d: got %d entries, total so far: %d",
			pageCount, len(computerSearchResult.Entries),
			len(allComputerEntries)+len(computerSearchResult.Entries))

		allComputerEntries = append(allComputerEntries, computerSearchResult.Entries...)

		pagingResult := ldap.FindControl(computerSearchResult.Controls, ldap.ControlTypePaging)
		if pagingResult == nil {
			break
		}
		pagingControl := pagingResult.(*ldap.ControlPaging)

		if len(pagingControl.Cookie) == 0 {
			break
		}

		computerPagingControl.SetCookie(pagingControl.Cookie)
	}

	computerPagingControl.SetCookie([]byte{})
	_, _ = conn.Search(computerSearchRequest)

	// -----------------------
	// PROCESS & STORE RESULTS
	// -----------------------
	accountCount := 0

	// Users
	for _, entry := range allUserEntries {
		samAccountName := entry.GetAttributeValue("sAMAccountName")
		usnCreated := entry.GetAttributeValue("uSNCreated")

		if samAccountName != "" && usnCreated != "" {
			domainNetBios := os.Getenv("DOMAIN_NETBIOS")
			domainFqdn := os.Getenv("DOMAIN_FQDN")

			// Store all variants in lowercase for consistent matching
			domainAccount := strings.ToLower(fmt.Sprintf("%s\\%s", domainNetBios, samAccountName))
			upnAccount := strings.ToLower(fmt.Sprintf("%s@%s", samAccountName, domainFqdn))
			bareUsername := strings.ToLower(samAccountName)

			// Use real AD uSNCreated value
			usnString := fmt.Sprintf("USN%s", usnCreated)

			_, err := db.Exec("INSERT OR REPLACE INTO ad_accounts (account, usn) VALUES (?, ?)", domainAccount, usnString)
			if err == nil {
				accountCount++
			}

			_, err = db.Exec("INSERT OR REPLACE INTO ad_accounts (account, usn) VALUES (?, ?)", upnAccount, usnString)
			if err == nil {
				accountCount++
			}

			_, err = db.Exec("INSERT OR REPLACE INTO ad_accounts (account, usn) VALUES (?, ?)", bareUsername, usnString)
			if err == nil {
				accountCount++
			}
		}
	}

	// Computers
	for _, entry := range allComputerEntries {
		samAccountName := entry.GetAttributeValue("sAMAccountName")
		usnCreated := entry.GetAttributeValue("uSNCreated")

		if samAccountName != "" && usnCreated != "" {
			// Store computer accounts in both lowercase and uppercase variants
			computerWithDollar := strings.ToLower(samAccountName)
			computerWithoutDollar := strings.ToLower(strings.TrimSuffix(samAccountName, "$"))
			computerWithDollarUpper := strings.ToUpper(samAccountName)
			computerWithoutDollarUpper := strings.ToUpper(strings.TrimSuffix(samAccountName, "$"))

			// Use real AD uSNCreated value
			usnString := fmt.Sprintf("USN%s", usnCreated)

			// Store lowercase variants
			_, err := db.Exec("INSERT OR REPLACE INTO ad_accounts (account, usn) VALUES (?, ?)", computerWithDollar, usnString)
			if err == nil {
				accountCount++
			}

			_, err = db.Exec("INSERT OR REPLACE INTO ad_accounts (account, usn) VALUES (?, ?)", computerWithoutDollar, usnString)
			if err == nil {
				accountCount++
			}

			// Store uppercase variants
			_, err = db.Exec("INSERT OR REPLACE INTO ad_accounts (account, usn) VALUES (?, ?)", computerWithDollarUpper, usnString)
			if err == nil {
				accountCount++
			}

			_, err = db.Exec("INSERT OR REPLACE INTO ad_accounts (account, usn) VALUES (?, ?)", computerWithoutDollarUpper, usnString)
			if err == nil {
				accountCount++
			}
		}
	}

	log.Printf("LDAP sync completed: %d accounts synchronized", accountCount)
	return nil
}

func lookupHandler(w http.ResponseWriter, r *http.Request) {
	account := strings.TrimPrefix(r.URL.Path, "/lookup/")

	// Normalize to lowercase for consistent lookups
	account = strings.ToLower(account)

	var usn string
	err := db.QueryRow("SELECT usn FROM ad_accounts WHERE LOWER(account) = LOWER(?)", account).Scan(&usn)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(LookupResponse{USN: usn})
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status": "ok", "service": "yossarian-db-service"}`)
}

func addTestDataHandler(w http.ResponseWriter, r *http.Request) {
	testAccounts := map[string]string{
		"CORP\\john.doe":   "USN123456789",
		"CORP\\jane.smith": "USN987654321",
		"svc_backup":       "USN111222333",
	}

	for account, usn := range testAccounts {
		_, err := db.Exec("INSERT OR REPLACE INTO ad_accounts (account, usn) VALUES (?, ?)", account, usn)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status": "ok", "added": %d}`, len(testAccounts))
}

func ldapSyncHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if ldapServer == "" || ldapBindDN == "" || ldapBindPassword == "" {
		http.Error(w, "LDAP not configured", http.StatusServiceUnavailable)
		return
	}

	log.Printf("Manual LDAP sync triggered")
	err := syncLDAPAccounts()
	if err != nil {
		http.Error(w, fmt.Sprintf("LDAP sync failed: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status": "ok", "message": "LDAP sync completed"}`)
}

func ldapStatusHandler(w http.ResponseWriter, r *http.Request) {
	// Get user count (divide by 3: domain\user, user@domain, user)
	var userCount int
	db.QueryRow("SELECT COUNT(*) FROM ad_accounts WHERE account LIKE '%@%'").Scan(&userCount)

	// Get computer count (no division needed: computer$ and computer)
	var computerCount int
	db.QueryRow("SELECT COUNT(*) FROM ad_accounts WHERE account LIKE '%$'").Scan(&computerCount)

	// Total unique accounts
	accountCount := userCount/3 + computerCount/2

	status := map[string]interface{}{
		"ldap_configured": ldapServer != "" && ldapBindDN != "" && ldapBindPassword != "",
		"ldap_server":     ldapServer,
		"sync_interval":   ldapSyncInterval,
		"account_count":   accountCount,
		"user_count":      userCount / 3,
		"computer_count":  computerCount / 2,
		"last_sync":       "Available in future version",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

func ldapTestHandler(w http.ResponseWriter, r *http.Request) {
	if ldapServer == "" || ldapBindDN == "" || ldapBindPassword == "" {
		http.Error(w, "LDAP not configured", http.StatusServiceUnavailable)
		return
	}

	// Test LDAP connection only
	conn, err := connectLDAP()
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `{"status": "error", "message": "LDAP connection failed: %v"}`, err)
		return
	}
	defer conn.Close()

	// Simple test search with limit 5
	searchRequest := ldap.NewSearchRequest(
		ldapSearchBase,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 5, 0, false,
		"(objectClass=user)",
		[]string{"sAMAccountName"},
		nil,
	)

	searchResult, err := conn.Search(searchRequest)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `{"status": "error", "message": "LDAP search failed: %v"}`, err)
		return
	}

	userCount := len(searchResult.Entries)

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status": "success", "message": "LDAP connection successful", "users_found": %d, "connection_test": "passed"}`, userCount)
}

func ldapLimitedSyncHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if ldapServer == "" || ldapBindDN == "" || ldapBindPassword == "" {
		http.Error(w, "LDAP not configured", http.StatusServiceUnavailable)
		return
	}

	// Call the full sync function with pagination
	log.Printf("Manual full LDAP sync triggered")
	err := syncLDAPAccounts()
	if err != nil {
		http.Error(w, fmt.Sprintf("LDAP sync failed: %v", err), http.StatusInternalServerError)
		return
	}

	// Get final count from database
	var accountCount int
	db.QueryRow("SELECT COUNT(*) FROM ad_accounts").Scan(&accountCount)

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status": "success", "message": "Full LDAP sync completed", "accounts_imported": %d}`, accountCount)
}

func accountsListHandler(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query("SELECT account, usn FROM ad_accounts ORDER BY account")
	if err != nil {
		http.Error(w, "Database query failed", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	accounts := make(map[string]string)
	for rows.Next() {
		var account, usn string
		if err := rows.Scan(&account, &usn); err != nil {
			continue
		}
		accounts[account] = usn
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"accounts": accounts,
		"total":    len(accounts),
	})
}

func sensitiveListHandler(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query("SELECT term, replacement FROM sensitive_terms ORDER BY term")
	if err != nil {
		http.Error(w, "Database query failed", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	terms := make(map[string]string)
	for rows.Next() {
		var term, replacement string
		if err := rows.Scan(&term, &replacement); err != nil {
			continue
		}
		terms[term] = replacement
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"terms": terms,
		"total": len(terms),
	})
}

func sensitiveAddHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Term        string `json:"term"`
		Replacement string `json:"replacement"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if req.Term == "" {
		http.Error(w, "Term is required", http.StatusBadRequest)
		return
	}
	if req.Replacement == "" {
		req.Replacement = "[SENSITIVE]"
	}

	_, err := db.Exec("INSERT INTO sensitive_terms (term, replacement) VALUES (?, ?)", req.Term, req.Replacement)
	if err != nil {
		http.Error(w, "Failed to add term", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

func sensitiveDeleteHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "DELETE" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	term := r.URL.Query().Get("term")
	if term == "" {
		http.Error(w, "Term parameter required", http.StatusBadRequest)
		return
	}

	_, err := db.Exec("DELETE FROM sensitive_terms WHERE term = ?", term)
	if err != nil {
		http.Error(w, "Failed to delete term", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

func orgSettingsUpdateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req map[string]string
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Update each setting
	for key, value := range req {
		// Validate allowed keys
		allowedKeys := map[string]bool{
			"disclaimer_enabled": true,
			"disclaimer_text":    true,
			"docs_enabled":       true,
			"docs_title":         true,
			"docs_url":           true,
		}

		if !allowedKeys[key] {
			continue // Skip unknown keys
		}

		_, err := db.Exec(
			"INSERT OR REPLACE INTO org_settings (key, value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)",
			key, value,
		)
		if err != nil {
			http.Error(w, "Failed to update settings", http.StatusInternalServerError)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

func orgSettingsPublicHandler(w http.ResponseWriter, r *http.Request) {
	// Only return public-facing settings (not admin-only settings)
	publicKeys := []string{
		"disclaimer_enabled",
		"disclaimer_text",
		"docs_enabled",
		"docs_title",
		"docs_url",
	}

	settings := make(map[string]string)
	for _, key := range publicKeys {
		var value string
		err := db.QueryRow("SELECT value FROM org_settings WHERE key = ?", key).Scan(&value)
		if err == nil {
			settings[key] = value
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(settings)
}

func orgSettingsListHandler(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query("SELECT key, value FROM org_settings ORDER BY key")
	if err != nil {
		http.Error(w, "Database query failed", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	settings := make(map[string]string)
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			continue
		}
		settings[key] = value
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"settings": settings,
	})
}

// Batch job handlers
func jobCreateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		JobID      string `json:"job_id"`
		Username   string `json:"username"`
		InputPath  string `json:"input_path"`
		OutputPath string `json:"output_path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if req.JobID == "" || req.Username == "" {
		http.Error(w, "job_id and username are required", http.StatusBadRequest)
		return
	}

	_, err := db.Exec(`INSERT INTO batch_jobs 
		(job_id, username, status, input_path, output_path) 
		VALUES (?, ?, 'queued', ?, ?)`,
		req.JobID, req.Username, req.InputPath, req.OutputPath)

	if err != nil {
		log.Printf("Failed to create job: %v", err)
		http.Error(w, "Failed to create job", http.StatusInternalServerError)
		return
	}

	log.Printf("[BATCH] Job created: %s for user %s", req.JobID, req.Username)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"job_id": req.JobID,
	})
}

func jobStatusHandler(w http.ResponseWriter, r *http.Request) {
	jobID := strings.TrimPrefix(r.URL.Path, "/jobs/status/")
	if jobID == "" {
		http.Error(w, "job_id required", http.StatusBadRequest)
		return
	}

	var job struct {
		JobID          string  `json:"job_id"`
		Username       string  `json:"username"`
		Status         string  `json:"status"`
		TotalFiles     int     `json:"total_files"`
		ProcessedFiles int     `json:"processed_files"`
		CreatedAt      string  `json:"created_at"`
		StartedAt      *string `json:"started_at"`
		CompletedAt    *string `json:"completed_at"`
		InputPath      *string `json:"input_path"`
		OutputPath     *string `json:"output_path"`
		ErrorMessage   *string `json:"error_message"`
	}

	err := db.QueryRow(`SELECT job_id, username, status, total_files, processed_files, 
		created_at, started_at, completed_at, input_path, output_path, error_message 
		FROM batch_jobs WHERE job_id = ?`, jobID).Scan(
		&job.JobID, &job.Username, &job.Status, &job.TotalFiles, &job.ProcessedFiles,
		&job.CreatedAt, &job.StartedAt, &job.CompletedAt, &job.InputPath, &job.OutputPath, &job.ErrorMessage)

	if err != nil {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(job)
}

func jobListHandler(w http.ResponseWriter, r *http.Request) {
	username := strings.TrimPrefix(r.URL.Path, "/jobs/list/")
	if username == "" {
		http.Error(w, "username required", http.StatusBadRequest)
		return
	}

	// Get optional 'after' parameter for filtering by date
	after := r.URL.Query().Get("after")
	var rows *sql.Rows
	var err error

	if after != "" {
		// Parse RFC3339 and convert to SQLite format
		afterTime, err := time.Parse(time.RFC3339, after)
		if err != nil {
			afterTime = time.Now().Add(-8 * time.Hour) // Fallback
		}
		sqliteFormat := afterTime.Format("2006-01-02 15:04:05")

		// Show all jobs, but hide completed jobs older than cutoff
		rows, err = db.Query(`SELECT job_id, status, total_files, processed_files,
					created_at, completed_at FROM batch_jobs
					WHERE username = ? AND (status != 'completed' OR completed_at IS NULL OR completed_at >= ?)
					ORDER BY created_at DESC LIMIT 50`, username, sqliteFormat)
	} else {
		// No filter, return all jobs
		rows, err = db.Query(`SELECT job_id, status, total_files, processed_files,
					created_at, completed_at FROM batch_jobs
					WHERE username = ? ORDER BY created_at DESC LIMIT 50`, username)
	}
	if err != nil {
		http.Error(w, "Database query failed", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	jobs := []map[string]interface{}{}
	for rows.Next() {
		var jobID, status, createdAt string
		var totalFiles, processedFiles int
		var completedAt *string

		if err := rows.Scan(&jobID, &status, &totalFiles, &processedFiles, &createdAt, &completedAt); err != nil {
			continue
		}

		jobs = append(jobs, map[string]interface{}{
			"job_id":          jobID,
			"status":          status,
			"total_files":     totalFiles,
			"processed_files": processedFiles,
			"created_at":      createdAt,
			"completed_at":    completedAt,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"jobs":  jobs,
		"total": len(jobs),
	})
}

func jobUpdateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		JobID          string  `json:"job_id"`
		Status         *string `json:"status"`
		TotalFiles     *int    `json:"total_files"`
		ProcessedFiles *int    `json:"processed_files"`
		ErrorMessage   *string `json:"error_message"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if req.JobID == "" {
		http.Error(w, "job_id required", http.StatusBadRequest)
		return
	}

	// Build dynamic UPDATE query
	updates := []string{}
	args := []interface{}{}

	if req.Status != nil {
		updates = append(updates, "status = ?")
		args = append(args, *req.Status)

		// Set timestamps based on status
		if *req.Status == "processing" {
			updates = append(updates, "started_at = CURRENT_TIMESTAMP")
		} else if *req.Status == "completed" || *req.Status == "failed" {
			updates = append(updates, "completed_at = CURRENT_TIMESTAMP")
		}
	}
	if req.TotalFiles != nil {
		updates = append(updates, "total_files = ?")
		args = append(args, *req.TotalFiles)
	}
	if req.ProcessedFiles != nil {
		updates = append(updates, "processed_files = ?")
		args = append(args, *req.ProcessedFiles)
	}
	if req.ErrorMessage != nil {
		updates = append(updates, "error_message = ?")
		args = append(args, *req.ErrorMessage)
	}

	if len(updates) == 0 {
		http.Error(w, "No fields to update", http.StatusBadRequest)
		return
	}

	args = append(args, req.JobID)
	query := fmt.Sprintf("UPDATE batch_jobs SET %s WHERE job_id = ?", strings.Join(updates, ", "))

	_, err := db.Exec(query, args...)
	if err != nil {
		log.Printf("Failed to update job: %v", err)
		http.Error(w, "Failed to update job", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}
func jobDeleteHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "DELETE" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	jobID := strings.TrimPrefix(r.URL.Path, "/jobs/delete/")
	if jobID == "" {
		http.Error(w, "job_id required", http.StatusBadRequest)
		return
	}

	_, err := db.Exec("DELETE FROM batch_jobs WHERE job_id = ?", jobID)
	if err != nil {
		log.Printf("[ERROR] Failed to delete job %s from database: %v", jobID, err)
		http.Error(w, "Failed to delete job", http.StatusInternalServerError)
		return
	}

	log.Printf("[BATCH] Job deleted from database: %s", jobID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "deleted", "job_id": jobID})
}
func jobCleanupListHandler(w http.ResponseWriter, r *http.Request) {
	// Get cutoff time from query parameter
	beforeStr := r.URL.Query().Get("before")
	if beforeStr == "" {
		http.Error(w, "before parameter required (RFC3339 format)", http.StatusBadRequest)
		return
	}

	beforeTime, err := time.Parse(time.RFC3339, beforeStr)
	if err != nil {
		http.Error(w, "Invalid before time format (use RFC3339)", http.StatusBadRequest)
		return
	}

	// Query jobs older than cutoff time
	rows, err := db.Query(`
		SELECT job_id, username 
		FROM batch_jobs 
		WHERE created_at < ? 
		ORDER BY created_at ASC
	`, beforeTime.Format("2006-01-02 15:04:05"))

	if err != nil {
		log.Printf("[ERROR] Failed to query old jobs: %v", err)
		http.Error(w, "Database query failed", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type JobInfo struct {
		JobID    string `json:"job_id"`
		Username string `json:"username"`
	}

	var jobs []JobInfo
	for rows.Next() {
		var job JobInfo
		if err := rows.Scan(&job.JobID, &job.Username); err != nil {
			continue
		}
		jobs = append(jobs, job)
	}

	log.Printf("[CLEANUP] Found %d jobs older than %s", len(jobs), beforeTime.Format("2006-01-02 15:04:05"))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"jobs":  jobs,
		"count": len(jobs),
	})
}

func jobQueuedHandler(w http.ResponseWriter, r *http.Request) {
	// Get all queued jobs
	rows, err := db.Query(`
		SELECT job_id, username, total_files, created_at, input_path, output_path 
		FROM batch_jobs 
		WHERE status = 'queued' 
		ORDER BY created_at ASC
	`)
	if err != nil {
		log.Printf("[ERROR] Failed to query queued jobs: %v", err)
		http.Error(w, "Database query failed", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type QueuedJob struct {
		JobID      string  `json:"job_id"`
		Username   string  `json:"username"`
		TotalFiles int     `json:"total_files"`
		CreatedAt  string  `json:"created_at"`
		InputPath  *string `json:"input_path"`
		OutputPath *string `json:"output_path"`
	}

	var jobs []QueuedJob
	for rows.Next() {
		var job QueuedJob
		if err := rows.Scan(&job.JobID, &job.Username, &job.TotalFiles, &job.CreatedAt, &job.InputPath, &job.OutputPath); err != nil {
			log.Printf("[ERROR] Failed to scan queued job: %v", err)
			continue
		}
		jobs = append(jobs, job)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"jobs":  jobs,
		"count": len(jobs),
	})
}

// Add after jobQueuedHandler
func batchNextHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get next queued job and atomically mark as processing
	tx, err := db.Begin()
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()

	var job struct {
		JobID    string `json:"job_id"`
		Username string `json:"username"`
		Status   string `json:"status"`
	}

	err = tx.QueryRow(`
		SELECT job_id, username, status 
		FROM batch_jobs 
		WHERE status = 'queued' 
		ORDER BY created_at ASC 
		LIMIT 1
	`).Scan(&job.JobID, &job.Username, &job.Status)

	if err == sql.ErrNoRows {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	if err != nil {
		log.Printf("[ERROR] Failed to query next job: %v", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	// Claim the job (mark as processing)
	_, err = tx.Exec(`
		UPDATE batch_jobs 
		SET status = 'processing', started_at = CURRENT_TIMESTAMP 
		WHERE job_id = ?
	`, job.JobID)

	if err != nil {
		log.Printf("[ERROR] Failed to claim job: %v", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	if err := tx.Commit(); err != nil {
		log.Printf("[ERROR] Failed to commit transaction: %v", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	log.Printf("[INFO] Claimed job %s for processing", job.JobID)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(job)
}

// API Key handlers

func generateAPIKey() (string, string, string) {
	// Generate 32 random bytes
	bytes := make([]byte, 32)
	rand.Read(bytes)
	
	// Create key with prefix
	key := "yoss_" + hex.EncodeToString(bytes)
	prefix := key[:13] // "yoss_" + 8 chars
	
	// Hash the full key for storage
	hash := sha256.Sum256([]byte(key))
	hashStr := hex.EncodeToString(hash[:])
	
	return key, prefix, hashStr
}

func hashAPIKey(key string) string {
	hash := sha256.Sum256([]byte(key))
	return hex.EncodeToString(hash[:])
}

func apiKeyCreateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Name     string `json:"name"`
		Username string `json:"username"`
		Scopes   string `json:"scopes"`
		// ExpiresIn is optional, in hours (0 = never)
		ExpiresIn int `json:"expires_in"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if req.Name == "" || req.Username == "" {
		http.Error(w, "name and username are required", http.StatusBadRequest)
		return
	}

	if req.Scopes == "" {
		req.Scopes = "read,write"
	}

	// Generate API key
	key, prefix, keyHash := generateAPIKey()

	// Calculate expiry
	var expiresAt *time.Time
	if req.ExpiresIn > 0 {
		t := time.Now().Add(time.Duration(req.ExpiresIn) * time.Hour)
		expiresAt = &t
	}

	// Insert into database
	var result sql.Result
	var err error
	if expiresAt != nil {
		result, err = db.Exec(`INSERT INTO api_keys (key_hash, key_prefix, name, username, scopes, expires_at) 
			VALUES (?, ?, ?, ?, ?, ?)`,
			keyHash, prefix, req.Name, req.Username, req.Scopes, expiresAt.Format("2006-01-02 15:04:05"))
	} else {
		result, err = db.Exec(`INSERT INTO api_keys (key_hash, key_prefix, name, username, scopes) 
			VALUES (?, ?, ?, ?, ?)`,
			keyHash, prefix, req.Name, req.Username, req.Scopes)
	}

	if err != nil {
		log.Printf("[ERROR] Failed to create API key: %v", err)
		http.Error(w, "Failed to create API key", http.StatusInternalServerError)
		return
	}

	id, _ := result.LastInsertId()
	log.Printf("[API-KEY] Created key %s for user %s (id=%d)", prefix, req.Username, id)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":         id,
		"key":        key, // Only returned once!
		"prefix":     prefix,
		"name":       req.Name,
		"scopes":     req.Scopes,
		"expires_at": expiresAt,
		"message":    "Store this key securely - it won't be shown again!",
	})
}

func apiKeyListHandler(w http.ResponseWriter, r *http.Request) {
	username := strings.TrimPrefix(r.URL.Path, "/api-keys/list/")
	
	// If no username in path, list all (admin only)
	var rows *sql.Rows
	var err error
	if username == "" || username == "all" {
		rows, err = db.Query(`SELECT id, key_prefix, name, username, scopes, created_at, expires_at, last_used_at, is_active 
			FROM api_keys ORDER BY created_at DESC`)
	} else {
		rows, err = db.Query(`SELECT id, key_prefix, name, username, scopes, created_at, expires_at, last_used_at, is_active 
			FROM api_keys WHERE username = ? ORDER BY created_at DESC`, username)
	}

	if err != nil {
		http.Error(w, "Database query failed", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type APIKeyInfo struct {
		ID         int64   `json:"id"`
		Prefix     string  `json:"prefix"`
		Name       string  `json:"name"`
		Username   string  `json:"username"`
		Scopes     string  `json:"scopes"`
		CreatedAt  string  `json:"created_at"`
		ExpiresAt  *string `json:"expires_at"`
		LastUsedAt *string `json:"last_used_at"`
		IsActive   bool    `json:"is_active"`
	}

	keys := []APIKeyInfo{}
	for rows.Next() {
		var k APIKeyInfo
		var isActive int
		if err := rows.Scan(&k.ID, &k.Prefix, &k.Name, &k.Username, &k.Scopes, &k.CreatedAt, &k.ExpiresAt, &k.LastUsedAt, &isActive); err != nil {
			continue
		}
		k.IsActive = isActive == 1
		keys = append(keys, k)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"keys":  keys,
		"total": len(keys),
	})
}

func apiKeyDeleteHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "DELETE" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	idStr := strings.TrimPrefix(r.URL.Path, "/api-keys/delete/")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid key ID", http.StatusBadRequest)
		return
	}

	result, err := db.Exec("DELETE FROM api_keys WHERE id = ?", id)
	if err != nil {
		http.Error(w, "Failed to delete API key", http.StatusInternalServerError)
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		http.Error(w, "API key not found", http.StatusNotFound)
		return
	}

	log.Printf("[API-KEY] Deleted key id=%d", id)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
}

func apiKeyRevokeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	idStr := strings.TrimPrefix(r.URL.Path, "/api-keys/revoke/")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid key ID", http.StatusBadRequest)
		return
	}

	_, err = db.Exec("UPDATE api_keys SET is_active = 0 WHERE id = ?", id)
	if err != nil {
		http.Error(w, "Failed to revoke API key", http.StatusInternalServerError)
		return
	}

	log.Printf("[API-KEY] Revoked key id=%d", id)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "revoked"})
}

func apiKeyValidateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Key string `json:"key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if req.Key == "" {
		http.Error(w, "key is required", http.StatusBadRequest)
		return
	}

	// Hash the provided key
	keyHash := hashAPIKey(req.Key)

	// Look up in database
	var id int64
	var username, scopes string
	var expiresAt *string
	var isActive int

	err := db.QueryRow(`SELECT id, username, scopes, expires_at, is_active FROM api_keys WHERE key_hash = ?`, keyHash).
		Scan(&id, &username, &scopes, &expiresAt, &isActive)

	if err == sql.ErrNoRows {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"valid":   false,
			"message": "Invalid API key",
		})
		return
	}

	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	// Check if active
	if isActive != 1 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"valid":   false,
			"message": "API key has been revoked",
		})
		return
	}

	// Check expiry
	if expiresAt != nil && *expiresAt != "" {
		expiry, err := time.Parse("2006-01-02 15:04:05", *expiresAt)
		if err == nil && time.Now().After(expiry) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"valid":   false,
				"message": "API key has expired",
			})
			return
		}
	}

	// Update last_used_at
	db.Exec("UPDATE api_keys SET last_used_at = CURRENT_TIMESTAMP WHERE id = ?", id)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"valid":    true,
		"username": username,
		"scopes":   scopes,
	})
}

func main() {
	// Load LDAP configuration
	ldapServer = os.Getenv("LDAP_SERVER") 
	ldapBindDN = os.Getenv("LDAP_BIND_DN")
	ldapBindPassword = os.Getenv("LDAP_BIND_PASSWORD")
	ldapSearchBase = os.Getenv("LDAP_SEARCH_BASE")
	dcCACertPath = os.Getenv("DC_CA_CERT_PATH")

	syncInterval := os.Getenv("LDAP_SYNC_INTERVAL")
	if syncInterval != "" {
		if interval, err := strconv.Atoi(syncInterval); err == nil {
			ldapSyncInterval = interval
		} else {
			ldapSyncInterval = 3600 // Default 1 hour
		}
	} else {
		ldapSyncInterval = 3600
	}

	if err := initDB(); err != nil {
		log.Fatalf("Failed to init database: %v", err)
	}

	// LDAP sync disabled for testing - use manual endpoints only
	if ldapServer != "" && ldapBindDN != "" && ldapBindPassword != "" {
		log.Printf("LDAP configured for manual testing and sync only")
	} else {
		log.Printf("LDAP not configured")
	}

	http.HandleFunc("/lookup/", lookupHandler)
	http.HandleFunc("/health", healthHandler)
	http.HandleFunc("/add-test-data", addTestDataHandler)
	http.HandleFunc("/ldap/sync", ldapSyncHandler)
	http.HandleFunc("/ldap/status", ldapStatusHandler)
	http.HandleFunc("/ldap/test", ldapTestHandler)
	http.HandleFunc("/ldap/sync-limited", ldapLimitedSyncHandler)
	http.HandleFunc("/ldap/sync-full", ldapLimitedSyncHandler) // Same function, production endpoint
	http.HandleFunc("/accounts/list", accountsListHandler)
	http.HandleFunc("/sensitive/list", sensitiveListHandler)
	http.HandleFunc("/sensitive/add", sensitiveAddHandler)
	http.HandleFunc("/sensitive/delete", sensitiveDeleteHandler)
	http.HandleFunc("/org-settings/list", orgSettingsListHandler)
	http.HandleFunc("/org-settings/update", orgSettingsUpdateHandler)
	http.HandleFunc("/org-settings/public", orgSettingsPublicHandler)

	// Batch job endpoints
	http.HandleFunc("/jobs/create", jobCreateHandler)
	http.HandleFunc("/jobs/status/", jobStatusHandler)
	http.HandleFunc("/jobs/list/", jobListHandler)
	http.HandleFunc("/jobs/update", jobUpdateHandler)
	http.HandleFunc("/jobs/queued", jobQueuedHandler)
	http.HandleFunc("/jobs/delete/", jobDeleteHandler)
	http.HandleFunc("/jobs/cleanup", jobCleanupListHandler)
	http.HandleFunc("/batch/next", batchNextHandler)

	// API key endpoints
	http.HandleFunc("/api-keys/create", apiKeyCreateHandler)
	http.HandleFunc("/api-keys/list/", apiKeyListHandler)
	http.HandleFunc("/api-keys/list", apiKeyListHandler)
	http.HandleFunc("/api-keys/delete/", apiKeyDeleteHandler)
	http.HandleFunc("/api-keys/revoke/", apiKeyRevokeHandler)
	http.HandleFunc("/api-keys/validate", apiKeyValidateHandler)

	log.Printf("Database service starting on port 8081")
	log.Fatal(http.ListenAndServe(":8081", nil))
}
