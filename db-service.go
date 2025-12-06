package main

import (
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

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
	);`

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

	log.Printf("Database service starting on port 8081")
	log.Fatal(http.ListenAndServe(":8081", nil))
}
