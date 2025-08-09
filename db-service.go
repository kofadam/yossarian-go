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
	);`
	
	_, err = db.Exec(createTableSQL)
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

	conn, err := connectLDAP()
	if err != nil {
		return fmt.Errorf("LDAP connection failed: %v", err)
	}
	defer conn.Close()

	// Search for user accounts
	userSearchRequest := ldap.NewSearchRequest(
		ldapSearchBase,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(&(objectClass=user)(!(objectClass=computer))(sAMAccountName=*))",
		[]string{"sAMAccountName", "distinguishedName"},
		nil,
	)

	userSearchResult, err := conn.Search(userSearchRequest)
	if err != nil {
		return fmt.Errorf("user search failed: %v", err)
	}

	// Search for computer accounts
	computerSearchRequest := ldap.NewSearchRequest(
		ldapSearchBase,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(&(objectClass=computer)(sAMAccountName=*))",
		[]string{"sAMAccountName", "distinguishedName"},
		nil,
	)

	computerSearchResult, err := conn.Search(computerSearchRequest)
	if err != nil {
		return fmt.Errorf("computer search failed: %v", err)
	}

	// Process results and update database
	accountCount := 0
	usn := 100000000 // Starting USN number

	// Process user accounts
	for _, entry := range userSearchResult.Entries {
		samAccountName := entry.GetAttributeValue("sAMAccountName")
		if samAccountName != "" {
			account := fmt.Sprintf("CORP\\%s", samAccountName)
			usnString := fmt.Sprintf("USN%d", usn)
			
			_, err := db.Exec("INSERT OR REPLACE INTO ad_accounts (account, usn) VALUES (?, ?)", account, usnString)
			if err != nil {
				log.Printf("Failed to insert user account %s: %v", account, err)
			} else {
				accountCount++
				usn++
			}
		}
	}

	// Process computer accounts
	for _, entry := range computerSearchResult.Entries {
		samAccountName := entry.GetAttributeValue("sAMAccountName")
		if samAccountName != "" {
			// Computer accounts already end with $
			account := samAccountName
			usnString := fmt.Sprintf("USN%d", usn)
			
			_, err := db.Exec("INSERT OR REPLACE INTO ad_accounts (account, usn) VALUES (?, ?)", account, usnString)
			if err != nil {
				log.Printf("Failed to insert computer account %s: %v", account, err)
			} else {
				accountCount++
				usn++
			}
		}
	}

	log.Printf("LDAP sync completed: %d accounts synchronized", accountCount)
	return nil
}

func lookupHandler(w http.ResponseWriter, r *http.Request) {
	account := strings.TrimPrefix(r.URL.Path, "/lookup/")
	
	var usn string
	err := db.QueryRow("SELECT usn FROM ad_accounts WHERE account = ?", account).Scan(&usn)
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
	var accountCount int
	err := db.QueryRow("SELECT COUNT(*) FROM ad_accounts").Scan(&accountCount)
	if err != nil {
		http.Error(w, "Database query failed", http.StatusInternalServerError)
		return
	}

	status := map[string]interface{}{
		"ldap_configured": ldapServer != "" && ldapBindDN != "" && ldapBindPassword != "",
		"ldap_server":     ldapServer,
		"sync_interval":   ldapSyncInterval,
		"account_count":   accountCount,
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

	// Test search without importing
	searchRequest := ldap.NewSearchRequest(
		ldapSearchBase,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 10, 0, false,
		"(&(objectClass=user)(!(objectClass=computer))(sAMAccountName=*))",
		[]string{"sAMAccountName", "distinguishedName"},
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

	log.Printf("Database service starting on port 8081")
	log.Fatal(http.ListenAndServe(":8081", nil))
}