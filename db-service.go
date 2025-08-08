package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	_ "github.com/mattn/go-sqlite3"
)

var (
	db     *sql.DB
	dbPath = "/data/yossarian.db"
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

func main() {
	if err := initDB(); err != nil {
		log.Fatalf("Failed to init database: %v", err)
	}

	http.HandleFunc("/lookup/", lookupHandler)
	http.HandleFunc("/health", healthHandler)
	http.HandleFunc("/add-test-data", addTestDataHandler)

	log.Printf("Database service starting on port 8081")
	log.Fatal(http.ListenAndServe(":8081", nil))
}