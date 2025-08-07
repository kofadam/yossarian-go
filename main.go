package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// User info structure for future OIDC
type UserInfo struct {
	Email   string
	Name    string
	Roles   []string
	IsAdmin bool
}

// Global storage for download and admin
var (
	lastSanitizedContent  string
	lastSanitizedFilename string
	adminSessions        = make(map[string]time.Time)
	sessionMutex         sync.Mutex
	templates            *template.Template
)

// Global mapping storage
var (
	ipMappings = make(map[string]string)
	ipCounter  = 1
	mapMutex   sync.Mutex
	
	// Admin configuration
	adminPassword     string
	sensitiveTermsOrg []string
	
	// Mock AD accounts
	adAccounts = map[string]string{
		"CORP\\john.doe":     "USN123456789",
		"CORP\\jane.smith":   "USN987654321", 
		"CORP\\admin":        "USN555666777",
		"svc_backup":         "USN111222333",
		"svc_monitoring":     "USN222333444",
		"SERVER-WEB$":        "USN444555666",
		"COMP01$":           "USN333444555",
	}
)

// Simple patterns
var (
	ipRegex         = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
	adRegex         = regexp.MustCompile(`CORP\\[a-zA-Z0-9._-]+|svc_[a-zA-Z0-9_]+|[A-Z0-9-]+\$`)
	jwtRegex        = regexp.MustCompile(`eyJ[A-Za-z0-9+/=]+\.[A-Za-z0-9+/=]+\.[A-Za-z0-9+/=_-]+`)
	privateKeyRegex = regexp.MustCompile(`-----BEGIN[^-]*KEY-----[\s\S]*?-----END[^-]*KEY-----`)
	sensitiveRegex  *regexp.Regexp
)

func init() {
	adminPassword = os.Getenv("ADMIN_PASSWORD")
	sensitiveTermsOrg = []string{"ProjectApollo", "ClientMegaCorp", "confidential", "classified", "restricted", "internal-only"}
	sensitiveRegex = regexp.MustCompile(`\b(` + strings.Join(sensitiveTermsOrg, "|") + `)\b`)
}

func initTemplates() {
	templates = template.Must(template.ParseGlob("templates/*.html"))
}

func generateSessionID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func isValidAdminSession(r *http.Request) bool {
	cookie, err := r.Cookie("admin_session")
	if err != nil {
		return false
	}
	
	sessionMutex.Lock()
	defer sessionMutex.Unlock()
	
	expiry, exists := adminSessions[cookie.Value]
	if !exists || time.Now().After(expiry) {
		delete(adminSessions, cookie.Value)
		return false
	}
	
	adminSessions[cookie.Value] = time.Now().Add(30 * time.Minute)
	return true
}

func getCurrentUserSafe(r *http.Request) (*UserInfo, bool) {
	// For now, check legacy admin session
	cookie, err := r.Cookie("admin_session")
	if err != nil {
		return nil, false
	}
	
	sessionMutex.Lock()
	defer sessionMutex.Unlock()
	
	if expiry, exists := adminSessions[cookie.Value]; exists {
		if time.Now().After(expiry) {
			delete(adminSessions, cookie.Value)
			return nil, false
		}
		return &UserInfo{
			Name:    "Administrator",
			Email:   "admin@localhost",
			IsAdmin: true,
		}, true
	}
	
	return nil, false
}

func adminRequired(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !isValidAdminSession(r) {
			http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
			return
		}
		handler(w, r)
	}
}

func sanitizeText(text string, userWords []string) string {
	mapMutex.Lock()
	defer mapMutex.Unlock()
	
	result := text
	
	// 1. Replace private keys
	result = privateKeyRegex.ReplaceAllString(result, "[PRIVATE-KEY-REDACTED]")
	
	// 2. Replace JWT tokens
	result = jwtRegex.ReplaceAllString(result, "[JWT-REDACTED]")
	
	// 3. Replace sensitive terms
	result = sensitiveRegex.ReplaceAllString(result, "[SENSITIVE]")
	
	// 4. Replace user words
	for _, word := range userWords {
		if word != "" && len(word) > 2 {
			result = strings.ReplaceAll(result, word, "[USER-SENSITIVE]")
		}
	}
	
	// 5. Replace AD accounts
	result = adRegex.ReplaceAllStringFunc(result, func(account string) string {
		if usn, exists := adAccounts[account]; exists {
			return usn
		}
		return "[AD-UNKNOWN]"
	})
	
	// 6. Replace IPs
	result = ipRegex.ReplaceAllStringFunc(result, func(ip string) string {
		if placeholder, exists := ipMappings[ip]; exists {
			return placeholder
		}
		placeholder := fmt.Sprintf("[IP-%03d]", ipCounter)
		ipMappings[ip] = placeholder
		ipCounter++
		return placeholder
	})
	
	return result
}

func isBinaryContent(content []byte) bool {
	// Simple binary detection - check for null bytes in first 512 bytes
	checkLen := 512
	if len(content) < checkLen {
		checkLen = len(content)
	}
	
	for i := 0; i < checkLen; i++ {
		if content[i] == 0 {
			return true
		}
	}
	return false
}

func isArchiveFile(filename string) bool {
	ext := strings.ToLower(filepath.Ext(filename))
	archives := []string{".zip", ".tar", ".gz", ".rar", ".7z"}
	for _, archive := range archives {
		if ext == archive || strings.HasSuffix(strings.ToLower(filename), ".tar.gz") {
			return true
		}
	}
	return false
}

func countMatches(text, pattern string) int {
	return strings.Count(text, pattern)
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status": "ok", "service": "yossarian-go"}`)
}

func debugHandler(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "text/plain")
    fmt.Fprintf(w, "Templates loaded: %v\n", templates != nil)
    if templates != nil {
        fmt.Fprintf(w, "Template names: %v\n", templates.DefinedTemplates())
    }
}

func uploadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	err := r.ParseMultipartForm(100 << 20) // 100MB total
	if err != nil {
		http.Error(w, "Files too large", http.StatusBadRequest)
		return
	}

	files := r.MultipartForm.File["file"]
	if len(files) == 0 {
		http.Error(w, "No files uploaded", http.StatusBadRequest)
		return
	}

	if len(files) > 10 {
		http.Error(w, "Maximum 10 files allowed", http.StatusBadRequest)
		return
	}

	// Get user words from cookie
	var userWords []string
	if cookie, err := r.Cookie("sensitive_words"); err == nil && cookie.Value != "" {
		words := strings.Split(cookie.Value, ",")
		for _, word := range words {
			word = strings.TrimSpace(word)
			if word != "" && len(word) > 1 {
				userWords = append(userWords, word)
			}
		}
	}

	results := make([]map[string]interface{}, 0)
	totalOriginalSize := 0
	totalSanitizedSize := 0

	for _, fileHeader := range files {
		// Check file size (50MB per file)
		if fileHeader.Size > 50*1024*1024 {
			continue // Skip files over 50MB
		}

		file, err := fileHeader.Open()
		if err != nil {
			continue
		}

		content, err := io.ReadAll(file)
		file.Close()
		if err != nil {
			continue
		}

		// Basic binary detection
		if isBinaryContent(content) && !isArchiveFile(fileHeader.Filename) {
			continue // Skip binary files
		}

		// Sanitize content
		sanitized := sanitizeText(string(content), userWords)
		
		// Store results
		result := map[string]interface{}{
			"filename":       fileHeader.Filename,
			"original_size":  len(content),
			"sanitized_size": len(sanitized),
			"total_ips":      countMatches(sanitized, "[IP-"),
			"ad_accounts":    countMatches(sanitized, "USN"),
			"jwt_tokens":     countMatches(sanitized, "[JWT-REDACTED]"),
			"private_keys":   countMatches(sanitized, "[PRIVATE-KEY-REDACTED]"),
			"sensitive_terms": countMatches(sanitized, "[SENSITIVE]"),
			"user_words":     countMatches(sanitized, "[USER-SENSITIVE]"),
			"sanitized_content": sanitized,
			"status":         "sanitized",
		}

		if len(sanitized) > 200 {
			result["sample"] = sanitized[:200]
		} else {
			result["sample"] = sanitized
		}

		results = append(results, result)
		totalOriginalSize += len(content)
		totalSanitizedSize += len(sanitized)
	}

	// Store for download (combine all sanitized content)
	combinedSanitized := ""
	for i, result := range results {
		combinedSanitized += fmt.Sprintf("=== FILE %d: %s ===\n", i+1, result["filename"])
		combinedSanitized += result["sanitized_content"].(string) + "\n\n" 
	}
	lastSanitizedContent = combinedSanitized
	lastSanitizedFilename = "sanitized-files.txt"

	// Return JSON response
	w.Header().Set("Content-Type", "application/json")
	response := map[string]interface{}{
		"files":              results,
		"total_files":        len(results),
		"total_original":     totalOriginalSize,
		"total_sanitized":    totalSanitizedSize,
		"total_ip_mappings":  len(ipMappings),
		"status":             "completed",
	}

	jsonBytes, _ := json.Marshal(response)
	w.Write(jsonBytes)
}

func downloadHandler(w http.ResponseWriter, r *http.Request) {
	if lastSanitizedContent == "" {
		http.Error(w, "No sanitized content available", http.StatusNotFound)
		return
	}
	
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"sanitized_%s\"", lastSanitizedFilename))
	fmt.Fprintf(w, "%s", lastSanitizedContent)
}

func mappingsHandler(w http.ResponseWriter, r *http.Request) {
	mapMutex.Lock()
	defer mapMutex.Unlock()
	
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment; filename=\"ip_mappings.csv\"")
	
	fmt.Fprintf(w, "original_ip,placeholder,type,timestamp\n")
	for original, placeholder := range ipMappings {
		fmt.Fprintf(w, "%s,%s,ip,%s\n", original, placeholder, time.Now().Format(time.RFC3339))
	}
}

func adminLoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `
		<h1>Yossarian Admin Login</h1>
		<form method="post">
			<p>
				<label>Admin Password:</label><br>
				<input type="password" name="password" required style="padding: 5px; width: 200px;">
			</p>
			<button type="submit">Login</button>
		</form>
		`)
		return
	}
	
	if r.Method == "POST" {
		r.ParseForm()
		password := r.FormValue("password")
		
		if adminPassword == "" {
			http.Error(w, "Admin password not configured", http.StatusInternalServerError)
			return
		}
		
		if password == adminPassword {
			sessionID := generateSessionID()
			
			sessionMutex.Lock()
			adminSessions[sessionID] = time.Now().Add(30 * time.Minute)
			sessionMutex.Unlock()
			
			cookie := &http.Cookie{
				Name:     "admin_session",
				Value:    sessionID,
				Path:     "/admin",
				HttpOnly: true,
				Secure:   false,
				MaxAge:   1800,
			}
			http.SetCookie(w, cookie)
			
			http.Redirect(w, r, "/admin", http.StatusSeeOther)
		} else {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `
			<h1>Yossarian Admin Login</h1>
			<p style="color: red;">Invalid password</p>
			<form method="post">
				<p>
					<label>Admin Password:</label><br>
					<input type="password" name="password" required style="padding: 5px; width: 200px;">
				</p>
				<button type="submit">Login</button>
			</form>
			`)
		}
	}
}

func adminDashboardHandler(w http.ResponseWriter, r *http.Request) {
	user, _ := getCurrentUserSafe(r)
	
	data := struct {
		UserName         string
		UserEmail        string
		IPMappings       int
		ADAccounts       int
		SensitiveTerms   int
		AuthMode         string
		OIDCEnabled      bool
	}{
		UserName:       "Administrator",
		UserEmail:      "admin@company.com",
		IPMappings:     len(ipMappings),
		ADAccounts:     len(adAccounts),
		SensitiveTerms: len(sensitiveTermsOrg),
		AuthMode:       "Password Only",
		OIDCEnabled:    false, // Will be true when OIDC is implemented
	}
	
	if user != nil {
		data.UserName = user.Name
		data.UserEmail = user.Email
	}
	
	w.Header().Set("Content-Type", "text/html")
	templates.ExecuteTemplate(w, "admin.html", data)
}

func adminLogoutHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("admin_session")
	if err == nil {
		sessionMutex.Lock()
		delete(adminSessions, cookie.Value)
		sessionMutex.Unlock()
	}
	
	http.SetCookie(w, &http.Cookie{
		Name:   "admin_session",
		Value:  "",
		Path:   "/admin",
		MaxAge: -1,
	})
	
	http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
}

func adminADHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		r.ParseForm()
		account := strings.TrimSpace(r.FormValue("account"))
		usn := strings.TrimSpace(r.FormValue("usn"))
		
		if account != "" && usn != "" {
			adAccounts[account] = usn
			http.Redirect(w, r, "/admin/ad-accounts", http.StatusSeeOther)
			return
		}
	}
	
	w.Header().Set("Content-Type", "text/html")
	
	accountsList := ""
	for account, usn := range adAccounts {
		accountsList += fmt.Sprintf("<tr><td>%s</td><td>%s</td></tr>", account, usn)
	}
	
	fmt.Fprintf(w, `
	<h1>AD Account Management</h1>
	
	<h2>Current AD Accounts</h2>
	<table border="1" style="border-collapse: collapse;">
		<tr><th>Account</th><th>USN</th></tr>
		%s
	</table>
	
	<h2>Add New Account</h2>
	<form method="post">
		<p>
			<label>Account (e.g., CORP\username):</label><br>
			<input type="text" name="account" required style="width: 300px; padding: 5px;">
		</p>
		<p>
			<label>USN (e.g., USN123456789):</label><br>
			<input type="text" name="usn" required style="width: 300px; padding: 5px;">
		</p>
		<button type="submit">Add Account</button>
	</form>
	
	<p><a href="/admin">← Back to Dashboard</a></p>
	`, accountsList)
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	data := struct {
		UserAuthenticated bool
		UserName         string
		UserEmail        string
		IsAdmin          bool
	}{
		UserAuthenticated: false,
		UserName:         "",
		UserEmail:        "",
		IsAdmin:          false,
	}
	
	// Check if user is authenticated (for future OIDC)
	if user, authenticated := getCurrentUserSafe(r); authenticated {
		data.UserAuthenticated = true
		data.UserName = user.Name
		data.UserEmail = user.Email
		data.IsAdmin = user.IsAdmin
	}
	
	w.Header().Set("Content-Type", "text/html")
	templates.ExecuteTemplate(w, "index.html", data)
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	
	if adminPassword == "" {
		adminPassword = "admin123"
		log.Println("WARNING: Using default admin password 'admin123'. Set ADMIN_PASSWORD environment variable.")
	}

	// Initialize templates
	initTemplates()

	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/health", healthHandler)
	http.HandleFunc("/upload", uploadHandler)
	http.HandleFunc("/mappings/csv", mappingsHandler)
	http.HandleFunc("/download/sanitized", downloadHandler)
	
	// Admin routes
	http.HandleFunc("/admin/login", adminLoginHandler)
	http.HandleFunc("/admin/logout", adminLogoutHandler)
	http.HandleFunc("/admin", adminRequired(adminDashboardHandler))
	http.HandleFunc("/admin/ad-accounts", adminRequired(adminADHandler))

	// Debug route
	http.HandleFunc("/debug", debugHandler)

	log.Printf("Server starting on port %s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}