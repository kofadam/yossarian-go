package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Global storage for download and admin
var (
	lastSanitizedContent  string
	lastSanitizedFilename string
	adminSessions        = make(map[string]time.Time)
	sessionMutex         sync.Mutex
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
	ipRegex        = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
	adRegex        = regexp.MustCompile(`CORP\\[a-zA-Z0-9._-]+|svc_[a-zA-Z0-9_]+|[A-Z0-9-]+\$`)
	jwtRegex       = regexp.MustCompile(`eyJ[A-Za-z0-9+/=]+\.[A-Za-z0-9+/=]+\.[A-Za-z0-9+/=_-]+`)
	privateKeyRegex = regexp.MustCompile(`-----BEGIN[^-]*KEY-----[\s\S]*?-----END[^-]*KEY-----`)
	sensitiveRegex *regexp.Regexp
)

func init() {
	adminPassword = os.Getenv("ADMIN_PASSWORD")
	sensitiveTermsOrg = []string{"ProjectApollo", "ClientMegaCorp", "confidential", "classified", "restricted", "internal-only"}
	sensitiveRegex = regexp.MustCompile(`\b(` + strings.Join(sensitiveTermsOrg, "|") + `)\b`)
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

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status": "ok", "service": "yossarian-go"}`)
}

func uploadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	err := r.ParseMultipartForm(100 << 20)
	if err != nil {
		http.Error(w, "File too large", http.StatusBadRequest)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "No file uploaded", http.StatusBadRequest)
		return
	}
	defer file.Close()

	content, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, "Failed to read file", http.StatusInternalServerError)
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
	
	// Sanitize content
	sanitized := sanitizeText(string(content), userWords)
	
	// Store for download
	lastSanitizedContent = sanitized
	lastSanitizedFilename = header.Filename
	
	// Get sample and escape for JSON
	sample := sanitized
	if len(sample) > 200 {
		sample = sample[:200]
	}
	
	sample = strings.ReplaceAll(sample, "\\", "\\\\")
	sample = strings.ReplaceAll(sample, "\"", "\\\"")
	sample = strings.ReplaceAll(sample, "\n", "\\n")
	sample = strings.ReplaceAll(sample, "\r", "\\r")
	sample = strings.ReplaceAll(sample, "\t", "\\t")
	
	// Return results
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{
		"filename": "%s",
		"original_size": %d,
		"sanitized_size": %d,
		"sample": "%s",
		"total_ips": %d,
		"user_words": %d,
		"status": "sanitized"
	}`, header.Filename, len(content), len(sanitized), sample, len(ipMappings), len(userWords))
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
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `
	<h1>Yossarian Admin Dashboard</h1>
	
	<h2>📊 System Stats</h2>
	<ul>
		<li>Active IP Mappings: %d</li>
		<li>AD Accounts Loaded: %d</li>
		<li>Organization Sensitive Terms: %d</li>
	</ul>
	
	<h2>🔧 Configuration</h2>
	<p><a href="/admin/ad-accounts">Manage AD Accounts</a></p>
	
	<h2>🏠 Navigation</h2>
	<p><a href="/">← Back to Main App</a></p>
	<p><a href="/admin/logout">Logout</a></p>
	`, len(ipMappings), len(adAccounts), len(sensitiveTermsOrg))
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
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `
	<h1>Yossarian Go - Personal Sanitization</h1>
	<p>Log sanitization with personal sensitive words | <a href="/admin">Admin Panel</a></p>
	<p><a href="/health">Health Check</a></p>
	
	<h2>Personal Sensitive Words</h2>
	<p>Add your own sensitive terms (stored in browser cookies):</p>
	<form id="wordsForm">
		<textarea id="sensitiveWords" placeholder="Enter words separated by commas, e.g.: MyCompany, SecretProject, internal-server" 
			style="width: 100%%; height: 80px;"></textarea>
		<br><br>
		<button type="button" onclick="saveWords()">Save Words</button>
		<button type="button" onclick="clearWords()">Clear All</button>
		<span id="status" style="margin-left: 10px;"></span>
	</form>
	
	<h2>Upload & Sanitize</h2>
	<form action="/upload" method="post" enctype="multipart/form-data">
		<input type="file" name="file" required>
		<button type="submit">Upload & Sanitize File</button>
	</form>
	
	<h2>Downloads</h2>
	<p><a href="/download/sanitized">Download Sanitized File</a></p>
	<p><a href="/mappings/csv">Download IP Mappings CSV</a></p>
	
	<script>
		window.onload = function() {
			loadWords();
		}
		
		function loadWords() {
			const words = getCookie('sensitive_words');
			if (words) {
				document.getElementById('sensitiveWords').value = words.replace(/,/g, ', ');
			}
		}
		
		function saveWords() {
			const words = document.getElementById('sensitiveWords').value;
			const cleanWords = words.split(',').map(w => w.trim()).filter(w => w).join(',');
			setCookie('sensitive_words', cleanWords, 30);
			document.getElementById('status').innerText = 'Words saved!';
			setTimeout(() => document.getElementById('status').innerText = '', 3000);
		}
		
		function clearWords() {
			document.getElementById('sensitiveWords').value = '';
			setCookie('sensitive_words', '', -1);
			document.getElementById('status').innerText = 'Words cleared!';
			setTimeout(() => document.getElementById('status').innerText = '', 3000);
		}
		
		function setCookie(name, value, days) {
			const expires = new Date();
			expires.setTime(expires.getTime() + (days * 24 * 60 * 60 * 1000));
			document.cookie = name + '=' + value + ';expires=' + expires.toUTCString() + ';path=/';
		}
		
		function getCookie(name) {
			const nameEQ = name + "=";
			const cookies = document.cookie.split(';');
			for(let i = 0; i < cookies.length; i++) {
				let cookie = cookies[i].trim();
				if (cookie.indexOf(nameEQ) === 0) {
					return cookie.substring(nameEQ.length);
				}
			}
			return null;
		}
	</script>
	`)
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

	log.Printf("Server starting on port %s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}