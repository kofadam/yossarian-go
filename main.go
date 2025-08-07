package main

import (
	"archive/zip"
	"bytes"
	// "compress/gzip"
	"crypto/rand"
	"encoding/hex"
	"net/url"
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
    lastSanitizedFiles    map[string]string
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
	passwordRegex   = regexp.MustCompile(`(?i)(:([^:@\s]{3,50})@|password["':=\s]+["']?([^"',\s]{3,50})["']?)`)
	// commentRegex    = regexp.MustCompile(`(?m)^#.*$`)
	sensitiveRegex  *regexp.Regexp
)

func init() {
	adminPassword = os.Getenv("ADMIN_PASSWORD")
	
	// Load sensitive terms from environment variable (ConfigMap)
	sensitiveTermsEnv := os.Getenv("SENSITIVE_TERMS")
	if sensitiveTermsEnv != "" {
		sensitiveTermsOrg = strings.Split(sensitiveTermsEnv, ",")
		// Trim whitespace from each term
		for i, term := range sensitiveTermsOrg {
			sensitiveTermsOrg[i] = strings.TrimSpace(term)
		}
		sensitiveRegex = regexp.MustCompile(`(?i)\b(` + strings.Join(sensitiveTermsOrg, "|") + `)\b`)
	} else {
		// No sensitive terms configured
		sensitiveTermsOrg = []string{}
		sensitiveRegex = nil
	}
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
	// 0. Remove comment blocks (they may contain sensitive metadata)
	// result = commentRegex.ReplaceAllString(result, "[COMMENT-REDACTED]")

	// 1. Replace private keys
	result = privateKeyRegex.ReplaceAllString(result, "[PRIVATE-KEY-REDACTED]")
	
	// 2. Replace JWT tokens
	result = jwtRegex.ReplaceAllString(result, "[JWT-REDACTED]")
	
	// 3. Replace passwords in connection strings and config files
	result = passwordRegex.ReplaceAllString(result, "[PASSWORD-REDACTED]")
	
	// 4. Replace sensitive terms (case-insensitive)
	if sensitiveRegex != nil {
		result = sensitiveRegex.ReplaceAllString(result, "[SENSITIVE]")
	}
	
	// 5. Replace user words
	for _, word := range userWords {
		if word != "" && len(word) > 2 {
			result = strings.ReplaceAll(result, word, "[USER-SENSITIVE]")
		}
	}
	
	// 6. Replace AD accounts
	result = adRegex.ReplaceAllStringFunc(result, func(account string) string {
		if usn, exists := adAccounts[account]; exists {
			return usn
		}
		return "[AD-UNKNOWN]"
	})
	
	// 7. Replace IPs
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

		// Handle ZIP files
		// Handle ZIP files
		if strings.ToLower(filepath.Ext(fileHeader.Filename)) == ".zip" {
			extractedFiles := extractZipContent(content)
			if len(extractedFiles) == 0 {
				log.Printf("No files extracted from ZIP: %s", fileHeader.Filename)
				continue
			}
			
			// Sanitize all extracted files
			var sanitizedFiles []ExtractedFile
			totalZipOriginalSize := 0
			totalZipSanitizedSize := 0
			
			for idx, extracted := range extractedFiles {
				if idx % 10 == 0 {
					log.Printf("Processing file %d/%d in ZIP: %s", idx+1, len(extractedFiles), extracted.Name)
				}
				sanitized := sanitizeText(extracted.Content, userWords)
				sanitizedFiles = append(sanitizedFiles, ExtractedFile{
					Name:    extracted.Name,
					Content: sanitized,
					Mode:    extracted.Mode,
					ModTime: extracted.ModTime,
				})
				totalZipOriginalSize += len(extracted.Content)
				totalZipSanitizedSize += len(sanitized)
			}
			
			// Recreate ZIP archive with sanitized content
			sanitizedZipData, err := createZipArchive(sanitizedFiles)
			if err != nil {
				log.Printf("Failed to recreate ZIP archive %s: %v", fileHeader.Filename, err)
				continue
			}
			
			// Store results for the entire ZIP file
			result := map[string]interface{}{
				"filename":       fileHeader.Filename,
				"original_size":  len(content),
				"sanitized_size": len(sanitizedZipData),
				"processing_time": "N/A", // TODO: Add timing
				"total_ips":      0, // Will be calculated below
				"ad_accounts":    0,
				"jwt_tokens":     0,
				"private_keys":   0,
				"sensitive_terms": 0,
				"user_words":     0,
				"sanitized_content": string(sanitizedZipData),
				"status":         "sanitized",
				"files_processed": len(extractedFiles),
			}
			
			// Calculate total findings across all files
			for _, sanitizedFile := range sanitizedFiles {
				result["total_ips"] = result["total_ips"].(int) + countMatches(sanitizedFile.Content, "[IP-")
				result["ad_accounts"] = result["ad_accounts"].(int) + countMatches(sanitizedFile.Content, "USN")
				result["jwt_tokens"] = result["jwt_tokens"].(int) + countMatches(sanitizedFile.Content, "[JWT-REDACTED]")
				result["private_keys"] = result["private_keys"].(int) + countMatches(sanitizedFile.Content, "[PRIVATE-KEY-REDACTED]")
				result["sensitive_terms"] = result["sensitive_terms"].(int) + countMatches(sanitizedFile.Content, "[SENSITIVE]")
				result["user_words"] = result["user_words"].(int) + countMatches(sanitizedFile.Content, "[USER-SENSITIVE]")
			}
			
			result["sample"] = fmt.Sprintf("ZIP archive with %d files processed", len(extractedFiles))
			
			results = append(results, result)
			totalOriginalSize += len(content)
			totalSanitizedSize += len(sanitizedZipData)
			
			log.Printf("Processed ZIP file: %s (%d files, %d->%d bytes)", fileHeader.Filename, len(extractedFiles), len(content), len(sanitizedZipData))
			continue
		}

		if strings.ToLower(filepath.Ext(fileHeader.Filename)) == ".zip" {
			extractedFiles := extractZipContent(content)
			for _, extracted := range extractedFiles {
				// Sanitize content with timing
				fileStartTime := time.Now()
				sanitized := sanitizeText(extracted.Content, userWords)
				processingTime := time.Since(fileStartTime)

				// Store results for each extracted file
				result := map[string]interface{}{
					"filename":       fmt.Sprintf("%s:%s", fileHeader.Filename, extracted.Name),
					"original_size":  len(extracted.Content),
					"sanitized_size": len(sanitized),
					"processing_time": fmt.Sprintf("%.2fms", float64(processingTime.Nanoseconds())/1000000.0),
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
				totalOriginalSize += len(extracted.Content)
				totalSanitizedSize += len(sanitized)
			}
			continue
		}
		// Sanitize content with timing
		fileStartTime := time.Now()
		sanitized := sanitizeText(string(content), userWords)
		processingTime := time.Since(fileStartTime)

		// Store results
		result := map[string]interface{}{
			"filename":       fileHeader.Filename,
			"original_size":  len(content),
			"sanitized_size": len(sanitized),
			"processing_time": fmt.Sprintf("%.2fms", float64(processingTime.Nanoseconds())/1000000.0),
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
	for _, result := range results {
		combinedSanitized += result["sanitized_content"].(string) + "\n\n"
	}
	lastSanitizedFiles = make(map[string]string)
	for _, result := range results {
		lastSanitizedFiles[result["filename"].(string)] = result["sanitized_content"].(string)
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

func extractZipContent(zipData []byte) []ExtractedFile {
    var extractedFiles []ExtractedFile
    
    reader, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
    if err != nil {
        log.Printf("Failed to read ZIP archive: %v", err)
        return extractedFiles
    }
    
    for _, file := range reader.File {
        // Skip directories
        if file.FileInfo().IsDir() {
            continue
        }
        
        // Skip very large files (>10MB extracted)
        if file.UncompressedSize64 > 10*1024*1024 {
            log.Printf("Skipping large file in ZIP: %s (%d bytes)", file.Name, file.UncompressedSize64)
            continue
        }
        
        // Open file within ZIP
        rc, err := file.Open()
        if err != nil {
            log.Printf("Failed to open file %s in ZIP: %v", file.Name, err)
            continue
        }
        
        // Read file content
        content, err := io.ReadAll(rc)
        rc.Close()
        if err != nil {
            log.Printf("Failed to read file %s in ZIP: %v", file.Name, err)
            continue
        }
        
        // Skip binary files
        if isBinaryContent(content) {
            log.Printf("Skipping binary file in ZIP: %s", file.Name)
            continue
        }
        
        extractedFiles = append(extractedFiles, ExtractedFile{
            Name:    file.Name,
            Content: string(content),
        })
        
        log.Printf("Extracted file from ZIP: %s (%d bytes)", file.Name, len(content))
    }
    
    return extractedFiles
}

func createZipArchive(files []ExtractedFile) ([]byte, error) {
    var buf bytes.Buffer
    zipWriter := zip.NewWriter(&buf)
    
    for _, file := range files {
        header := &zip.FileHeader{
            Name:   file.Name,
            Method: zip.Deflate,
        }
        header.SetMode(file.Mode)
        header.SetModTime(file.ModTime)
        
        writer, err := zipWriter.CreateHeader(header)
        if err != nil {
            return nil, fmt.Errorf("failed to create file header for %s: %v", file.Name, err)
        }
        
        _, err = writer.Write([]byte(file.Content))
        if err != nil {
            return nil, fmt.Errorf("failed to write file %s: %v", file.Name, err)
        }
    }
    
    err := zipWriter.Close()
    if err != nil {
        return nil, fmt.Errorf("failed to close zip writer: %v", err)
    }
    
    return buf.Bytes(), nil
}

type ExtractedFile struct {
    Name    string
    Content string
    Mode    os.FileMode
    ModTime time.Time
}

func downloadHandler(w http.ResponseWriter, r *http.Request) {
    if lastSanitizedContent == "" {
        http.Error(w, "No sanitized content available", http.StatusNotFound)
        return
    }
    
    w.Header().Set("Content-Type", "application/octet-stream")
    w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"sanitized_%s\"", lastSanitizedFilename))
    w.Write([]byte(lastSanitizedContent))
}

func individualFileHandler(w http.ResponseWriter, r *http.Request) {
    filename := strings.TrimPrefix(r.URL.Path, "/download/sanitized/")
    filename, _ = url.QueryUnescape(filename)
    
    if content, exists := lastSanitizedFiles[filename]; exists {
        // Determine content type based on file extension
        contentType := "text/plain"
        if strings.HasSuffix(strings.ToLower(filename), ".zip") {
            contentType = "application/zip"
        }
        
        w.Header().Set("Content-Type", contentType)
        w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
        w.Write([]byte(content))
    } else {
        http.Error(w, "File not found", http.StatusNotFound)
    }
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
	err := templates.ExecuteTemplate(w, "index.html", data)
    if err != nil {
        log.Printf("Template error: %v", err)
        http.Error(w, "Template error", http.StatusInternalServerError)
        return
    }
}

// func individualFileHandler(w http.ResponseWriter, r *http.Request) {
//     filename := strings.TrimPrefix(r.URL.Path, "/download/sanitized/")
//     filename, _ = url.QueryUnescape(filename)
    
//     if content, exists := lastSanitizedFiles[filename]; exists {
//         w.Header().Set("Content-Type", "text/plain")
//         w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
//         fmt.Fprintf(w, "%s", content)
//     } else {
//         http.Error(w, "File not found", http.StatusNotFound)
//     }
// }

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
	http.HandleFunc("/download/sanitized/", individualFileHandler)
	
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
