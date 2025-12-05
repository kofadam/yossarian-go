package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	// "compress/gzip"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	// ✅ ADD: Prometheus client libraries
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// User info structure for future OIDC
type UserInfo struct {
	Email   string
	Name    string
	Roles   []string
	IsAdmin bool
}

// Version information - set during build
var (
	Version   = "v0.7.0"
	BuildTime = "unknown"
	GitCommit = "unknown"
)

// Global storage for download and admin
var (
	lastSanitizedContent  string
	lastSanitizedFilename string
	lastSanitizedFiles    map[string]string
	adminSessions         = make(map[string]time.Time)
	sessionUsers          = make(map[string]string)   // sessionID -> username
	sessionRoles          = make(map[string][]string) // sessionID -> roles
	sessionMutex          sync.Mutex
	templates             *template.Template
)

// Detailed replacement tracking
type Replacement struct {
	Category  string
	File      string
	Line      int
	Original  string
	Sanitized string
}

var (
	detailedReplacements []Replacement
	replacementMutex     sync.Mutex
)

var (
	adLookupCache = make(map[string]string)
	cacheMutex    sync.RWMutex
)

func recordReplacement(category, filename string, lineNum int, original, sanitized string) {
	replacementMutex.Lock()
	defer replacementMutex.Unlock()

	detailedReplacements = append(detailedReplacements, Replacement{
		Category:  category,
		File:      filename,
		Line:      lineNum,
		Original:  original,
		Sanitized: sanitized,
	})
}

func lookupADAccountCached(account string) string {
	// Check cache first
	cacheMutex.RLock()
	if cached, exists := adLookupCache[account]; exists {
		cacheMutex.RUnlock()
		adCacheHits.Inc() // ✅ ADD: Record cache hit
		return cached
	}
	cacheMutex.RUnlock()

	adCacheMisses.Inc() // ✅ ADD: Record cache miss

	// Not in cache, do lookup
	usn := lookupADAccount(account)

	// Cache the result (including empty results)
	cacheMutex.Lock()
	adLookupCache[account] = usn
	cacheMutex.Unlock()

	return usn
}

// Global mapping storage
var (
	ipMappings = make(map[string]string)
	ipCounter  = 1
	mapMutex   sync.Mutex

	// Admin configuration
	adminPassword     string
	sensitiveTermsOrg []string
	serverPrefixes    []string
	serverRegex       *regexp.Regexp

	// File upload limits (configurable via environment)
	maxTotalUploadSizeMB int
	maxFileSizeMB        int
	maxZipFileSizeMB     int
	maxFileCount         int

	// OIDC configuration
	oidcEnabled      bool
	oidcIssuerURL    string
	oidcClientID     string
	oidcClientSecret string
	oidcRedirectURL  string
	oidcProvider     *oidc.Provider
	oauth2Config     *oauth2.Config
	customHTTPClient *http.Client

	// AD service configuration
	adServiceURL string

	// Auto SSO configuration
	autoSSOEnabled bool
)

// ✅ ADD: Prometheus metrics
var (
	// HTTP request metrics
	httpRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "yossarian_http_requests_total",
			Help: "Total number of HTTP requests",
		},
		[]string{"method", "endpoint", "status"},
	)

	// Upload metrics
	uploadSize = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "yossarian_upload_size_bytes",
			Help:    "Size of uploaded files in bytes",
			Buckets: []float64{1024, 10240, 102400, 1048576, 10485760, 104857600}, // 1KB to 100MB
		},
		[]string{"file_type"},
	)

	processingDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "yossarian_processing_duration_seconds",
			Help:    "Time taken to process files",
			Buckets: []float64{0.1, 0.5, 1, 2, 5, 10, 30, 60}, // 0.1s to 60s
		},
		[]string{"operation"},
	)

	// Pattern detection metrics
	patternsDetected = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "yossarian_patterns_detected_total",
			Help: "Total number of sensitive patterns detected",
		},
		[]string{"pattern_type"},
	)

	// Error counter
	errorsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "yossarian_errors_total",
			Help: "Total number of errors by type",
		},
		[]string{"error_type"},
	)

	// AD cache metrics
	adCacheHits = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "yossarian_ad_cache_hits_total",
			Help: "Total number of AD cache hits",
		},
	)

	adCacheMisses = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "yossarian_ad_cache_misses_total",
			Help: "Total number of AD cache misses",
		},
	)

	// Active sessions gauge
	activeSessions = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "yossarian_active_sessions",
			Help: "Number of active user sessions",
		},
	)
)

// Simple patterns
var (
	ipRegex         = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
	adRegex         = regexp.MustCompile(`\b[A-Z0-9-]+\\[a-zA-Z0-9._-]{4,15}\b|\b[a-zA-Z0-9._-]{4,15}@[a-zA-Z0-9.-]+\b|\b[A-Z0-9-]{4,15}\$\b|\b(?:A-M|B-P|D-[1-9CKLMQT]|H-[FP]|J-P|L-[1-9P]|S-C|T-[CL])-[A-Za-z0-9-]{6,11}\b|\bD-PC-[A-Za-z0-9-]{5,10}\b|\b(?:a-m|b-p|d-[1-9cklmqt]|h-[fp]|j-p|l-[1-9p]|s-c|t-[cl])-[a-zA-Z0-9-]{6,11}\b|\bd-pc-[a-zA-Z0-9-]{5,10}\b|\b(?:dvd|til|DVD|TIL)[0-9a-zA-Z]{1,20}\b|\\\\([A-Z0-9-]+)\\|\\\\[^\\]+\\[^\\]+\\([a-zA-Z0-9._-]{4,15})\\|\\Users\\([a-zA-Z0-9._-]{4,15})\\|/([a-zA-Z0-9._-]{4,15})/`)
	jwtRegex        = regexp.MustCompile(`eyJ[A-Za-z0-9+/=]+\.[A-Za-z0-9+/=]+\.[A-Za-z0-9+/=_-]+`)
	privateKeyRegex = regexp.MustCompile(`-----BEGIN[^-]*KEY-----[\s\S]*?-----END[^-]*KEY-----`)
	passwordRegex   = regexp.MustCompile(`(?i)(:([^:@\s]{3,50})@|password["':=\s]+["']?([^"',\s]{3,50})["']?)`)
	// commentRegex    = regexp.MustCompile(`(?m)^#.*$`)
	sensitiveRegex *regexp.Regexp
)
var sensitiveTermsMap = make(map[string]string)

func loadSensitiveTerms() {
	if adServiceURL == "" {
		return
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(fmt.Sprintf("%s/sensitive/list", adServiceURL))
	if err != nil {
		log.Printf("Failed to load sensitive terms from database: %v", err)
		loadSensitiveTermsFromConfigMap()
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		log.Printf("Database service returned %d for sensitive terms", resp.StatusCode)
		loadSensitiveTermsFromConfigMap()
		return
	}

	var result struct {
		Terms map[string]string `json:"terms"`
		Total int               `json:"total"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		log.Printf("Failed to decode sensitive terms: %v", err)
		loadSensitiveTermsFromConfigMap()
		return
	}

	// Store terms with their replacements
	sensitiveTermsMap = result.Terms
	sensitiveTermsOrg = make([]string, 0, len(result.Terms))
	for term := range result.Terms {
		sensitiveTermsOrg = append(sensitiveTermsOrg, term)
	}

	if len(sensitiveTermsOrg) > 0 {
		sensitiveRegex = regexp.MustCompile(`(?i)\b(` + strings.Join(sensitiveTermsOrg, "|") + `)\b`)
		log.Printf("Loaded %d sensitive terms from database", len(sensitiveTermsOrg))
	} else {
		sensitiveRegex = nil
		log.Printf("No sensitive terms found in database")
	}
}

func loadServerPrefixes() {
	serverPrefixesEnv := os.Getenv("SERVER_PREFIXES")
	if serverPrefixesEnv != "" {
		serverPrefixes = strings.Split(serverPrefixesEnv, ",")
		for i, prefix := range serverPrefixes {
			serverPrefixes[i] = strings.TrimSpace(prefix)
		}

		// Build dynamic regex for server patterns
		// Format: SLLS-prd-dbserver, ABCD-dev-appserver
		escapedPrefixes := make([]string, len(serverPrefixes))
		for i, prefix := range serverPrefixes {
			escapedPrefixes[i] = regexp.QuoteMeta(prefix)
		}

		// Pattern: (SLLS|ABCD|...)-(prd|dev|tst|uat|sit|qa|prod|stg)-[alphanumeric]{2,20}
		serverPattern := fmt.Sprintf(`\b(?:%s)-(?:prd|dev|tst|uat|sit|qa|prod|stg)-[a-zA-Z0-9]{2,20}\b`, strings.Join(escapedPrefixes, "|"))
		serverRegex = regexp.MustCompile(serverPattern)

		log.Printf("Loaded %d server prefixes from ConfigMap", len(serverPrefixes))
	} else {
		serverPrefixes = []string{}
		serverRegex = nil
		log.Printf("No server prefixes configured")
	}
}

func loadSensitiveTermsFromConfigMap() {
	sensitiveTermsEnv := os.Getenv("SENSITIVE_TERMS")
	if sensitiveTermsEnv != "" {
		sensitiveTermsOrg = strings.Split(sensitiveTermsEnv, ",")
		for i, term := range sensitiveTermsOrg {
			sensitiveTermsOrg[i] = strings.TrimSpace(term)
		}
		sensitiveRegex = regexp.MustCompile(`(?i)\b(` + strings.Join(sensitiveTermsOrg, "|") + `)\b`)
		log.Printf("Loaded %d sensitive terms from ConfigMap", len(sensitiveTermsOrg))
	} else {
		sensitiveTermsOrg = []string{}
		sensitiveRegex = nil
		log.Printf("No sensitive terms configured")
	}
}

// Removed loadComputerPrefixes() function - was causing memory issues

// Helper function to get environment variable as integer with default
func getEnvAsInt(key string, defaultValue int) int {
	valueStr := os.Getenv(key)
	if valueStr == "" {
		return defaultValue
	}
	value, err := strconv.Atoi(valueStr)
	if err != nil {
		log.Printf("WARNING: Invalid value for %s: %s, using default: %d", key, valueStr, defaultValue)
		return defaultValue
	}
	return value
}

func init() {
	adminPassword = os.Getenv("ADMIN_PASSWORD")

	// AD service endpoint
	adServiceURL = os.Getenv("AD_SERVICE_URL")
	if adServiceURL == "" {
		adServiceURL = "http://yossarian-db-service:8081"
	}

	// Configure file upload limits from environment (with defaults)
	maxTotalUploadSizeMB = getEnvAsInt("MAX_TOTAL_UPLOAD_SIZE_MB", 100)
	maxFileSizeMB = getEnvAsInt("MAX_FILE_SIZE_MB", 50)
	maxZipFileSizeMB = getEnvAsInt("MAX_ZIP_FILE_SIZE_MB", 10)
	maxFileCount = getEnvAsInt("MAX_FILE_COUNT", 10)

	log.Printf("File upload limits configured: Total=%dMB, PerFile=%dMB, ZipFile=%dMB, MaxFiles=%d",
		maxTotalUploadSizeMB, maxFileSizeMB, maxZipFileSizeMB, maxFileCount)

	// OIDC configuration
	oidcEnabled = os.Getenv("OIDC_ENABLED") == "true"
	oidcIssuerURL = os.Getenv("OIDC_ISSUER_URL")
	oidcClientID = os.Getenv("OIDC_CLIENT_ID")
	oidcClientSecret = os.Getenv("OIDC_CLIENT_SECRET")
	oidcRedirectURL = os.Getenv("OIDC_REDIRECT_URL")

	// Setup custom HTTP client with CA support
	customHTTPClient = getHTTPClient()

	// Initialize OIDC if enabled
	if oidcEnabled && oidcIssuerURL != "" {
		ctx := context.WithValue(context.Background(), oauth2.HTTPClient, customHTTPClient)

		provider, err := oidc.NewProvider(ctx, oidcIssuerURL)

		if err != nil {
			log.Printf("WARNING: Failed to initialize OIDC provider: %v", err)
			oidcEnabled = false
			autoSSOEnabled = false
		} else {
			oidcProvider = provider
			oauth2Config = &oauth2.Config{
				ClientID:     oidcClientID,
				ClientSecret: oidcClientSecret,
				RedirectURL:  oidcRedirectURL,
				Endpoint:     provider.Endpoint(),
				Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
			}
			autoSSOEnabled = true // Enable auto SSO when OIDC is successfully configured
			log.Printf("OIDC enabled with issuer: %s", oidcIssuerURL)
			log.Printf("Auto SSO enforcement: ENABLED - all users must authenticate via OIDC")
		}
	} else {
		autoSSOEnabled = false
		log.Printf("OIDC not configured - Auto SSO enforcement: DISABLED")
	}

	// Load sensitive terms from database (legacy ConfigMap as fallback)
	loadSensitiveTerms()

	// Load server prefixes from ConfigMap
	loadServerPrefixes()
}

func getHTTPClient() *http.Client {
	certPath := os.Getenv("CA_CERT_PATH")
	if certPath == "" {
		return http.DefaultClient
	}

	if _, err := os.Stat(certPath); err == nil {
		caCert, err := os.ReadFile(certPath)
		if err == nil {
			caCertPool := x509.NewCertPool()
			if caCertPool.AppendCertsFromPEM(caCert) {
				return &http.Client{
					Transport: &http.Transport{
						TLSClientConfig: &tls.Config{
							RootCAs: caCertPool,
						},
					},
				}
			}
		}
	}

	return http.DefaultClient
}

func oidcLoginHandler(w http.ResponseWriter, r *http.Request) {
	if !oidcEnabled {
		http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
		return
	}

	state := generateSessionID() // Reuse your existing function

	// Store state in session for CSRF protection
	sessionMutex.Lock()
	adminSessions[state] = time.Now().Add(10 * time.Minute)
	sessionMutex.Unlock()

	http.Redirect(w, r, oauth2Config.AuthCodeURL(state), http.StatusSeeOther)
}

func oidcCallbackHandler(w http.ResponseWriter, r *http.Request) {
	if !oidcEnabled {
		http.Error(w, "OIDC not enabled", http.StatusInternalServerError)
		return
	}

	// Verify state
	state := r.URL.Query().Get("state")
	sessionMutex.Lock()
	_, validState := adminSessions[state]
	delete(adminSessions, state)
	sessionMutex.Unlock()

	if !validState {
		http.Error(w, "Invalid state", http.StatusBadRequest)
		return
	}

	// Exchange code for token
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, customHTTPClient)
	token, err := oauth2Config.Exchange(ctx, r.URL.Query().Get("code"))
	if err != nil {
		http.Error(w, "Failed to exchange token", http.StatusInternalServerError)
		return
	}

	// Get user info
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "No id_token", http.StatusInternalServerError)
		return
	}

	verifier := oidcProvider.Verifier(&oidc.Config{ClientID: oidcClientID})
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		http.Error(w, "Failed to verify token", http.StatusInternalServerError)
		return
	}

	// Extract claims including roles
	var claims struct {
		Email             string `json:"email"`
		Name              string `json:"name"`
		PreferredUsername string `json:"preferred_username"`
		ResourceAccess    struct {
			YossarianGo struct {
				Roles []string `json:"roles"`
			} `json:"yossarian-go"`
		} `json:"resource_access"`
		RealmAccess struct {
			Roles []string `json:"roles"`
		} `json:"realm_access"`
	}
	idToken.Claims(&claims)

	// Use preferred_username or email as display name
	username := claims.PreferredUsername
	if username == "" {
		username = claims.Email
	}
	if username == "" {
		username = "SSO User"
	}

	// Extract roles (try client roles first, then realm roles)
	var userRoles []string
	if len(claims.ResourceAccess.YossarianGo.Roles) > 0 {
		userRoles = claims.ResourceAccess.YossarianGo.Roles
	} else {
		userRoles = claims.RealmAccess.Roles
	}

	log.Printf("OIDC: User %s has roles: %v", username, userRoles)
	if username == "" {
		username = claims.Email
	}
	if username == "" {
		username = "SSO User"
	}

	// Create session
	sessionID := generateSessionID()
	sessionMutex.Lock()
	adminSessions[sessionID] = time.Now().Add(30 * time.Minute)
	sessionUsers[sessionID] = username
	sessionRoles[sessionID] = userRoles
	activeSessions.Inc() // ✅ ADD: Track active sessions
	sessionMutex.Unlock()

	log.Printf("OIDC: User %s logged in successfully", username)

	cookie := &http.Cookie{
		Name:     "admin_session",
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		MaxAge:   1800,
	}
	http.SetCookie(w, cookie)

	http.Redirect(w, r, "/", http.StatusSeeOther)
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

func hasRole(r *http.Request, requiredRole string) bool {
	cookie, err := r.Cookie("admin_session")
	if err != nil {
		return false
	}

	sessionMutex.Lock()
	defer sessionMutex.Unlock()

	if roles, exists := sessionRoles[cookie.Value]; exists {
		for _, role := range roles {
			if role == requiredRole {
				return true
			}
		}
	}
	return false
}

func showAccessDenied(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusForbidden)
	fmt.Fprintf(w, `
	<!DOCTYPE html>
	<html>
	<head>
		<title>Access Denied - Yossarian Go</title>
		<style>
			body { font-family: Arial, sans-serif; text-align: center; margin-top: 100px; }
			.container { max-width: 500px; margin: 0 auto; }
			.error-icon { font-size: 64px; color: #d32f2f; margin-bottom: 20px; }
			h1 { color: #d32f2f; margin-bottom: 20px; }
			p { color: #666; margin-bottom: 30px; line-height: 1.5; }
			.btn { background: #1976d2; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px; }
		</style>
	</head>
	<body>
		<div class="container">
			<div class="error-icon">🚫</div>
			<h1>Access Denied</h1>
			<p>You don't have the required permissions to access Yossarian Go.</p>
			<p>Please contact your administrator to request <strong>admin</strong> or <strong>user</strong> role access.</p>
			<a href="/auth/logout" class="btn">Logout & Try Different Account</a>
		</div>
	</body>
	</html>
	`)
}

func adminRequired(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !isValidAdminSession(r) {
			http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
			return
		}
		// Check if user has admin role
		if !hasRole(r, "admin") {
			http.Error(w, "Access denied: Admin role required", http.StatusForbidden)
			return
		}
		handler(w, r)
	}
}

// lookupADAccount queries the AD service for account USN
func lookupADAccount(account string) string {
	if adServiceURL == "" {
		return ""
	}

	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(fmt.Sprintf("%s/lookup/%s", adServiceURL, url.QueryEscape(account)))
	if err != nil {
		log.Printf("AD lookup failed for %s: %v", account, err)
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return ""
	}

	var result struct {
		USN string `json:"usn"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return ""
	}

	return result.USN
}

func sanitizeText(text string, userWords []string, trackReplacements bool, filename string) (string, map[string]int) {
	mapMutex.Lock()
	defer mapMutex.Unlock()

	// Track statistics for logging
	stats := map[string]int{
		"private_keys":    0,
		"jwt_tokens":      0,
		"passwords":       0,
		"ad_accounts":     0,
		"ad_cache_hits":   0,
		"ad_cache_misses": 0,
		"sensitive_terms": 0,
		"user_words":      0,
		"ip_addresses":    0,
	}

	result := text
	// 0. Remove comment blocks (they may contain sensitive metadata)
	// result = commentRegex.ReplaceAllString(result, "[COMMENT-REDACTED]")

	// 1. Replace private keys
	privateKeyMatches := privateKeyRegex.FindAllStringIndex(result, -1)
	stats["private_keys"] = len(privateKeyMatches)

	if trackReplacements && len(privateKeyMatches) > 0 {
		for _, match := range privateKeyMatches {
			original := result[match[0]:match[1]]
			lineNum := strings.Count(result[:match[0]], "\n") + 1
			recordReplacement("Private_Key", filename, lineNum, original, "[PRIVATE-KEY-REDACTED]")
		}
	}

	result = privateKeyRegex.ReplaceAllString(result, "[PRIVATE-KEY-REDACTED]")
	if stats["private_keys"] > 0 {
		log.Printf("[DEBUG] Pattern detection - Private keys: %d found", stats["private_keys"])
	}

	// 2. Replace JWT tokens
	jwtMatches := jwtRegex.FindAllStringIndex(result, -1)
	stats["jwt_tokens"] = len(jwtMatches)

	if trackReplacements && len(jwtMatches) > 0 {
		for _, match := range jwtMatches {
			original := result[match[0]:match[1]]
			lineNum := strings.Count(result[:match[0]], "\n") + 1
			recordReplacement("JWT_Token", filename, lineNum, original, "[JWT-REDACTED]")
		}
	}

	result = jwtRegex.ReplaceAllString(result, "[JWT-REDACTED]")
	if stats["jwt_tokens"] > 0 {
		log.Printf("[DEBUG] Pattern detection - JWT tokens: %d found", stats["jwt_tokens"])
	}

	// 3. Replace passwords in connection strings and config files
	passwordMatches := passwordRegex.FindAllStringIndex(result, -1)
	stats["passwords"] = len(passwordMatches)

	if trackReplacements && len(passwordMatches) > 0 {
		for _, match := range passwordMatches {
			original := result[match[0]:match[1]]
			lineNum := strings.Count(result[:match[0]], "\n") + 1
			recordReplacement("Password", filename, lineNum, original, "[PASSWORD-REDACTED]")
		}
	}

	result = passwordRegex.ReplaceAllString(result, "[PASSWORD-REDACTED]")
	if stats["passwords"] > 0 {
		log.Printf("[DEBUG] Pattern detection - Passwords: %d found", stats["passwords"])
	}

	// 4. Replace AD accounts with caching (case-insensitive)
	adCandidates := adRegex.FindAllStringIndex(result, -1)
	adCandidateCount := len(adCandidates)

	matchIndex := 0
	result = adRegex.ReplaceAllStringFunc(result, func(account string) string {
		matchPos := adCandidates[matchIndex]
		matchIndex++
		// Always normalize to lowercase for consistent cache lookups
		normalizedAccount := strings.ToLower(account)

		// Check cache first
		cacheMutex.RLock()
		cached, inCache := adLookupCache[normalizedAccount]
		cacheMutex.RUnlock()

		if inCache {
			stats["ad_cache_hits"]++
			adCacheHits.Inc()
			adCacheHits.Inc() // ✅ ADD: Record to Prometheus
			if cached != "" {
				stats["ad_accounts"]++
				return cached
			}
			return account
		}

		// Not in cache, do lookup
		stats["ad_cache_misses"]++
		adCacheMisses.Inc()
		if usn := lookupADAccountCached(normalizedAccount); usn != "" {
			stats["ad_accounts"]++

			// Track replacement
			if trackReplacements {
				lineNum := strings.Count(result[:matchPos[0]], "\n") + 1
				recordReplacement("AD_Account", filename, lineNum, account, usn)
			}

			return usn
		}
		// If not found in AD database, preserve original text (not an AD account)
		return account
	})

	if adCandidateCount > 0 {
		log.Printf("[DEBUG] Pattern detection - AD accounts: %d candidates, %d confirmed (cache hit: %d, miss: %d)",
			adCandidateCount, stats["ad_accounts"], stats["ad_cache_hits"], stats["ad_cache_misses"])
	}

	// 4b. Replace server accounts with dynamic prefix matching
	if serverRegex != nil {
		result = serverRegex.ReplaceAllStringFunc(result, func(account string) string {
			normalizedAccount := strings.ToLower(account)
			if usn := lookupADAccountCached(normalizedAccount); usn != "" {
				return usn
			}
			return account
		})
	}

	// 5. Replace sensitive terms with custom replacements
	if sensitiveRegex != nil {
		sensitiveMatches := sensitiveRegex.FindAllStringIndex(result, -1)
		stats["sensitive_terms"] = len(sensitiveMatches)

		matchIndexSensitive := 0
		result = sensitiveRegex.ReplaceAllStringFunc(result, func(match string) string {
			matchPos := sensitiveMatches[matchIndexSensitive]
			matchIndexSensitive++

			replacement := "[SENSITIVE]"
			for term, customReplacement := range sensitiveTermsMap {
				if strings.EqualFold(match, term) {
					replacement = customReplacement
					break
				}
			}

			// Track replacement
			if trackReplacements {
				lineNum := strings.Count(result[:matchPos[0]], "\n") + 1
				recordReplacement("Sensitive_Term", filename, lineNum, match, replacement)
			}

			return replacement
		})

		if stats["sensitive_terms"] > 0 {
			log.Printf("[DEBUG] Pattern detection - Sensitive terms: %d found", stats["sensitive_terms"])
		}
	}

	// 6. Replace user words
	for _, word := range userWords {
		if word != "" && len(word) > 2 {
			// Find all occurrences
			if trackReplacements {
				startPos := 0
				for {
					idx := strings.Index(result[startPos:], word)
					if idx == -1 {
						break
					}
					actualPos := startPos + idx
					lineNum := strings.Count(result[:actualPos], "\n") + 1
					recordReplacement("User_Word", filename, lineNum, word, "[USER-SENSITIVE]")
					startPos = actualPos + len(word)
					stats["user_words"]++
				}
			} else {
				count := strings.Count(result, word)
				stats["user_words"] += count
			}
			result = strings.ReplaceAll(result, word, "[USER-SENSITIVE]")
		}
	}
	if stats["user_words"] > 0 {
		log.Printf("[DEBUG] Pattern detection - User words: %d found", stats["user_words"])
	}

	// 7. Replace IPs
	ipMatches := ipRegex.FindAllStringIndex(result, -1)
	uniqueIPs := make(map[string]bool)
	for _, match := range ipMatches {
		ip := result[match[0]:match[1]]
		uniqueIPs[ip] = true
	}

	matchIndexIP := 0
	result = ipRegex.ReplaceAllStringFunc(result, func(ip string) string {
		matchPos := ipMatches[matchIndexIP]
		matchIndexIP++

		stats["ip_addresses"]++
		var placeholder string
		if existing, exists := ipMappings[ip]; exists {
			placeholder = existing
		} else {
			placeholder = fmt.Sprintf("[IP-%03d]", ipCounter)
			ipMappings[ip] = placeholder
			ipCounter++
		}

		// Track replacement
		if trackReplacements {
			lineNum := strings.Count(result[:matchPos[0]], "\n") + 1
			recordReplacement("IP_Address", filename, lineNum, ip, placeholder)
		}

		return placeholder
	})

	if len(uniqueIPs) > 0 {
		log.Printf("[DEBUG] Pattern detection - IP addresses: %d total occurrences, %d unique",
			stats["ip_addresses"], len(uniqueIPs))
	}

	return result, stats
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

func mainHealthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status": "ok", "service": "yossarian-go", "version": "%s", "build_time": "%s", "commit": "%s"}`, Version, BuildTime, GitCommit)
}

func userInfoHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("admin_session")
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"authenticated": false}`)
		return
	}

	sessionMutex.Lock()
	username, exists := sessionUsers[cookie.Value]
	sessionMutex.Unlock()

	if !exists {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"authenticated": false}`)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"authenticated": true, "username": "%s"}`, username)
}

func configLimitsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	config := map[string]interface{}{
		"max_total_upload_size_mb": maxTotalUploadSizeMB,
		"max_file_size_mb":         maxFileSizeMB,
		"max_zip_file_size_mb":     maxZipFileSizeMB,
		"max_file_count":           maxFileCount,
	}
	json.NewEncoder(w).Encode(config)
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

	// Get username for audit logging
	username := "anonymous"
	if cookie, err := r.Cookie("admin_session"); err == nil {
		sessionMutex.Lock()
		if user, exists := sessionUsers[cookie.Value]; exists {
			username = user
		}
		sessionMutex.Unlock()
	}

	err := r.ParseMultipartForm(int64(maxTotalUploadSizeMB) << 20)
	if err != nil {
		log.Printf("[ERROR] File upload failed: form parsing error for user=%s: %v", username, err)
		http.Error(w, fmt.Sprintf("Files too large (max %dMB total)", maxTotalUploadSizeMB), http.StatusBadRequest)
		return
	}

	files := r.MultipartForm.File["file"]
	if len(files) == 0 {
		log.Printf("[WARN] File upload rejected: no files provided by user=%s", username)
		http.Error(w, "No files uploaded", http.StatusBadRequest)
		return
	}

	if len(files) > maxFileCount {
		log.Printf("[ERROR] File upload rejected: %d files exceeds limit of %d for user=%s",
			len(files), maxFileCount, username)
		http.Error(w, fmt.Sprintf("Maximum %d files allowed", maxFileCount), http.StatusBadRequest)
		return
	}

	log.Printf("[INFO] File upload started: user=%s, files=%d", username, len(files))

	// Check if detailed report was requested
	generateDetailedReport := r.FormValue("generate_detailed_report") == "true"
	if generateDetailedReport {
		// Clear previous detailed replacements
		replacementMutex.Lock()
		detailedReplacements = []Replacement{}
		replacementMutex.Unlock()
		log.Printf("[INFO] Detailed replacement report requested by user=%s", username)
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

	// Clear previous files only at start of new batch
	if lastSanitizedFiles == nil {
		lastSanitizedFiles = make(map[string]string)
	}

	for _, fileHeader := range files {
		// Check file size
		if fileHeader.Size > int64(maxFileSizeMB)*1024*1024 {
			log.Printf("[ERROR] File rejected: %s exceeds %dMB limit (%d bytes)",
				fileHeader.Filename, maxFileSizeMB, fileHeader.Size)
			continue
		}

		log.Printf("[DEBUG] File received: %s (%d bytes)", fileHeader.Filename, fileHeader.Size)

		file, err := fileHeader.Open()
		if err != nil {
			log.Printf("[ERROR] Failed to open file %s: %v", fileHeader.Filename, err)
			continue
		}

		content, err := io.ReadAll(file)
		file.Close()
		if err != nil {
			log.Printf("[ERROR] Failed to read file %s: %v", fileHeader.Filename, err)
			continue
		}

		// Basic binary detection
		isBinary := isBinaryContent(content)
		isArchive := isArchiveFile(fileHeader.Filename)
		log.Printf("[DEBUG] File type check: %s - binary=%v, archive=%v", fileHeader.Filename, isBinary, isArchive)

		if isBinary && !isArchive {
			log.Printf("[WARN] File skipped: %s (binary content detected)", fileHeader.Filename)
			continue // Skip binary files
		}

		log.Printf("[INFO] Processing file: %s (%.2f KB)", fileHeader.Filename, float64(len(content))/1024)

		// Handle ZIP files
		if strings.ToLower(filepath.Ext(fileHeader.Filename)) == ".zip" {
			log.Printf("[INFO] ZIP archive detected: %s (%.2f MB)", fileHeader.Filename, float64(len(content))/1024/1024)
			fileStartTime := time.Now()

			log.Printf("[DEBUG] Extracting ZIP contents: %s", fileHeader.Filename)
			extractedFiles := extractZipContent(content)
			extractionTime := time.Since(fileStartTime)

			if len(extractedFiles) == 0 {
				log.Printf("[ERROR] No files extracted from ZIP: %s", fileHeader.Filename)
				continue
			}

			totalUncompressedSize := 0
			for _, ef := range extractedFiles {
				totalUncompressedSize += len(ef.Content)
			}

			log.Printf("[INFO] ZIP extraction complete: %s - %d files extracted (%.2f MB uncompressed) in %.2fs",
				fileHeader.Filename, len(extractedFiles), float64(totalUncompressedSize)/1024/1024, extractionTime.Seconds())
			log.Printf("[INFO] Processing ZIP contents: %s (%d files)", fileHeader.Filename, len(extractedFiles))

			// Sanitize all extracted files
			var sanitizedFiles []ExtractedFile
			totalZipOriginalSize := 0
			totalZipSanitizedSize := 0
			totalZipStats := map[string]int{
				"private_keys": 0, "jwt_tokens": 0, "passwords": 0,
				"ad_accounts": 0, "sensitive_terms": 0, "user_words": 0,
				"ip_addresses": 0,
			}

			for idx, extracted := range extractedFiles {
				log.Printf("[DEBUG] Processing file %d/%d in ZIP: %s (%.2f KB)",
					idx+1, len(extractedFiles), extracted.Name, float64(len(extracted.Content))/1024)

				fileStartTime := time.Now()
				fullFilename := fmt.Sprintf("%s:%s", fileHeader.Filename, extracted.Name)
				sanitized, fileStats := sanitizeText(extracted.Content, userWords, generateDetailedReport, fullFilename)
				processingTime := time.Since(fileStartTime)

				log.Printf("[PERF] Sanitized %d/%d: %s (%.2fs)", idx+1, len(extractedFiles), extracted.Name, processingTime.Seconds())

				// Aggregate statistics
				for key, value := range fileStats {
					totalZipStats[key] += value
				}
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
			log.Printf("[INFO] Recreating sanitized ZIP archive: %s", fileHeader.Filename)
			recreateStartTime := time.Now()

			sanitizedZipData, err := createZipArchive(sanitizedFiles)
			if err != nil {
				log.Printf("[ERROR] Failed to recreate ZIP archive %s: %v", fileHeader.Filename, err)
				continue
			}

			recreationTime := time.Since(recreateStartTime)
			log.Printf("[DEBUG] ZIP recreation completed in %.2fs", recreationTime.Seconds())

			// Calculate processing time for ZIP (use file start time)
			zipProcessingTime := time.Since(fileStartTime)

			compressionRatio := (1.0 - float64(len(sanitizedZipData))/float64(totalZipOriginalSize)) * 100
			log.Printf("[INFO] ZIP archive created: %s (%.2f MB sanitized, %.2f MB original, %.1f%% compression)",
				fileHeader.Filename, float64(len(sanitizedZipData))/1024/1024,
				float64(totalZipOriginalSize)/1024/1024, compressionRatio)

			// Store results for the entire ZIP file
			result := map[string]interface{}{
				"filename":          fileHeader.Filename,
				"original_size":     len(content),
				"sanitized_size":    len(sanitizedZipData),
				"processing_time":   fmt.Sprintf("%.2fs", zipProcessingTime.Seconds()),
				"total_ips":         0, // Will be calculated below
				"ad_accounts":       0,
				"jwt_tokens":        0,
				"private_keys":      0,
				"sensitive_terms":   0,
				"user_words":        0,
				"status":            "sanitized",
				"files_processed":   len(extractedFiles),
				"sanitized_content": string(sanitizedZipData), // Keep for download, exclude from reports
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

			log.Printf("[INFO] ZIP processing summary: %s", fileHeader.Filename)
			log.Printf("[INFO]   Files: %d processed", len(extractedFiles))
			log.Printf("[INFO]   Size: %.2f MB → %.2f MB (%.1f%% reduction)",
				float64(totalZipOriginalSize)/1024/1024,
				float64(totalZipSanitizedSize)/1024/1024,
				(1.0-float64(totalZipSanitizedSize)/float64(totalZipOriginalSize))*100)
			log.Printf("[INFO]   Patterns: IPs=%d, AD=%d, JWT=%d, Keys=%d, Sensitive=%d, UserWords=%d",
				totalZipStats["ip_addresses"], totalZipStats["ad_accounts"], totalZipStats["jwt_tokens"],
				totalZipStats["private_keys"], totalZipStats["sensitive_terms"], totalZipStats["user_words"])
			log.Printf("[PERF] Total processing time: %.2fs (%.2f MB/sec)",
				zipProcessingTime.Seconds(), float64(totalZipOriginalSize)/1024/1024/zipProcessingTime.Seconds())

			log.Printf("[AUDIT] ZIP processed: user=%s, file=%s, files=%d, total_patterns=%d",
				username, fileHeader.Filename, len(extractedFiles),
				totalZipStats["ip_addresses"]+totalZipStats["ad_accounts"]+totalZipStats["jwt_tokens"]+
					totalZipStats["private_keys"]+totalZipStats["sensitive_terms"]+totalZipStats["user_words"])

			continue
		}

		if strings.ToLower(filepath.Ext(fileHeader.Filename)) == ".zip" {
			extractedFiles := extractZipContent(content)
			for _, extracted := range extractedFiles {
				// Sanitize content with timing
				fileStartTime := time.Now()
				sanitized, _ := sanitizeText(extracted.Content, userWords, false, extracted.Name)
				processingTime := time.Since(fileStartTime)

				// Store results for each extracted file
				result := map[string]interface{}{
					"filename":          fmt.Sprintf("%s:%s", fileHeader.Filename, extracted.Name),
					"original_size":     len(extracted.Content),
					"sanitized_size":    len(sanitized),
					"processing_time":   fmt.Sprintf("%.2fs", processingTime.Seconds()),
					"total_ips":         countMatches(sanitized, "[IP-"),
					"ad_accounts":       countMatches(sanitized, "USN"),
					"jwt_tokens":        countMatches(sanitized, "[JWT-REDACTED]"),
					"private_keys":      countMatches(sanitized, "[PRIVATE-KEY-REDACTED]"),
					"sensitive_terms":   countMatches(sanitized, "[SENSITIVE]"),
					"user_words":        countMatches(sanitized, "[USER-SENSITIVE]"),
					"sanitized_content": sanitized,
					"status":            "sanitized",
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
		log.Printf("[PERF] Sanitization started: %s", fileHeader.Filename)

		sanitized, sanitizeStats := sanitizeText(string(content), userWords, generateDetailedReport, fileHeader.Filename)
		processingTime := time.Since(fileStartTime)

		processingRateMBps := float64(len(content)) / 1024 / 1024 / processingTime.Seconds()
		log.Printf("[PERF] Sanitization completed: %s in %.2fs (%.2f MB/sec)",
			fileHeader.Filename, processingTime.Seconds(), processingRateMBps)

		totalPatterns := sanitizeStats["private_keys"] + sanitizeStats["jwt_tokens"] +
			sanitizeStats["passwords"] + sanitizeStats["ad_accounts"] +
			sanitizeStats["sensitive_terms"] + sanitizeStats["user_words"] +
			len(ipMappings)

		log.Printf("[INFO] Results - File: %s, IPs: %d, AD: %d, JWT: %d, Keys: %d, Sensitive: %d, UserWords: %d, Total: %d",
			fileHeader.Filename,
			sanitizeStats["ip_addresses"],
			sanitizeStats["ad_accounts"],
			sanitizeStats["jwt_tokens"],
			sanitizeStats["private_keys"],
			sanitizeStats["sensitive_terms"],
			sanitizeStats["user_words"],
			totalPatterns)
		// ✅ ADD: Record metrics to Prometheus
		fileExt := filepath.Ext(fileHeader.Filename)
		uploadSize.WithLabelValues(fileExt).Observe(float64(len(content)))
		processingDuration.WithLabelValues("upload").Observe(processingTime.Seconds())

		// Record pattern detections from sanitizeStats
		patternsDetected.WithLabelValues("ip_address").Add(float64(sanitizeStats["ip_addresses"]))
		patternsDetected.WithLabelValues("ad_account").Add(float64(sanitizeStats["ad_accounts"]))
		patternsDetected.WithLabelValues("jwt_token").Add(float64(sanitizeStats["jwt_tokens"]))
		patternsDetected.WithLabelValues("private_key").Add(float64(sanitizeStats["private_keys"]))
		patternsDetected.WithLabelValues("password").Add(float64(sanitizeStats["passwords"]))
		patternsDetected.WithLabelValues("sensitive_term").Add(float64(sanitizeStats["sensitive_terms"]))
		patternsDetected.WithLabelValues("user_word").Add(float64(sanitizeStats["user_words"]))
		// Store results
		result := map[string]interface{}{
			"filename":          fileHeader.Filename,
			"original_size":     len(content),
			"sanitized_size":    len(sanitized),
			"processing_time":   fmt.Sprintf("%.2fs", processingTime.Seconds()),
			"total_ips":         countMatches(sanitized, "[IP-"),
			"ad_accounts":       countMatches(sanitized, "USN"),
			"jwt_tokens":        countMatches(sanitized, "[JWT-REDACTED]"),
			"private_keys":      countMatches(sanitized, "[PRIVATE-KEY-REDACTED]"),
			"sensitive_terms":   countMatches(sanitized, "[SENSITIVE]"),
			"user_words":        countMatches(sanitized, "[USER-SENSITIVE]"),
			"sanitized_content": sanitized,
			"status":            "sanitized",
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
		if content, exists := result["sanitized_content"]; exists && content != nil {
			combinedSanitized += content.(string) + "\n\n"
		}
	}
	// Store files for download
	log.Printf("[INFO] Storing %d files for download", len(results))

	storedCount := 0
	totalStoredSize := 0

	// Don't recreate map - append to existing files
	for _, result := range results {
		if content, exists := result["sanitized_content"]; exists && content != nil {
			filename := result["filename"].(string)
			contentStr := content.(string)
			lastSanitizedFiles[filename] = contentStr

			storedCount++
			totalStoredSize += len(contentStr)

			log.Printf("[DEBUG] File stored for download: %s (%.2f KB)", filename, float64(len(contentStr))/1024)
		}
	}

	log.Printf("[INFO] Storage complete: %d files stored (%.2f MB total)",
		storedCount, float64(totalStoredSize)/1024/1024)
	log.Printf("[INFO] Total files available for download: %d", len(lastSanitizedFiles))

	lastSanitizedContent = combinedSanitized
	lastSanitizedFilename = "sanitized-files.txt"

	// Final processing summary
	totalProcessingTime := time.Since(time.Now()) // This will be updated in next change
	overallRateMBps := float64(totalOriginalSize) / 1024 / 1024 / totalProcessingTime.Seconds()

	log.Printf("[INFO] ========== Upload Processing Complete ==========")
	log.Printf("[INFO] User: %s", username)
	log.Printf("[INFO] Files Processed: %d", len(results))
	log.Printf("[INFO] Total Size: %.2f MB → %.2f MB (%.1f%% reduction)",
		float64(totalOriginalSize)/1024/1024,
		float64(totalSanitizedSize)/1024/1024,
		(1.0-float64(totalSanitizedSize)/float64(totalOriginalSize))*100)
	log.Printf("[INFO] IP Mappings Created: %d", len(ipMappings))
	log.Printf("[PERF] Overall Rate: %.2f MB/sec", overallRateMBps)

	// Aggregate all patterns across all files
	totalPatterns := 0
	for _, result := range results {
		totalPatterns += result["total_ips"].(int) + result["ad_accounts"].(int) +
			result["jwt_tokens"].(int) + result["private_keys"].(int) +
			result["sensitive_terms"].(int) + result["user_words"].(int)
	}

	log.Printf("[AUDIT] Upload completed: user=%s, files=%d, total_size_mb=%.2f, patterns_found=%d",
		username, len(results), float64(totalOriginalSize)/1024/1024, totalPatterns)
	log.Printf("[INFO] ===============================================")

	// Return JSON response
	w.Header().Set("Content-Type", "application/json")
	response := map[string]interface{}{
		"files":             results,
		"total_files":       len(results),
		"total_original":    totalOriginalSize,
		"total_sanitized":   totalSanitizedSize,
		"total_ip_mappings": len(ipMappings),
		"status":            "completed",
	}

	jsonBytes, _ := json.Marshal(response)
	w.Write(jsonBytes)
}

func extractZipContent(zipData []byte) []ExtractedFile {
	var extractedFiles []ExtractedFile

	reader, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		log.Printf("[ERROR] Failed to read ZIP archive: %v", err)
		return extractedFiles
	}

	totalFiles := len(reader.File)
	skippedDirs := 0
	skippedLarge := 0
	skippedBinary := 0
	failedOpen := 0
	failedRead := 0

	log.Printf("[DEBUG] ZIP contains %d entries", totalFiles)

	for _, file := range reader.File {
		// Skip directories
		if file.FileInfo().IsDir() {
			skippedDirs++
			continue
		}

		// Skip very large files in ZIP
		if file.UncompressedSize64 > uint64(maxZipFileSizeMB)*1024*1024 {
			log.Printf("[WARN] Skipping large file in ZIP: %s (%.2f MB, max %dMB)",
				file.Name, float64(file.UncompressedSize64)/1024/1024, maxZipFileSizeMB)
			skippedLarge++
			continue
		}

		// Open file within ZIP
		rc, err := file.Open()
		if err != nil {
			log.Printf("[ERROR] Failed to open file %s in ZIP: %v", file.Name, err)
			failedOpen++
			continue
		}

		// Read file content
		content, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			log.Printf("[ERROR] Failed to read file %s in ZIP: %v", file.Name, err)
			failedRead++
			continue
		}

		// Skip binary files
		if isBinaryContent(content) {
			log.Printf("[WARN] Skipping binary file in ZIP: %s", file.Name)
			skippedBinary++
			continue
		}

		extractedFiles = append(extractedFiles, ExtractedFile{
			Name:    file.Name,
			Content: string(content),
			Mode:    file.Mode(),
			ModTime: file.Modified,
		})

		log.Printf("[DEBUG] Extracted: %s (%.2f KB)", file.Name, float64(len(content))/1024)
	}

	log.Printf("[INFO] ZIP extraction summary: %d total entries, %d extracted, %d skipped (dirs=%d, large=%d, binary=%d, errors=%d)",
		totalFiles, len(extractedFiles),
		skippedDirs+skippedLarge+skippedBinary+failedOpen+failedRead,
		skippedDirs, skippedLarge, skippedBinary, failedOpen+failedRead)

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

func downloadDetailedReportHandler(w http.ResponseWriter, r *http.Request) {
	// Get username for audit logging
	username := "anonymous"
	if cookie, err := r.Cookie("admin_session"); err == nil {
		sessionMutex.Lock()
		if user, exists := sessionUsers[cookie.Value]; exists {
			username = user
		}
		sessionMutex.Unlock()
	}

	log.Printf("[INFO] Detailed report download requested: user=%s", username)

	replacementMutex.Lock()
	defer replacementMutex.Unlock()

	if len(detailedReplacements) == 0 {
		log.Printf("[WARN] No detailed replacements available for user=%s", username)
		http.Error(w, "No detailed report available. Please enable the option before processing files.", http.StatusNotFound)
		return
	}

	// Generate CSV
	var buf bytes.Buffer
	buf.WriteString("Category,File,Line,Original,Sanitized\n")

	for _, repl := range detailedReplacements {
		// Escape CSV fields
		category := escapeCSV(repl.Category)
		file := escapeCSV(repl.File)
		original := escapeCSV(repl.Original)
		sanitized := escapeCSV(repl.Sanitized)

		fmt.Fprintf(&buf, "%s,%s,%d,%s,%s\n", category, file, repl.Line, original, sanitized)
	}

	reportSize := buf.Len()
	log.Printf("[INFO] Detailed report generated: %d replacements, %.2f KB",
		len(detailedReplacements), float64(reportSize)/1024)

	// Send CSV file
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"yossarian-detailed-report-%s.csv\"",
		time.Now().Format("2006-01-02")))
	w.Write(buf.Bytes())

	log.Printf("[AUDIT] Detailed report downloaded: user=%s, replacements=%d, size_kb=%.2f",
		username, len(detailedReplacements), float64(reportSize)/1024)
}

func escapeCSV(field string) string {
	// If field contains comma, quote, or newline, wrap in quotes and escape internal quotes
	if strings.ContainsAny(field, ",\"\n\r") {
		return `"` + strings.ReplaceAll(field, `"`, `""`) + `"`
	}
	return field
}

func downloadAllZipHandler(w http.ResponseWriter, r *http.Request) {
	// Get username for audit logging
	username := "anonymous"
	if cookie, err := r.Cookie("admin_session"); err == nil {
		sessionMutex.Lock()
		if user, exists := sessionUsers[cookie.Value]; exists {
			username = user
		}
		sessionMutex.Unlock()
	}

	log.Printf("[INFO] Download all ZIP requested: user=%s, files_available=%d", username, len(lastSanitizedFiles))

	if len(lastSanitizedFiles) == 0 {
		log.Printf("[WARN] Download failed: no sanitized files available for user=%s", username)
		http.Error(w, "No sanitized files available", http.StatusNotFound)
		return
	}

	// Create ZIP archive with all sanitized files
	var buf bytes.Buffer
	zipWriter := zip.NewWriter(&buf)

	for filename, content := range lastSanitizedFiles {
		writer, err := zipWriter.Create(filename)
		if err != nil {
			http.Error(w, "Failed to create ZIP", http.StatusInternalServerError)
			return
		}
		_, err = writer.Write([]byte(content))
		if err != nil {
			http.Error(w, "Failed to write file to ZIP", http.StatusInternalServerError)
			return
		}
	}

	err := zipWriter.Close()
	if err != nil {
		log.Printf("[ERROR] Failed to finalize ZIP for user=%s: %v", username, err)
		http.Error(w, "Failed to finalize ZIP", http.StatusInternalServerError)
		return
	}

	zipSize := buf.Len()
	log.Printf("[INFO] ZIP archive created for download: %.2f MB (%d files)",
		float64(zipSize)/1024/1024, len(lastSanitizedFiles))

	// Send ZIP file
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", "attachment; filename=\"sanitized-files.zip\"")
	w.Write(buf.Bytes())

	log.Printf("[AUDIT] Download completed: user=%s, type=all_files_zip, size_mb=%.2f, file_count=%d",
		username, float64(zipSize)/1024/1024, len(lastSanitizedFiles))
}

func individualFileHandler(w http.ResponseWriter, r *http.Request) {
	filename := strings.TrimPrefix(r.URL.Path, "/download/sanitized/")
	filename, _ = url.QueryUnescape(filename)

	// Get username for audit logging
	username := "anonymous"
	if cookie, err := r.Cookie("admin_session"); err == nil {
		sessionMutex.Lock()
		if user, exists := sessionUsers[cookie.Value]; exists {
			username = user
		}
		sessionMutex.Unlock()
	}

	log.Printf("[INFO] Individual file download requested: user=%s, file=%s", username, filename)

	if content, exists := lastSanitizedFiles[filename]; exists {
		// Determine content type based on file extension
		contentType := "text/plain"
		if strings.HasSuffix(strings.ToLower(filename), ".zip") {
			contentType = "application/zip"
		}

		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
		w.Write([]byte(content))

		log.Printf("[AUDIT] Download completed: user=%s, type=individual_file, file=%s, size_mb=%.2f",
			username, filename, float64(len(content))/1024/1024)
	} else {
		log.Printf("[ERROR] Download failed: file not found: user=%s, file=%s", username, filename)
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

		// Show SSO button if OIDC enabled
		ssoButton := ""
		if oidcEnabled {
			ssoButton = `<p style="text-align: center; margin: 20px 0;">
				<a href="/auth/oidc/login" style="display: inline-block; padding: 10px 20px; background: #1976d2; color: white; text-decoration: none; border-radius: 4px;">
					🔐 Login with SSO
				</a>
			</p>
			<p style="text-align: center;">OR</p>`
		}

		fmt.Fprintf(w, `
		<h1>Yossarian Admin Login</h1>
		%s
		<form method="post">
			<p>
				<label>Admin Password:</label><br>
				<input type="password" name="password" required style="padding: 5px; width: 200px;">
			</p>
			<button type="submit">Login with Password</button>
		</form>
		`, ssoButton)
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
			activeSessions.Inc()
			sessionMutex.Unlock()

			cookie := &http.Cookie{
				Name:     "admin_session",
				Value:    sessionID,
				Path:     "/",
				HttpOnly: true,
				Secure:   true,
				MaxAge:   1800,
			}
			http.SetCookie(w, cookie)

			http.Redirect(w, r, "/", http.StatusSeeOther)
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
		UserName       string
		UserEmail      string
		IPMappings     int
		ADAccounts     int
		SensitiveTerms int
		AuthMode       string
		OIDCEnabled    bool
	}{
		UserName:       "Administrator",
		UserEmail:      "admin@company.com",
		IPMappings:     len(ipMappings),
		ADAccounts:     0, // Now handled by database service
		SensitiveTerms: len(sensitiveTermsOrg),
		AuthMode:       "Password Only",
		OIDCEnabled:    oidcEnabled,
	}

	// Get actual logged-in user from session
	cookie, err := r.Cookie("admin_session")
	if err == nil {
		sessionMutex.Lock()
		if username, exists := sessionUsers[cookie.Value]; exists {
			data.UserName = username
			data.UserEmail = username
			if oidcEnabled {
				data.AuthMode = "Enterprise SSO"
			}
		}
		sessionMutex.Unlock()
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
		activeSessions.Dec()
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

func proxyLDAPStatus(w http.ResponseWriter, r *http.Request) {
	resp, err := http.Get(fmt.Sprintf("%s/ldap/status", adServiceURL))
	if err != nil {
		http.Error(w, "Service unavailable", http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()

	w.Header().Set("Content-Type", "application/json")
	io.Copy(w, resp.Body)
}

func proxyAccountsList(w http.ResponseWriter, r *http.Request) {
	resp, err := http.Get(fmt.Sprintf("%s/accounts/list", adServiceURL))
	if err != nil {
		http.Error(w, "Service unavailable", http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()

	w.Header().Set("Content-Type", "application/json")
	io.Copy(w, resp.Body)
}

func proxyLDAPSync(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	resp, err := http.Post(fmt.Sprintf("%s/ldap/sync-full", adServiceURL), "application/json", nil)
	if err != nil {
		http.Error(w, "Service unavailable", http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()

	w.Header().Set("Content-Type", "application/json")
	io.Copy(w, resp.Body)
}

func proxyLDAPTest(w http.ResponseWriter, r *http.Request) {
	resp, err := http.Get(fmt.Sprintf("%s/ldap/test", adServiceURL))
	if err != nil {
		http.Error(w, "Service unavailable", http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()

	w.Header().Set("Content-Type", "application/json")
	io.Copy(w, resp.Body)
}

func proxySensitiveList(w http.ResponseWriter, r *http.Request) {
	resp, err := http.Get(fmt.Sprintf("%s/sensitive/list", adServiceURL))
	if err != nil {
		http.Error(w, "Service unavailable", http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()

	w.Header().Set("Content-Type", "application/json")
	io.Copy(w, resp.Body)
}

func proxySensitiveAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	resp, err := http.Post(fmt.Sprintf("%s/sensitive/add", adServiceURL), "application/json", r.Body)
	if err != nil {
		http.Error(w, "Service unavailable", http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()

	w.Header().Set("Content-Type", "application/json")
	io.Copy(w, resp.Body)

	// Reload terms after adding
	go loadSensitiveTerms()
}

func proxySensitiveDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != "DELETE" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	term := r.URL.Query().Get("term")
	req, _ := http.NewRequest("DELETE", fmt.Sprintf("%s/sensitive/delete?term=%s", adServiceURL, url.QueryEscape(term)), nil)
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "Service unavailable", http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()

	w.Header().Set("Content-Type", "application/json")
	io.Copy(w, resp.Body)

	// Reload terms after deleting
	go loadSensitiveTerms()
}

func adminADHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		r.ParseForm()
		account := strings.TrimSpace(r.FormValue("account"))
		usn := strings.TrimSpace(r.FormValue("usn"))

		if account != "" && usn != "" {
			// TODO: Add database service management endpoint
			http.Redirect(w, r, "/admin/ad-accounts", http.StatusSeeOther)
			return
		}
	}

	w.Header().Set("Content-Type", "text/html")

	accountsList := ""
	// TODO: Query database service for AD accounts list
	accountsList = "<tr><td colspan='2'>Database service integration pending</td></tr>"

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
	// Auto SSO: Check if enabled and user not authenticated
	if autoSSOEnabled && !isValidAdminSession(r) {
		log.Printf("Auto SSO: Redirecting unauthenticated user to OIDC login")
		http.Redirect(w, r, "/auth/oidc/login", http.StatusSeeOther)
		return
	}

	// Auto SSO: Validate user has required roles
	if autoSSOEnabled && isValidAdminSession(r) {
		if !hasRole(r, "admin") && !hasRole(r, "user") {
			log.Printf("Auto SSO: Access denied - user lacks required roles")
			showAccessDenied(w, r)
			return
		}
	}

	data := struct {
		UserAuthenticated bool
		UserName          string
		UserEmail         string
		IsAdmin           bool
	}{
		UserAuthenticated: false,
		UserName:          "",
		UserEmail:         "",
		IsAdmin:           false,
	}

	// Check if user is authenticated
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

func clearDownloadCacheHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Clear the global download cache
	lastSanitizedFiles = make(map[string]string)
	lastSanitizedContent = ""
	lastSanitizedFilename = ""

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status": "cleared"}`)
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
	http.HandleFunc("/health", mainHealthHandler)
	http.HandleFunc("/api/userinfo", userInfoHandler)
	http.HandleFunc("/api/config", configLimitsHandler)
	http.HandleFunc("/upload", uploadHandler)
	http.HandleFunc("/mappings/csv", mappingsHandler)
	http.HandleFunc("/download/sanitized", downloadAllZipHandler)
	http.HandleFunc("/download/sanitized/single", downloadHandler)
	http.HandleFunc("/download/sanitized/", individualFileHandler)
	http.HandleFunc("/download/detailed-report", downloadDetailedReportHandler)
	http.HandleFunc("/clear-download-cache", clearDownloadCacheHandler)

	// Admin routes
	http.HandleFunc("/admin/login", adminLoginHandler)
	http.HandleFunc("/admin/logout", adminLogoutHandler)

	// OIDC routes
	http.HandleFunc("/auth/oidc/login", oidcLoginHandler)
	http.HandleFunc("/auth/oidc/callback", oidcCallbackHandler)

	http.HandleFunc("/admin", adminRequired(adminDashboardHandler))
	http.HandleFunc("/admin/ad-accounts", adminRequired(adminADHandler))

	// Admin API proxies
	http.HandleFunc("/admin/api/ldap/status", adminRequired(proxyLDAPStatus))
	http.HandleFunc("/admin/api/accounts/list", adminRequired(proxyAccountsList))
	http.HandleFunc("/admin/api/ldap/sync", adminRequired(proxyLDAPSync))
	http.HandleFunc("/admin/api/ldap/test", adminRequired(proxyLDAPTest))
	http.HandleFunc("/admin/api/sensitive/list", adminRequired(proxySensitiveList))
	http.HandleFunc("/admin/api/sensitive/add", adminRequired(proxySensitiveAdd))
	http.HandleFunc("/admin/api/sensitive/delete", adminRequired(proxySensitiveDelete))

	// Debug route
	http.HandleFunc("/debug", debugHandler)

	// ✅ ADD: Prometheus metrics endpoint
	http.Handle("/metrics", promhttp.Handler())

	log.Printf("Server starting on port %s with /metrics endpoint", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
