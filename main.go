package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"embed"

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

	// MinIO client libraries
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	// ✅ ADD: Prometheus client libraries
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Embedded static files for API documentation
//go:embed openapi.yaml
var openapiSpec []byte

//go:embed docs/swagger-ui.html
var swaggerUIHTML []byte

//go:embed docs/swagger-ui.css
var swaggerUICSS []byte

//go:embed docs/swagger-ui-bundle.js
var swaggerUIBundleJS []byte

//go:embed docs/swagger-ui-standalone-preset.js
var swaggerUIPresetJS []byte

// User info structure for future OIDC
type UserInfo struct {
	Email   string
	Name    string
	Roles   []string
	IsAdmin bool
}

// Version information - set during build
var (
	Version   = "v0.13.0"
	BuildTime = "unknown"
	GitCommit = "unknown"
)

// Global storage for download and admin
var (
	// MinIO configuration (v0.13.0)
	runMode               string
	minioClient           *minio.Client
	minioEndpoint         string
	minioAccessKey        string
	minioSecretKey        string
	minioBucket           string
	minioUseSSL           bool
	workerPollInterval    int = 5
	lastSanitizedContent  string
	lastSanitizedFilename string
	lastSanitizedFiles    map[string]string
	adminSessions         = make(map[string]time.Time)
	sessionUsers          = make(map[string]string)    // sessionID -> username
	sessionRoles          = make(map[string][]string)  // sessionID -> roles
	sessionTokens         = make(map[string]string)    // sessionID -> ID token
	sessionTokenExpiry    = make(map[string]time.Time) // sessionID -> token expiry
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

type ExtractedFile struct {
	Name    string
	Content string
	Mode    os.FileMode
	ModTime time.Time
}

var (
	detailedReplacements []Replacement
	replacementMutex     sync.Mutex
)

var (
	adLookupCache = make(map[string]string)
	cacheMutex    sync.RWMutex
)

// Batch processing (MinIO-based, no local storage needed)

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

// Prometheus metrics for v0.13.0+ split architecture
var (
	// ===== SHARED METRICS (Frontend + Worker) =====

	// AD cache metrics (used by both frontend and worker)
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

	// Active sessions gauge (frontend only, but defined globally)
	activeSessions = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "yossarian_active_sessions",
			Help: "Number of active user sessions",
		},
	)

	// ===== BATCH JOB METRICS (Worker) =====

	// Batch job status counts
	batchJobsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "yossarian_batch_jobs_total",
			Help: "Total number of batch jobs by status",
		},
		[]string{"status"}, // queued, processing, completed, failed
	)

	// Batch job queue depth (current count of queued jobs)
	batchJobQueueDepth = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "yossarian_batch_job_queue_depth",
			Help: "Current number of queued batch jobs",
		},
	)

	// Batch processing duration
	batchProcessingDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "yossarian_batch_processing_duration_seconds",
			Help:    "Time taken to process batch jobs",
			Buckets: []float64{1, 5, 10, 30, 60, 120, 300, 600}, // 1s to 10min
		},
	)

	// Batch files processed
	batchFilesProcessed = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "yossarian_batch_files_processed_total",
			Help: "Total number of files processed in batch jobs",
		},
	)

	// Batch patterns detected
	batchPatternsDetected = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "yossarian_batch_patterns_detected_total",
			Help: "Total number of sensitive patterns detected in batch jobs",
		},
		[]string{"pattern_type"}, // ip_address, ad_account, jwt_token, etc.
	)

	// ===== MinIO METRICS (Worker) =====

	// MinIO operations
	minioOperationsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "yossarian_minio_operations_total",
			Help: "Total number of MinIO operations",
		},
		[]string{"operation"}, // upload, download, delete
	)

	// MinIO operation duration
	minioOperationDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "yossarian_minio_operation_duration_seconds",
			Help:    "Duration of MinIO operations",
			Buckets: []float64{0.1, 0.5, 1, 2, 5, 10, 30}, // 0.1s to 30s
		},
		[]string{"operation"}, // upload, download, delete
	)

	// MinIO operation errors
	minioOperationErrors = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "yossarian_minio_operation_errors_total",
			Help: "Total number of MinIO operation errors",
		},
		[]string{"operation"}, // upload, download, delete
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
			// Only enable auto SSO if explicitly requested
			autoSSOEnabled = os.Getenv("AUTO_SSO_ENABLED") == "true"
			log.Printf("OIDC enabled with issuer: %s", oidcIssuerURL)
			log.Printf("Auto SSO enforcement: %v", autoSSOEnabled)
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

	// Calculate token expiry (ID tokens typically expire in 5-30 minutes)
	tokenExpiry := time.Now().Add(time.Duration(idToken.Expiry.Sub(time.Now())))

	sessionMutex.Lock()
	adminSessions[sessionID] = tokenExpiry // Use token expiry, not arbitrary 30 min
	sessionUsers[sessionID] = username
	sessionRoles[sessionID] = userRoles
	sessionTokens[sessionID] = rawIDToken
	sessionTokenExpiry[sessionID] = tokenExpiry
	activeSessions.Inc()
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

// Batch job helper functions
func generateJobID(username string) string {
	timestamp := time.Now().Format("20060102-150405")
	return fmt.Sprintf("batch-%s-%s", username, timestamp)
}

func updateJobStatus(jobID, status string, totalFiles, processedFiles int, errorMsg string) error {
	client := &http.Client{Timeout: 5 * time.Second}

	updateData := map[string]interface{}{
		"job_id":          jobID,
		"status":          status,
		"total_files":     totalFiles,
		"processed_files": processedFiles,
	}

	if errorMsg != "" {
		updateData["error_message"] = errorMsg
	}

	jsonData, _ := json.Marshal(updateData)
	resp, err := client.Post(
		fmt.Sprintf("%s/jobs/update", adServiceURL),
		"application/json",
		bytes.NewBuffer(jsonData),
	)

	if err != nil {
		return fmt.Errorf("failed to update job status: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("job update failed with status %d", resp.StatusCode)
	}

	return nil
}

func isValidAdminSession(r *http.Request) bool {
	cookie, err := r.Cookie("admin_session")
	if err != nil {
		return false
	}

	sessionMutex.Lock()
	defer sessionMutex.Unlock()

	// Check if session exists
	expiry, exists := adminSessions[cookie.Value]
	if !exists {
		return false
	}

	// Check if Keycloak token is expired
	tokenExpiry, hasTokenExpiry := sessionTokenExpiry[cookie.Value]
	if hasTokenExpiry && time.Now().After(tokenExpiry) {
		// Token expired - force re-authentication
		delete(adminSessions, cookie.Value)
		delete(sessionUsers, cookie.Value)
		delete(sessionRoles, cookie.Value)
		delete(sessionTokens, cookie.Value)
		delete(sessionTokenExpiry, cookie.Value)
		activeSessions.Dec()
		log.Printf("[AUTH] Session %s expired due to Keycloak token expiry", cookie.Value[:8])
		return false
	}

	// For password-based sessions (no token), use Yossarian expiry
	if !hasTokenExpiry && time.Now().After(expiry) {
		delete(adminSessions, cookie.Value)
		delete(sessionUsers, cookie.Value)
		delete(sessionRoles, cookie.Value)
		activeSessions.Dec()
		return false
	}

	// Do NOT extend session - respect Keycloak token lifetime
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
			// Check if this is an API endpoint
			if strings.HasPrefix(r.URL.Path, "/admin/api/") || strings.HasPrefix(r.URL.Path, "/api/") {
				// Return JSON error for API endpoints
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized", "message": "Session expired or invalid"})
				return
			}
			// HTML redirect for regular admin pages
			http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
			return
		}
		// Check if user has admin role
		if !hasRole(r, "admin") {
			// Check if this is an API endpoint
			if strings.HasPrefix(r.URL.Path, "/admin/api/") || strings.HasPrefix(r.URL.Path, "/api/") {
				// Return JSON error for API endpoints
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(map[string]string{"error": "forbidden", "message": "Admin role required"})
				return
			}
			// HTML error for regular pages
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

	// Count null bytes - if more than 1% are nulls, it's binary
	nullCount := 0
	for i := 0; i < checkLen; i++ {
		if content[i] == 0 {
			nullCount++
		}
	}

	// If more than 1% null bytes, consider it binary
	return float64(nullCount)/float64(checkLen) > 0.01
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

	// Session validation (required for both OIDC and single-user mode)
	if !isValidAdminSession(r) {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "session_expired",
			"message": "Your session has expired. Please log in again.",
		})
		return
	}

	// Get username from session (guaranteed to exist after validation above)
	username := "anonymous"
	if cookie, err := r.Cookie("admin_session"); err == nil {
		sessionMutex.Lock()
		if user, exists := sessionUsers[cookie.Value]; exists {
			username = user
		}
		sessionMutex.Unlock()
	}

	if username == "anonymous" {
		// This should never happen after session validation, but safety check
		log.Printf("[ERROR] Session valid but username not found - rejecting upload")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "authentication_required",
			"message": "Please log in to upload files.",
		})
		return
	}

	if parseErr := r.ParseMultipartForm(int64(maxTotalUploadSizeMB) << 20); parseErr != nil {
		log.Printf("[ERROR] File upload failed: form parsing error for user=%s: %v", username, parseErr)
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

	log.Printf("[INFO] File upload started: user=%s, files=%d, mode=%s", username, len(files), runMode)

	// Check if detailed report was requested
	shouldGenerateDetailedReport := r.FormValue("generate_detailed_report") == "true"
	if shouldGenerateDetailedReport {
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

	// === NEW v0.13.0: Frontend Mode - ZIP files go to MinIO ===
	if runMode == "frontend" {
		for _, fileHeader := range files {
			if strings.ToLower(filepath.Ext(fileHeader.Filename)) == ".zip" {
				log.Printf("[FRONTEND] ZIP file detected: %s - uploading to MinIO", fileHeader.Filename)

				file, err := fileHeader.Open()
				if err != nil {
					log.Printf("[ERROR] Failed to open ZIP: %v", err)
					http.Error(w, "Failed to read ZIP file", http.StatusInternalServerError)
					return
				}

				// Read ZIP content
				zipContent, err := io.ReadAll(file)
				file.Close()
				if err != nil {
					log.Printf("[ERROR] Failed to read ZIP: %v", err)
					http.Error(w, "Failed to read ZIP file", http.StatusInternalServerError)
					return
				}

				// Generate job ID
				jobID := generateJobID(username)
				ctx := context.Background()

				// Upload to MinIO
				objectName := fmt.Sprintf("%s/%s/input.zip", username, jobID)
				if err := uploadToMinIO(ctx, objectName, bytes.NewReader(zipContent), int64(len(zipContent))); err != nil {
					log.Printf("[ERROR] Failed to upload to MinIO: %v", err)
					http.Error(w, "Failed to upload file", http.StatusInternalServerError)
					return
				}

				// Count files in ZIP
				zipReader, err := zip.NewReader(bytes.NewReader(zipContent), int64(len(zipContent)))
				if err != nil {
					log.Printf("[ERROR] Failed to read ZIP: %v", err)
					http.Error(w, "Invalid ZIP file", http.StatusBadRequest)
					return
				}
				totalFiles := len(zipReader.File)

				// Create job record in database
				jobData := map[string]interface{}{
					"job_id":      jobID,
					"username":    username,
					"total_files": totalFiles,
					"status":      "queued",
				}

				jsonData, _ := json.Marshal(jobData)
				resp, err := http.Post(
					fmt.Sprintf("%s/jobs/create", adServiceURL),
					"application/json",
					bytes.NewBuffer(jsonData),
				)
				if err != nil {
					log.Printf("[ERROR] Failed to create job record: %v", err)
					http.Error(w, "Failed to create job record", http.StatusInternalServerError)
					return
				}
				defer resp.Body.Close()

				if resp.StatusCode != http.StatusOK {
					body, _ := io.ReadAll(resp.Body)
					log.Printf("[ERROR] Database service error: %s", string(body))
					http.Error(w, "Failed to create job record", http.StatusInternalServerError)
					return
				}

				log.Printf("[FRONTEND] Batch job %s created: user=%s, files=%d", jobID, username, totalFiles)

				// Return success response
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{
					"job_id":      jobID,
					"status":      "queued",
					"total_files": totalFiles,
					"message":     "Batch job submitted successfully",
				})
				return
			}
		}
	}

	// === Regular file processing (both frontend and worker mode) ===
	results := make([]map[string]interface{}, 0)
	totalOriginalSize := 0
	totalSanitizedSize := 0

	if lastSanitizedFiles == nil {
		lastSanitizedFiles = make(map[string]string)
	}

	for _, fileHeader := range files {
		// Check file size
		if fileHeader.Size > int64(maxFileSizeMB)*1024*1024 {
			log.Printf("[ERROR] File rejected: %s exceeds %dMB limit", fileHeader.Filename, maxFileSizeMB)
			continue
		}

		log.Printf("[DEBUG] Processing file: %s (%d bytes)", fileHeader.Filename, fileHeader.Size)

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

		// Skip binary files
		if isBinaryContent(content) && !isArchiveFile(fileHeader.Filename) {
			log.Printf("[WARN] File skipped: %s (binary content)", fileHeader.Filename)
			continue
		}

		log.Printf("[INFO] Sanitizing file: %s (%.2f KB)", fileHeader.Filename, float64(len(content))/1024)

		// Sanitize content
		fileStartTime := time.Now()
		sanitized, sanitizeStats := sanitizeText(string(content), userWords, shouldGenerateDetailedReport, fileHeader.Filename)
		processingTime := time.Since(fileStartTime)

		log.Printf("[PERF] Sanitized %s in %.2fs", fileHeader.Filename, processingTime.Seconds())

		// Metrics removed - single file processing is not the primary use case in v0.13.0+
		// Batch job metrics are recorded in worker processing instead

		// Store results
		result := map[string]interface{}{
			"filename":          fileHeader.Filename,
			"original_size":     len(content),
			"sanitized_size":    len(sanitized),
			"processing_time":   fmt.Sprintf("%.2fs", processingTime.Seconds()),
			"total_ips":         sanitizeStats["ip_addresses"],
			"ad_accounts":       sanitizeStats["ad_accounts"],
			"jwt_tokens":        sanitizeStats["jwt_tokens"],
			"private_keys":      sanitizeStats["private_keys"],
			"sensitive_terms":   sanitizeStats["sensitive_terms"],
			"user_words":        sanitizeStats["user_words"],
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

		// Store for download
		lastSanitizedFiles[fileHeader.Filename] = sanitized
	}

	// Combine all sanitized content
	combinedSanitized := ""
	for _, result := range results {
		if content, exists := result["sanitized_content"]; exists && content != nil {
			combinedSanitized += content.(string) + "\n\n"
		}
	}

	lastSanitizedContent = combinedSanitized
	lastSanitizedFilename = "sanitized-files.txt"

	log.Printf("[INFO] Upload complete: user=%s, files=%d, size=%.2fMB",
		username, len(results), float64(totalOriginalSize)/1024/1024)

	// Return JSON response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"files":             results,
		"total_files":       len(results),
		"total_original":    totalOriginalSize,
		"total_sanitized":   totalSanitizedSize,
		"total_ip_mappings": len(ipMappings),
		"status":            "completed",
	})
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
		time.Now().Format("2006-01-02_15-04-05")))
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
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"yossarian-ip-mappings-%s.csv\"",
		time.Now().Format("2006-01-02_15-04-05")))

	fmt.Fprintf(w, "original_ip,placeholder,type,timestamp\n")
	for original, placeholder := range ipMappings {
		fmt.Fprintf(w, "%s,%s,ip,%s\n", original, placeholder, time.Now().Format(time.RFC3339))
	}
}

func adminLoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		w.Header().Set("Content-Type", "text/html")

		// Determine mode and styling
		ssoButton := ""
		modeIndicator := `<div style="display: inline-flex; align-items: center; gap: 8px; padding: 8px 16px; background: rgba(25, 118, 210, 0.1); border-radius: 20px; font-size: 13px; color: #1976d2; margin-bottom: 24px;">
			<span>🔐</span>
			<span>Single-User Mode</span>
		</div>`

		if oidcEnabled {
			modeIndicator = `<div style="display: inline-flex; align-items: center; gap: 8px; padding: 8px 16px; background: rgba(46, 125, 50, 0.1); border-radius: 20px; font-size: 13px; color: #2e7d32; margin-bottom: 24px;">
				<span>🏢</span>
				<span>Enterprise SSO</span>
			</div>`
			ssoButton = `<a href="/auth/oidc/login" class="sso-button">
				🔐 Login with Enterprise SSO
			</a>
			<div class="divider"><span>OR</span></div>`
		}

		fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Login - Yossarian Go</title>
	<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🛡️</text></svg>">
	<style>
		* { margin: 0; padding: 0; box-sizing: border-box; }
		
		body {
			font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
			background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%);
			min-height: 100vh;
			display: flex;
			align-items: center;
			justify-content: center;
			padding: 20px;
		}
		
		.login-container {
			background: white;
			border-radius: 16px;
			box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
			width: 100%%;
			max-width: 420px;
			overflow: hidden;
		}
		
		.login-header {
			background: linear-gradient(135deg, #1976d2, #1565c0);
			color: white;
			padding: 40px 32px 32px;
			text-align: center;
		}
		
		.login-icon {
			font-size: 56px;
			margin-bottom: 16px;
			display: block;
		}
		
		.login-title {
			font-size: 28px;
			font-weight: 600;
			margin-bottom: 8px;
		}
		
		.login-subtitle {
			font-size: 14px;
			opacity: 0.9;
		}
		
		.login-body {
			padding: 32px;
			text-align: center;
		}
		
		.form-group {
			text-align: left;
			margin-bottom: 24px;
		}
		
		.form-label {
			display: block;
			font-size: 14px;
			font-weight: 500;
			color: #424242;
			margin-bottom: 8px;
		}
		
		.form-input {
			width: 100%%;
			padding: 14px 16px;
			border: 2px solid #e0e0e0;
			border-radius: 8px;
			font-size: 15px;
			transition: all 0.2s;
			font-family: inherit;
		}
		
		.form-input:focus {
			outline: none;
			border-color: #1976d2;
			box-shadow: 0 0 0 3px rgba(25, 118, 210, 0.1);
		}
		
		.login-button {
			width: 100%%;
			padding: 14px 24px;
			background: linear-gradient(135deg, #1976d2, #1565c0);
			color: white;
			border: none;
			border-radius: 8px;
			font-size: 15px;
			font-weight: 500;
			cursor: pointer;
			transition: all 0.2s;
			box-shadow: 0 2px 8px rgba(25, 118, 210, 0.3);
		}
		
		.login-button:hover {
			transform: translateY(-1px);
			box-shadow: 0 4px 12px rgba(25, 118, 210, 0.4);
		}
		
		.login-button:active {
			transform: translateY(0);
		}
		
		.login-footer {
			padding: 16px 32px;
			background: #f5f5f5;
			text-align: center;
			font-size: 12px;
			color: #757575;
		}
		
		.divider {
			text-align: center;
			color: #9e9e9e;
			font-size: 13px;
			margin: 16px 0;
			position: relative;
		}
		
		.divider span {
			background: white;
			padding: 0 12px;
			position: relative;
			z-index: 1;
		}
		
		.divider::before {
			content: '';
			position: absolute;
			top: 50%%;
			left: 0;
			right: 0;
			height: 1px;
			background: #e0e0e0;
			z-index: 0;
		}
		
		.sso-button {
			display: block;
			padding: 14px 24px;
			background: linear-gradient(135deg, #1976d2, #1565c0);
			color: white;
			text-decoration: none;
			border-radius: 8px;
			font-weight: 500;
			text-align: center;
			margin-bottom: 16px;
			box-shadow: 0 2px 8px rgba(25, 118, 210, 0.3);
			transition: all 0.2s;
		}
		
		.sso-button:hover {
			transform: translateY(-1px);
			box-shadow: 0 4px 12px rgba(25, 118, 210, 0.4);
		}
		
		@media (max-width: 480px) {
			.login-container { border-radius: 0; }
			.login-header { padding: 32px 24px 24px; }
			.login-body { padding: 24px; }
		}
	</style>
</head>
<body>
	<div class="login-container">
		<div class="login-header">
			<span class="login-icon">🛡️</span>
			<h1 class="login-title">Yossarian Go</h1>
			<p class="login-subtitle">Secure Log Sanitization</p>
		</div>
		
		<div class="login-body">
			%s
			
			%s
			
			<form method="post">
				<div class="form-group">
					<label class="form-label">Admin Password</label>
					<input type="password" name="password" class="form-input" placeholder="Enter password" required autofocus>
				</div>
				
				<button type="submit" class="login-button">
					🔓 Login
				</button>
			</form>
		</div>
		
		<div class="login-footer">
			🛡️ Yossarian Go - Secure Log Sanitization
		</div>
	</div>
</body>
</html>`, modeIndicator, ssoButton)
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
			sessionUsers[sessionID] = "Administrator"           // Add username to map
			sessionRoles[sessionID] = []string{"admin", "user"} // Grant admin role for password login
			activeSessions.Inc()
			sessionMutex.Unlock()

			cookie := &http.Cookie{
				Name:     "admin_session",
				Value:    sessionID,
				Path:     "/",
				HttpOnly: true,
				Secure:   false, // Allow HTTP for local development
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
		delete(sessionUsers, cookie.Value)
		delete(sessionRoles, cookie.Value)
		delete(sessionTokens, cookie.Value)
		delete(sessionTokenExpiry, cookie.Value)
		activeSessions.Dec()
		sessionMutex.Unlock()

		log.Printf("[AUTH] User logged out: session=%s", cookie.Value[:8])
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

func proxyOrgSettingsList(w http.ResponseWriter, r *http.Request) {
	resp, err := http.Get(fmt.Sprintf("%s/org-settings/list", adServiceURL))
	if err != nil {
		http.Error(w, "Service unavailable", http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()

	w.Header().Set("Content-Type", "application/json")
	io.Copy(w, resp.Body)
}

func proxyOrgSettingsUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	resp, err := http.Post(fmt.Sprintf("%s/org-settings/update", adServiceURL), "application/json", r.Body)
	if err != nil {
		http.Error(w, "Service unavailable", http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()

	w.Header().Set("Content-Type", "application/json")
	io.Copy(w, resp.Body)
}

func proxyOrgSettingsPublic(w http.ResponseWriter, r *http.Request) {
	resp, err := http.Get(fmt.Sprintf("%s/org-settings/public", adServiceURL))
	if err != nil {
		http.Error(w, "Service unavailable", http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()

	w.Header().Set("Content-Type", "application/json")
	io.Copy(w, resp.Body)
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

	// Single-user mode: Require password login
	if !oidcEnabled && !isValidAdminSession(r) {
		log.Printf("Single-user mode: Redirecting to admin login")
		http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
		return
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

// Batch job API handlers
func jobStatusAPIHandler(w http.ResponseWriter, r *http.Request) {
	jobID := strings.TrimPrefix(r.URL.Path, "/api/jobs/status/")
	if jobID == "" {
		http.Error(w, "job_id required", http.StatusBadRequest)
		return
	}

	// Proxy to db-service
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(fmt.Sprintf("%s/jobs/status/%s", adServiceURL, jobID))
	if err != nil {
		http.Error(w, "Failed to get job status", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	w.Header().Set("Content-Type", "application/json")
	io.Copy(w, resp.Body)
}

func jobListAPIHandler(w http.ResponseWriter, r *http.Request) {
	// Get username from session
	username := "anonymous"
	if cookie, err := r.Cookie("admin_session"); err == nil {
		sessionMutex.Lock()
		if user, exists := sessionUsers[cookie.Value]; exists {
			username = user
		}
		sessionMutex.Unlock()
	}

	// Proxy to db-service
	client := &http.Client{Timeout: 5 * time.Second}
	// Only show jobs from last 8 hours
	cutoff := time.Now().Add(-8 * time.Hour).Format(time.RFC3339)
	resp, err := client.Get(fmt.Sprintf("%s/jobs/list/%s?after=%s", adServiceURL, username, cutoff))
	if err != nil {
		http.Error(w, "Failed to get job list", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	w.Header().Set("Content-Type", "application/json")
	io.Copy(w, resp.Body)
}

// Removed: myJobsPageHandler - My Jobs is now integrated into SPA (index.html panel)

func jobDownloadHandler(w http.ResponseWriter, r *http.Request) {
	jobID := strings.TrimPrefix(r.URL.Path, "/jobs/download/")
	if jobID == "" {
		http.Error(w, "job_id required", http.StatusBadRequest)
		return
	}

	// Get job info
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(fmt.Sprintf("%s/jobs/status/%s", adServiceURL, jobID))
	if err != nil {
		http.Error(w, "Failed to get job status", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	var jobInfo struct {
		JobID      string  `json:"job_id"`
		Username   string  `json:"username"`
		Status     string  `json:"status"`
		OutputPath *string `json:"output_path"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&jobInfo); err != nil {
		http.Error(w, "Failed to parse job info", http.StatusInternalServerError)
		return
	}

	if jobInfo.Status != "completed" {
		http.Error(w, "Job not completed yet", http.StatusBadRequest)
		return
	}

	// Download from MinIO
	minioPath := fmt.Sprintf("%s/%s/output.zip", jobInfo.Username, jobID)

	log.Printf("[DOWNLOAD] Fetching from MinIO: %s", minioPath)

	obj, err := downloadFromMinIO(context.Background(), minioPath)
	if err != nil {
		log.Printf("[ERROR] Failed to download from MinIO: %v", err)
		http.Error(w, "Output file not found", http.StatusNotFound)
		return
	}
	defer obj.Close()

	// Get file info for content length
	stat, err := obj.Stat()
	if err != nil {
		log.Printf("[ERROR] Failed to stat MinIO object: %v", err)
		http.Error(w, "Failed to get file info", http.StatusInternalServerError)
		return
	}

	// Stream file to user
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"sanitized-%s.zip\"", jobID))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", stat.Size))

	if _, err := io.Copy(w, obj); err != nil {
		log.Printf("[ERROR] Failed to stream file: %v", err)
	}

	log.Printf("[DOWNLOAD] Completed: %s (%d bytes)", minioPath, stat.Size)
}

func jobReportsDownloadHandler(w http.ResponseWriter, r *http.Request) {
	// Require authentication for report downloads
	if !isValidAdminSession(r) {
		http.Error(w, "Authentication required", http.StatusUnauthorized)
		return
	}

	// Parse URL: /jobs/reports/{job_id}/{report_type}
	pathParts := strings.Split(strings.TrimPrefix(r.URL.Path, "/jobs/reports/"), "/")
	if len(pathParts) != 2 {
		http.Error(w, "Invalid path format. Expected: /jobs/reports/{job_id}/{report_type}", http.StatusBadRequest)
		return
	}

	jobID := pathParts[0]
	reportType := pathParts[1]

	// Get username from validated session
	username := "Administrator" // Default for single-user mode
	if cookie, err := r.Cookie("admin_session"); err == nil {
		sessionMutex.Lock()
		if user, exists := sessionUsers[cookie.Value]; exists {
			username = user
		}
		sessionMutex.Unlock()
	}

	// Verify job exists and belongs to user
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(fmt.Sprintf("%s/jobs/status/%s", adServiceURL, jobID))
	if err != nil {
		log.Printf("[ERROR] Failed to verify job %s: %v", jobID, err)
		http.Error(w, "Failed to verify job", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		http.Error(w, "Job not found", http.StatusNotFound)
		return
	}

	var jobInfo struct {
		JobID    string `json:"job_id"`
		Username string `json:"username"`
		Status   string `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&jobInfo); err != nil {
		http.Error(w, "Failed to parse job info", http.StatusInternalServerError)
		return
	}

	// Verify user owns this job (or is admin)
	if jobInfo.Username != username && !hasRole(r, "admin") {
		log.Printf("[SECURITY] User %s attempted to access job %s owned by %s", username, jobID, jobInfo.Username)
		http.Error(w, "Access denied", http.StatusForbidden)
		return
	}

	// Determine MinIO object name and response details
	var minioObjectName string
	var contentType string
	var filename string
	switch reportType {
	case "ip-mappings.csv":
		minioObjectName = fmt.Sprintf("%s/%s/reports/ip-mappings.csv", jobInfo.Username, jobID)
		contentType = "text/csv"
		filename = fmt.Sprintf("%s-ip-mappings.csv", jobID)
	case "detailed-report.csv":
		minioObjectName = fmt.Sprintf("%s/%s/reports/detailed-report.csv", jobInfo.Username, jobID)
		contentType = "text/csv"
		filename = fmt.Sprintf("%s-detailed-report.csv", jobID)
	case "summary.json":
		minioObjectName = fmt.Sprintf("%s/%s/reports/summary.json", jobInfo.Username, jobID)
		contentType = "application/json"
		filename = fmt.Sprintf("%s-summary.json", jobID)
	default:
		http.Error(w, "Invalid report type. Valid types: ip-mappings.csv, detailed-report.csv, summary.json", http.StatusBadRequest)
		return
	}
	// Download from MinIO
	ctx := context.Background()
	obj, err := downloadFromMinIO(ctx, minioObjectName)
	if err != nil {
		log.Printf("[WARN] Report not found in MinIO: %s for job %s", reportType, jobID)
		http.Error(w, fmt.Sprintf("Report %s not available for this job", reportType), http.StatusNotFound)
		return
	}
	defer obj.Close()
	// Get file info for content length
	stat, err := obj.Stat()
	if err != nil {
		log.Printf("[ERROR] Failed to stat MinIO object: %v", err)
		http.Error(w, "Failed to get file info", http.StatusInternalServerError)
		return
	}
	// Stream file to user
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", stat.Size))
	if _, err := io.Copy(w, obj); err != nil {
		log.Printf("[ERROR] Failed to stream report: %v", err)
		return
	}
	log.Printf("[AUDIT] Report downloaded: user=%s, job=%s, report=%s, size_kb=%.2f",
		username, jobID, reportType, float64(stat.Size)/1024)
}
func jobDeleteAPIHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "DELETE" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	jobID := strings.TrimPrefix(r.URL.Path, "/api/jobs/delete/")
	if jobID == "" {
		http.Error(w, "job_id required", http.StatusBadRequest)
		return
	}

	// Get username for authorization
	username := "anonymous"
	if cookie, err := r.Cookie("admin_session"); err == nil {
		sessionMutex.Lock()
		if user, exists := sessionUsers[cookie.Value]; exists {
			username = user
		}
		sessionMutex.Unlock()
	}

	// Verify job exists and belongs to user
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(fmt.Sprintf("%s/jobs/status/%s", adServiceURL, jobID))
	if err != nil {
		log.Printf("[ERROR] Failed to verify job %s: %v", jobID, err)
		http.Error(w, "Failed to verify job", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		http.Error(w, "Job not found", http.StatusNotFound)
		return
	}

	var jobInfo struct {
		JobID    string `json:"job_id"`
		Username string `json:"username"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&jobInfo); err != nil {
		http.Error(w, "Failed to parse job info", http.StatusInternalServerError)
		return
	}

	// Verify user owns this job (or is admin)
	if jobInfo.Username != username && !hasRole(r, "admin") {
		log.Printf("[SECURITY] User %s attempted to delete job %s owned by %s", username, jobID, jobInfo.Username)
		http.Error(w, "Access denied", http.StatusForbidden)
		return
	}

	// Delete from database
	deleteReq, _ := http.NewRequest("DELETE", fmt.Sprintf("%s/jobs/delete/%s", adServiceURL, jobID), nil)
	deleteResp, err := client.Do(deleteReq)
	if err != nil {
		log.Printf("[ERROR] Failed to delete job %s from database: %v", jobID, err)
		http.Error(w, "Failed to delete job from database", http.StatusInternalServerError)
		return
	}
	deleteResp.Body.Close()

	// Delete files from MinIO
	ctx := context.Background()
	inputObj := fmt.Sprintf("%s/%s/input.zip", jobInfo.Username, jobID)
	outputObj := fmt.Sprintf("%s/%s/output.zip", jobInfo.Username, jobID)
	reportsPrefix := fmt.Sprintf("%s/%s/reports/", jobInfo.Username, jobID)

	deleteFromMinIO(ctx, inputObj)
	deleteFromMinIO(ctx, outputObj)
	deleteFromMinIO(ctx, reportsPrefix+"ip-mappings.csv")
	deleteFromMinIO(ctx, reportsPrefix+"summary.json")

	log.Printf("[AUDIT] Job deleted: user=%s, job=%s", username, jobID)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "deleted",
		"job_id":  jobID,
		"message": "Job and all associated files deleted successfully",
	})
}

func jobCancelAPIHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	jobID := strings.TrimPrefix(r.URL.Path, "/api/jobs/cancel/")
	if jobID == "" {
		http.Error(w, "job_id required", http.StatusBadRequest)
		return
	}

	// Get username for authorization
	username := "anonymous"
	if cookie, err := r.Cookie("admin_session"); err == nil {
		sessionMutex.Lock()
		if user, exists := sessionUsers[cookie.Value]; exists {
			username = user
		}
		sessionMutex.Unlock()
	}

	// Verify job exists and belongs to user
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(fmt.Sprintf("%s/jobs/status/%s", adServiceURL, jobID))
	if err != nil {
		log.Printf("[ERROR] Failed to verify job %s: %v", jobID, err)
		http.Error(w, "Failed to verify job", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		http.Error(w, "Job not found", http.StatusNotFound)
		return
	}

	var jobInfo struct {
		JobID    string `json:"job_id"`
		Username string `json:"username"`
		Status   string `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&jobInfo); err != nil {
		http.Error(w, "Failed to parse job info", http.StatusInternalServerError)
		return
	}

	// Verify user owns this job (or is admin)
	if jobInfo.Username != username && !hasRole(r, "admin") {
		log.Printf("[SECURITY] User %s attempted to cancel job %s owned by %s", username, jobID, jobInfo.Username)
		http.Error(w, "Access denied", http.StatusForbidden)
		return
	}

	// Only allow cancelling queued or processing jobs
	if jobInfo.Status != "queued" && jobInfo.Status != "processing" {
		http.Error(w, fmt.Sprintf("Cannot cancel job with status: %s", jobInfo.Status), http.StatusBadRequest)
		return
	}

	// Update job status to cancelled
	updateData := map[string]interface{}{
		"job_id": jobID,
		"status": "cancelled",
	}

	jsonData, _ := json.Marshal(updateData)
	updateResp, err := client.Post(
		fmt.Sprintf("%s/jobs/update", adServiceURL),
		"application/json",
		bytes.NewBuffer(jsonData),
	)
	if err != nil {
		log.Printf("[ERROR] Failed to cancel job %s: %v", jobID, err)
		http.Error(w, "Failed to cancel job", http.StatusInternalServerError)
		return
	}
	defer updateResp.Body.Close()

	if updateResp.StatusCode != 200 {
		http.Error(w, "Failed to update job status", http.StatusInternalServerError)
		return
	}

	log.Printf("[AUDIT] Job cancelled: user=%s, job=%s", username, jobID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "cancelled",
		"job_id":  jobID,
		"message": "Job cancelled successfully",
	})
}

func batchJobCleanupTask() {
	// Run cleanup every 6 hours
	ticker := time.NewTicker(6 * time.Hour)
	defer ticker.Stop()

	// Run immediately on startup
	performBatchCleanup()

	for range ticker.C {
		performBatchCleanup()
	}
}

func performBatchCleanup() {
	log.Printf("[CLEANUP] Starting 48-hour batch job cleanup")

	retentionHours := 48
	cutoffTime := time.Now().Add(-time.Duration(retentionHours) * time.Hour)

	// Get all jobs older than 48 hours from database
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(fmt.Sprintf("%s/jobs/cleanup?before=%s", adServiceURL, cutoffTime.Format(time.RFC3339)))
	if err != nil {
		log.Printf("[CLEANUP] Failed to get cleanup list: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		log.Printf("[CLEANUP] Database service returned %d", resp.StatusCode)
		return
	}

	var result struct {
		Jobs []struct {
			JobID    string `json:"job_id"`
			Username string `json:"username"`
		} `json:"jobs"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		log.Printf("[CLEANUP] Failed to decode response: %v", err)
		return
	}

	if len(result.Jobs) == 0 {
		log.Printf("[CLEANUP] No jobs to clean up")
		return
	}

	log.Printf("[CLEANUP] Found %d jobs older than %d hours", len(result.Jobs), retentionHours)

	deletedCount := 0
	errorCount := 0
	ctx := context.Background()

	for _, job := range result.Jobs {
		// Delete from database
		deleteReq, _ := http.NewRequest("DELETE",
			fmt.Sprintf("%s/jobs/delete/%s", adServiceURL, job.JobID), nil)
		dbResp, err := http.DefaultClient.Do(deleteReq)
		if err != nil {
			log.Printf("[CLEANUP] Failed to delete job %s from database: %v", job.JobID, err)
			errorCount++
			continue
		}
		dbResp.Body.Close()

		// Delete files from MinIO
		inputObj := fmt.Sprintf("%s/%s/input.zip", job.Username, job.JobID)
		outputObj := fmt.Sprintf("%s/%s/output.zip", job.Username, job.JobID)
		reportsPrefix := fmt.Sprintf("%s/%s/reports/", job.Username, job.JobID)

		deleteFromMinIO(ctx, inputObj)
		deleteFromMinIO(ctx, outputObj)
		deleteFromMinIO(ctx, reportsPrefix+"ip-mappings.csv")
		deleteFromMinIO(ctx, reportsPrefix+"summary.json")

		deletedCount++
		log.Printf("[CLEANUP] Deleted job %s (user: %s)", job.JobID, job.Username)
	}

	log.Printf("[CLEANUP] Cleanup complete: %d deleted, %d errors", deletedCount, errorCount)

	// Record batch job deletion metrics
	if deletedCount > 0 {
		batchJobsTotal.WithLabelValues("deleted").Add(float64(deletedCount))
	}
}

// initMinIO initializes the MinIO client
func initMinIO() (*minio.Client, error) {
	endpoint := minioEndpoint
	accessKey := minioAccessKey
	secretKey := minioSecretKey
	useSSL := minioUseSSL

	// Initialize MinIO client
	client, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(accessKey, secretKey, ""),
		Secure: useSSL,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create MinIO client: %v", err)
	}

	log.Printf("[MINIO] Connected to %s (SSL: %v)", endpoint, useSSL)

	// Ensure bucket exists
	if err := ensureBucket(client, minioBucket); err != nil {
		return nil, fmt.Errorf("failed to ensure bucket exists: %v", err)
	}

	return client, nil
}

// ensureBucket creates the bucket if it doesn't exist
func ensureBucket(client *minio.Client, bucketName string) error {
	ctx := context.Background()

	exists, err := client.BucketExists(ctx, bucketName)
	if err != nil {
		return fmt.Errorf("failed to check bucket existence: %v", err)
	}

	if !exists {
		err = client.MakeBucket(ctx, bucketName, minio.MakeBucketOptions{})
		if err != nil {
			// Ignore "bucket already exists" error
			errMsg := err.Error()
			if !strings.Contains(errMsg, "already own it") &&
				!strings.Contains(errMsg, "BucketAlreadyOwnedByYou") &&
				!strings.Contains(errMsg, "BucketAlreadyExists") {
				return fmt.Errorf("failed to create bucket: %v", err)
			}
			log.Printf("[MINIO] Bucket already exists: %s", bucketName)
		} else {
			log.Printf("[MINIO] Created bucket: %s", bucketName)
		}
	} else {
		log.Printf("[MINIO] Bucket exists: %s", bucketName)
	}

	return nil
}

// uploadToMinIO uploads a file to MinIO
func uploadToMinIO(ctx context.Context, objectName string, reader io.Reader, size int64) error {
	if minioClient == nil {
		return fmt.Errorf("MinIO client not initialized")
	}

	startTime := time.Now()
	_, err := minioClient.PutObject(ctx, minioBucket, objectName, reader, size, minio.PutObjectOptions{
		ContentType: "application/zip",
	})
	duration := time.Since(startTime)

	if err != nil {
		minioOperationErrors.WithLabelValues("upload").Inc()
		return fmt.Errorf("failed to upload to MinIO: %v", err)
	}

	// Record metrics
	minioOperationsTotal.WithLabelValues("upload").Inc()
	minioOperationDuration.WithLabelValues("upload").Observe(duration.Seconds())

	log.Printf("[MINIO] Uploaded: %s (%d bytes) in %.2fs", objectName, size, duration.Seconds())
	return nil
}

// downloadFromMinIO downloads a file from MinIO
func downloadFromMinIO(ctx context.Context, objectName string) (*minio.Object, error) {
	if minioClient == nil {
		return nil, fmt.Errorf("MinIO client not initialized")
	}

	startTime := time.Now()
	object, err := minioClient.GetObject(ctx, minioBucket, objectName, minio.GetObjectOptions{})
	duration := time.Since(startTime)

	if err != nil {
		minioOperationErrors.WithLabelValues("download").Inc()
		return nil, fmt.Errorf("failed to download from MinIO: %v", err)
	}

	// Record metrics
	minioOperationsTotal.WithLabelValues("download").Inc()
	minioOperationDuration.WithLabelValues("download").Observe(duration.Seconds())

	log.Printf("[MINIO] Downloaded: %s in %.2fs", objectName, duration.Seconds())
	return object, nil
}

// deleteFromMinIO deletes a file from MinIO
func deleteFromMinIO(ctx context.Context, objectName string) error {
	if minioClient == nil {
		return fmt.Errorf("MinIO client not initialized")
	}

	startTime := time.Now()
	err := minioClient.RemoveObject(ctx, minioBucket, objectName, minio.RemoveObjectOptions{})
	duration := time.Since(startTime)

	if err != nil {
		minioOperationErrors.WithLabelValues("delete").Inc()
		return fmt.Errorf("failed to delete from MinIO: %v", err)
	}

	// Record metrics
	minioOperationsTotal.WithLabelValues("delete").Inc()
	minioOperationDuration.WithLabelValues("delete").Observe(duration.Seconds())

	log.Printf("[MINIO] Deleted: %s in %.2fs", objectName, duration.Seconds())
	return nil
}

// pollDatabaseForJobs queries the database for queued batch jobs and processes them
func pollDatabaseForJobs() {
	// Query database for next queued job
	resp, err := http.Get(fmt.Sprintf("%s/batch/next", adServiceURL))
	if err != nil {
		log.Printf("[WORKER] Error querying database: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		// No jobs in queue (this is normal)
		return
	}

	if resp.StatusCode != 200 {
		log.Printf("[WORKER] Database service returned status %d", resp.StatusCode)
		return
	}

	// Parse job info
	var job struct {
		JobID    string `json:"job_id"`
		Username string `json:"username"`
		Status   string `json:"status"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&job); err != nil {
		log.Printf("[WORKER] Error decoding job: %v", err)
		return
	}

	log.Printf("[WORKER] Found queued job: %s (user: %s)", job.JobID, job.Username)

	// Record job picked up from queue
	batchJobsTotal.WithLabelValues("processing").Inc()

	// Process the job
	if err := processBatchJobFromMinIO(job.JobID, job.Username); err != nil {
		log.Printf("[WORKER] Error processing job %s: %v", job.JobID, err)

		// Record failed job metric
		batchJobsTotal.WithLabelValues("failed").Inc()

		// Mark job as failed
		failResp, _ := http.Post(
			fmt.Sprintf("%s/batch/%s/fail", adServiceURL, job.JobID),
			"application/json",
			strings.NewReader(fmt.Sprintf(`{"error": "%s"}`, err.Error())),
		)
		if failResp != nil {
			failResp.Body.Close()
		}
		return
	}

	log.Printf("[WORKER] Job completed successfully: %s", job.JobID)
}

// updateQueueDepthMetric queries database for current queue depth
func updateQueueDepthMetric() {
	resp, err := http.Get(fmt.Sprintf("%s/jobs/queued", adServiceURL))
	if err != nil {
		return
	}
	defer resp.Body.Close()

	var result struct {
		Count int `json:"count"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return
	}

	batchJobQueueDepth.Set(float64(result.Count))
}

// startBatchWorker runs the main worker polling loop
func startBatchWorker() {
	pollInterval := workerPollInterval
	if pollInterval == 0 {
		pollInterval = 5 // Default 5 seconds
	}

	log.Printf("[WORKER] Batch worker started (poll interval: %d seconds)", pollInterval)

	ticker := time.NewTicker(time.Duration(pollInterval) * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		// Update queue depth metric
		updateQueueDepthMetric()

		// Process jobs
		pollDatabaseForJobs()
	}
}

// processBatchJobFromMinIO downloads job from MinIO, processes it, and uploads results
func isJobCancelled(jobID string) bool {
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(fmt.Sprintf("%s/jobs/status/%s", adServiceURL, jobID))
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	var jobInfo struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&jobInfo); err != nil {
		return false
	}

	return jobInfo.Status == "cancelled"
}

func processBatchJobFromMinIO(jobID, username string) error {
	ctx := context.Background()
	log.Printf("[WORKER] Processing job %s for user %s", jobID, username)

	// Clear global maps from previous job to prevent memory accumulation
	mapMutex.Lock()
	ipMappings = make(map[string]string)
	ipCounter = 1
	mapMutex.Unlock()

	cacheMutex.Lock()
	adLookupCache = make(map[string]string)
	cacheMutex.Unlock()

	// Clear detailed replacements tracking
	replacementMutex.Lock()
	detailedReplacements = []Replacement{}
	replacementMutex.Unlock()

	log.Printf("[WORKER] Cleared global caches for new job")

	// Update status to processing
	updateJobStatus(jobID, "processing", 0, 0, "")
	jobStartTime := time.Now()

	// Download input.zip from MinIO
	objectName := fmt.Sprintf("%s/%s/input.zip", username, jobID)
	object, err := downloadFromMinIO(ctx, objectName)
	if err != nil {
		return fmt.Errorf("failed to download input from MinIO: %v", err)
	}
	defer object.Close()

	// Read the ZIP content
	zipContent, err := io.ReadAll(object)
	if err != nil {
		return fmt.Errorf("failed to read ZIP content: %v", err)
	}

	log.Printf("[WORKER] Downloaded input.zip for job %s (%d bytes)", jobID, len(zipContent))

	// Extract and process files (reuse existing processBatchJob logic)
	zipReader, err := zip.NewReader(bytes.NewReader(zipContent), int64(len(zipContent)))
	if err != nil {
		return fmt.Errorf("failed to read ZIP: %v", err)
	}

	// Extract files
	var extractedFiles []ExtractedFile
	for _, file := range zipReader.File {
		if file.FileInfo().IsDir() {
			continue
		}

		rc, err := file.Open()
		if err != nil {
			log.Printf("[WORKER] Failed to open file %s: %v", file.Name, err)
			continue
		}

		content, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			log.Printf("[WORKER] Failed to read file %s: %v", file.Name, err)
			continue
		}

		extractedFiles = append(extractedFiles, ExtractedFile{
			Name:    file.Name,
			Content: string(content), // Convert []byte to string
			Mode:    file.Mode(),
			ModTime: file.Modified,
		})
	}

	log.Printf("[WORKER] Extracted %d files from job %s", len(extractedFiles), jobID)

	// Create output ZIP (streaming approach to reduce memory)
	var outputZipBuffer bytes.Buffer
	zipWriter := zip.NewWriter(&outputZipBuffer)

	totalStats := map[string]int{
		"ip_addresses":    0,
		"ad_accounts":     0,
		"jwt_tokens":      0,
		"private_keys":    0,
		"passwords":       0,
		"sensitive_terms": 0,
		"user_words":      0,
	}

	for i, file := range extractedFiles {
		// Check if job was cancelled
		if isJobCancelled(jobID) {
			log.Printf("[WORKER] Job %s cancelled by user, aborting at file %d/%d", jobID, i+1, len(extractedFiles))
			updateJobStatus(jobID, "cancelled", len(extractedFiles), i, "Cancelled by user")
			return fmt.Errorf("job cancelled by user")
		}

		log.Printf("[WORKER] Sanitizing file %d/%d: %s", i+1, len(extractedFiles), file.Name)

		// Call your existing sanitize function (no user words for batch jobs)
		sanitizedContent, stats := sanitizeText(file.Content, nil, false, file.Name)

		// Aggregate stats
		totalStats["ip_addresses"] += stats["total_ips"]
		totalStats["ad_accounts"] += stats["ad_accounts"]
		totalStats["jwt_tokens"] += stats["jwt_tokens"]
		totalStats["private_keys"] += stats["private_keys"]
		totalStats["passwords"] += stats["passwords"]
		totalStats["sensitive_terms"] += stats["sensitive_terms"]
		totalStats["user_words"] += stats["user_words"]

		// Write directly to ZIP (streaming - don't hold all files in memory)
		header := &zip.FileHeader{
			Name:   file.Name,
			Method: zip.Deflate,
		}
		header.SetMode(file.Mode)
		header.SetModTime(file.ModTime)

		writer, err := zipWriter.CreateHeader(header)
		if err != nil {
			log.Printf("[WORKER] Failed to create ZIP entry for %s: %v", file.Name, err)
			continue
		}

		if _, err := writer.Write([]byte(sanitizedContent)); err != nil {
			log.Printf("[WORKER] Failed to write file to ZIP: %v", err)
			continue
		}

		// Release memory immediately after writing each file
		sanitizedContent = ""

		// Trigger GC every 10 large files to keep memory under control
		if i%10 == 0 && i > 0 {
			// Small sleep to allow GC to catch up on large batches
			time.Sleep(100 * time.Millisecond)
		}

		// Update progress
		updateJobStatus(jobID, "processing", len(extractedFiles), i+1, "")

		if i%50 == 0 || i == len(extractedFiles)-1 {
			log.Printf("[WORKER] Job %s progress: %d/%d files (%.1f%%)",
				jobID, i+1, len(extractedFiles), float64(i+1)/float64(len(extractedFiles))*100)
		}
	}

	if err := zipWriter.Close(); err != nil {
		return fmt.Errorf("failed to finalize output ZIP: %v", err)
	}

	outputZipData := outputZipBuffer.Bytes()
	log.Printf("[WORKER] Created output.zip for job %s (%d bytes)", jobID, len(outputZipData))

	// Generate reports (IP mappings, summary)
	log.Printf("[WORKER] Job %s: generating reports", jobID)

	// Calculate processing time
	processingTime := time.Since(jobStartTime)

	// 1. IP Mappings Report
	ipMappingsReport := generateIPMappingsReportInMemory()

	// 2. Processing Summary
	summaryReport := generateProcessingSummaryInMemory(jobID, len(extractedFiles), totalStats, processingTime)

	// Upload reports to MinIO (use existing ctx from function start)

	// Upload IP mappings
	ipMappingsObjectName := fmt.Sprintf("%s/%s/reports/ip-mappings.csv", username, jobID)
	if err := uploadToMinIO(ctx, ipMappingsObjectName, bytes.NewReader([]byte(ipMappingsReport)), int64(len(ipMappingsReport))); err != nil {
		log.Printf("[WORKER] Warning: Failed to upload IP mappings report: %v", err)
	} else {
		log.Printf("[WORKER] Uploaded IP mappings report (%d bytes)", len(ipMappingsReport))
	}

	// Upload summary
	summaryObjectName := fmt.Sprintf("%s/%s/reports/summary.json", username, jobID)
	if err := uploadToMinIO(ctx, summaryObjectName, bytes.NewReader([]byte(summaryReport)), int64(len(summaryReport))); err != nil {
		log.Printf("[WORKER] Warning: Failed to upload summary report: %v", err)
	} else {
		log.Printf("[WORKER] Uploaded summary report (%d bytes)", len(summaryReport))
	}

	// Upload output.zip to MinIO
	outputObjectName := fmt.Sprintf("%s/%s/output.zip", username, jobID)
	if err := uploadToMinIO(ctx, outputObjectName, bytes.NewReader(outputZipData), int64(len(outputZipData))); err != nil {
		return fmt.Errorf("failed to upload output to MinIO: %v", err)
	}

	log.Printf("[WORKER] Uploaded output.zip for job %s", jobID)

	// Record Prometheus metrics
	batchProcessingDuration.Observe(processingTime.Seconds())
	batchFilesProcessed.Add(float64(len(extractedFiles)))
	batchJobsTotal.WithLabelValues("completed").Inc()

	// Record pattern detection metrics
	batchPatternsDetected.WithLabelValues("ip_address").Add(float64(totalStats["ip_addresses"]))
	batchPatternsDetected.WithLabelValues("ad_account").Add(float64(totalStats["ad_accounts"]))
	batchPatternsDetected.WithLabelValues("jwt_token").Add(float64(totalStats["jwt_tokens"]))
	batchPatternsDetected.WithLabelValues("private_key").Add(float64(totalStats["private_keys"]))
	batchPatternsDetected.WithLabelValues("password").Add(float64(totalStats["passwords"]))
	batchPatternsDetected.WithLabelValues("sensitive_term").Add(float64(totalStats["sensitive_terms"]))
	batchPatternsDetected.WithLabelValues("user_word").Add(float64(totalStats["user_words"]))

	// Update job status to completed
	log.Printf("[WORKER] Job %s completed in %.2f seconds", jobID, processingTime.Seconds())
	updateJobStatus(jobID, "completed", len(extractedFiles), len(extractedFiles), "")

	return nil
}

// cleanupOldJobsWorker removes jobs older than 48 hours from MinIO and database
func cleanupOldJobsWorker() {
	log.Printf("[WORKER] Running cleanup task (8-hour retention)")

	cutoffTime := time.Now().Add(-8 * time.Hour)

	// Query database for old jobs
	resp, err := http.Get(fmt.Sprintf("%s/jobs/cleanup?before=%s",
		adServiceURL, cutoffTime.Format(time.RFC3339)))
	if err != nil {
		log.Printf("[WORKER] Failed to query old jobs: %v", err)
		return
	}
	defer resp.Body.Close()

	var result struct {
		Jobs []struct {
			JobID    string `json:"job_id"`
			Username string `json:"username"`
		} `json:"jobs"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		log.Printf("[WORKER] Failed to decode cleanup jobs: %v", err)
		return
	}

	if len(result.Jobs) == 0 {
		log.Printf("[WORKER] No old jobs to clean up")
		return
	}

	log.Printf("[WORKER] Found %d old jobs to clean up", len(result.Jobs))

	ctx := context.Background()
	cleanedCount := 0

	for _, job := range result.Jobs {
		// Delete from MinIO
		inputObj := fmt.Sprintf("%s/%s/input.zip", job.Username, job.JobID)
		outputObj := fmt.Sprintf("%s/%s/output.zip", job.Username, job.JobID)

		deleteFromMinIO(ctx, inputObj)
		deleteFromMinIO(ctx, outputObj)

		// Delete from database
		req, _ := http.NewRequest("DELETE",
			fmt.Sprintf("%s/jobs/delete/%s", adServiceURL, job.JobID), nil)
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			resp.Body.Close()
			cleanedCount++
		}
	}

	log.Printf("[WORKER] Cleanup complete: %d jobs removed", cleanedCount)
}

// generateIPMappingsReportInMemory creates IP mappings CSV in memory
func generateIPMappingsReportInMemory() string {
	mapMutex.Lock()
	defer mapMutex.Unlock()

	var buf strings.Builder
	buf.WriteString("original_ip,placeholder,timestamp\n")

	for original, placeholder := range ipMappings {
		buf.WriteString(fmt.Sprintf("%s,%s,%s\n", original, placeholder, time.Now().Format(time.RFC3339)))
	}

	return buf.String()
}

// generateProcessingSummaryInMemory creates processing summary JSON in memory
func generateProcessingSummaryInMemory(jobID string, fileCount int, stats map[string]int, duration time.Duration) string {
	summary := map[string]interface{}{
		"job_id":          jobID,
		"timestamp":       time.Now().Format(time.RFC3339),
		"total_files":     fileCount,
		"processing_time": duration.String(),
		"patterns_found": map[string]int{
			"ip_addresses":    stats["ip_addresses"],
			"ad_accounts":     stats["ad_accounts"],
			"jwt_tokens":      stats["jwt_tokens"],
			"private_keys":    stats["private_keys"],
			"passwords":       stats["passwords"],
			"sensitive_terms": stats["sensitive_terms"],
			"user_words":      stats["user_words"],
		},
		"total_patterns": stats["ip_addresses"] + stats["ad_accounts"] + stats["jwt_tokens"] +
			stats["private_keys"] + stats["passwords"] + stats["sensitive_terms"] + stats["user_words"],
	}

	data, _ := json.MarshalIndent(summary, "", "  ")
	return string(data)
}

// tourContentHandler serves tour content JSON from ConfigMap
func tourContentHandler(w http.ResponseWriter, r *http.Request) {
	// Extract language from path: /api/tour/en or /api/tour/he
	lang := strings.TrimPrefix(r.URL.Path, "/api/tour/")
	if lang == "" {
		lang = "en" // default to English
	}

	// Validate language
	if lang != "en" && lang != "he" {
		http.Error(w, "Unsupported language. Use 'en' or 'he'", http.StatusBadRequest)
		return
	}

	// Try to read from ConfigMap mount path
	tourConfigPath := os.Getenv("TOUR_CONFIG_PATH")
	if tourConfigPath == "" {
		tourConfigPath = "/config/tour" // default mount path
	}

	filePath := fmt.Sprintf("%s/tour-%s.json", tourConfigPath, lang)
	content, err := os.ReadFile(filePath)
	if err != nil {
		// If file not found, return embedded fallback (minimal tour)
		log.Printf("[TOUR] Config file not found at %s, returning fallback", filePath)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fallback := `{"meta":{"version":"1.0","language":"` + lang + `"},"steps":[],"ui":{"buttons":{"next":"Next","prev":"Back","skip":"Skip","finish":"Done"},"tourButton":"Start Tour"}}`
		w.Write([]byte(fallback))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600") // Cache for 1 hour
	w.Write(content)
}

// OpenAPI spec handler
func openapiHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/x-yaml")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Write(openapiSpec)
}

// Swagger UI HTML handler
func swaggerUIHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(swaggerUIHTML)
}

// Swagger UI static assets handler
func swaggerUIAssetsHandler(w http.ResponseWriter, r *http.Request) {
	asset := strings.TrimPrefix(r.URL.Path, "/docs/")

	switch asset {
	case "swagger-ui.css":
		w.Header().Set("Content-Type", "text/css")
		w.Write(swaggerUICSS)
	case "swagger-ui-bundle.js":
		w.Header().Set("Content-Type", "application/javascript")
		w.Write(swaggerUIBundleJS)
	case "swagger-ui-standalone-preset.js":
		w.Header().Set("Content-Type", "application/javascript")
		w.Write(swaggerUIPresetJS)
	default:
		http.NotFound(w, r)
	}
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// NEW v0.13.0: Load MODE and MinIO configuration
	runMode = os.Getenv("MODE")
	if runMode == "" {
		runMode = "frontend" // Default to frontend for backwards compatibility
	}
	log.Printf("[STARTUP] Running in %s mode", strings.ToUpper(runMode))

	minioEndpoint = os.Getenv("MINIO_ENDPOINT")
	minioAccessKey = os.Getenv("MINIO_ACCESS_KEY")
	minioSecretKey = os.Getenv("MINIO_SECRET_KEY")
	minioBucket = os.Getenv("MINIO_BUCKET")
	if minioBucket == "" {
		minioBucket = "yossarian-jobs"
	}
	minioUseSSL = os.Getenv("MINIO_USE_SSL") == "true"

	if interval := os.Getenv("WORKER_POLL_INTERVAL"); interval != "" {
		if val, err := strconv.Atoi(interval); err == nil {
			workerPollInterval = val
		}
	}

	// Initialize MinIO if configured
	if minioEndpoint != "" {
		var err error
		minioClient, err = initMinIO()
		if err != nil {
			log.Fatalf("[FATAL] MinIO initialization failed: %v", err)
		}
		log.Printf("[STARTUP] MinIO initialized successfully")
	} else if runMode == "frontend" {
		log.Printf("[WARN] Frontend mode but MinIO not configured - batch processing will fail")
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

	// Batch job routes
	http.HandleFunc("/api/jobs/status/", jobStatusAPIHandler)
	http.HandleFunc("/api/jobs/list", jobListAPIHandler)
	// Removed: /jobs/my-jobs route - My Jobs is now integrated into SPA (index.html panel)
	http.HandleFunc("/jobs/download/", jobDownloadHandler)
	http.HandleFunc("/jobs/reports/", jobReportsDownloadHandler)
	http.HandleFunc("/api/jobs/delete/", jobDeleteAPIHandler)
	http.HandleFunc("/api/jobs/cancel/", jobCancelAPIHandler)

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
	http.HandleFunc("/admin/api/org-settings/list", adminRequired(proxyOrgSettingsList))
	http.HandleFunc("/admin/api/org-settings/update", adminRequired(proxyOrgSettingsUpdate))
	http.HandleFunc("/api/org-settings/public", proxyOrgSettingsPublic) // No auth required - public endpoint

	// Tour content endpoint (no auth required - public endpoint)
	http.HandleFunc("/api/tour/", tourContentHandler)

	// API Documentation (OpenAPI + Swagger UI)
	http.HandleFunc("/api/openapi.yaml", openapiHandler)
	http.HandleFunc("/docs", swaggerUIHandler)
	http.HandleFunc("/docs/", swaggerUIAssetsHandler)

	// Debug route
	http.HandleFunc("/debug", debugHandler)

	// ✅ ADD: Prometheus metrics endpoint
	http.Handle("/metrics", promhttp.Handler())

	// NEW v0.13.0: Worker mode specific startup
	if runMode == "worker" {
		log.Printf("[WORKER] Starting batch worker...")

		// Start batch worker in background
		go startBatchWorker()

		// Start cleanup task (runs every 6 hours)
		go func() {
			ticker := time.NewTicker(6 * time.Hour)
			defer ticker.Stop()

			// Run cleanup immediately on startup
			cleanupOldJobsWorker()

			// Then run every 6 hours
			for range ticker.C {
				cleanupOldJobsWorker()
			}
		}()

		log.Printf("[WORKER] Batch worker and cleanup task started")
	}

	log.Printf("Server starting on port %s with /metrics endpoint", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
