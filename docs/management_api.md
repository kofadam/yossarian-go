## 📋 **Yossarian Go - Complete REST API Reference**

### **🏠 Main Application API** (Port 8080)

#### Core Endpoints

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/` | Session | Main web interface (HTML) |
| `GET` | `/health` | None | Application health check |
| `GET` | `/metrics` | None | Prometheus metrics |
| `GET` | `/api/userinfo` | Session | Current user authentication info |
| `GET` | `/api/config` | Session/API | Get configuration limits |

#### File Processing

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `POST` | `/upload` | Session/API | **Upload and sanitize files** |
| `GET` | `/download/sanitized` | Session/API | **Download all sanitized files (ZIP)** |
| `GET` | `/download/sanitized/single` | Session/API | Download combined sanitized content |
| `GET` | `/download/sanitized/{filename}` | Session/API | Download specific sanitized file |
| `GET` | `/download/detailed-report` | Session/API | Download detailed replacement CSV |
| `GET` | `/mappings/csv` | Session/API | **Download IP mappings audit report (CSV)** |
| `POST` | `/clear-download-cache` | Session/API | Clear download cache |

#### Batch Jobs

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/api/jobs/list` | Session/API | **List user's batch jobs** |
| `GET` | `/api/jobs/status/{job_id}` | Session/API | **Get job status** |
| `GET` | `/jobs/download/{job_id}` | Session/API | **Download sanitized output ZIP** |
| `GET` | `/jobs/reports/{job_id}/ip-mappings.csv` | Session/API | Download IP mappings for job |
| `GET` | `/jobs/reports/{job_id}/summary.json` | Session/API | Download processing summary |
| `GET` | `/jobs/reports/{job_id}/detailed-report.csv` | Session/API | Download detailed report |
| `POST` | `/api/jobs/cancel/{job_id}` | Session/API | **Cancel a queued/processing job** |
| `DELETE` | `/api/jobs/delete/{job_id}` | Session/API | **Delete a job and its files** |

### **🔐 Authentication Endpoints** (Port 8080)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/admin/login` | Admin login page |
| `POST` | `/admin/login` | Admin password authentication |
| `GET` | `/admin/logout` | Admin logout |
| `GET` | `/auth/oidc/login` | **Enterprise SSO login** |
| `GET` | `/auth/oidc/callback` | OIDC callback handler |

### **🔑 API Key Management** (Port 8080) - v0.13.17+

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/admin/api/keys/list` | Admin | **List all API keys** |
| `POST` | `/admin/api/keys/create` | Admin | **Create new API key** |
| `DELETE` | `/admin/api/keys/revoke` | Admin | **Revoke an API key** |

### **⚙️ Admin Panel Endpoints** (Port 8080)

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/admin` | Admin | **Admin dashboard** |
| `GET` | `/admin/ad-accounts` | Admin | AD account management |
| `GET` | `/admin/api/ldap/status` | Admin | LDAP connection status |
| `POST` | `/admin/api/ldap/sync` | Admin | Trigger LDAP sync |
| `GET` | `/admin/api/ldap/test` | Admin | Test LDAP connectivity |
| `GET` | `/admin/api/accounts/list` | Admin | List imported AD accounts |
| `GET` | `/admin/api/sensitive/list` | Admin | List sensitive terms |
| `POST` | `/admin/api/sensitive/add` | Admin | Add sensitive term |
| `DELETE` | `/admin/api/sensitive/delete` | Admin | Delete sensitive term |
| `GET` | `/admin/api/org-settings/list` | Admin | List organization settings |
| `POST` | `/admin/api/org-settings/update` | Admin | Update organization settings |
| `GET` | `/api/org-settings/public` | None | Public organization settings |

### **📚 Documentation Endpoints** (Port 8080)

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/api/docs` | None | OpenAPI/Swagger UI |
| `GET` | `/api/openapi.yaml` | None | OpenAPI specification |
| `GET` | `/api/tour/{lang}` | None | Guided tour content (en/he) |

---

### **🗄️ Database Service API** (Port 8081)

#### Health & Status

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Database service health |

#### AD Account Lookups

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/lookup/{account}` | **Lookup AD account USN mapping** |
| `GET` | `/accounts/list` | **List all imported AD accounts** |

#### LDAP Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/ldap/status` | **LDAP configuration and account counts** |
| `GET` | `/ldap/test` | **Test LDAP connectivity** |
| `POST` | `/ldap/sync-limited` | Manual limited import (testing) |
| `POST` | `/ldap/sync-full` | **Manual full AD import** |

#### Sensitive Terms

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/sensitive/list` | List all sensitive terms |
| `POST` | `/sensitive/add` | Add new sensitive term |
| `DELETE` | `/sensitive/delete` | Delete sensitive term |

#### Organization Settings

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/org-settings/list` | List all settings |
| `POST` | `/org-settings/update` | Update settings |
| `GET` | `/org-settings/public` | Public settings only |

#### Batch Job Management (Internal)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/jobs/create` | Create new job record |
| `GET` | `/jobs/status/{job_id}` | Get job status |
| `GET` | `/jobs/list/{username}` | List user's jobs |
| `POST` | `/jobs/update` | Update job progress |
| `DELETE` | `/jobs/delete/{job_id}` | Delete job record |
| `GET` | `/jobs/queued` | List all queued jobs |
| `GET` | `/jobs/cleanup` | List old jobs for cleanup |
| `GET` | `/batch/next` | **Get next queued job (worker only)** |

#### API Key Management (Internal)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/keys/list` | List all API keys |
| `POST` | `/api/keys/create` | Create new API key |
| `DELETE` | `/api/keys/revoke` | Revoke API key |
| `GET` | `/api/keys/validate/{key_id}` | Validate API key |
| `POST` | `/api/keys/touch/{key_id}` | Update last_used timestamp |

#### Development/Testing

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/add-test-data` | Add test data (development) |

---

## 🔑 **API Key Authentication** (v0.13.17+)

### Creating an API Key

```bash
# Via Admin Panel (recommended)
# 1. Login to Yossarian Go
# 2. Go to Admin → API Keys tab
# 3. Click "Generate New API Key"
# 4. Copy the key (shown only once!)

# Key format: yoss_<64-character-hex-string>
```

### Using API Keys

```bash
# Set your API key
API_KEY="yoss_7943b78f71f7e846127233de083eb7ce9d0876f292e09486f753aea4553de371"

# All requests use X-API-Key header
curl -H "X-API-Key: $API_KEY" http://yossarian.example.com/api/jobs/list
```

---

## 📥 **Most Important Endpoints:**

### **For Pipeline Integration (API Key):**

```bash
# Set API key
API_KEY="yoss_your_key_here"
BASE_URL="http://yossarian.example.com"

# 1. Upload files for sanitization
curl -X POST "$BASE_URL/upload" \
  -H "X-API-Key: $API_KEY" \
  -F "file=@logs.zip"
# Returns: {"job_id": "batch-api-20260129-193057", "status": "queued", "total_files": 20}

# 2. Poll job status
curl -H "X-API-Key: $API_KEY" "$BASE_URL/api/jobs/status/batch-api-20260129-193057"
# Returns: {"status": "completed", "processed_files": 20, ...}

# 3. Download sanitized output
curl -H "X-API-Key: $API_KEY" "$BASE_URL/jobs/download/batch-api-20260129-193057" -o sanitized.zip

# 4. Download IP mappings report
curl -H "X-API-Key: $API_KEY" "$BASE_URL/jobs/reports/batch-api-20260129-193057/ip-mappings.csv"

# 5. Download processing summary
curl -H "X-API-Key: $API_KEY" "$BASE_URL/jobs/reports/batch-api-20260129-193057/summary.json"
```

### **For Regular Use (Browser Session):**

```bash
# Upload and sanitize files (requires session cookie)
curl -b cookies.txt -F "file=@logfile.log" http://localhost:8080/upload

# Download sanitized files
curl -b cookies.txt -O http://localhost:8080/download/sanitized

# Get audit trail
curl -b cookies.txt -O http://localhost:8080/mappings/csv
```

### **For Administration:**

```bash
# Check AD sync status
curl http://localhost:8081/ldap/status

# Import all AD accounts
curl -X POST http://localhost:8081/ldap/sync-full

# Test LDAP connectivity
curl http://localhost:8081/ldap/test

# List imported accounts
curl http://localhost:8081/accounts/list

# List API keys (via admin proxy)
curl -b cookies.txt http://localhost:8080/admin/api/keys/list
```

### **For Health Monitoring:**

```bash
# Main app health
curl http://localhost:8080/health
# Returns: {"status":"ok","service":"yossarian-go","version":"v0.13.17",...}

# Database service health
curl http://localhost:8081/health
# Returns: {"status":"ok","service":"yossarian-db-service"}

# Prometheus metrics
curl http://localhost:8080/metrics
```

---

## 🔍 **Quick SQLite Search Commands:**

**1. Search for specific user/computer:**
```bash
kubectl exec -it deployment/yossarian-db-service -n yossarian-go -- \
  sqlite3 /data/yossarian.db "SELECT * FROM ad_accounts WHERE account LIKE '%real-user%';"
```

**2. Search for computer accounts:**
```bash
kubectl exec -it deployment/yossarian-db-service -n yossarian-go -- \
  sqlite3 /data/yossarian.db "SELECT * FROM ad_accounts WHERE account LIKE '%SERVER01%';"
```

**3. Count all entries:**
```bash
kubectl exec -it deployment/yossarian-db-service -n yossarian-go -- \
  sqlite3 /data/yossarian.db "SELECT COUNT(*) FROM ad_accounts;"
```

**4. Show all computer accounts:**
```bash
kubectl exec -it deployment/yossarian-db-service -n yossarian-go -- \
  sqlite3 /data/yossarian.db "SELECT * FROM ad_accounts WHERE account LIKE '%$' LIMIT 10;"
```

**5. Check if user exists in any format:**
```bash
kubectl exec -it deployment/yossarian-db-service -n yossarian-go -- \
  sqlite3 /data/yossarian.db "SELECT * FROM ad_accounts WHERE UPPER(account) LIKE '%JOHN.DOE%';"
```

**6. List all API keys:**
```bash
kubectl exec -it deployment/yossarian-db-service -n yossarian-go -- \
  sqlite3 /data/yossarian.db "SELECT key_id, name, username, created_at, last_used_at FROM api_keys;"
```

**7. Check batch job status:**
```bash
kubectl exec -it deployment/yossarian-db-service -n yossarian-go -- \
  sqlite3 /data/yossarian.db "SELECT job_id, username, status, total_files, processed_files FROM batch_jobs ORDER BY created_at DESC LIMIT 10;"
```

---

## 📊 **Response Examples**

### Upload Response (Single File)
```json
{
  "files": [{
    "filename": "server.log",
    "original_size": 1024000,
    "sanitized_size": 1020000,
    "processing_time": "0.85s",
    "total_ips": 45,
    "ad_accounts": 12,
    "jwt_tokens": 2,
    "private_keys": 0,
    "sensitive_terms": 8,
    "status": "sanitized"
  }],
  "total_files": 1,
  "total_ip_mappings": 45,
  "status": "completed"
}
```

### Upload Response (Batch Job)
```json
{
  "job_id": "batch-Administrator-20260129-193057",
  "status": "queued",
  "total_files": 20,
  "message": "Batch job submitted successfully"
}
```

### Job Status Response
```json
{
  "job_id": "batch-Administrator-20260129-193057",
  "username": "Administrator",
  "status": "completed",
  "total_files": 20,
  "processed_files": 20,
  "created_at": "2026-01-29T19:30:57Z",
  "started_at": "2026-01-29T19:31:00Z",
  "completed_at": "2026-01-29T19:31:16Z",
  "error_message": null
}
```

### API Key List Response
```json
{
  "keys": [
    {
      "key_id": "yoss_7943b78f71f7",
      "name": "CI Pipeline",
      "username": "Administrator",
      "created_at": "2026-01-29T12:00:00Z",
      "last_used_at": "2026-01-29T19:30:57Z",
      "expires_at": null,
      "is_active": true
    }
  ],
  "total": 1
}
```

---

**🛡️ Yossarian Go v0.13.17 - The complete enterprise log sanitization API suite!**

**Last Updated:** January 2026
