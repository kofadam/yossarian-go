# Yossarian Go - Technical Architecture

This document provides detailed technical information about Yossarian Go's architecture, components, and deployment patterns.

---

## 🏗️ System Architecture

### Split Architecture (v0.13.0+)

```
┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│ Frontend Pods    │────▶│ MinIO Storage    │◀────│ Worker Pods      │
│ (Scalable 1-10+) │     │ (Batch Files)    │     │ (Scalable 1-N)   │
│ - Web UI         │     │ - input.zip      │     │ - Job Queue      │
│ - Upload Handler │     │ - output.zip     │     │ - Processing     │
│ - OIDC Auth      │     │ - 8hr retention  │     │ - AD Lookups     │
│ - API Key Auth   │     └──────────────────┘     │ - Init Containers│
└──────────────────┘                              └──────────────────┘
         │                                                  │
         └──────────────────────┬───────────────────────────┘
                                │
                       ┌────────▼─────────┐
                       │  DB Service Pod  │
                       │  - Job Queue     │
                       │  - AD Cache      │
                       │  - API Keys      │
                       │  - Org Settings  │
                       └──────────────────┘
```

---

## 📦 Components

### 1. Frontend Pods

**Purpose:** Handle all user-facing interactions
**Scaling:** Horizontal (1-10+ pods via HPA)
**Storage:** None (stateless)
**Init Containers:** Wait for MinIO and DB Service (v0.13.18+)

**Responsibilities:**
- ✅ Serve web UI (index.html, admin.html, api-docs.html)
- ✅ Handle OIDC authentication
- ✅ Handle API key authentication (v0.13.17+)
- ✅ Process single-file uploads (in-memory, synchronous)
- ✅ Accept batch job uploads → forward to MinIO
- ✅ Create job records in database (via db-service)
- ✅ Serve job status queries
- ✅ Proxy download requests to worker
- ✅ Serve OpenAPI/Swagger documentation

**Does NOT:**
- ❌ Process batch jobs
- ❌ Store files locally
- ❌ Generate reports

**Environment Variables:**
```bash
MODE=frontend
PORT=8080
MINIO_ENDPOINT=minio:9000
MINIO_ACCESS_KEY=yossarian
MINIO_SECRET_KEY=<secret>
MINIO_BUCKET=yossarian-jobs
AD_SERVICE_URL=http://yossarian-db-service:8081
OIDC_ENABLED=true
OIDC_ISSUER_URL=https://keycloak.example.com/realms/myrealm
```

---

### 2. Worker Pods

**Purpose:** Process batch jobs asynchronously
**Scaling:** Horizontal (1-N pods, v0.13.18+ removed PVC dependency)
**Storage:** None (uses MinIO for all file storage)
**Init Containers:** Wait for MinIO and DB Service (v0.13.18+)

**Responsibilities:**
- ✅ Poll database for queued jobs (5-second interval)
- ✅ Download input files from MinIO
- ✅ Extract and sanitize files (streaming architecture)
- ✅ Generate reports (IP mappings, processing summary, detailed CSV)
- ✅ Upload results to MinIO
- ✅ Serve download requests
- ✅ Clean up old jobs (8-hour retention)
- ✅ Cancel stale jobs (1-hour timeout)
- ✅ Support API key authenticated downloads

**Does NOT:**
- ❌ Serve web UI
- ❌ Handle user authentication (validates session/API key only)
- ❌ Process single-file uploads

**Environment Variables:**
```bash
MODE=worker
PORT=8080
MINIO_ENDPOINT=minio:9000
MINIO_ACCESS_KEY=yossarian
MINIO_SECRET_KEY=<secret>
MINIO_BUCKET=yossarian-jobs
AD_SERVICE_URL=http://yossarian-db-service:8081
WORKER_POLL_INTERVAL=5
WORKER_CANCELLATION_TIMEOUT=3600  # 1 hour
```

**Memory Optimization (v0.13.8+):**
- Streaming file processing (no full content in memory)
- Progressive ZIP extraction
- Per-file sanitization (release memory after each file)
- Reduced resource limits: 512Mi request, 2Gi limit

**Init Containers (v0.13.18+):**
```yaml
initContainers:
  - name: wait-for-minio
    image: busybox:1.36
    command: ['sh', '-c', 'until nc -z minio 9000; do sleep 2; done']
  - name: wait-for-db
    image: busybox:1.36
    command: ['sh', '-c', 'until nc -z yossarian-db-service 8081; do sleep 2; done']
```

---

### 3. MinIO

**Purpose:** Centralized file storage
**Scaling:** Single pod with RWO PVC
**Storage:** RWO PVC (100Gi default)

**Storage Structure:**
```
yossarian-jobs/
├── {username}/
│   ├── {job_id}/
│   │   ├── input.zip       # Original upload
│   │   └── output.zip      # Sanitized results
│   │   └── reports/
│   │       ├── ip-mappings.csv
│   │       ├── summary.json
│   │       └── detailed-report.csv (optional)
```

**Access Patterns:**
- Frontend: Write input.zip
- Worker: Read input.zip, Write output.zip + reports
- User: Download output.zip + reports (via worker proxy)

**Retention:** 8 hours after job completion

---

### 4. DB Service Pod

**Purpose:** Metadata, job queue, and API key management
**Scaling:** Single pod with RWO PVC
**Storage:** SQLite on RWO PVC (10Gi)

**Tables:**
- `batch_jobs` - Job queue and status tracking
- `ad_accounts` - AD lookup cache (refreshed via LDAP sync)
- `sensitive_terms` - Organization-wide sensitive patterns
- `org_settings` - Disclaimer, documentation links
- `api_keys` - API key storage and validation (v0.13.17+)

**API Endpoints:**
```
# Job Management
POST   /jobs/create       - Create new batch job
GET    /jobs/status/:id   - Get job status
GET    /jobs/list/:user   - List user's jobs
POST   /jobs/update       - Update job progress/status
DELETE /jobs/delete/:id   - Delete job record
GET    /batch/next        - Get next queued job (worker only)

# LDAP/AD
GET    /ldap/status       - LDAP connection status
POST   /ldap/sync-full    - Trigger full AD sync
GET    /accounts/list     - List all AD accounts

# Sensitive Terms
GET    /sensitive/list    - List sensitive terms
POST   /sensitive/add     - Add sensitive term
DELETE /sensitive/delete  - Remove sensitive term

# API Keys (v0.13.17+)
GET    /api/keys/list     - List all API keys
POST   /api/keys/create   - Create new API key
DELETE /api/keys/revoke   - Revoke API key
GET    /api/keys/validate - Validate API key
POST   /api/keys/touch    - Update last_used timestamp
```

---

## 🔑 Authentication Architecture

### Dual Authentication (v0.13.17+)

Yossarian Go supports two authentication methods:

```
┌─────────────────────────────────────────────────────────────┐
│                    Authentication Layer                      │
├─────────────────────────────┬───────────────────────────────┤
│     Session-Based Auth      │      API Key Auth             │
│  (Browser/Interactive)      │   (Pipeline/Headless)         │
├─────────────────────────────┼───────────────────────────────┤
│  - OIDC/Keycloak SSO        │  - X-API-Key header           │
│  - Password (single-user)   │  - No cookies required        │
│  - Cookie-based sessions    │  - Stateless requests         │
│  - Role-based access        │  - Per-key permissions        │
│  - Token expiry from IdP    │  - Optional expiration        │
└─────────────────────────────┴───────────────────────────────┘
```

### Session-Based Authentication Flow (OIDC)

```
1. User accesses Yossarian
   ↓
2. Frontend redirects to Keycloak (if AUTO_SSO=true)
   ↓
3. User authenticates with Keycloak
   ↓
4. Keycloak redirects back with authorization code
   ↓
5. Frontend exchanges code for ID token
   ↓
6. Frontend extracts user info + roles from token
   ↓
7. Frontend creates session (expires with token)
   ↓
8. User accesses application
```

### API Key Authentication Flow (v0.13.17+)

```
1. Admin creates API key via Admin Panel
   ↓
2. System generates: yoss_<64-char-hex>
   ↓
3. Key stored as SHA256 hash in database
   ↓
4. Full key shown once to admin (copy immediately!)
   ↓
5. Pipeline uses key in X-API-Key header
   ↓
6. Each request:
   a. Extract key from header
   b. Hash key with SHA256
   c. Lookup hash in api_keys table
   d. Validate: is_active=1, not expired
   e. Update last_used_at timestamp
   f. Process request as key owner
```

**API Key Database Schema:**
```sql
CREATE TABLE api_keys (
    key_id TEXT PRIMARY KEY,        -- yoss_<first-12-chars>
    key_hash TEXT NOT NULL UNIQUE,  -- SHA256 of full key
    name TEXT NOT NULL,             -- User-provided description
    username TEXT NOT NULL,         -- Owner (from session)
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_used_at DATETIME,
    expires_at DATETIME,            -- NULL = never expires
    is_active INTEGER DEFAULT 1
);
```

**Role-Based Access:**
- `admin` role: Full admin panel access, can manage all jobs, can create API keys
- `user` role: Upload files, view own jobs
- No role: Access denied (if AUTO_SSO=true)
- API key: Inherits permissions of creating user

### Data Isolation

**Per-User MinIO Paths:**
```
yossarian-jobs/
├── alice/
│   └── batch-alice-20260112-143022/
├── bob/
│   └── batch-bob-20260112-143045/
└── api-CI-Pipeline/          # API key jobs use key name
    └── batch-api-20260129-193057/
```

**Download Authorization:**
- User must own job OR be admin
- Session validation OR API key validation before streaming
- No direct MinIO access from users

---

## 🔄 Data Flow

### Single File Upload (Synchronous)

```
1. User uploads file (< 50MB)
   ↓
2. Frontend receives upload (validates session OR API key)
   ↓
3. Frontend processes in-memory:
   - Sanitize content
   - Replace patterns
   - Generate IP mappings
   ↓
4. Frontend returns sanitized content immediately
   ⏱️ Time: <2 seconds
```

### Batch Job Upload (Asynchronous)

```
1. User/Pipeline uploads ZIP (up to 500MB)
   ↓
2. Frontend receives upload (validates session OR API key)
   ↓
3. Frontend uploads to MinIO:
   minio://yossarian-jobs/{user}/{job_id}/input.zip
   ↓
4. Frontend creates DB record:
   INSERT INTO batch_jobs (job_id, username, status='queued')
   ↓
5. Frontend returns to user:
   {"job_id": "batch-user-20260129-193057", "status": "queued"}
   ⏱️ Time: ~5 seconds (just upload time)
```

### Worker Processing Loop

```
while true:
    1. Query DB: SELECT * FROM batch_jobs WHERE status='queued' LIMIT 1
    
    2. If job found:
        a. Claim job: UPDATE batch_jobs SET status='processing'
        
        b. Download from MinIO:
           minio://yossarian-jobs/{user}/{job_id}/input.zip
        
        c. Extract ZIP (streaming, per-file)
        
        d. Process files (sanitize with AD lookups, pattern detection)
        
        e. Generate reports:
           - ip-mappings.csv
           - summary.json
           - detailed-report.csv (if enabled)
        
        f. Create output ZIP (streaming)
        
        g. Upload to MinIO:
           minio://yossarian-jobs/{user}/{job_id}/output.zip
           minio://yossarian-jobs/{user}/{job_id}/reports/*
        
        h. Update DB: UPDATE batch_jobs SET status='completed'
        
        ⏱️ Time: ~30 seconds for 50MB ZIP with 100 files
    
    3. Sleep 5 seconds
```

### Job Download (Session or API Key)

```
1. User/Pipeline requests download
   ↓
2. Request includes session cookie OR X-API-Key header
   ↓
3. Request routes to worker pod (via HTTPProxy)
   ↓
4. Worker validates authentication
   ↓
5. Worker checks job ownership (user must own job OR be admin)
   ↓
6. Worker checks MinIO for output.zip
   ↓
7. Worker streams file to user
   ↓
8. User receives sanitized.zip
```

---

## 📊 Monitoring Architecture

### Prometheus Metrics Endpoints

**Frontend Pods:**
```
http://frontend-pod:8080/metrics
```

**Worker Pods:**
```
http://worker-pod:8080/metrics
```

**DB Service:**
```
http://db-service-pod:8081/health  # Basic health only
```

### Metrics Collection Flow

```
                    ┌──────────────┐
                    │  Prometheus  │
                    │   Operator   │
                    └──────┬───────┘
                           │
           ┌───────────────┼───────────────┐
           │               │               │
           ▼               ▼               ▼
   ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
   │ServiceMonitor│ │ServiceMonitor│ │ServiceMonitor│
   │  (frontend)  │ │   (worker)  │ │ (db-service)│
   └──────┬───────┘ └──────┬───────┘ └──────┬──────┘
          │                │                 │
          ▼                ▼                 ▼
    frontend:8080    worker:8080      db-service:8081
      /metrics          /metrics          /health
```

### Key Metrics

**HTTP Requests:**
```
yossarian_http_requests_total{method="POST",endpoint="/upload",status="200"}
```

**Upload Sizes:**
```
yossarian_upload_size_bytes{file_type="zip"} (histogram)
```

**Processing Duration:**
```
yossarian_processing_duration_seconds{operation="upload"} (histogram)
yossarian_batch_processing_duration_seconds (histogram)
```

**Pattern Detection:**
```
yossarian_patterns_detected_total{pattern_type="ip_address"}
yossarian_patterns_detected_total{pattern_type="ad_account"}
yossarian_batch_patterns_detected_total{pattern_type="..."}
```

**Cache Performance:**
```
yossarian_ad_cache_hits_total
yossarian_ad_cache_misses_total
```

**Active Sessions:**
```
yossarian_active_sessions (gauge)
```

**Batch Jobs:**
```
yossarian_batch_jobs_total{status="queued|processing|completed|failed"}
yossarian_batch_job_queue_depth (gauge)
yossarian_batch_files_processed_total
```

**MinIO Operations:**
```
yossarian_minio_operations_total{operation="upload|download|delete"}
yossarian_minio_operation_duration_seconds{operation="..."}
yossarian_minio_operation_errors_total{operation="..."}
```

---

## 🚀 Deployment Patterns

### Standard Deployment

```yaml
# 3 frontend pods (horizontal scaling)
frontend:
  replicas: 3
  resources:
    requests:
      memory: 512Mi
      cpu: 250m

# 2 worker pods (horizontal scaling, v0.13.18+)
worker:
  replicas: 2
  resources:
    requests:
      memory: 512Mi
      cpu: 250m

# MinIO for storage
minio:
  persistence:
    size: 100Gi

# DB service for metadata
database:
  persistence:
    size: 10Gi
```

### High-Availability Deployment

```yaml
# Scale frontend for more users
frontend:
  replicas: 10
  autoscaling:
    enabled: true
    minReplicas: 5
    maxReplicas: 20
    targetCPUUtilizationPercentage: 70

# Scale workers for more throughput
worker:
  replicas: 5
  resources:
    requests:
      memory: 512Mi
      cpu: 500m
    limits:
      memory: 2Gi
      cpu: 1000m

# Larger MinIO storage
minio:
  persistence:
    size: 500Gi

# Enable monitoring
metrics:
  serviceMonitor:
    enabled: true
```

### Air-Gap Deployment

1. **Wrap chart with Distribution Tooling:**
```bash
dt wrap oci://ghcr.io/kofadam/charts/yossarian-go:0.13.18 -o /tmp/wrapped
```

2. **Transfer to air-gap environment:**
```bash
# Copy wrapped chart to air-gap
scp /tmp/wrapped/yossarian-go-0.13.18.wrap.tgz airgap-server:/tmp/
```

3. **Push to internal registry:**
```bash
dt unwrap /tmp/yossarian-go-0.13.18.wrap.tgz \
  oci://registry.internal.local/charts --yes
```

4. **Install from internal registry:**
```bash
helm install yossarian oci://registry.internal.local/charts/yossarian-go \
  --version 0.13.18
```

---

## 🔧 Advanced Configuration

### Custom CA Certificates

**For OIDC:**
```yaml
auth:
  oidc:
    enabled: true
    caSecret: oidc-ca-cert
    caKey: ca.crt
```

**For LDAPS:**
```yaml
database:
  ldap:
    enabled: true
    caSecret: ldap-ca-cert
    caKey: ca.crt
```

See [Certificate Configuration Guide](CERTIFICATE-CONFIGURATION-GUIDE.md) for details.

### Job Cancellation

```yaml
worker:
  cancellationTimeout: 3600  # Cancel jobs after 1 hour
```

Set to `0` to disable (not recommended).

### Memory Tuning

```yaml
worker:
  resources:
    requests:
      memory: 512Mi  # Minimum for basic operation
    limits:
      memory: 2Gi    # Sufficient for most workloads
      
# For very large files (500MB+):
worker:
  resources:
    limits:
      memory: 4Gi
```

### API Key Configuration

API keys are managed via the Admin Panel. No additional Helm configuration required.

**Best Practices:**
- Create separate API keys for each pipeline/integration
- Use descriptive names (e.g., "Jenkins CI", "GitLab Runner")
- Set expiration dates for temporary access
- Revoke unused keys promptly
- Monitor `last_used_at` for inactive keys

---

## 📋 Resource Requirements

### Minimum Requirements

| Component | CPU Request | Memory Request | Storage |
|-----------|-------------|----------------|---------|
| Frontend  | 250m        | 512Mi          | None    |
| Worker    | 250m        | 512Mi          | None    |
| MinIO     | 250m        | 512Mi          | 100Gi   |
| DB Service| 100m        | 128Mi          | 5Gi     |

### Recommended Production

| Component | CPU Request | Memory Request | Storage |
|-----------|-------------|----------------|---------|
| Frontend  | 500m        | 1Gi            | None    |
| Worker    | 1000m       | 2Gi            | None    |
| MinIO     | 500m        | 1Gi            | 500Gi   |
| DB Service| 200m        | 512Mi          | 20Gi    |

---

## 🐛 Troubleshooting

### Worker OOMKilled

**Symptoms:** Worker pod crashes with `OOMKilled` status

**Solutions:**
1. Increase memory limit: `worker.resources.limits.memory: 4Gi`
2. Reduce batch size: Process smaller ZIP files
3. Check for memory leaks in logs

### Jobs Stuck in Queue

**Symptoms:** Jobs stay in `queued` status indefinitely

**Checks:**
1. Verify worker pod is running: `kubectl get pods -n yossarian-go`
2. Check worker logs: `kubectl logs -n yossarian-go deployment/yossarian-worker`
3. Verify MinIO connectivity: `kubectl exec -n yossarian-go deploy/yossarian-worker -- wget -O- http://minio:9000/minio/health/live`
4. Check init containers completed: `kubectl describe pod -n yossarian-go -l mode=worker`

### AD Sync Failures

**Symptoms:** AD accounts not updating, lookups returning empty

**Solutions:**
1. Check LDAP connectivity: Use admin panel "Test LDAP"
2. Verify certificate: Check `database.ldap.caSecret` is correct
3. Check bind credentials: Ensure `LDAP_BIND_PASSWORD` is valid
4. Review search base: Confirm `LDAP_SEARCH_BASE` covers all users

### API Key Authentication Failures

**Symptoms:** 401 Unauthorized with valid API key

**Checks:**
1. Verify key format: Must start with `yoss_`
2. Check key is active: Admin Panel → API Keys
3. Check key not expired: Review `expires_at` in database
4. Verify header format: `X-API-Key: yoss_...` (case-sensitive)

### Pods Crash Loop on Startup

**Symptoms:** Frontend/Worker pods restart repeatedly

**Solutions (v0.13.18+):**
1. Init containers should prevent this - check they completed
2. Verify MinIO is healthy: `kubectl get pods -n yossarian-go -l app=minio`
3. Verify DB service is healthy: `kubectl get pods -n yossarian-go -l app=yossarian-db-service`
4. Check init container logs: `kubectl logs -n yossarian-go <pod> -c wait-for-minio`

---

## 📚 Additional Resources

- [Helm Chart README](../helm/yossarian-go/README.md)
- [Distribution Tooling Guide](DISTRIBUTION-TOOLING-GUIDE.md)
- [Certificate Configuration](CERTIFICATE-CONFIGURATION-GUIDE.md)
- [Development Guide](DEVELOPMENT.md)
- [API Documentation](/api/openapi.yaml)

---

**Document Version:** v0.13.17  
**Last Updated:** January 2026
