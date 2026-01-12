# Yossarian Go - Technical Architecture

This document provides detailed technical information about Yossarian Go's architecture, components, and deployment patterns.

---

## 🏗️ System Architecture

### Split Architecture (v0.13.0+)

```
┌──────────────────┐     ┌──────────────────┐     ┌──────────────┐
│ Frontend Pods    │────▶│ MinIO Storage    │◀─────│ Worker Pod   │
│ (Scalable 1-10+) │     │ (Batch Files)    │     │ (Single Pod) │
│ - Web UI         │     │ - input.zip      │     │ - Job Queue  │
│ - Upload Handler │     │ - output.zip     │     │ - Processing │
│ - OIDC Auth      │     │ - 8hr retention  │     │ - AD Lookups │
└──────────────────┘     └──────────────────┘     └──────────────┘
         │                                                  │
         └──────────────────────┬───────────────────────────┘
                                │
                       ┌────────▼─────────┐
                       │  DB Service Pod  │
                       │  - Job Queue     │
                       │  - AD Cache      │
                       │  - Org Settings  │
                       └──────────────────┘
```

---

## 📦 Components

### 1. Frontend Pods

**Purpose:** Handle all user-facing interactions
**Scaling:** Horizontal (1-10+ pods via HPA)
**Storage:** None (stateless)

**Responsibilities:**
- ✅ Serve web UI (index.html, admin.html, my-jobs.html)
- ✅ Handle OIDC authentication
- ✅ Process single-file uploads (in-memory, synchronous)
- ✅ Accept batch job uploads → forward to MinIO
- ✅ Create job records in database (via db-service)
- ✅ Serve job status queries
- ✅ Proxy download requests to worker

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

### 2. Worker Pod

**Purpose:** Process batch jobs asynchronously
**Scaling:** Fixed 1 pod (RWO PVC limitation)
**Storage:** RWO PVC at /data/jobs/

**Responsibilities:**
- ✅ Poll database for queued jobs (5-second interval)
- ✅ Download input files from MinIO
- ✅ Extract and sanitize files (streaming architecture)
- ✅ Generate reports (IP mappings, processing summary, detailed CSV)
- ✅ Upload results to MinIO
- ✅ Serve download requests
- ✅ Clean up old jobs (8-hour retention)
- ✅ Cancel stale jobs (1-hour timeout, v0.13.8+)

**Does NOT:**
- ❌ Serve web UI
- ❌ Handle user authentication
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

**Memory Optimization (v0.13.8):**
- Streaming file processing (no full content in memory)
- Progressive ZIP extraction
- Per-file sanitization (release memory after each file)
- Reduced resource limits: 256Mi request, 512Mi limit

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

**Purpose:** Metadata and job queue management
**Scaling:** Single pod with RWO PVC
**Storage:** SQLite on RWO PVC (10Gi)

**Tables:**
- `batch_jobs` - Job queue and status tracking
- `ad_accounts` - AD lookup cache (refreshed via LDAP sync)
- `sensitive_terms` - Organization-wide sensitive patterns
- `org_settings` - Disclaimer, documentation links

**API Endpoints:**
```
POST   /jobs/create       - Create new batch job
GET    /jobs/status/:id   - Get job status
GET    /jobs/list/:user   - List user's jobs
POST   /jobs/update       - Update job progress/status
DELETE /jobs/delete/:id   - Delete job record
GET    /batch/next        - Get next queued job (worker only)

GET    /ldap/status       - LDAP connection status
POST   /ldap/sync-full    - Trigger full AD sync
GET    /accounts/list     - List all AD accounts
GET    /sensitive/list    - List sensitive terms
POST   /sensitive/add     - Add sensitive term
DELETE /sensitive/delete  - Remove sensitive term
```

---

## 🔄 Data Flow

### Single File Upload (Synchronous)

```
1. User uploads file (< 50MB)
   ↓
2. Frontend receives upload
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
1. User uploads ZIP (up to 500MB)
   ↓
2. Frontend receives upload
   ↓
3. Frontend uploads to MinIO:
   minio://yossarian-jobs/{user}/{job_id}/input.zip
   ↓
4. Frontend creates DB record:
   INSERT INTO batch_jobs (job_id, username, status='queued')
   ↓
5. Frontend returns to user:
   {"job_id": "abc123", "status": "queued"}
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
        
        h. Update DB: UPDATE batch_jobs SET status='complete'
        
        ⏱️ Time: ~30 seconds for 50MB ZIP with 100 files
    
    3. Sleep 5 seconds
```

### Job Download

```
1. User clicks download
   ↓
2. Request routes to worker pod (via HTTPProxy)
   ↓
3. Worker checks MinIO for output.zip
   ↓
4. Worker streams file to user
   ↓
5. User receives sanitized.zip
```

---

## 🔒 Security Architecture

### Authentication Flow (OIDC)

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

**Role-Based Access:**
- `admin` role: Full admin panel access, can manage all jobs
- `user` role: Upload files, view own jobs
- No role: Access denied (if AUTO_SSO=true)

### Data Isolation

**Per-User MinIO Paths:**
```
yossarian-jobs/
├── alice/
│   └── batch-alice-20260112-143022/
├── bob/
│   └── batch-bob-20260112-143045/
└── carol/
    └── batch-carol-20260112-143101/
```

**Download Authorization:**
- User must own job OR be admin
- Session validation before streaming
- No direct MinIO access from users

---

## 📊 Monitoring Architecture

### Prometheus Metrics Endpoints

**Frontend Pods:**
```
http://frontend-pod:8080/metrics
```

**Worker Pod:**
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
```

**Pattern Detection:**
```
yossarian_patterns_detected_total{pattern_type="ip_address"}
yossarian_patterns_detected_total{pattern_type="ad_account"}
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

---

## 🚀 Deployment Patterns

### Standard Deployment

```yaml
# 3 frontend pods (horizontal scaling)
frontend:
  replicas: 3
  resources:
    requests:
      memory: 128Mi
      cpu: 100m

# 1 worker pod (PVC constraint)
worker:
  replicas: 1
  resources:
    requests:
      memory: 256Mi  # Optimized in v0.13.8
      cpu: 500m

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

# Worker remains single pod
worker:
  replicas: 1  # Cannot scale (RWO PVC)
  resources:
    requests:
      memory: 512Mi
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
dt wrap oci://ghcr.io/kofadam/yossarian-go:0.13.8 -o /tmp/wrapped
```

2. **Transfer to air-gap environment:**
```bash
# Copy wrapped chart to air-gap
scp /tmp/wrapped/yossarian-go-0.13.8.wrap.tgz airgap-server:/tmp/
```

3. **Push to internal registry:**
```bash
dt push /tmp/yossarian-go-0.13.8.wrap.tgz \
  oci://registry.internal.local/yossarian-go:0.13.8
```

4. **Install from internal registry:**
```bash
helm install yossarian oci://registry.internal.local/yossarian-go:0.13.8
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
      memory: 256Mi  # Minimum for basic operation
    limits:
      memory: 512Mi  # Sufficient for most workloads
      
# For very large files (500MB+):
worker:
  resources:
    limits:
      memory: 1Gi
```

---

## 📋 Resource Requirements

### Minimum Requirements

| Component | CPU Request | Memory Request | Storage |
|-----------|-------------|----------------|---------|
| Frontend  | 100m        | 128Mi          | None    |
| Worker    | 500m        | 256Mi          | 50Gi    |
| MinIO     | 250m        | 512Mi          | 100Gi   |
| DB Service| 100m        | 128Mi          | 10Gi    |

### Recommended Production

| Component | CPU Request | Memory Request | Storage |
|-----------|-------------|----------------|---------|
| Frontend  | 200m        | 256Mi          | None    |
| Worker    | 1000m       | 512Mi          | 100Gi   |
| MinIO     | 500m        | 1Gi            | 500Gi   |
| DB Service| 200m        | 256Mi          | 20Gi    |

---

## 🐛 Troubleshooting

### Worker OOMKilled

**Symptoms:** Worker pod crashes with `OOMKilled` status

**Solutions:**
1. Increase memory limit: `worker.resources.limits.memory: 1Gi`
2. Reduce batch size: Process smaller ZIP files
3. Check for memory leaks in logs

### Jobs Stuck in Queue

**Symptoms:** Jobs stay in `queued` status indefinitely

**Checks:**
1. Verify worker pod is running: `kubectl get pods -n yossarian-go`
2. Check worker logs: `kubectl logs -n yossarian-go deployment/yossarian-worker`
3. Verify MinIO connectivity: `kubectl exec -n yossarian-go deploy/yossarian-worker -- wget -O- http://minio:9000/minio/health/live`

### AD Sync Failures

**Symptoms:** AD accounts not updating, lookups returning empty

**Solutions:**
1. Check LDAP connectivity: Use admin panel "Test LDAP"
2. Verify certificate: Check `database.ldap.caSecret` is correct
3. Check bind credentials: Ensure `LDAP_BIND_PASSWORD` is valid
4. Review search base: Confirm `LDAP_SEARCH_BASE` covers all users

---

## 📚 Additional Resources

- [Helm Chart README](../helm/yossarian-go/README.md)
- [Distribution Tooling Guide](DISTRIBUTION-TOOLING-GUIDE.md)
- [Certificate Configuration](CERTIFICATE-CONFIGURATION-GUIDE.md)
- [Development Guide](DEVELOPMENT.md)

---

**Document Version:** v0.13.8  
**Last Updated:** January 2026
