# Yossarian Go - Enterprise Log Sanitization System

![Go Version](https://img.shields.io/badge/Go-1.23-00ADD8?logo=go)
![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker)
![Kubernetes](https://img.shields.io/badge/Kubernetes-Native-326CE5?logo=kubernetes)
![Helm](https://img.shields.io/badge/Helm-Chart-0F1689?logo=helm)
![License](https://img.shields.io/badge/License-MIT-green)
![Version](https://img.shields.io/badge/Version-v0.10.0-blue)

🛡️ **Air-gapped log sanitization with batch processing and Material Design UI**

## Overview

Enterprise-grade log sanitization system built in Go, designed for air-gapped environments. Automatically detects and replaces sensitive information in log files with anonymized tokens. **Now with batch processing support** for handling 300+ file ZIPs asynchronously. Handles 100MB+ files with comprehensive pattern detection, zero data retention, and enterprise authentication.

**Named after the Catch-22 character who censored letters** - Yossarian Go sanitizes your logs so you can safely share them with external support teams, vendors, or less-secure storage.

***User Interface***
<img width="1799" height="973" alt="image" src="https://github.com/user-attachments/assets/ee2a3bc4-f713-4398-b1bc-7a69c80429ef" />
<img width="1799" height="973" alt="image" src="https://github.com/user-attachments/assets/0a18972a-9bf8-4284-978c-a7de4e8683f6" />


***Admin Panel***
<img width="1717" height="1004" alt="image" src="https://github.com/user-attachments/assets/911a3421-ca6c-49c7-9592-6cc789c4602e" />

---

## ✨ Features

### 🔍 **Pattern Detection**
- **IP Addresses** → `[IP-001]` with consistent mapping across files
- **AD Accounts** → USN format (`CORP\user` → `USN123456789`)
  - Domain accounts (`DOMAIN\username`)
  - UPN format (`user@domain.com`)
  - Computer accounts (`COMPUTER$`)
  - Real AD lookups via LDAP integration
- **JWT Tokens** → `[JWT-REDACTED]`
- **Private Keys** → `[PRIVATE-KEY-REDACTED]` (PEM format)
- **Passwords** → `[PASSWORD-REDACTED]` (connection strings, configs)
- **Organization Sensitive Terms** → `[SENSITIVE]` (admin-configured)
- **Personal Sensitive Words** → `[USER-SENSITIVE]` (browser-stored, encrypted)

### 🎨 **Material Design UI**
- Multi-file upload (up to 10 files, 50MB each)
- ZIP archive support (auto-extract and sanitize)
- Drag & drop + click-to-browse interface
- Real-time progress tracking
- Comprehensive results dashboard
- Downloadable sanitized files and audit reports
- Detailed replacement report (CSV with line numbers)
- **"My Jobs" page** for batch job status tracking (NEW in v0.10.0)

### ⚡ **Batch Processing** (NEW in v0.10.0)
- **Asynchronous Processing** - Upload large ZIPs and return later
- **300+ File Support** - Handles massive archives without timeout
- **Background Workers** - Processes jobs while you work
- **Job Tracking** - Monitor progress via "My Jobs" page
- **Persistent Storage** - Jobs survive pod restarts
- **User Attribution** - Each user sees only their jobs
- **Progress Updates** - Real-time status (queued/processing/completed/failed)
- **Automatic Routing** - ZIP files auto-detected and queued

**How it Works:**
```
Upload ZIP → Job Created → Background Processing → Download Results
            (instant)     (minutes to hours)      (via My Jobs page)
```

### 🏢 **Organization Settings**
- **Configurable Disclaimer** - Custom warning banner on main page
- **Documentation Links** - Custom docs URL and title
- **Admin-Managed** - No code changes required
- **Markdown Support** - Rich text formatting for disclaimers
- **Persistent Storage** - SQLite database for settings

### 🔒 **Security & Compliance**
- **Zero persistence** - All processing in-memory, no data retention*
- **Air-gap ready** - No external dependencies required
- **Enterprise SSO** - Keycloak/OIDC integration with role-based access
- **Session management** - Secure admin sessions with token expiry
- **Audit trails** - Complete IP mapping exports for compliance
- **Encrypted storage** - Personal words encrypted in browser localStorage

*Note: Batch jobs are temporarily stored on PVC during processing (configurable retention)

### 📊 **Monitoring & Observability**
- **Prometheus metrics** - `/metrics` endpoint with comprehensive instrumentation
- **Alert rules** - Production-ready alerts for availability, performance, errors
- **Grafana dashboards** - Pre-built dashboards for visualization
- **Cache metrics** - AD lookup cache hit/miss tracking (23x performance boost)
- **Pattern detection stats** - Real-time detection counters by type
- **Performance metrics** - Processing duration histograms
- **Batch job metrics** - Job queue depth, processing times (NEW in v0.10.0)

### ⚡ **Performance**
- **Processing Speed** - ~1MB/second for complex logs
- **Large Files** - Handles 100MB+ files without crashes
- **Batch Mode** - Processes 300+ file ZIPs in background
- **Caching** - AD lookup caching provides 23x speedup
- **Scalability** - Kubernetes-native with horizontal pod autoscaling
- **Optimization** - Sub-3 second processing for typical files

---

## 🗃️ Architecture

### Microservices Design
```
┌─────────────────┐    ┌─────────────────┐    ┌──────────────┐
│ Main App Pods   │───▶│ DB Service Pod  │───▶│ Active Dir   │
│ (yossarian-go)  │    │ (SQLite + HTTP) │    │ (LDAP/LDAPS) │
│ - Web UI        │    │ - AD Lookups    │    └──────────────┘
│ - Sanitization  │    │ - LDAP Sync     │
│ - File Upload   │    │ - Real USNs     │
│ - Auth/Sessions │    │ - Org Settings  │
│ - Batch Worker  │◀───│ - Batch Jobs DB │◀─┐
└─────────────────┘    └─────────────────┘  │
        │                                    │
        ▼                                    │
┌─────────────────┐                          │
│ Keycloak (OIDC) │                          │
│ - SSO Auth      │                          │
│ - Role Mgmt     │                          │
└─────────────────┘                          │
                                             │
┌────────────────────────────────────────────┘
│ Persistent Storage (PVCs):
│  ├─ Database (5Gi) - SQLite, job metadata
│  └─ Batch Jobs (100Gi) - Uploaded ZIPs, outputs
```

**Components:**
- **Main App** - Stateless pods (horizontal scaling), batch background worker
- **DB Service** - SQLite database with HTTP API, batch job tracking
- **Storage** - RWO PVCs for database and batch job storage
- **Networking** - Contour HTTPProxy with session affinity
- **Monitoring** - Prometheus Operator + Grafana

**NEW in v0.10.0:**
- Background batch processor in main app
- Job queue management in database
- Persistent storage for batch jobs
- "My Jobs" UI for status tracking

---

## 🚀 Quick Start

### Helm Chart (Recommended)

**Pull from GitHub Container Registry:**
```bash
# Pull the chart
helm pull oci://ghcr.io/kofadam/yossarian-go/yossarian-go --version 0.10.0

# Extract
tar xzf yossarian-go-0.10.0.tgz

# Install
helm install yossarian ./yossarian-go \
  -f values-prod.yaml \
  -n yossarian-go \
  --create-namespace
```

**Or install directly:**
```bash
helm install yossarian oci://ghcr.io/kofadam/yossarian-go/yossarian-go \
  --version 0.10.0 \
  -n yossarian-go \
  --create-namespace
```

**Features:**
- ✅ Automated PVC provisioning (DB + Batch storage)
- ✅ Multi-environment support (dev/prod/local)
- ✅ ConfigMap-driven configuration
- ✅ External secrets integration
- ✅ Complete monitoring stack

See [Helm Chart Documentation](#helm-deployment) for details.

### Docker Compose (Local Development)
```bash
# Clone repository
git clone https://github.com/kofadam/yossarian-go.git
cd yossarian-go

# Start services
docker-compose up -d

# Access application
http://localhost:8080        # Main interface
http://localhost:8080/admin  # Admin panel (password: admin123)
```

**Note:** Docker Compose does not include batch processing storage. For full batch support, use Kubernetes with Helm.

### Pull Pre-Built Images
```bash
# Main application (v0.10.0)
docker pull ghcr.io/kofadam/yossarian-go:v0.10.0

# Database service (v0.10.0)
docker pull ghcr.io/kofadam/yossarian-go-db-service:v0.10.0
```

[View Main App](https://github.com/users/kofadam/packages/container/package/yossarian-go) | [View DB Service](https://github.com/users/kofadam/packages/container/package/yossarian-go-db-service) | [View Helm Chart](https://github.com/users/kofadam/packages/container/package/yossarian-go%2Fyossarian-go)

---

## ⚙️ Configuration

### Environment Variables

#### **Main Application (`yossarian-go`)**

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8080` | HTTP server port |
| `ADMIN_PASSWORD` | `admin123` | Admin panel password (if OIDC disabled) |
| `AD_SERVICE_URL` | `http://yossarian-db-service:8081` | Database service endpoint |
| `MAX_TOTAL_UPLOAD_SIZE_MB` | `100` | Total upload size limit (online mode) |
| `MAX_FILE_SIZE_MB` | `50` | Individual file size limit (online mode) |
| `MAX_ZIP_FILE_SIZE_MB` | `10` | Files inside ZIP archives limit |
| `MAX_FILE_COUNT` | `10` | Maximum number of files per upload (online mode) |

**NEW in v0.10.0:**
- ZIP files automatically route to batch mode (no file count/size limits)
- Batch jobs stored at `/data/jobs/{username}/{job-id}/`
- Requires PVC mounted at `/data` for persistence

#### **OIDC/Keycloak Configuration**

| Variable | Required | Description |
|----------|----------|-------------|
| `OIDC_ENABLED` | No | Enable SSO authentication (`true`/`false`) |
| `OIDC_ISSUER_URL` | Yes* | Keycloak realm URL |
| `OIDC_CLIENT_ID` | Yes* | Client ID in Keycloak |
| `OIDC_CLIENT_SECRET` | Yes* | Client secret |
| `OIDC_REDIRECT_URL` | Yes* | OAuth callback URL |
| `CA_CERT_PATH` | No | Custom CA certificate path |

*Required if `OIDC_ENABLED=true`

**Keycloak Roles:**
- `admin` - Full admin panel access + batch jobs
- `user` - Standard user access + batch jobs

#### **Database Service (`yossarian-go-db-service`)**

| Variable | Required | Description |
|----------|----------|-------------|
| `LDAP_SERVER` | Yes* | LDAP/LDAPS URL (e.g., `ldaps://dc.example.com:636`) |
| `LDAP_BIND_DN` | Yes* | Service account DN |
| `LDAP_BIND_PASSWORD` | Yes* | Service account password |
| `LDAP_SEARCH_BASE` | Yes* | Search base (e.g., `DC=example,DC=com`) |
| `LDAP_SYNC_INTERVAL` | No | Auto-sync interval in seconds (default: 3600) |
| `DOMAIN_NETBIOS` | Yes* | NetBIOS domain name (e.g., `CORP`) |
| `DOMAIN_FQDN` | Yes* | Fully qualified domain (e.g., `corp.example.com`) |
| `DC_CA_CERT_PATH` | No | Domain controller CA certificate |

*Required for AD integration

**NEW in v0.10.0:**
- Database stores batch job metadata (status, progress, timestamps)
- Job API endpoints: `/jobs/create`, `/jobs/status/{id}`, `/jobs/list/{user}`

---

## 🎯 Batch Processing

### How It Works

**Upload Flow:**
1. User uploads a ZIP file via web UI
2. System detects `.zip` extension
3. Job created with unique ID: `batch-{username}-{timestamp}`
4. ZIP stored in `/data/jobs/{username}/{job-id}/input.zip`
5. Job registered in database (status: `queued`)
6. User receives immediate response with job ID

**Background Processing:**
1. Background worker polls `/data/jobs/` directory every 5-10 seconds
2. Finds queued jobs from database
3. Extracts ZIP files
4. Sanitizes each file using existing engine
5. Updates progress every 10 files
6. Creates output ZIP with sanitized files
7. Marks job as `completed` or `failed`

**Download Flow:**
1. User visits "My Jobs" page (`/jobs/my-jobs`)
2. Sees list of jobs with status/progress
3. Clicks download on completed jobs
4. Downloads `/data/jobs/{username}/{job-id}/output/sanitized.zip`

### Storage Requirements

**Recommended PVC Sizes:**
- **Development**: 10Gi (testing with small ZIPs)
- **Production**: 100-200Gi (depending on usage)
- **Formula**: `(Average ZIP size × Concurrent jobs × 2) + buffer`

**Example:**
- Average ZIP: 50MB
- Concurrent jobs: 10
- Storage needed: `50MB × 10 × 2 = 1GB` (×2 for input + output)
- Recommended: 10Gi (with 90% free space)

### Job Management

**Job States:**
- `queued` - Job created, waiting for background processor
- `processing` - Currently being processed
- `completed` - Output ZIP ready for download
- `failed` - Error occurred (see error message in job details)

**API Endpoints:**
- `GET /api/jobs/status/{job_id}` - Get job details
- `GET /api/jobs/list` - Get user's jobs (last 50)
- `GET /jobs/my-jobs` - Web UI for job management
- `GET /jobs/download/{job_id}` - Download completed job

**Monitoring:**
```bash
# Check batch processor logs
kubectl logs -n yossarian-go -l app=yossarian-go | grep BATCH

# List jobs on filesystem
kubectl exec -n yossarian-go deployment/yossarian-go -- ls -la /data/jobs

# Check database job count
kubectl exec -n yossarian-go deployment/yossarian-db-service -- \
  curl http://localhost:8081/jobs/list/USERNAME
```

---

## 🏢 Organization Settings

### Configure Custom Disclaimer and Documentation

**Admin Panel** → **Organization Tab**

1. **Disclaimer Settings**
   - Enable/disable disclaimer banner on main page
   - Markdown-formatted text (supports **bold**, *italic*, lists)
   - Appears as orange warning banner

2. **Documentation Settings**
   - Enable/disable documentation link
   - Custom title and URL
   - Appears as green info card with link

**Example:**
```markdown
**Warning**: This is a production system. Logs may contain sensitive data.
- Only upload logs approved for external sharing
- Review sanitized output before distribution
- Contact security@example.com for questions
```

**Settings are stored in SQLite** and persist across pod restarts.

---

## 📊 Monitoring

### Prometheus Metrics

Available at `/metrics`:

**HTTP Metrics:**
- `yossarian_http_requests_total` - Request counter (method, endpoint, status)
- `yossarian_upload_size_bytes` - Upload size histogram by file type
- `yossarian_processing_duration_seconds` - Processing time histogram

**Pattern Detection:**
- `yossarian_patterns_detected_total` - Detection counter by pattern type
  - Labels: `ip_address`, `ad_account`, `jwt_token`, `private_key`, `password`, `sensitive_term`, `user_word`

**Performance:**
- `yossarian_ad_cache_hits_total` - AD lookup cache hits
- `yossarian_ad_cache_misses_total` - AD lookup cache misses
- `yossarian_active_sessions` - Current active user sessions
- `yossarian_errors_total` - Error counter by type

**NEW in v0.10.0 - Batch Processing:**
- `yossarian_batch_jobs_total` - Total jobs by status (queued/processing/completed/failed)
- `yossarian_batch_processing_duration_seconds` - Job processing time
- `yossarian_batch_queue_depth` - Number of queued jobs

### Alert Rules

**Critical Alerts:**
- `YossarianDown` - Application unavailable
- `YossarianPodRestartLoop` - Pods crash looping
- `YossarianDBServiceDown` - Database service unavailable
- `YossarianBatchPVCFull` - Batch storage > 90% full (NEW)

**Warning Alerts:**
- `YossarianHighErrorRate` - Error rate > 5%
- `YossarianSlowFileProcessing` - P95 processing > 10s
- `YossarianHighMemoryUsage` - Memory > 85%
- `YossarianHighADCacheMissRate` - Cache miss > 30%
- `YossarianBatchJobsStuck` - Jobs stuck in processing > 1 hour (NEW)

**Info Alerts:**
- `YossarianHighUploadVolume` - Unusual upload traffic
- `YossarianLargeFilesUploaded` - Files > 50MB processed
- `YossarianNoRequests` - No activity detected

---

## 📦 Helm Deployment

### Installation

```bash
# Add Helm repository (OCI registry)
helm pull oci://ghcr.io/kofadam/yossarian-go/yossarian-go --version 0.10.0

# Install with default values (development)
helm install yossarian oci://ghcr.io/kofadam/yossarian-go/yossarian-go \
  --version 0.10.0 \
  -n yossarian-go \
  --create-namespace

# Install with production values
helm install yossarian oci://ghcr.io/kofadam/yossarian-go/yossarian-go \
  --version 0.10.0 \
  -f values-prod.yaml \
  -n yossarian-go \
  --create-namespace
```

### Configuration

**Minimal values.yaml:**
```yaml
config:
  oidc:
    issuerUrl: "https://keycloak.company.com/auth/realms/company"
    clientId: "yossarian-go"
    redirectUrl: "https://yossarian.company.com/auth/oidc/callback"
  
  ldap:
    server: "ldaps://dc.company.com:636"
    bindDn: "CN=svc-yossarian,OU=Services,DC=company,DC=com"
    searchBase: "DC=company,DC=com"

secrets:
  adminPassword: "change-me"
  oidcClientSecret: "your-secret"
  ldapBindPassword: "your-password"

ingress:
  fqdn: "yossarian.company.com"

storage:
  batchJobs:
    size: 100Gi  # Adjust based on expected workload
```

### Upgrading

```bash
# Upgrade to new version
helm upgrade yossarian oci://ghcr.io/kofadam/yossarian-go/yossarian-go \
  --version 0.10.0 \
  -f values-prod.yaml \
  -n yossarian-go

# Rollback if needed
helm rollback yossarian -n yossarian-go
```

### Chart Values

Key configuration options:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `replicaCount.app` | `2` | Main app replicas |
| `storage.database.size` | `5Gi` | SQLite database PVC |
| `storage.batchJobs.size` | `100Gi` | Batch jobs PVC (NEW) |
| `resources.app.limits.memory` | `2Gi` | Memory for batch processing |
| `ingress.enabled` | `true` | Enable Contour HTTPProxy |
| `monitoring.prometheus.enabled` | `true` | Enable metrics |

See [chart README](https://github.com/kofadam/yossarian-go/tree/main/helm) for full documentation.

---

## 🐳 Kubernetes Deployment (Manual YAML)

For deployments without Helm, see the [fixed YAML files](https://github.com/kofadam/yossarian-go/tree/main/k8s) which include:

- ✅ Batch processing PVC (100Gi)
- ✅ Fixed service name consistency
- ✅ LDAP password in secrets
- ✅ Corrected CA certificate paths
- ✅ Increased resources for batch processing

**Quick Deploy:**
```bash
# Clone repository
git clone https://github.com/kofadam/yossarian-go.git
cd yossarian-go/k8s

# Update configuration
vi 02-configmap.yaml    # Update OIDC/LDAP URLs
vi 03-secrets.yaml      # Add your secrets

# Deploy
kubectl apply -f .
```

---

## 🔧 Development

### Build from Source
```bash
# Clone repository
git clone https://github.com/kofadam/yossarian-go.git
cd yossarian-go

# Build main app (v0.10.0)
./build.sh v0.10.0

# Build database service (v0.10.0)
./build-db-service.sh v0.10.0

# Run locally
docker-compose up -d
```

### Project Structure
```
yossarian-go/
├── main.go                 # Main application + batch worker
├── db-service.go          # Database microservice + job API
├── templates/
│   ├── index.html         # Main UI
│   └── admin.html         # Admin panel
├── helm/                  # Helm chart (NEW)
│   ├── Chart.yaml
│   ├── values.yaml
│   └── templates/
├── k8s/                   # Kubernetes YAMLs
│   ├── 01-namespace.yaml
│   ├── 05-pvcs.yaml       # Includes batch PVC (NEW)
│   └── ...
├── Dockerfile             # Main app image
├── Dockerfile.db-service  # DB service image
├── docker-compose.yml     # Local development
└── build.sh              # Build script
```

### Testing Batch Processing

```bash
# Create test ZIP with multiple files
mkdir test-batch
for i in {1..50}; do
  echo "Log $i from 192.168.1.$i - User: CORP\\user$i" > test-batch/file$i.log
done
zip -r test-batch.zip test-batch/

# Upload via API
curl -F "file=@test-batch.zip" http://localhost:8080/upload

# Response:
# {
#   "status": "batch_queued",
#   "job_id": "batch-username-20251220-120000",
#   "jobs_url": "/jobs/my-jobs"
# }

# Check job status
curl http://localhost:8080/api/jobs/status/batch-username-20251220-120000

# Check background processor logs
kubectl logs -n yossarian-go -l app=yossarian-go | grep BATCH
```

---

## 🔒 Security Considerations

### Air-Gap Deployment
- All resources bundled inline (no CDN dependencies)
- Works completely offline
- No external API calls required

### Data Handling
- **Zero persistence** - No logs stored on disk (except batch jobs during processing)
- **In-memory processing** - All sanitization in RAM
- **Immediate cleanup** - Files cleared after download
- **Session-only storage** - Download cache cleared on logout
- **Batch job retention** - Configurable cleanup policy (default: manual)

### Authentication
- **Enterprise SSO** - Keycloak/OIDC integration
- **Role-based access** - Admin vs user permissions
- **Session management** - Secure cookie-based sessions
- **Token validation** - Real-time Keycloak token expiry checks
- **User attribution** - Batch jobs tied to authenticated users

### Compliance
- **Audit trails** - IP mapping exports for compliance
- **Detailed reports** - CSV exports with line-by-line changes
- **Consistent replacements** - Same value always gets same token
- **Reversible mappings** - Download mapping tables for verification
- **Job tracking** - Complete audit trail of batch processing

---

## 📈 Performance Benchmarks

**Online Mode (3MB log file, 35K patterns):**
- Processing time: 2.6 seconds
- Cache hit rate: 98%+
- Memory usage: <200MB per file
- Throughput: ~1MB/second

**Batch Mode (50-file ZIP, 150MB total, NEW in v0.10.0):**
- Queue time: <1 second
- Processing time: ~3 minutes
- Memory usage: <500MB per job
- Concurrent jobs: 5-10 (depends on resources)

**Optimizations:**
- AD lookup caching: 23x performance boost
- Regex optimization: 12% accuracy improvement
- Word boundary matching: Eliminates false positives
- In-memory processing: No disk I/O overhead
- Background processing: No user wait time for large files

---

## 🔄 Migration Guide

### Upgrading from v0.9.x to v0.10.0

**Breaking Changes:**
- ZIP files now automatically route to batch mode (async processing)
- New PVC required for batch job storage (100Gi recommended)
- Service name standardized to `yossarian-go-service`

**Upgrade Steps:**

**Using Helm:**
```bash
# Pull new chart
helm pull oci://ghcr.io/kofadam/yossarian-go/yossarian-go --version 0.10.0

# Upgrade
helm upgrade yossarian ./yossarian-go \
  --set image.app.tag=v0.10.0 \
  --set image.dbService.tag=v0.10.0 \
  -f values-prod.yaml \
  -n yossarian-go
```

**Using kubectl:**
```bash
# Update images in deployments
kubectl set image deployment/yossarian-go \
  yossarian-go=ghcr.io/kofadam/yossarian-go:v0.10.0 \
  -n yossarian-go

kubectl set image deployment/yossarian-db-service \
  yossarian-db-service=ghcr.io/kofadam/yossarian-go-db-service:v0.10.0 \
  -n yossarian-go

# Create batch PVC
kubectl apply -f k8s/05-pvcs.yaml

# Restart deployments
kubectl rollout restart deployment/yossarian-go -n yossarian-go
kubectl rollout restart deployment/yossarian-db-service -n yossarian-go
```

**Verification:**
```bash
# Check PVCs
kubectl get pvc -n yossarian-go
# Expected: yossarian-db-pvc (5Gi), yossarian-batch-pvc (100Gi)

# Check logs for batch processor
kubectl logs -n yossarian-go -l app=yossarian-go | grep BATCH
# Expected: [BATCH] Background processor initialized

# Test batch mode
curl -F "file=@test.zip" http://your-domain/upload
# Expected: {"status": "batch_queued", "job_id": "..."}
```

---

## 🤝 Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Follow existing code style
4. Add tests for new features
5. Submit a pull request

**Development Guidelines:**
- Use exact FIND/REPLACE blocks for changes
- Test incrementally
- Document API changes
- Update README for new features
- Test batch processing with large ZIPs

---

## 📄 License

MIT License - See LICENSE file for details

---

## 🙏 Acknowledgments

- Named after the character from Joseph Heller's "Catch-22"
- Built with Go, SQLite, and Material Design
- Kubernetes-native architecture
- Enterprise-ready monitoring with Prometheus
- Inspired by real enterprise security needs

---

## 📞 Support

- **GitHub Issues**: [Report bugs or request features](https://github.com/kofadam/yossarian-go/issues)
- **Helm Chart**: [OCI Registry](https://github.com/users/kofadam/packages/container/package/yossarian-go%2Fyossarian-go)
- **Documentation**: This README + [Helm Chart README](https://github.com/kofadam/yossarian-go/tree/main/helm)
- **Version**: v0.10.0
- **Last Updated**: December 2025

---

## 🗺️ Roadmap

### v0.11.0 (Planned)
- [ ] Email notifications for completed batch jobs
- [ ] Job retention policies (auto-cleanup after N days)
- [ ] Batch job priority queues
- [ ] Multi-file detailed CSV reports

### v1.0.0 (Future)
- [ ] S3/Object storage backend option
- [ ] Distributed processing (multiple workers)
- [ ] Web UI for job management (pause/cancel/retry)
- [ ] Advanced pattern detection (ML-based)

---

**🛡️ Yossarian Go - Making logs safe to share, at any scale**
