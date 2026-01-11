# Yossarian Go - Enterprise Log Sanitization System

![Go Version](https://img.shields.io/badge/Go-1.23-00ADD8?logo=go)
![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker)
![Kubernetes](https://img.shields.io/badge/Kubernetes-Native-326CE5?logo=kubernetes)
![License](https://img.shields.io/badge/License-MIT-green)
![Version](https://img.shields.io/badge/Version-v0.13.3-blue)

🛡️ **Enterprise log sanitization with MinIO-backed batch processing**

## Overview

Enterprise-grade log sanitization system built in Go for air-gapped environments. Automatically detects and replaces sensitive information in log files with anonymized tokens. Features scalable architecture with MinIO-backed asynchronous batch processing for handling large workloads.

**Named after the Catch-22 character who censored letters** - Yossarian Go sanitizes your logs so you can safely share them with external support teams, vendors, or less-secure storage.

<img width="1799" alt="Main Interface" src="https://github.com/user-attachments/assets/ee2a3bc4-f713-4398-b1bc-7a69c80429ef" />

---

## ✨ Key Features

### 🔍 Pattern Detection
- **IP Addresses** → `[IP-001]` with consistent mapping
- **AD Accounts** → USN format via LDAP integration (`CORP\user` → `USN123456789`)
- **JWT Tokens** → `[JWT-REDACTED]`
- **Private Keys** → `[PRIVATE-KEY-REDACTED]`
- **Passwords** → `[PASSWORD-REDACTED]`
- **Custom Sensitive Terms** → Admin-configured patterns

### ⚡ Scalable Architecture (v0.13.0+)
- **Split Architecture**: Horizontally scalable frontend + dedicated worker
- **MinIO Storage**: Centralized object storage for batch jobs
- **Async Processing**: Upload and return later - no waiting for large files
- **Job Cancellation**: Cancel queued/processing jobs (v0.13.8+)
- **Auto-Cleanup**: 8-hour retention policy for completed jobs
- **Performance**: ~0.2s processing time for 4-file batches
- **Memory Optimized**: Streaming architecture prevents OOMKilled crashes (v0.13.8)

### 🔒 Security & Compliance
- **Zero persistence**: No data retention after download (8-hour window for batch jobs)
- **Air-gap ready**: No external dependencies
- **Enterprise SSO**: OIDC/Keycloak integration
- **Audit trails**: Complete IP mapping exports

### 📊 Monitoring
- **Prometheus metrics**: `/metrics` endpoint
- **Grafana dashboards**: Pre-built visualization
- **Performance tracking**: Cache hit rates, processing times

---

## 🗃️ Architecture

### Split Architecture (v0.13.0+)
```
┌──────────────────┐     ┌──────────────────┐     ┌──────────────┐
│ Frontend Pods    │────▶│ MinIO Storage    │◀────│ Worker Pod   │
│ (Scalable 1-10+) │     │ (Batch Files)    │     │ (Single Pod) │
│ - Web UI         │     │ - input.zip      │     │ - Job Queue  │
│ - Upload Handler │     │ - output.zip     │     │ - Processing │
│ - OIDC Auth      │     │ - 8hr retention  │     │ - AD Lookups │
└──────────────────┘     └──────────────────┘     └──────────────┘
         │                                                  │
         └────────────────────┬──────────────────────────┘
                              │
                     ┌────────▼─────────┐
                     │  DB Service Pod  │
                     │  - Job Queue     │
                     │  - AD Cache      │
                     │  - Org Settings  │
                     └──────────────────┘
```

**Workflow:**
1. User uploads ZIP → Frontend stores in MinIO → Job queued in database
2. Worker polls database → Downloads from MinIO → Processes files → Uploads results
3. User downloads results → Files auto-deleted after 8 hours

**Components:**
- **Frontend**: Stateless pods (horizontal scaling) handling UI and uploads
- **Worker**: Single pod with PVC processing batch jobs from MinIO queue
- **MinIO**: Centralized object storage for batch files (input/output ZIPs)
- **DB Service**: SQLite with HTTP API for job queue and metadata

---

## 🚀 Quick Start

### Docker Compose (Local Development)
```bash
git clone https://github.com/kofadam/yossarian-go.git
cd yossarian-go

# Start services (includes MinIO)
docker-compose up -d

# Access application
open http://localhost:8080
```

### Kubernetes Deployment

**Prerequisites:**
- Kubernetes cluster
- Persistent volume provisioner
- Contour ingress controller (or modify HTTPProxy)

**Deploy:**
```bash
# Build images
./build.sh v0.13.3
./build-db-service.sh v0.12.3

# Tag for your registry
docker tag yossarian-go/yossarian-go:v0.13.3 your-registry/yossarian-go:v0.13.3
docker tag yossarian-go/yossarian-go-db-service:v0.12.3 your-registry/yossarian-go-db-service:v0.12.3

# Push to registry
docker push your-registry/yossarian-go:v0.13.3
docker push your-registry/yossarian-go-db-service:v0.12.3

# Deploy to Kubernetes
kubectl apply -f k8s/
```

**Required Resources:**
- MinIO StatefulSet (50Gi PVC)
- Frontend Deployment (3 replicas, no PVC)
- Worker Deployment (1 replica, 50Gi PVC for processing)
- DB Service Deployment (1 replica, 10Gi PVC for SQLite)

---

## ⚙️ Configuration

### Environment Variables

**Main Application (Frontend & Worker):**
```bash
MODE=frontend                    # Or "worker"
PORT=8080
ADMIN_PASSWORD=changeme          # If OIDC disabled

# MinIO (v0.13.0+)
MINIO_ENDPOINT=minio:9000
MINIO_ACCESS_KEY=yossarian
MINIO_SECRET_KEY=changeme
MINIO_BUCKET=yossarian-jobs
MINIO_USE_SSL=false

# Database Service
AD_SERVICE_URL=http://yossarian-db-service:8081

# File Limits
MAX_TOTAL_UPLOAD_SIZE_MB=100
MAX_FILE_SIZE_MB=50
MAX_FILE_COUNT=10
```

**OIDC/Keycloak:**
```bash
OIDC_ENABLED=true
OIDC_ISSUER_URL=https://keycloak.example.com/realms/myrealm
OIDC_CLIENT_ID=yossarian-go
OIDC_CLIENT_SECRET=changeme
OIDC_REDIRECT_URL=https://yossarian.example.com/auth/oidc/callback
AUTO_SSO_ENABLED=true
```

**Database Service:**
```bash
# LDAP/Active Directory
LDAP_SERVER=ldaps://dc.example.com:636
LDAP_BIND_DN=CN=svc-yossarian,OU=Service,DC=example,DC=com
LDAP_BIND_PASSWORD=changeme
LDAP_SEARCH_BASE=DC=example,DC=com
LDAP_SYNC_INTERVAL=3600
```

---

## 🔒 Security Considerations

### Data Lifecycle
- **Upload**: Stored in MinIO temporarily
- **Processing**: Worker downloads to local PVC, processes, uploads results
- **Download**: Results streamed from MinIO
- **Cleanup**: Files auto-deleted 8 hours after job completion

### Air-Gap Deployment
- No external dependencies (CDN, APIs, etc.)
- All resources bundled inline
- Works completely offline

### Authentication
- Enterprise SSO via OIDC/Keycloak
- Role-based access control (admin/user)
- Secure session management
- User-attributed batch jobs

---

## 📈 Performance

**Single File Processing:**
- 3MB file with 35K patterns: 2.6 seconds
- Throughput: ~1MB/second
- Memory: <200MB per file

**Batch Processing:**
- 4-file ZIP: 0.2 seconds
- AD lookup caching: 23x performance boost
- Cache hit rate: 98%+

**Scalability:**
- Frontend: Horizontal scaling (1-10+ pods)
- Worker: Single pod with queue-based processing
- Concurrent batch jobs: Limited by worker resources

---

## 🔄 Upgrading to v0.13.3

**Breaking Changes from v0.12.x:**
- MinIO now required for batch processing
- Split architecture (frontend/worker instead of single deployment)
- New environment variables for MinIO configuration

**Migration Steps:**
1. Deploy MinIO StatefulSet
2. Update frontend deployment (remove PVC, add MinIO config)
3. Create worker deployment (1 replica with PVC)
4. Update HTTPProxy routing (downloads → worker)
5. Test batch upload and download flow

---

## 🛠️ Development

### Project Structure
```
yossarian-go/
├── main.go                    # Main app (frontend + worker modes)
├── db-service.go              # Database service + job queue API
├── templates/                 # HTML templates
│   ├── index.html            # Main upload UI
│   ├── admin.html            # Admin panel
│   └── my-jobs.html          # Batch job status page
├── k8s/                      # Kubernetes manifests
│   ├── 01-minio.yaml         # MinIO StatefulSet
│   ├── 02-frontend.yaml      # Frontend Deployment
│   ├── 03-worker.yaml        # Worker Deployment
│   └── 04-httpproxy.yaml     # Ingress routing
├── Dockerfile                # Main app image
├── Dockerfile.db-service     # DB service image
├── docker-compose.yml        # Local dev (includes MinIO)
├── build.sh                  # Build main app
└── build-db-service.sh       # Build DB service
```

### Building
```bash
# Build main app
./build.sh v0.13.3

# Build database service
./build-db-service.sh v0.12.3

# Run locally with MinIO
docker-compose up -d
```

### Testing Batch Processing
```bash
# Create test ZIP
zip test.zip file1.log file2.log file3.log

# Upload
curl -F "file=@test.zip" http://localhost:8080/upload

# Check status (get job_id from response)
curl http://localhost:8080/api/jobs/status/{job_id}

# Download results when completed
curl -O http://localhost:8080/jobs/download/{job_id}
```

---

## 📄 License

MIT License - See LICENSE file for details

---

## 🙏 Acknowledgments

- Named after Joseph Heller's "Catch-22" character
- Built with Go, SQLite, MinIO, and Material Design
- Kubernetes-native with Prometheus monitoring

---

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/kofadam/yossarian-go/issues)
- **Version**: v0.13.3
- **Last Updated**: January 2026

---

**🛡️ Yossarian Go - Making logs safe to share, at any scale**
