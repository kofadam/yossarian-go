# Yossarian Go - Development Guide

This guide covers building, testing, and contributing to Yossarian Go.

---

## 🛠️ Development Environment Setup

### Prerequisites

- **Go 1.23+**
- **Docker 20.10+**
- **Docker Compose 2.x**
- **Kubernetes cluster** (for testing deployments)
- **Helm 3.x** (for chart development)
- **Git**

### Clone Repository

```bash
git clone https://github.com/kofadam/yossarian-go.git
cd yossarian-go
```

---

## 📦 Project Structure

```
yossarian-go/
├── main.go                    # Main application (frontend + worker modes)
├── db-service.go              # Database service + job queue + API keys
├── templates/                 # HTML templates
│   ├── index.html            # Main upload UI
│   ├── admin.html            # Admin panel (includes API Keys tab)
│   └── api-docs.html         # OpenAPI/Swagger documentation
├── grafana/                  # Grafana dashboards
│   ├── yossarian-overview.json
│   └── yossarian-worker-details.json
├── helm/                     # Helm charts
│   ├── README.md
│   ├── yossarian-go-0.13.18.tgz
│   └── yossarian-go/        # Chart source
├── docs/                     # Documentation
│   ├── ARCHITECTURE.md
│   ├── DISTRIBUTION-TOOLING-GUIDE.md
│   ├── CERTIFICATE-CONFIGURATION-GUIDE.md
│   └── DEVELOPMENT.md (this file)
├── scripts/                  # Testing scripts
│   ├── generate-test-logs.sh # Generate test log files
│   └── TEST-LOG-GENERATOR.md
├── Dockerfile                # Main app image
├── Dockerfile.db-service     # DB service image
├── docker-compose.yml        # Local development stack
├── build.sh                  # Build main app
└── build-db-service.sh       # Build DB service
```

---

## 🏗️ Building

### Build Main Application

```bash
# Build with version tag
./build.sh v0.13.17

# Or manually
VERSION=v0.13.17
BUILD_TIME=$(date -u '+%Y-%m-%d_%H:%M:%S')
GIT_COMMIT=$(git rev-parse --short HEAD)

docker build \
  --build-arg VERSION=${VERSION} \
  --build-arg BUILD_TIME=${BUILD_TIME} \
  --build-arg GIT_COMMIT=${GIT_COMMIT} \
  -t yossarian-go/yossarian-go:${VERSION} \
  .
```

### Build Database Service

```bash
# Build with version tag
./build-db-service.sh v0.12.4

# Or manually
docker build \
  -f Dockerfile.db-service \
  -t yossarian-go/yossarian-go-db-service:v0.12.4 \
  .
```

---

## 🧪 Local Testing

### Quick Start with Docker Compose

```bash
# Start all services
docker-compose up -d

# Check logs
docker-compose logs -f

# Access application
open http://localhost:8080

# Access MinIO console
open http://localhost:9101
# Credentials: yossarian / yossarian123

# Stop services
docker-compose down

# Clean volumes (reset data)
docker-compose down -v
```

### Test Individual Components

**Frontend Only:**
```bash
docker run --rm -p 8080:8080 \
  -e MODE=frontend \
  -e ADMIN_PASSWORD=test123 \
  -e OIDC_ENABLED=false \
  yossarian-go/yossarian-go:v0.13.17
```

**Worker Only:**
```bash
docker run --rm -p 8082:8080 \
  -e MODE=worker \
  -v $(pwd)/data:/data \
  yossarian-go/yossarian-go:v0.13.17
```

**Database Service:**
```bash
docker run --rm -p 8083:8081 \
  -v $(pwd)/data:/data \
  yossarian-go/yossarian-go-db-service:v0.12.4
```

---

## 🎯 Testing Workflows

### Test Single File Upload (Browser Session)

```bash
# Create test file
echo "Test log with 192.168.1.1 and CORP\user123" > test.log

# Upload (requires session cookie from browser login)
curl -b cookies.txt -F "file=@test.log" http://localhost:8080/upload

# Should return sanitized content with:
# - IP replaced with [IP-001]
# - AD account replaced with USN (if in database)
```

### Test Batch Job Processing (Browser Session)

```bash
# Create test files
echo "Log 1 with 10.0.0.1" > log1.txt
echo "Log 2 with 10.0.0.2" > log2.txt
echo "Log 3 with CORP\admin" > log3.txt

# Create ZIP
zip batch-test.zip log1.txt log2.txt log3.txt

# Upload batch job
RESPONSE=$(curl -b cookies.txt -F "file=@batch-test.zip" http://localhost:8080/upload)
echo $RESPONSE

# Extract job ID
JOB_ID=$(echo $RESPONSE | jq -r '.job_id')
echo "Job ID: $JOB_ID"

# Check status (repeat until completed)
curl -b cookies.txt http://localhost:8080/api/jobs/status/$JOB_ID | jq

# Download results when completed
curl -b cookies.txt -O http://localhost:8080/jobs/download/$JOB_ID

# Download reports
curl -b cookies.txt -O http://localhost:8080/jobs/reports/$JOB_ID/ip-mappings.csv
curl -b cookies.txt -O http://localhost:8080/jobs/reports/$JOB_ID/summary.json
```

---

## 🔑 API Key Authentication Testing

API keys enable headless/pipeline integration without browser sessions. Available since v0.13.17.

### Creating an API Key

1. **Via Admin Panel:**
   - Login to Yossarian Go
   - Go to **Admin** → **API Keys** tab
   - Click **Generate New API Key**
   - Copy the key (shown only once!)

2. **API Key Format:** `yoss_<64-character-hex-string>`

### Test API Key Authentication

```bash
# Set your API key
API_KEY="yoss_your_api_key_here"
BASE_URL="http://localhost:8080"  # or your deployment URL

# Verify API key works
curl -H "X-API-Key: $API_KEY" $BASE_URL/api/jobs/list
```

### Single File Upload with API Key

```bash
# Create test file with sensitive data
echo "Server 192.168.1.100 user CORP\john.doe logged in at 10:30" > test.log

# Upload file
curl -X POST $BASE_URL/upload \
  -H "X-API-Key: $API_KEY" \
  -F "file=@test.log"

# Response includes sanitized content directly
```

### Batch Processing Pipeline with API Key

```bash
# 1. Create test files
mkdir -p test-logs
for i in {1..5}; do
  echo "Server 10.0.0.$i user CORP\user$i processed request" > test-logs/app-$i.log
done
zip -r batch-test.zip test-logs/

# 2. Upload ZIP file
RESPONSE=$(curl -s -X POST $BASE_URL/upload \
  -H "X-API-Key: $API_KEY" \
  -F "file=@batch-test.zip")
echo $RESPONSE | jq

# 3. Extract job ID
JOB_ID=$(echo $RESPONSE | jq -r '.job_id')
echo "Job ID: $JOB_ID"

# 4. Poll status until completed
while true; do
  STATUS=$(curl -s -H "X-API-Key: $API_KEY" "$BASE_URL/api/jobs/status/$JOB_ID")
  echo $STATUS | jq -r '.status'
  if [[ $(echo $STATUS | jq -r '.status') == "completed" ]]; then
    break
  fi
  sleep 2
done

# 5. Download sanitized output
curl -H "X-API-Key: $API_KEY" "$BASE_URL/jobs/download/$JOB_ID" -o sanitized-output.zip
unzip -l sanitized-output.zip

# 6. View sanitized content
unzip -p sanitized-output.zip | head -20

# 7. Download IP mappings report
curl -H "X-API-Key: $API_KEY" "$BASE_URL/jobs/reports/$JOB_ID/ip-mappings.csv"

# 8. Download summary report
curl -H "X-API-Key: $API_KEY" "$BASE_URL/jobs/reports/$JOB_ID/summary.json" | jq
```

### API Key Endpoints Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/upload` | Submit files for sanitization |
| `GET` | `/api/jobs/list` | List user's jobs |
| `GET` | `/api/jobs/status/{job_id}` | Get job status |
| `GET` | `/jobs/download/{job_id}` | Download sanitized output |
| `POST` | `/api/jobs/cancel/{job_id}` | Cancel a job |
| `DELETE` | `/api/jobs/delete/{job_id}` | Delete a job |
| `GET` | `/jobs/reports/{job_id}/ip-mappings.csv` | IP mapping report |
| `GET` | `/jobs/reports/{job_id}/summary.json` | Processing summary |
| `GET` | `/mappings/csv` | Current session IP mappings |
| `GET` | `/health` | Health check (no auth required) |
| `GET` | `/metrics` | Prometheus metrics (no auth required) |

### Generate Test Logs

Use the included test log generator for comprehensive testing:

```bash
cd scripts/

# Generate 20 log files with 10,000 lines each
./generate-test-logs.sh

# Create bundle
zip -r test-logs-bundle.zip test-logs/

# Upload via API
curl -X POST $BASE_URL/upload \
  -H "X-API-Key: $API_KEY" \
  -F "file=@test-logs-bundle.zip"
```

The generator creates logs with:
- IP addresses (public and private ranges)
- AD accounts (CORP\user, user@domain.com, bare usernames)
- JWT tokens
- Passwords in connection strings
- Private keys
- Custom sensitive terms

---

## 🔧 Development Workflow

### Making Code Changes

1. **Edit source files** (main.go, db-service.go, templates/*)

2. **Rebuild images:**
```bash
./build.sh v0.13.17-dev
./build-db-service.sh v0.12.4-dev
```

3. **Update docker-compose.yml** to use `-dev` tags:
```yaml
services:
  frontend:
    image: yossarian-go/yossarian-go:v0.13.17-dev
  worker:
    image: yossarian-go/yossarian-go:v0.13.17-dev
  db-service:
    image: yossarian-go/yossarian-go-db-service:v0.12.4-dev
```

4. **Restart services:**
```bash
docker-compose up -d --force-recreate
```

5. **Test changes**

6. **Check logs:**
```bash
docker-compose logs -f frontend worker
```

### Hot Reload (Templates Only)

For template changes without rebuilding:

```bash
# Mount templates directory
docker run --rm -p 8080:8080 \
  -v $(pwd)/templates:/app/templates \
  -e MODE=frontend \
  -e ADMIN_PASSWORD=test123 \
  yossarian-go/yossarian-go:v0.13.17
```

Restart container after template changes.

---

## 📊 Testing Monitoring

### Verify Metrics Endpoints

```bash
# Frontend metrics
curl http://localhost:8080/metrics

# Worker metrics
curl http://localhost:8082/metrics

# Should see:
# - yossarian_http_requests_total
# - yossarian_upload_size_bytes
# - yossarian_processing_duration_seconds
# - yossarian_patterns_detected_total
# - yossarian_ad_cache_hits_total
# - yossarian_ad_cache_misses_total
# - yossarian_active_sessions
# - yossarian_batch_jobs_total
# - yossarian_batch_processing_duration_seconds
```

### Test with Prometheus (Optional)

Add to `docker-compose.yml`:

```yaml
prometheus:
  image: prom/prometheus:latest
  ports:
    - "9090:9090"
  volumes:
    - ./prometheus.yml:/etc/prometheus/prometheus.yml
  command:
    - '--config.file=/etc/prometheus/prometheus.yml'
```

Create `prometheus.yml`:

```yaml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'yossarian-frontend'
    static_configs:
      - targets: ['frontend:8080']
  
  - job_name: 'yossarian-worker'
    static_configs:
      - targets: ['worker:8080']
```

Access Prometheus at http://localhost:9090

---

## 🎨 Helm Chart Development

### Lint Chart

```bash
cd helm/yossarian-go
helm lint .
```

### Template Validation

```bash
# Dry-run with default values
helm template yossarian . --namespace yossarian-go

# Test with custom values
helm template yossarian . \
  --namespace yossarian-go \
  --set ingress.host=test.example.com \
  --set auth.adminPassword=test123
```

### Test Installation

```bash
# Install to test cluster
helm install yossarian-test ./helm/yossarian-go \
  --namespace yossarian-test \
  --create-namespace \
  --set ingress.enabled=false \
  --set auth.adminPassword=test123

# Check deployment
kubectl get pods -n yossarian-test

# Uninstall
helm uninstall yossarian-test -n yossarian-test
kubectl delete namespace yossarian-test
```

### Package and Publish Chart

```bash
cd helm

# Package
helm package yossarian-go
# Creates: yossarian-go-0.13.18.tgz

# Push to OCI registry
helm push yossarian-go-0.13.18.tgz oci://ghcr.io/kofadam/charts
```

---

## 🐛 Debugging

### Check Container Logs

```bash
# Frontend
docker-compose logs -f frontend

# Worker
docker-compose logs -f worker

# Database
docker-compose logs -f db-service

# MinIO
docker-compose logs -f minio
```

### Exec into Containers

```bash
# Frontend shell
docker-compose exec frontend sh

# Check MinIO connectivity
docker-compose exec frontend wget -O- http://minio:9000/minio/health/live

# Check database connectivity
docker-compose exec frontend wget -O- http://db-service:8081/health
```

### Check MinIO Contents

```bash
# Install MinIO client
brew install minio/stable/mc  # macOS
# or
wget https://dl.min.io/client/mc/release/linux-amd64/mc
chmod +x mc

# Configure
mc alias set local http://localhost:9100 yossarian yossarian123

# List buckets
mc ls local

# List job files
mc ls local/yossarian-jobs/

# Download file
mc cp local/yossarian-jobs/user/job-123/output.zip ./output.zip
```

### Check Database Contents

```bash
# Copy database file
docker cp yossarian-db-service:/data/yossarian.db ./yossarian.db

# Open with sqlite3
sqlite3 yossarian.db

# Check tables
.tables

# Check batch jobs
SELECT * FROM batch_jobs;

# Check AD accounts
SELECT COUNT(*) FROM ad_accounts;

# Check API keys
SELECT key_id, name, username, created_at, last_used_at FROM api_keys;
```

---

## 🚀 Deployment Testing

### Test in Minikube

```bash
# Start minikube
minikube start --memory 8192 --cpus 4

# Build images in minikube
eval $(minikube docker-env)
./build.sh v0.13.17
./build-db-service.sh v0.12.4

# Install chart
helm install yossarian ./helm/yossarian-go \
  --namespace yossarian-go \
  --create-namespace \
  --set ingress.enabled=false \
  --set auth.adminPassword=test123

# Port forward to access
kubectl port-forward -n yossarian-go svc/yossarian-frontend 8080:8080

# Access
open http://localhost:8080
```

### Test in Kind

```bash
# Create cluster
kind create cluster --name yossarian-test

# Load images
kind load docker-image yossarian-go/yossarian-go:v0.13.17 --name yossarian-test
kind load docker-image yossarian-go/yossarian-go-db-service:v0.12.4 --name yossarian-test
kind load docker-image quay.io/minio/minio:RELEASE.2024-01-01T00-00-00Z --name yossarian-test

# Install chart
helm install yossarian ./helm/yossarian-go \
  --namespace yossarian-go \
  --create-namespace \
  --set ingress.enabled=false \
  --set auth.adminPassword=test123

# Port forward
kubectl port-forward -n yossarian-go svc/yossarian-frontend 8080:8080
```

### Test in MicroK8s

```bash
# Enable required addons
microk8s enable dns storage metallb

# Install from OCI registry
helm install yossarian oci://ghcr.io/kofadam/charts/yossarian-go \
  --version 0.13.18 \
  --namespace yossarian-go \
  --create-namespace \
  --set ingress.enabled=false \
  --set auth.adminPassword=test123

# Check pods (should see init containers complete first)
kubectl get pods -n yossarian-go -w

# Get LoadBalancer IP
kubectl get svc -n yossarian-go yossarian-frontend
```

---

## 📋 Pre-Release Checklist

Before releasing a new version:

- [ ] Update version in `README.md`
- [ ] Update version in `helm/yossarian-go/Chart.yaml`
- [ ] Update version in `helm/yossarian-go/values.yaml` (image tags)
- [ ] Update `helm/yossarian-go/CHANGELOG.md`
- [ ] Build and tag Docker images
- [ ] Push images to registry
- [ ] Test Helm chart installation
- [ ] Package Helm chart
- [ ] Push Helm chart to OCI registry
- [ ] Test API key authentication
- [ ] Create Git tag
- [ ] Create GitHub release
- [ ] Update main README.md

---

## 🔐 API Key Management

### Database Schema

API keys are stored in the `api_keys` table:

```sql
CREATE TABLE api_keys (
    key_id TEXT PRIMARY KEY,           -- yoss_<hash>
    key_hash TEXT NOT NULL,            -- SHA256 hash of full key
    name TEXT NOT NULL,                -- User-provided name
    username TEXT NOT NULL,            -- Owner username
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_used_at DATETIME,
    expires_at DATETIME,               -- NULL = never expires
    is_active INTEGER DEFAULT 1
);
```

### Admin API Endpoints

```bash
# List API keys (admin only)
curl -b cookies.txt http://localhost:8080/admin/api/keys/list

# Create API key (admin only)
curl -X POST -b cookies.txt \
  -H "Content-Type: application/json" \
  -d '{"name": "CI Pipeline"}' \
  http://localhost:8080/admin/api/keys/create

# Revoke API key (admin only)
curl -X DELETE -b cookies.txt \
  http://localhost:8080/admin/api/keys/revoke?key_id=yoss_abc123
```

---

## 🤝 Contributing

### Code Style

- **Go formatting:** Use `gofmt` or `go fmt`
- **Comments:** Add comments for exported functions
- **Error handling:** Always check and handle errors
- **Logging:** Use structured logging with context

### Pull Request Process

1. Fork the repository
2. Create a feature branch (`feature/my-feature`)
3. Make your changes
4. Test locally with docker-compose
5. Test API key authentication if touching auth code
6. Update documentation if needed
7. Commit with descriptive messages
8. Push to your fork
9. Open pull request with description

### Commit Message Format

```
<type>: <subject>

<body>

<footer>
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation only
- `style`: Code style changes (formatting)
- `refactor`: Code refactoring
- `test`: Adding tests
- `chore`: Maintenance tasks

**Example:**
```
feat: add API key authentication

Add X-API-Key header authentication for pipeline integration.
Keys are managed via Admin panel and stored with SHA256 hashing.

- POST /admin/api/keys/create - Generate new key
- DELETE /admin/api/keys/revoke - Revoke existing key
- GET /admin/api/keys/list - List all keys

Closes #42
```

---

## 📚 Additional Resources

- [Technical Architecture](ARCHITECTURE.md)
- [Helm Chart README](../helm/yossarian-go/README.md)
- [Distribution Tooling Guide](DISTRIBUTION-TOOLING-GUIDE.md)
- [Certificate Configuration](CERTIFICATE-CONFIGURATION-GUIDE.md)
- [OpenAPI Documentation](/api/openapi.yaml)

---

## 🆘 Getting Help

- **Issues**: [GitHub Issues](https://github.com/kofadam/yossarian-go/issues)
- **Discussions**: [GitHub Discussions](https://github.com/kofadam/yossarian-go/discussions)

---

**Document Version:** v0.13.17  
**Last Updated:** January 2026
