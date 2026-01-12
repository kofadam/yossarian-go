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
├── db-service.go              # Database service + job queue API
├── templates/                 # HTML templates
│   ├── index.html            # Main upload UI
│   ├── admin.html            # Admin panel
│   └── my-jobs.html          # Batch job status page
├── grafana/                  # Grafana dashboards
│   ├── yossarian-overview.json
│   └── yossarian-worker-details.json
├── helm/                     # Helm charts
│   ├── README.md
│   ├── yossarian-go-0.13.8.tgz
│   └── yossarian-go/        # Chart source
├── docs/                     # Documentation
│   ├── ARCHITECTURE.md
│   ├── DISTRIBUTION-TOOLING-GUIDE.md
│   ├── CERTIFICATE-CONFIGURATION-GUIDE.md
│   └── DEVELOPMENT.md (this file)
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
./build.sh v0.13.8

# Or manually
VERSION=v0.13.8
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
./build-db-service.sh v0.12.3

# Or manually
docker build \
  -f Dockerfile.db-service \
  -t yossarian-go/yossarian-go-db-service:v0.12.3 \
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
  yossarian-go/yossarian-go:v0.13.8
```

**Worker Only:**
```bash
docker run --rm -p 8082:8080 \
  -e MODE=worker \
  -v $(pwd)/data:/data \
  yossarian-go/yossarian-go:v0.13.8
```

**Database Service:**
```bash
docker run --rm -p 8083:8081 \
  -v $(pwd)/data:/data \
  yossarian-go/yossarian-go-db-service:v0.12.3
```

---

## 🎯 Testing Workflows

### Test Single File Upload

```bash
# Create test file
echo "Test log with 192.168.1.1 and CORP\user123" > test.log

# Upload
curl -F "file=@test.log" http://localhost:8080/upload

# Should return sanitized content with:
# - IP replaced with [IP-001]
# - AD account replaced with USN (if in database)
```

### Test Batch Job Processing

```bash
# Create test files
echo "Log 1 with 10.0.0.1" > log1.txt
echo "Log 2 with 10.0.0.2" > log2.txt
echo "Log 3 with CORP\admin" > log3.txt

# Create ZIP
zip batch-test.zip log1.txt log2.txt log3.txt

# Upload batch job
RESPONSE=$(curl -F "file=@batch-test.zip" http://localhost:8080/upload)
echo $RESPONSE

# Extract job ID
JOB_ID=$(echo $RESPONSE | jq -r '.job_id')
echo "Job ID: $JOB_ID"

# Check status (repeat until completed)
curl http://localhost:8080/api/jobs/status/$JOB_ID | jq

# Download results when completed
curl -O http://localhost:8080/jobs/download/$JOB_ID

# Download reports
curl -O http://localhost:8080/jobs/reports/$JOB_ID/ip-mappings.csv
curl -O http://localhost:8080/jobs/reports/$JOB_ID/summary.json
```

### Test LDAP Sync

```bash
# Requires LDAP server configured in docker-compose.yml

# Trigger sync
curl -X POST http://localhost:8083/ldap/sync-full

# Check status
curl http://localhost:8083/ldap/status | jq

# List accounts
curl http://localhost:8083/accounts/list | jq
```

---

## 🔧 Development Workflow

### Making Code Changes

1. **Edit source files** (main.go, db-service.go, templates/*)

2. **Rebuild images:**
```bash
./build.sh v0.13.8-dev
./build-db-service.sh v0.12.3-dev
```

3. **Update docker-compose.yml** to use `-dev` tags:
```yaml
services:
  frontend:
    image: yossarian-go/yossarian-go:v0.13.8-dev
  worker:
    image: yossarian-go/yossarian-go:v0.13.8-dev
  db-service:
    image: yossarian-go/yossarian-go-db-service:v0.12.3-dev
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
  yossarian-go/yossarian-go:v0.13.8
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

### Package Chart

```bash
cd helm
helm package yossarian-go
# Creates: yossarian-go-0.13.8.tgz
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
```

---

## 🚀 Deployment Testing

### Test in Minikube

```bash
# Start minikube
minikube start --memory 8192 --cpus 4

# Build images in minikube
eval $(minikube docker-env)
./build.sh v0.13.8
./build-db-service.sh v0.12.3

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
kind load docker-image yossarian-go/yossarian-go:v0.13.8 --name yossarian-test
kind load docker-image yossarian-go/yossarian-go-db-service:v0.12.3 --name yossarian-test
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
- [ ] Create Git tag
- [ ] Create GitHub release
- [ ] Update main README.md

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
5. Update documentation if needed
6. Commit with descriptive messages
7. Push to your fork
8. Open pull request with description

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
feat: add job cancellation timeout

Add WORKER_CANCELLATION_TIMEOUT environment variable to automatically
cancel jobs that have been processing for too long.

Defaults to 3600 seconds (1 hour). Set to 0 to disable.

Fixes #123
```

---

## 📚 Additional Resources

- [Technical Architecture](ARCHITECTURE.md)
- [Helm Chart README](../helm/yossarian-go/README.md)
- [Distribution Tooling Guide](DISTRIBUTION-TOOLING-GUIDE.md)
- [Certificate Configuration](CERTIFICATE-CONFIGURATION-GUIDE.md)

---

## 🆘 Getting Help

- **Issues**: [GitHub Issues](https://github.com/kofadam/yossarian-go/issues)
- **Discussions**: [GitHub Discussions](https://github.com/kofadam/yossarian-go/discussions)

---

**Document Version:** v0.13.8  
**Last Updated:** January 2026
