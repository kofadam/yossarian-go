# Yossarian Go - Enterprise Log Sanitization System

![Go Version](https://img.shields.io/badge/Go-1.23-00ADD8?logo=go)
![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker)
![Kubernetes](https://img.shields.io/badge/Kubernetes-Native-326CE5?logo=kubernetes)
![Helm](https://img.shields.io/badge/Helm-v0.13.17-0F1689?logo=helm)
![License](https://img.shields.io/badge/License-MIT-green)
![Version](https://img.shields.io/badge/Version-v0.13.17-blue)

🛡️ **Enterprise log sanitization with MinIO-backed batch processing**

Automatically detects and replaces sensitive information in log files with anonymized tokens. Built for air-gapped environments with horizontal scaling, OIDC authentication, and Prometheus monitoring.

**Named after the Catch-22 character who censored letters** - Yossarian Go sanitizes your logs so you can safely share them with external support teams, vendors, or less-secure storage.

<img width="1675" height="860" alt="image" src="https://github.com/user-attachments/assets/2f63923c-7f18-47a2-8d52-48e56d25a39c" />
<img width="1675" height="794" alt="image" src="https://github.com/user-attachments/assets/9ec20333-009a-4222-9c47-b4c1de9b4709" />

---

## ✨ What Gets Protected?

- **🌐 IP Addresses** → `[IP-001]` with consistent mapping
- **👤 AD Accounts** → USN format via LDAP (`CORP\user` → `USN123456789`)
- **🎫 JWT Tokens** → `[JWT-REDACTED]`
- **🔑 Private Keys** → `[PRIVATE-KEY-REDACTED]`
- **🔒 Passwords** → `[PASSWORD-REDACTED]`
- **🏢 Custom Terms** → Admin-configured organizational patterns

---

## 🚀 Quick Start

### Option 1: Helm Chart (Recommended)

```bash
# Standard installation
helm install yossarian oci://ghcr.io/kofadam/charts/yossarian-go \
  --version 0.13.18 \
  --namespace yossarian-go \
  --create-namespace \
  --set ingress.host=yossarian.example.com \
  --set auth.adminPassword=changeme
```

**📦 Air-Gap Installation** (using Distribution Tooling for Helm):
```bash
# Wrap chart with all container images included
dt wrap oci://ghcr.io/kofadam/yossarian-go:0.13.17

# Push to air-gapped registry
dt unwrap yossarian-go-0.13.17.wrap.tgz your-registry.yourdomain.local/project/charts --yes

# Install in air-gap environment
helm install yossarian oci://your-registry.yourdomain.local/project/charts/yossarian-go
```

> **💡 New to Distribution Tooling?** It bundles all container images with the Helm chart for true air-gap deployment. Learn more: [Distribution Tooling Guide](docs/DISTRIBUTION-TOOLING-GUIDE.md)

**📚 Documentation:**
- [Complete Helm Chart Documentation](helm/yossarian-go/README.md)
- [API Integration Guide](docs/API-INTEGRATION-GUIDE.md)
- [Air-Gap Installation Guide](docs/DISTRIBUTION-TOOLING-GUIDE.md)
- [Certificate Configuration](docs/CERTIFICATE-CONFIGURATION-GUIDE.md)
- [Technical Architecture](docs/ARCHITECTURE.md)

### Option 2: Docker Compose (Local Development)

```bash
git clone https://github.com/kofadam/yossarian-go.git
cd yossarian-go
docker-compose up -d
open http://localhost:8080
```

---

## 🎯 Key Features

### ⚡ Scalable Architecture
- **Split Architecture**: Horizontally scalable frontend + workers
- **MinIO Storage**: Centralized object storage for batch jobs
- **Async Processing**: Upload large files and download results later
- **Job Cancellation**: Cancel queued/processing jobs
- **Auto-Cleanup**: 8-hour retention policy for completed jobs
- **Memory Optimized**: Streaming architecture prevents OOM crashes

### 🔒 Security & Compliance
- **Zero Persistence**: No data retained after download
- **Air-Gap Ready**: No external dependencies required
- **Enterprise SSO**: OIDC/Keycloak integration
- **API Key Auth**: Stateless authentication for pipelines
- **Audit Trails**: Complete IP mapping exports

### 📊 Monitoring & Observability
- **Prometheus Metrics**: `/metrics` endpoint on all components
- **Grafana Dashboards**: Pre-built overview and worker detail dashboards
- **ServiceMonitor**: Native Prometheus Operator integration
- **Performance Tracking**: Cache hit rates, processing times, queue depth

---

## 🔌 API Integration

Integrate Yossarian Go into your CI/CD pipelines and automation workflows:

```bash
# Create an API key in Admin Panel → API Keys
export API_KEY="yoss_your_key_here"

# Upload and sanitize a ZIP file
curl -X POST "https://yossarian.example.com/upload" \
  -H "X-API-Key: $API_KEY" \
  -F "file=@logs.zip"

# Check job status
curl -H "X-API-Key: $API_KEY" \
  "https://yossarian.example.com/api/jobs/status/batch-user-20260129-120000"

# Download results
curl -H "X-API-Key: $API_KEY" \
  "https://yossarian.example.com/jobs/download/batch-user-20260129-120000" \
  -o sanitized.zip
```

See the [API Integration Guide](docs/API-INTEGRATION-GUIDE.md) for complete documentation with examples in Bash, Python, and Jenkins.

---

## 📈 Performance

- **Single File**: 3MB file with 35K patterns in 2.6 seconds
- **Batch Processing**: 4-file ZIP in 0.2 seconds
- **AD Lookup Caching**: 23x performance boost (98%+ cache hit rate)
- **Scalability**: Frontend scales 1-10+ pods, workers scale horizontally

---

## ⚙️ Configuration Highlights

### Essential Settings (via Helm values.yaml)

```yaml
# Domain & Access
ingress:
  host: yossarian.example.com
  tls: true

# Authentication
auth:
  oidc:
    enabled: true
    issuerUrl: https://keycloak.example.com/realms/myrealm
    clientId: yossarian-go
    autoSSO: true  # Force SSO login

# Active Directory Integration
ldap:
  enabled: true
  server: ldaps://dc.example.com:636
  bindDN: CN=svc-yossarian,OU=Service,DC=example,DC=com

# Monitoring
metrics:
  serviceMonitor:
    enabled: true
    additionalLabels:
      prometheus: kube-prometheus

# Storage & Performance
minio:
  persistence:
    size: 100Gi
worker:
  replicas: 2  # Horizontally scalable
  resources:
    requests:
      memory: 256Mi
```

See [complete values.yaml documentation](helm/yossarian-go/README.md#configuration) for all options.

---

## 📊 Monitoring Setup

### Quick Start with Prometheus Operator

```bash
# Enable ServiceMonitor in Helm values
helm upgrade yossarian oci://ghcr.io/kofadam/yossarian-go \
  --version 0.13.17 \
  --reuse-values \
  --set metrics.serviceMonitor.enabled=true \
  --set metrics.serviceMonitor.additionalLabels.prometheus=kube-prometheus
```

### Import Grafana Dashboards

1. Download dashboards from [grafana/](grafana/) directory
2. Import via Grafana UI: **Dashboards** → **Import** → Upload JSON
3. Available dashboards:
   - **Yossarian Overview**: System health, job queue, processing stats
   - **Worker Details**: Memory usage, cache performance, processing times

**Exposed Metrics:**
- `yossarian_http_requests_total` - HTTP request counter
- `yossarian_upload_size_bytes` - File upload sizes
- `yossarian_processing_duration_seconds` - Processing time histogram
- `yossarian_patterns_detected_total` - Detected sensitive patterns
- `yossarian_ad_cache_hits_total` / `ad_cache_misses_total` - Cache performance
- `yossarian_active_sessions` - Current user sessions

---

## 🔄 Upgrading

### From v0.13.8 to v0.13.17

```bash
helm upgrade yossarian oci://ghcr.io/kofadam/yossarian-go \
  --version 0.13.17 \
  --namespace yossarian-go \
  --reuse-values
```

**What's New in v0.13.17:**
- ✅ **API Key Authentication** - Stateless auth for pipelines and automation
- ✅ **Horizontal Worker Scaling** - Workers now scale (MinIO-backed, no PVC)
- ✅ **Helm Chart Fixes** - MinIO Deployment, tour ConfigMap, TLS handling
- ✅ **Interactive Tour** - Multi-language onboarding (EN/HE)
- ✅ **API Documentation** - Complete integration guide with examples

**Breaking Changes:** None (fully backwards compatible)

See [CHANGELOG](helm/yossarian-go/CHANGELOG.md) for complete version history.

---

## 📚 Documentation

| Document | Description |
|----------|-------------|
| [Helm Chart README](helm/yossarian-go/README.md) | Complete installation and configuration guide |
| [API Integration Guide](docs/API-INTEGRATION-GUIDE.md) | REST API for pipelines and automation |
| [Distribution Tooling Guide](docs/DISTRIBUTION-TOOLING-GUIDE.md) | Air-gap deployment with bundled images |
| [Certificate Configuration](docs/CERTIFICATE-CONFIGURATION-GUIDE.md) | OIDC and LDAPS certificate setup |
| [Technical Architecture](docs/ARCHITECTURE.md) | System design and component details |
| [Development Guide](docs/DEVELOPMENT.md) | Building, testing, and contributing |

---

## 🛠️ Development

```bash
# Clone repository
git clone https://github.com/kofadam/yossarian-go.git
cd yossarian-go

# Build images
./build.sh v0.13.17
./build-db-service.sh v0.12.3

# Run locally
docker-compose up -d
```

See [Development Guide](docs/DEVELOPMENT.md) for detailed instructions.

---

## 📄 License

MIT License - See [LICENSE](LICENSE) file for details

---

## 🙏 Acknowledgments

- Named after Joseph Heller's "Catch-22" character
- Built with Go, SQLite, MinIO, and Material Design
- Kubernetes-native with Prometheus monitoring

---

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/kofadam/yossarian-go/issues)
- **Discussions**: [GitHub Discussions](https://github.com/kofadam/yossarian-go/discussions)
- **Version**: v0.13.17
- **Last Updated**: January 2026

---

**🛡️ Yossarian Go - Making logs safe to share, at any scale**
