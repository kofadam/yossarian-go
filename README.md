# Yossarian Go - Enterprise Log Sanitization System

![Go Version](https://img.shields.io/badge/Go-1.23-00ADD8?logo=go)
![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker)
![License](https://img.shields.io/badge/License-MIT-green)
![Version](https://img.shields.io/badge/Version-v0.9.9-blue)

🛡️ **Air-gapped log sanitization with Material Design UI**

## Overview

Enterprise-grade log sanitization system built in Go, designed for air-gapped environments. Automatically detects and replaces sensitive information in log files with anonymized tokens. Handles 100MB+ files with comprehensive pattern detection, zero data retention, and enterprise authentication.

**Named after the Catch-22 character who censored letters** - Yossarian Go sanitizes your logs so you can safely share them with external support teams, vendors, or less-secure storage.

<img width="1717" height="1004" alt="image" src="https://github.com/user-attachments/assets/f86af307-f3a4-4661-9c53-02f2a507a275" />

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

### 🏢 **Organization Settings** (NEW in v0.9.9)
- **Configurable Disclaimer** - Custom warning banner on main page
- **Documentation Links** - Custom docs URL and title
- **Admin-Managed** - No code changes required
- **Markdown Support** - Rich text formatting for disclaimers
- **Persistent Storage** - SQLite database for settings

### 🔐 **Security & Compliance**
- **Zero persistence** - All processing in-memory, no data retention
- **Air-gap ready** - No external dependencies required
- **Enterprise SSO** - Keycloak/OIDC integration with role-based access
- **Session management** - Secure admin sessions with token expiry
- **Audit trails** - Complete IP mapping exports for compliance
- **Encrypted storage** - Personal words encrypted in browser localStorage

### 📊 **Monitoring & Observability**
- **Prometheus metrics** - `/metrics` endpoint with comprehensive instrumentation
- **Alert rules** - Production-ready alerts for availability, performance, errors
- **Grafana dashboards** - Pre-built dashboards for visualization
- **Cache metrics** - AD lookup cache hit/miss tracking (23x performance boost)
- **Pattern detection stats** - Real-time detection counters by type
- **Performance metrics** - Processing duration histograms

### ⚡ **Performance**
- **Processing Speed** - ~1MB/second for complex logs
- **Large Files** - Handles 100MB+ files without crashes
- **Caching** - AD lookup caching provides 23x speedup
- **Scalability** - Kubernetes-native with horizontal pod autoscaling
- **Optimization** - Sub-3 second processing for typical files

---

## 🏗️ Architecture

### Microservices Design
```
┌─────────────────┐    ┌─────────────────┐    ┌──────────────┐
│ Main App Pods   │───▶│ DB Service Pod  │───▶│ Active Dir   │
│ (yossarian-go)  │    │ (SQLite + HTTP) │    │ (LDAP/LDAPS) │
│ - Web UI        │    │ - AD Lookups    │    └──────────────┘
│ - Sanitization  │    │ - LDAP Sync     │
│ - File Upload   │    │ - Real USNs     │
│ - Auth/Sessions │    │ - Org Settings  │
└─────────────────┘    └─────────────────┘
        │
        ▼
┌─────────────────┐
│ Keycloak (OIDC) │
│ - SSO Auth      │
│ - Role Mgmt     │
└─────────────────┘
```

**Components:**
- **Main App** - Stateless pods (horizontal scaling)
- **DB Service** - SQLite database with HTTP API
- **Storage** - RWO PVC for database persistence
- **Networking** - Contour HTTPProxy with session affinity
- **Monitoring** - Prometheus Operator + Grafana

---

## 🚀 Quick Start

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

### Pull Pre-Built Images
```bash
# Main application
docker pull ghcr.io/kofadam/yossarian-go:v0.9.9.0

# Database service
docker pull ghcr.io/kofadam/yossarian-go-db-service:v0.9.9
```

[View on GHCR](https://github.com/users/kofadam/packages/container/package/yossarian-go) | [DB Service](https://github.com/users/kofadam/packages/container/package/yossarian-go-db-service)

### Kubernetes Deployment
```yaml
# Example deployment (adjust for your environment)
apiVersion: apps/v1
kind: Deployment
metadata:
  name: yossarian-go
spec:
  replicas: 3
  selector:
    matchLabels:
      app: yossarian-go
  template:
    metadata:
      labels:
        app: yossarian-go
    spec:
      containers:
      - name: yossarian-go
        image: ghcr.io/kofadam/yossarian-go:v0.9.9.0
        ports:
        - containerPort: 8080
        env:
        - name: AD_SERVICE_URL
          value: "http://yossarian-db-service:8081"
        - name: OIDC_ENABLED
          value: "true"
        - name: OIDC_ISSUER_URL
          value: "https://keycloak.example.com/realms/myrealm"
        # ... additional config
```

---

## ⚙️ Configuration

### Environment Variables

#### **Main Application (`yossarian-go`)**

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8080` | HTTP server port |
| `ADMIN_PASSWORD` | `admin123` | Admin panel password (if OIDC disabled) |
| `AD_SERVICE_URL` | `http://yossarian-db-service:8081` | Database service endpoint |
| `MAX_TOTAL_UPLOAD_SIZE_MB` | `100` | Total upload size limit |
| `MAX_FILE_SIZE_MB` | `50` | Individual file size limit |
| `MAX_ZIP_FILE_SIZE_MB` | `10` | Files inside ZIP archives limit |
| `MAX_FILE_COUNT` | `10` | Maximum number of files per upload |

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
- `admin` - Full admin panel access
- `user` - Standard user access

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

### Alert Rules

**Critical Alerts:**
- `YossarianDown` - Application unavailable
- `YossarianPodRestartLoop` - Pods crash looping
- `YossarianDBServiceDown` - Database service unavailable

**Warning Alerts:**
- `YossarianHighErrorRate` - Error rate > 5%
- `YossarianSlowFileProcessing` - P95 processing > 10s
- `YossarianHighMemoryUsage` - Memory > 85%
- `YossarianHighADCacheMissRate` - Cache miss > 30%

**Info Alerts:**
- `YossarianHighUploadVolume` - Unusual upload traffic
- `YossarianLargeFilesUploaded` - Files > 50MB processed
- `YossarianNoRequests` - No activity detected

---

## 🔧 Development

### Build from Source
```bash
# Clone repository
git clone https://github.com/kofadam/yossarian-go.git
cd yossarian-go

# Build main app
./build.sh v0.9.9.0

# Build database service
./build-db-service.sh v0.9.9

# Run locally
docker-compose up -d
```

### Project Structure
```
yossarian-go/
├── main.go                 # Main application
├── db-service.go          # Database microservice
├── templates/
│   ├── index.html         # Main UI
│   └── admin.html         # Admin panel
├── Dockerfile             # Main app image
├── Dockerfile.db-service  # DB service image
├── docker-compose.yml     # Local development
└── build.sh              # Build script
```

### Testing
```bash
# Run with Docker Compose
docker-compose up -d

# Test main page
curl http://localhost:8080/health

# Test org settings API
curl http://localhost:8080/api/org-settings/public

# Test admin endpoints (requires auth)
curl -u admin:admin123 http://localhost:8080/admin/api/org-settings/list
```

---

## 🔒 Security Considerations

### Air-Gap Deployment
- All resources bundled inline (no CDN dependencies)
- Works completely offline
- No external API calls required

### Data Handling
- **Zero persistence** - No logs stored on disk
- **In-memory processing** - All sanitization in RAM
- **Immediate cleanup** - Files cleared after download
- **Session-only storage** - Download cache cleared on logout

### Authentication
- **Enterprise SSO** - Keycloak/OIDC integration
- **Role-based access** - Admin vs user permissions
- **Session management** - Secure cookie-based sessions
- **Token validation** - Real-time Keycloak token expiry checks

### Compliance
- **Audit trails** - IP mapping exports for compliance
- **Detailed reports** - CSV exports with line-by-line changes
- **Consistent replacements** - Same value always gets same token
- **Reversible mappings** - Download mapping tables for verification

---

## 📈 Performance Benchmarks

**Typical Performance (3MB log file, 35K patterns):**
- Processing time: 2.6 seconds
- Cache hit rate: 98%+
- Memory usage: <200MB per file
- Throughput: ~1MB/second

**Optimizations:**
- AD lookup caching: 23x performance boost
- Regex optimization: 12% accuracy improvement
- Word boundary matching: Eliminates false positives
- In-memory processing: No disk I/O overhead

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

---

## 📝 License

MIT License - See LICENSE file for details

---

## 🙏 Acknowledgments

- Named after the character from Joseph Heller's "Catch-22"
- Built with Go, SQLite, and Material Design
- Kubernetes-native architecture
- Enterprise-ready monitoring with Prometheus

---

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/kofadam/yossarian-go/issues)
- **Documentation**: This README
- **Version**: v0.9.9.0
- **Last Updated**: December 2025

---

**🛡️ Yossarian Go - Making logs safe to share**
