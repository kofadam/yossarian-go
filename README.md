# Yossarian Go - Enterprise Log & Code Sanitization System

![Go Version](https://img.shields.io/badge/Go-1.23-00ADD8?logo=go)
![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker)
![Kubernetes](https://img.shields.io/badge/Kubernetes-Native-326CE5?logo=kubernetes)
![Helm](https://img.shields.io/badge/Helm-v0.13.20-0F1689?logo=helm)
![License](https://img.shields.io/badge/License-MIT-green)
![Version](https://img.shields.io/badge/Version-v0.13.20-blue)

🛡️ **Enterprise sanitization for logs AND source code**

Automatically detects and replaces sensitive information in log files and source code with anonymized tokens or safe placeholder values. Built for air-gapped environments with horizontal scaling, OIDC authentication, and Prometheus monitoring.

**Named after the Catch-22 character who censored letters** - Yossarian Go sanitizes your files so you can safely share them with external support teams, vendors, or customers.

---

## ✨ Two Sanitization Modes

### 🔒 Secure Files (Log Sanitization)
For sharing logs with support teams and vendors:
- **IP Addresses** → `[IP-001]` with consistent mapping
- **AD Accounts** → USN format via LDAP
- **JWT Tokens** → `[JWT-REDACTED]`
- **Private Keys** → `[PRIVATE-KEY-REDACTED]`
- **Passwords** → `[PASSWORD-REDACTED]`
- **Custom Terms** → Admin-configured patterns

### 🧹 Code Scan (Source Code Sanitization) — NEW in v0.13.20
For sharing code with customers, vendors, or public repos:
- **Internal URLs** → `http://example.com` (preserves port/path)
- **IP Addresses** → `192.0.2.x` (RFC 5737 documentation range)
- **API Keys** → `[AWS-KEY-REDACTED]`, `[STRIPE-KEY-REDACTED]`, etc.
- **Passwords** → `CHANGE_ME_PASSWORD` (preserves JSON structure)
- **Secrets** → `[SECRET-REDACTED]`
- **Coordinates** → `0.0000, 0.0000`
- **Supports**: ZIP, tar.gz archives with structure preserved

---

## 🚀 Quick Start

### Helm Chart (Recommended)
```bash
helm install yossarian oci://ghcr.io/kofadam/charts/yossarian-go \
  --version 0.13.20 \
  --namespace yossarian-go \
  --create-namespace \
  --set ingress.host=yossarian.example.com
```

### Docker Compose (Local Development)
```bash
git clone https://github.com/kofadam/yossarian-go.git
cd yossarian-go
docker-compose up -d
open http://localhost:8080
```

---

## 🎯 Key Features

- **Split Architecture**: Horizontally scalable frontend + workers
- **MinIO Storage**: Batch processing for large archives
- **Air-Gap Ready**: No external dependencies
- **Enterprise SSO**: OIDC/Keycloak integration
- **API Key Auth**: Stateless authentication for CI/CD pipelines
- **Prometheus Metrics**: Full observability with Grafana dashboards

---

## 📚 Documentation

| Document | Description |
|----------|-------------|
| [Helm Chart README](helm/yossarian-go/README.md) | Installation and configuration |
| [Code Scan Guide](docs/CODE-SCAN-GUIDE.md) | Source code sanitization |
| [API Integration Guide](docs/API-INTEGRATION-GUIDE.md) | REST API for automation |
| [Distribution Tooling Guide](docs/DISTRIBUTION-TOOLING-GUIDE.md) | Air-gap deployment |
| [Certificate Configuration](docs/CERTIFICATE-CONFIGURATION-GUIDE.md) | OIDC and LDAPS setup |
| [Technical Architecture](docs/ARCHITECTURE.md) | System design |

---

## 📈 Performance

- **Single File**: 3MB file with 35K patterns in 2.6 seconds
- **Batch Processing**: Archives processed asynchronously
- **AD Lookup Caching**: 23x performance boost (98%+ cache hit rate)

---

## 🔄 What's New in v0.13.20

- ✅ **Code Scan Feature** - Sanitize source code with safe placeholder values
- ✅ **Archive Support** - ZIP and tar.gz batch processing for Code Scan
- ✅ **Enhanced Secret Detection** - AWS, Stripe, GitHub, Slack, OpenAI, SendGrid keys
- ✅ **Generic Secrets** - JWT_SECRET, api_secret, secret_key patterns
- ✅ **Coordinate Sanitization** - Decimal, DMS, Geo URI, and object formats

See [CHANGELOG](helm/yossarian-go/CHANGELOG.md) for complete version history.

---

## 📄 License

MIT License - See [LICENSE](LICENSE) file for details

---

**🛡️ Yossarian Go - Making logs and code safe to share**
