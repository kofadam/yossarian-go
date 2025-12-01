# Yossarian Go - Enterprise Log Sanitization System

![GHCR](https://img.shields.io/badge/GHCR-yossarian--go-blue?logo=docker)
![GHCR](https://img.shields.io/badge/GHCR-yossarian--go--db--service-blue?logo=docker)

🛡️ **Air-gapped log sanitization with Material Design UI**

## Overview
Enterprise-grade log sanitization system built in Go, designed for air-gapped environments. Handles 100MB+ files with comprehensive pattern detection and zero data retention.

## Features
### 🔍 Pattern Detection
- **IP Addresses** → `[IP-ADDRESS-REDACTED]` with consistent mapping
- **AD Accounts** → USN format (`CORP\user` → `USN123456789`)
- **JWT Tokens** → `[JWT-REDACTED]`
- **Private Keys** → `[PRIVATE-KEY-REDACTED]`
- **Sensitive Terms** → `[SENSITIVE]` (organization-defined)
- **User Words** → `[USER-SENSITIVE]` (personal cookie-stored)

### 🎨 Material Design UI
- Multi-file upload (up to 10 files, 50MB each)
- Drag & drop + click-to-browse
- Real-time progress tracking
- Comprehensive results dashboard
- Downloadable sanitized files and audit reports

### 🔒 Security & Compliance
- **Zero persistence** – all processing in-memory
- **Air-gap ready** – no external dependencies
- **Audit trails** – complete IP mapping exports
- **Session-based auth** – secure admin panel

### 📊 Monitoring & Observability
- **Prometheus metrics** - `/metrics` endpoint with comprehensive instrumentation
- **Alert rules** - Production-ready alerts for availability, performance, and errors
- **Grafana dashboards** - Pre-built dashboards for visualization
- **Cache metrics** - AD lookup cache hit/miss tracking
- **Pattern detection** - Real-time pattern detection statistics

<img width="1402" height="993" alt="image" src="https://github.com/user-attachments/assets/88a14f1f-d9b0-4afd-909b-21c554df5777" />

## Docker Images
The following images are published on GitHub Container Registry:

- **yossarian-go**  
  ```
  docker pull ghcr.io/kofadam/yossarian-go:v0.9.6
  ```
- **yossarian-go-db-service**  
  ```
  docker pull ghcr.io/kofadam/yossarian-go-db-service:v0.9.9
  ```

[View on GHCR](https://github.com/users/kofadam/packages/container/package/yossarian-go) | [DB Service](https://github.com/users/kofadam/packages/container/package/yossarian-go-db-service)

## Quick Start
### Docker Deployment
```bash
# Build and run
docker-compose up --build

# Access the application
http://localhost:8080        # Main interface
http://localhost:8080/admin  # Admin panel (password: admin123)
```
## Monitoring

### Prometheus Metrics

The application exposes metrics at `/metrics`:

- `yossarian_http_requests_total` - HTTP request counter by method/endpoint/status
- `yossarian_upload_size_bytes` - Histogram of uploaded file sizes
- `yossarian_processing_duration_seconds` - Processing time histogram
- `yossarian_patterns_detected_total` - Counter for each pattern type (IP, AD, JWT, etc.)
- `yossarian_errors_total` - Error counter by type
- `yossarian_ad_cache_hits_total` - AD cache hit counter
- `yossarian_ad_cache_misses_total` - AD cache miss counter
- `yossarian_active_sessions` - Current active sessions gauge

### Alert Rules

Production-ready alerts included:

**Critical Alerts:**
- `YossarianDown` - Application completely down
- `YossarianPodRestartLoop` - Pod crash looping
- `YossarianDBServiceDown` - Database service unavailable

**Warning Alerts:**
- `YossarianHighErrorRate` - Error rate > 5%
- `YossarianSlowFileProcessing` - P95 processing time > 10s
- `YossarianHighMemoryUsage` - Memory usage > 85%
- `YossarianHighADCacheMissRate` - Cache miss rate > 30%

**Info Alerts:**
- `YossarianHighUploadVolume` - High upload traffic
- `YossarianLargeFilesUploaded` - Large files being processed
- `YossarianNoRequests` - No traffic received
