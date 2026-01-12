# Yossarian Go Helm Chart - CHANGELOG

## [0.13.8] - 2026-01-12

### ✨ Added
- **ServiceMonitor template** for Prometheus Operator integration
  - Separate ServiceMonitors for frontend, worker, and database
  - Configurable scrape interval and timeout
  - Support for custom labels for Prometheus discovery
- **Distribution Tooling for Helm (dt4h) support** for air-gap deployments
  - Added `distribution.carto.run/images` annotation
  - All images now use specific versions (no `:latest` tags)
  - Full air-gap installation documentation
- **Comprehensive certificate extraction guide**
  - OpenSSL commands for OIDC provider certificates
  - OpenSSL commands for Active Directory LDAPS certificates
  - Clear separation between OIDC (`CA_CERT_PATH`) and LDAPS (`DC_CA_CERT_PATH`) certificates
  - Troubleshooting commands for certificate issues
- **Separate ConfigMaps for certificates**
  - `yossarian-go-ca-bundle` for OIDC authentication (frontend/worker)
  - `yossarian-go-dc-ca-bundle` for AD LDAPS sync (database service)
- **Grafana dashboard documentation**
  - Instructions for importing two pre-built dashboards
  - Example Prometheus alert rules
  - Metrics endpoint documentation
- **Job cancellation configuration**
  - New `worker.cancellationTimeout` value for stuck job detection
  - Default 1 hour timeout (configurable)

### 🔧 Changed
- **Reduced worker memory limits** (v0.13.8 optimization)
  - Request: 512Mi → 256Mi
  - Limit: 2Gi → 512Mi
  - Reflects actual memory usage improvements in v0.13.8
- **Improved ServiceMonitor configuration**
  - Added `scrapeTimeout` parameter
  - Better documentation for `additionalLabels`
  - Clearer namespace configuration
- **Enhanced values.yaml documentation**
  - Detailed comments for OIDC vs LDAPS certificate usage
  - OpenSSL extraction commands in inline comments
  - Better explanation of Distribution Tooling support

### 🐛 Fixed
- **Certificate mounting for database service**
  - Database service now correctly uses `dc-ca-bundle` ConfigMap for LDAPS
  - Previously incorrectly used `ca-bundle` ConfigMap (OIDC cert)
  - Environment variable `DC_CA_CERT_PATH` now properly set only when `ldap.caCert` is provided
- **Image version tags**
  - Changed from `:latest` to specific versions for air-gap compatibility
  - Updated to v0.13.8 for main app, v0.12.3 for db-service
  - MinIO and curl now use pinned versions

### 📚 Documentation
- **README.md**
  - Added air-gap installation section with dt4h examples
  - Added certificate extraction guide with OpenSSL commands
  - Added Prometheus metrics documentation
  - Added Grafana dashboard import instructions
  - Added example PrometheusRule for alerting
- **New guides**
  - `DISTRIBUTION-TOOLING-GUIDE.md` - Comprehensive dt4h usage
  - `CERTIFICATE-CONFIGURATION-GUIDE.md` - Certificate setup guide

### 🔄 Migration Notes

**From 0.13.3 to 0.13.8:**

#### No Breaking Changes
This is a **fully backwards compatible** update. Existing installations will continue to work without any changes to values.yaml.

#### Optional: Enable New Features

**Enable Prometheus monitoring:**
```yaml
metrics:
  enabled: true
  serviceMonitor:
    enabled: true
    additionalLabels:
      prometheus: kube-prometheus  # Match your Prometheus selector
```

**Add LDAPS certificate (if using Active Directory):**
```yaml
ldap:
  enabled: true
  caCert: |
    -----BEGIN CERTIFICATE-----
    [Your DC certificate]
    -----END CERTIFICATE-----
```

**Configure job cancellation timeout:**
```yaml
worker:
  cancellationTimeout: 3600  # Default: 1 hour
```

**Reduce worker memory (optional, if experiencing resource constraints):**
```yaml
worker:
  resources:
    requests:
      memory: 256Mi  # Was 512Mi
    limits:
      memory: 512Mi  # Was 2Gi
```

#### Upgrade Command

```bash
helm upgrade yossarian oci://ghcr.io/kofadam/yossarian-go \
  --version 0.13.8 \
  -n yossarian-go \
  -f your-custom-values.yaml
```

No downtime expected. Rolling update strategy applies to frontend (3 pods).

### 📦 Image Versions

| Component | Image | Version |
|-----------|-------|---------|
| Frontend/Worker | `ghcr.io/kofadam/yossarian-go` | v0.13.8 |
| Database Service | `ghcr.io/kofadam/yossarian-go-db-service` | v0.12.3 |
| MinIO | `quay.io/minio/minio` | RELEASE.2024-01-01T00-00-00Z |
| CronJob (curl) | `curlimages/curl` | 8.5.0 |

### 🎯 Application Features (v0.13.8)

- ✅ Memory optimization (23x cache performance improvement)
- ✅ Job cancellation for stuck processing jobs
- ✅ Prometheus metrics (`/metrics` endpoint)
- ✅ Grafana dashboard templates
- ✅ Split architecture (frontend/worker)
- ✅ MinIO-backed batch processing
- ✅ Enterprise SSO (OIDC)
- ✅ Active Directory sync
- ✅ Air-gap ready

---

## [0.13.3] - 2026-01-06

### Initial Release
- Split architecture with frontend and worker components
- MinIO integration for batch processing
- OIDC authentication support
- Active Directory LDAPS integration
- Contour HTTPProxy and standard Ingress support
- Configurable resource limits
- PVC-based persistence
- CronJob for AD sync

### Components
- Frontend (3 replicas, stateless)
- Worker (1 replica, RWO PVC)
- Database service (1 replica, SQLite)
- MinIO (1 replica, object storage)

---

**Legend:**
- ✨ Added - New features
- 🔧 Changed - Modified existing features
- 🐛 Fixed - Bug fixes
- 📚 Documentation - Documentation improvements
- 🔄 Migration - Migration guide
- 📦 Images - Container image versions
- 🎯 Features - Application-level features
