# Yossarian Go Helm Chart

Enterprise-grade log sanitization system for Kubernetes environments.

## Overview

Yossarian Go automatically detects and replaces sensitive information (IP addresses, usernames, passwords, tokens, keys) in log files, making them safe to share with external support teams or vendors.

**Features:**
- 🔒 Pattern detection (IPs, AD accounts, JWT tokens, private keys, passwords)
- ⚡ Scalable architecture (MinIO-backed batch processing)
- 🔐 Enterprise SSO (any OIDC provider: Okta, Auth0, Keycloak, Azure AD)
- 📊 Prometheus metrics + Grafana dashboards
- 🌐 Air-gap ready (no external dependencies)
- 🗑️ Auto-cleanup (8-hour retention)

## Prerequisites

- Kubernetes 1.24+
- Helm 3.8+
- Persistent volume provisioner (for RWO volumes)
- Ingress controller (Contour HTTPProxy or nginx/traefik)
- (Optional) OIDC provider for enterprise authentication
- (Optional) LDAP/Active Directory for account lookups

## Air-Gap / Offline Installation

This chart supports **Distribution Tooling for Helm** for air-gap environments:

```bash
# Using Distribution Tooling for Helm (dt4h)
# See: https://github.com/vmware-labs/distribution-tooling-for-helm

# 1. Wrap the chart with all images
dt wrap oci://ghcr.io/kofadam/yossarian-go:0.13.8 \
  --output-dir ./wrapped-charts

# 2. Push to your air-gap registry
dt push ./wrapped-charts/yossarian-go-0.13.8.wrap.tgz \
  --to-registry your-registry.local

# 3. Install from air-gap registry
helm install yossarian oci://your-registry.local/yossarian-go \
  --version 0.13.8 \
  -n yossarian-go --create-namespace
```

**Images included:**
- `ghcr.io/kofadam/yossarian-go:v0.13.8` - Main application
- `ghcr.io/kofadam/yossarian-go-db-service:v0.12.3` - Database service
- `quay.io/minio/minio:RELEASE.2024-01-01T00-00-00Z` - Object storage
- `curlimages/curl:8.5.0` - CronJob utility

## Quick Start

```bash
# Install directly from GitHub Container Registry (OCI)
helm install yossarian oci://ghcr.io/kofadam/yossarian-go \
  --version 0.13.3 \
  --namespace yossarian-go \
  --create-namespace \
  --set ingress.host=yossarian.example.com \
  --set auth.adminPassword=your-secure-password
```

## Configuration

### Minimal Configuration (No OIDC, No LDAP)

```yaml
# minimal-values.yaml
ingress:
  host: yossarian.example.com

auth:
  adminPassword: "secure-password-here"
```

```bash
helm install yossarian oci://ghcr.io/kofadam/yossarian-go \
  --version 0.13.3 \
  -f minimal-values.yaml \
  -n yossarian-go --create-namespace
```

### Enterprise with Okta

```yaml
# okta-values.yaml
ingress:
  host: yossarian.company.com
  className: nginx  # or traefik, etc.
  useContourHTTPProxy: false  # Use standard Ingress

oidc:
  enabled: true
  issuerURL: "https://company.okta.com"
  clientID: "yossarian-client"
  clientSecret: "secret-from-okta"
  redirectURL: "https://yossarian.company.com/auth/oidc/callback"
  autoSSO: true
```

### Full Enterprise (OIDC + Active Directory)

```yaml
# enterprise-values.yaml
ingress:
  host: yossarian.company.com

oidc:
  enabled: true
  issuerURL: "https://keycloak.company.com/realms/main"
  clientID: "yossarian-go"
  clientSecret: "keycloak-secret"
  redirectURL: "https://yossarian.company.com/auth/oidc/callback"

ldap:
  enabled: true
  server: "ldaps://dc.company.com:636"
  bindDN: "CN=svc-yossarian,OU=Service,DC=company,DC=com"
  bindPassword: "ldap-password"
  searchBase: "DC=company,DC=com"

domain:
  netbios: "COMPANY"
  fqdn: "company.com"
```

## Certificate Configuration Guide

### When Do You Need Custom CA Certificates?

You need to provide custom CA certificates in two scenarios:

1. **OIDC/Keycloak with Self-Signed Certificates** - For authenticating users (frontend/worker)
2. **Active Directory with LDAPS** - For syncing AD accounts (database service)

**Important:** These are **separate certificates** used by **different components**:
- `customCA.certificate` → Used by frontend/worker for OIDC (`CA_CERT_PATH`)
- `ldap.caCert` → Used by database service for AD LDAPS (`DC_CA_CERT_PATH`)

### Extract OIDC Provider Certificate (Keycloak, Okta, etc.)

If your OIDC provider uses a self-signed certificate or internal CA:

```bash
# Extract certificate from OIDC server
openssl s_client -showcerts -connect keycloak.company.com:443 </dev/null 2>/dev/null | \
  openssl x509 -outform PEM > oidc-ca.pem

# Verify the certificate
openssl x509 -in oidc-ca.pem -text -noout | grep -E "Subject:|Issuer:|Not Before|Not After"

# View the certificate content (for values.yaml)
cat oidc-ca.pem
```

**values.yaml configuration:**
```yaml
customCA:
  enabled: true
  certificate: |
    -----BEGIN CERTIFICATE-----
    MIIDXTCCAkWgAwIBAgIJAKZ... (paste output from oidc-ca.pem)
    -----END CERTIFICATE-----

oidc:
  enabled: true
  issuerURL: "https://keycloak.company.com/realms/myrealm"
  clientID: "yossarian-go"
  clientSecret: "your-client-secret"
  redirectURL: "https://yossarian.company.com/auth/oidc/callback"
```

### Extract Active Directory LDAPS Certificate

For AD account synchronization over LDAPS (port 636):

```bash
# Extract certificate from Domain Controller
openssl s_client -showcerts -connect dc.company.com:636 </dev/null 2>/dev/null | \
  openssl x509 -outform PEM > dc-ca.pem

# Verify the certificate
openssl x509 -in dc-ca.pem -text -noout | grep -E "Subject:|Issuer:|Not Before|Not After"

# View the certificate content (for values.yaml)
cat dc-ca.pem
```

**values.yaml configuration:**
```yaml
ldap:
  enabled: true
  server: "ldaps://dc.company.com:636"
  bindDN: "CN=svc-yossarian,OU=Service,DC=company,DC=com"
  bindPassword: "your-ldap-password"
  searchBase: "DC=company,DC=com"
  caCert: |
    -----BEGIN CERTIFICATE-----
    MIIDXTCCAkWgAwIBAgIJAKZ... (paste output from dc-ca.pem)
    -----END CERTIFICATE-----

domain:
  netbios: "COMPANY"
  fqdn: "company.com"
```

### Using Both OIDC and LDAPS with Certificates

If you need both (full enterprise setup with self-signed certs):

```yaml
# Full enterprise with custom certificates
customCA:
  enabled: true
  certificate: |
    -----BEGIN CERTIFICATE-----
    [OIDC/Keycloak CA certificate]
    -----END CERTIFICATE-----

oidc:
  enabled: true
  issuerURL: "https://keycloak.company.com/realms/main"
  clientID: "yossarian-go"
  clientSecret: "keycloak-secret"
  redirectURL: "https://yossarian.company.com/auth/oidc/callback"

ldap:
  enabled: true
  server: "ldaps://dc.company.com:636"
  bindDN: "CN=svc-yossarian,OU=Service,DC=company,DC=com"
  bindPassword: "ad-password"
  searchBase: "DC=company,DC=com"
  caCert: |
    -----BEGIN CERTIFICATE-----
    [Active Directory CA certificate]
    -----END CERTIFICATE-----

domain:
  netbios: "COMPANY"
  fqdn: "company.com"
```

### Troubleshooting Certificate Issues

**OIDC certificate issues (frontend/worker):**
```bash
# Check if certificate is mounted correctly
kubectl exec -n yossarian-go deployment/yossarian-frontend -- \
  cat /etc/ssl/certs/ca-bundle.crt

# Check OIDC connection logs
kubectl logs -n yossarian-go deployment/yossarian-frontend | grep -i "oidc\|certificate\|tls"
```

**LDAPS certificate issues (database service):**
```bash
# Check if DC certificate is mounted correctly
kubectl exec -n yossarian-go deployment/yossarian-db-service -- \
  cat /etc/ssl/certs/ca-bundle.crt

# Test LDAPS connection manually
kubectl exec -n yossarian-go deployment/yossarian-db-service -- \
  curl -v telnet://dc.company.com:636

# Check LDAP sync logs
kubectl logs -n yossarian-go deployment/yossarian-db-service | grep -i "ldap\|certificate"
```

**Verify certificate validity:**
```bash
# Check certificate expiration
openssl x509 -in your-cert.pem -noout -dates

# Check certificate subject/issuer
openssl x509 -in your-cert.pem -noout -subject -issuer

# Test TLS connection to server
openssl s_client -connect dc.company.com:636 -CAfile dc-ca.pem </dev/null
```

## OIDC Provider Examples

### Okta
```yaml
oidc:
  issuerURL: "https://your-domain.okta.com"
```

### Auth0
```yaml
oidc:
  issuerURL: "https://your-domain.auth0.com"
```

### Keycloak
```yaml
oidc:
  issuerURL: "https://keycloak.company.com/realms/myrealm"
```

### Azure AD
```yaml
oidc:
  issuerURL: "https://login.microsoftonline.com/{tenant-id}/v2.0"
```

### Google
```yaml
oidc:
  issuerURL: "https://accounts.google.com"
```

## Storage Configuration

```yaml
persistence:
  minio:
    size: 100Gi
    storageClass: "fast-ssd"  # Optional
  
  database:
    size: 5Gi
  
  worker:
    size: 50Gi
```

## Resource Limits

```yaml
frontend:
  replicas: 3
  resources:
    requests:
      cpu: 250m
      memory: 512Mi
    limits:
      cpu: 1000m
      memory: 2Gi

worker:
  replicas: 1  # Must be 1
  resources:
    requests:
      cpu: 250m
      memory: 512Mi
    limits:
      cpu: 1000m
      memory: 2Gi
```

## Upgrading

```bash
helm upgrade yossarian oci://ghcr.io/kofadam/yossarian-go \
  --version 0.13.3 \
  -n yossarian-go \
  -f custom-values.yaml
```

## Uninstall

```bash
helm uninstall yossarian -n yossarian-go

# Optionally delete PVCs
kubectl delete pvc -n yossarian-go -l app.kubernetes.io/instance=yossarian
```

## Values

| Parameter | Description | Default |
|-----------|-------------|---------|
| `ingress.enabled` | Enable ingress | `true` |
| `ingress.host` | Ingress hostname | `yossarian.example.com` |
| `ingress.useContourHTTPProxy` | Use Contour HTTPProxy instead of standard Ingress | `true` |
| `auth.adminPassword` | Admin password (if OIDC disabled) | `changeme` |
| `oidc.enabled` | Enable OIDC authentication | `false` |
| `oidc.issuerURL` | OIDC provider URL | `""` |
| `ldap.enabled` | Enable LDAP/AD integration | `false` |
| `persistence.minio.size` | MinIO storage size | `100Gi` |
| `persistence.worker.size` | Worker storage size | `50Gi` |
| `frontend.replicas` | Frontend pod count | `3` |
| `worker.replicas` | Worker pod count (must be 1) | `1` |

See [values.yaml](values.yaml) for all available options.

## Troubleshooting

### Check worker logs
```bash
kubectl logs -n yossarian-go deployment/yossarian-worker
```

### Verify MinIO connectivity
```bash
kubectl exec -n yossarian-go deployment/yossarian-worker -- \
  curl http://yossarian-minio:9000/minio/health/live
```

### Test OIDC connection
```bash
kubectl logs -n yossarian-go deployment/yossarian-frontend | grep OIDC
```

### Trigger manual AD sync
```bash
kubectl create job --from=cronjob/yossarian-ad-sync manual-sync-$(date +%s) -n yossarian-go
```

## Monitoring & Observability

### Prometheus Metrics

Enable Prometheus metrics collection:

```yaml
metrics:
  enabled: true
  serviceMonitor:
    enabled: true
    interval: 30s
    # Add labels for Prometheus discovery
    additionalLabels:
      prometheus: kube-prometheus
```

**Exposed metrics:**
- `yossarian_http_requests_total` - HTTP request counter by endpoint/status
- `yossarian_upload_size_bytes` - File upload size histogram
- `yossarian_processing_duration_seconds` - Processing time by operation
- `yossarian_patterns_detected_total` - Patterns detected by type
- `yossarian_ad_cache_hits_total` / `yossarian_ad_cache_misses_total` - Cache performance
- `yossarian_active_sessions` - Active user sessions gauge

**Metrics endpoints:**
- Frontend: `http://yossarian-frontend:8080/metrics`
- Worker: `http://yossarian-worker:8080/metrics`
- Database: `http://yossarian-db-service:8081/health`

### Grafana Dashboards

Two pre-built Grafana dashboards are available in the project repository:

1. **Yossarian Overview** - High-level operational metrics
   - Queue depth, jobs completed, active sessions
   - Job processing rates and durations (P50/P95/P99)
   - Pattern detection rates
   - AD cache hit ratio

2. **Yossarian Worker Details** - Deep dive into batch processing
   - Worker health (memory/CPU)
   - Batch job processing metrics
   - MinIO operations
   - Pattern detection by type
   - AD cache performance

**Import dashboards:**

```bash
# Via Grafana Web UI
# New → Import → Upload JSON file

# Via Grafana API
curl -X POST http://grafana:3000/api/dashboards/db \
  -H "Authorization: Bearer <your-token>" \
  -H "Content-Type: application/json" \
  -d @yossarian-overview-dashboard.json

# Via Kubernetes ConfigMap (if using grafana-sidecar)
kubectl create configmap yossarian-dashboards \
  --from-file=yossarian-overview-dashboard.json \
  --from-file=yossarian-worker-details-dashboard.json \
  -n monitoring
kubectl label configmap yossarian-dashboards grafana_dashboard=1 -n monitoring
```

**Dashboard JSON files available at:**
- https://github.com/kofadam/yossarian-go/tree/main/grafana-dashboards

### Alert Rules (Example)

```yaml
# Example PrometheusRule for alerting
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: yossarian-alerts
spec:
  groups:
    - name: yossarian
      interval: 30s
      rules:
        - alert: YossarianQueueBacklog
          expr: yossarian_batch_jobs_queued > 10
          for: 5m
          annotations:
            summary: "Batch job queue backlog detected"
            description: "{{ $value }} jobs queued for >5 minutes"
        
        - alert: YossarianHighMemoryUsage
          expr: container_memory_usage_bytes{pod=~"yossarian-worker.*"} > 1.5e9
          for: 5m
          annotations:
            summary: "Worker memory usage high"
            description: "Worker using {{ $value | humanize }}B of memory"
        
        - alert: YossarianADCacheLow
          expr: rate(yossarian_ad_cache_hits_total[5m]) / (rate(yossarian_ad_cache_hits_total[5m]) + rate(yossarian_ad_cache_misses_total[5m])) < 0.8
          for: 10m
          annotations:
            summary: "AD cache hit rate below 80%"
```

## Support

- **Issues**: [GitHub Issues](https://github.com/kofadam/yossarian-go/issues)
- **Documentation**: [https://github.com/kofadam/yossarian-go](https://github.com/kofadam/yossarian-go)
- **License**: MIT
