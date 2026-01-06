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

## Support

- **Issues**: [GitHub Issues](https://github.com/kofadam/yossarian-go/issues)
- **Documentation**: [https://github.com/kofadam/yossarian-go](https://github.com/kofadam/yossarian-go)
- **License**: MIT
