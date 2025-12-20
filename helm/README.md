# Yossarian Go Helm Chart

Enterprise-grade log sanitization system with batch processing support.

## Overview

This Helm chart deploys Yossarian Go v0.10.0+ with:
- Main application (2-3 replicas)
- Database service (SQLite + HTTP API)
- Batch job processing with PVC storage
- OIDC/SSO authentication
- LDAP/Active Directory integration
- Automated AD synchronization
- Prometheus metrics
- TLS/HTTPS via Contour HTTPProxy

## Prerequisites

- Kubernetes 1.19+
- Helm 3.0+
- PersistentVolume support (for database and batch jobs)
- Contour ingress controller
- cert-manager (optional, for TLS)
- Keycloak or compatible OIDC provider
- Active Directory / LDAP server

## Quick Start

### 1. Clone Repository
```bash
git clone https://github.com/kofadam/yossarian-go.git
cd yossarian-go/helm
```

### 2. Create Namespace
```bash
kubectl create namespace yossarian-go
```

### 3. Configure Values
Edit `values.yaml` or create `values-custom.yaml`:

```yaml
# Minimal required configuration
config:
  oidc:
    issuerUrl: "https://your-keycloak.com/auth/realms/your-realm"
    clientId: "yossarian-go"
    redirectUrl: "https://yossarian.yourdomain.com/auth/oidc/callback"
  
  ldap:
    server: "ldaps://your-dc.company.com:636"
    bindDn: "CN=service-account,OU=Services,DC=company,DC=com"
    searchBase: "DC=company,DC=com"

secrets:
  adminPassword: "your-secure-password"
  oidcClientSecret: "your-oidc-secret"
  ldapBindPassword: "your-ldap-password"

ingress:
  fqdn: "yossarian.yourdomain.com"
```

### 4. Install Chart
```bash
# Development
helm install yossarian . -f values.yaml

# Production
helm install yossarian . -f values-prod.yaml
```

### 5. Access Application
```bash
# Get the URL
helm status yossarian

# Or port-forward for testing
kubectl port-forward -n yossarian-go svc/yossarian-service 8080:80
```

## Configuration

### Core Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `global.namespace` | Kubernetes namespace | `yossarian-go` |
| `global.environment` | Environment name | `development` |
| `image.app.repository` | Main app image | `ghcr.io/kofadam/yossarian-go` |
| `image.app.tag` | App version | `v0.10.0` |
| `image.dbService.repository` | DB service image | `ghcr.io/kofadam/yossarian-go-db-service` |
| `image.dbService.tag` | DB service version | `v0.10.0` |

### Replicas

| Parameter | Description | Default |
|-----------|-------------|---------|
| `replicaCount.app` | Main app replicas | `2` |
| `replicaCount.dbService` | DB service replicas | `1` |

### Storage

| Parameter | Description | Default |
|-----------|-------------|---------|
| `storage.database.enabled` | Enable database PVC | `true` |
| `storage.database.size` | Database PVC size | `5Gi` |
| `storage.batchJobs.enabled` | Enable batch jobs PVC | `true` |
| `storage.batchJobs.size` | Batch jobs PVC size | `100Gi` |

### OIDC Configuration

| Parameter | Description | Required |
|-----------|-------------|----------|
| `config.oidc.enabled` | Enable OIDC auth | Yes |
| `config.oidc.issuerUrl` | OIDC issuer URL | Yes |
| `config.oidc.clientId` | OIDC client ID | Yes |
| `config.oidc.redirectUrl` | OAuth2 callback URL | Yes |
| `secrets.oidcClientSecret` | OIDC client secret | Yes |

### LDAP Configuration

| Parameter | Description | Required |
|-----------|-------------|----------|
| `config.ldap.server` | LDAP server URL | Yes |
| `config.ldap.bindDn` | Bind DN | Yes |
| `config.ldap.searchBase` | Search base DN | Yes |
| `secrets.ldapBindPassword` | LDAP password | Yes |

### File Upload Limits

| Parameter | Description | Default |
|-----------|-------------|---------|
| `config.maxTotalUploadSizeMB` | Max total upload | `100` |
| `config.maxFileSizeMB` | Max single file | `50` |
| `config.maxZipFileSizeMB` | Max file in ZIP | `10` |
| `config.maxFileCount` | Max file count | `10` |

## Advanced Usage

### Using External Secrets

Instead of storing secrets in values.yaml:

```bash
# Create secret manually
kubectl create secret generic yossarian-secrets \
  --from-literal=ADMIN_PASSWORD=xxx \
  --from-literal=OIDC_CLIENT_SECRET=xxx \
  --from-literal=LDAP_BIND_PASSWORD=xxx \
  -n yossarian-go

# Then disable secret creation in values.yaml
# and reference external secret in deployments
```

### Custom CA Certificate

```yaml
customCA:
  enabled: true
  certificate: |
    -----BEGIN CERTIFICATE-----
    MIIDXTCCAkWgAwIBAgIJAKJ...
    -----END CERTIFICATE-----
```

### Resource Limits

```yaml
resources:
  app:
    requests:
      memory: "1Gi"
      cpu: "500m"
    limits:
      memory: "4Gi"
      cpu: "2000m"
```

### Node Affinity

```yaml
nodeSelector:
  workload-type: application

affinity:
  podAntiAffinity:
    preferredDuringSchedulingIgnoredDuringExecution:
      - weight: 100
        podAffinityTerm:
          labelSelector:
            matchExpressions:
              - key: app.kubernetes.io/name
                operator: In
                values:
                  - yossarian-go
          topologyKey: kubernetes.io/hostname
```

## Operations

### Upgrade

```bash
# Upgrade to new version
helm upgrade yossarian . --set image.app.tag=v0.10.1

# With custom values
helm upgrade yossarian . -f values-prod.yaml
```

### Rollback

```bash
helm rollback yossarian
```

### Uninstall

```bash
helm uninstall yossarian

# Clean up PVCs (optional - will delete data!)
kubectl delete pvc -n yossarian-go yossarian-db-pvc yossarian-batch-pvc
```

### Backup

```bash
# Backup database PVC
kubectl exec -n yossarian-go deployment/yossarian-db \
  -- tar czf - /data > yossarian-db-backup-$(date +%Y%m%d).tar.gz

# Backup batch jobs PVC
kubectl exec -n yossarian-go deployment/yossarian \
  -- tar czf - /data/jobs > yossarian-jobs-backup-$(date +%Y%m%d).tar.gz
```

### Monitoring

```bash
# View Prometheus metrics
kubectl port-forward -n yossarian-go svc/yossarian-service 8080:80
curl http://localhost:8080/metrics

# View logs
kubectl logs -n yossarian-go -l app.kubernetes.io/name=yossarian-go --tail=100 -f
```

## Troubleshooting

### Pods Not Starting

```bash
# Check pod status
kubectl get pods -n yossarian-go

# View pod events
kubectl describe pod -n yossarian-go <pod-name>

# Check logs
kubectl logs -n yossarian-go <pod-name>
```

### PVC Issues

```bash
# Check PVC status
kubectl get pvc -n yossarian-go

# Check PV
kubectl get pv

# Fix permissions
kubectl exec -n yossarian-go deployment/yossarian -- chmod -R 755 /data
```

### OIDC Authentication Failing

```bash
# Test OIDC issuer URL
curl https://your-keycloak.com/auth/realms/your-realm/.well-known/openid-configuration

# Check logs for auth errors
kubectl logs -n yossarian-go -l app.kubernetes.io/name=yossarian-go | grep OIDC
```

### LDAP Connection Issues

```bash
# Test LDAP from pod
kubectl exec -n yossarian-go deployment/yossarian-db -- \
  curl http://localhost:8081/ldap/test

# Check LDAP logs
kubectl logs -n yossarian-go -l app.kubernetes.io/component=database | grep LDAP
```

### Batch Jobs Not Processing

```bash
# Check batch storage
kubectl exec -n yossarian-go deployment/yossarian -- ls -la /data/jobs

# Check background processor logs
kubectl logs -n yossarian-go -l app.kubernetes.io/name=yossarian-go | grep BATCH

# Manually trigger job (if needed)
kubectl exec -n yossarian-go deployment/yossarian -- \
  ls /data/jobs/<username>/<job-id>/
```

## Security Considerations

1. **Change Default Passwords**: Always change default admin password in production
2. **Use External Secrets**: Consider using Vault, Sealed Secrets, or External Secrets Operator
3. **Enable Network Policies**: Restrict pod-to-pod communication
4. **Regular Updates**: Keep images up-to-date with security patches
5. **Audit Logs**: Enable and monitor audit logging
6. **TLS Everywhere**: Ensure TLS is enabled for all external access
7. **RBAC**: Implement proper RBAC policies

## Support

- GitHub Issues: https://github.com/kofadam/yossarian-go/issues
- Documentation: https://github.com/kofadam/yossarian-go/blob/main/README.md

## License

[Your License Here]
