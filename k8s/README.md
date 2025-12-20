# Yossarian Go v0.10.0 - Fixed YAML Deployment Files

## 🎯 Overview

These corrected YAML files fix issues from the original deployment and add **batch processing support (v0.10.0)**.

## ✅ Issues Fixed

| Issue | Before | After |
|-------|--------|-------|
| **Service Name** | `yossarian-service` | `yossarian-go-service` (consistent) |
| **LDAP Password** | ❌ Missing | ✅ Added to secrets |
| **CA Cert Path** | `dc-ca-bundle.crt` | `ca-bundle.crt` (consistent) |
| **DB Storage** | 1Gi | 5Gi (room for batch metadata) |
| **Batch Storage** | ❌ None | ✅ 100Gi PVC at `/data/jobs` |
| **App Resources** | 256Mi/512Mi | 512Mi/2Gi (for batch processing) |

## 📦 What's New in v0.10.0

### Batch Processing Features
- ✅ **100GB PVC** for batch job storage
- ✅ **Background processor** for async ZIP processing
- ✅ **Job tracking** with status API
- ✅ **"My Jobs" page** for users
- ✅ **Handles 300+ file ZIPs** easily

### Architecture Changes
```
/data/
├── yossarian.db           # SQLite database (on yossarian-db-pvc)
└── jobs/                  # Batch job storage (on yossarian-batch-pvc)
    └── {username}/
        └── batch-{timestamp}/
            ├── input.zip
            └── output/
                └── sanitized.zip
```

## 🚀 Deployment Instructions

### Prerequisites
- Kubernetes 1.19+
- StorageClass configured (e.g., `default`)
- Contour ingress controller
- cert-manager (optional, for TLS)
- Keycloak or OIDC provider
- Active Directory / LDAP server

### Step 1: Update Configuration

#### Edit `02-configmap.yaml`:
```yaml
# Update these values for your environment:
OIDC_ISSUER_URL: "https://YOUR-KEYCLOAK.com/auth/realms/YOUR-REALM"
OIDC_CLIENT_ID: "yossarian-go"
OIDC_REDIRECT_URL: "https://YOUR-DOMAIN.com/auth/oidc/callback"
LDAP_SERVER: "ldaps://YOUR-DC.com:636"
LDAP_BIND_DN: "CN=YOUR-SERVICE-ACCOUNT,OU=Services,DC=company,DC=com"
LDAP_SEARCH_BASE: "DC=company,DC=com"
DOMAIN_NETBIOS: "YOUR-DOMAIN"
DOMAIN_FQDN: "company.com"
```

#### Edit `03-secrets.yaml`:
```bash
# Generate base64 encoded secrets:
echo -n "your-admin-password" | base64
echo -n "your-oidc-client-secret" | base64
echo -n "your-ldap-bind-password" | base64

# Update the values in 03-secrets.yaml
```

#### Edit `04-ca-bundle-configmap.yaml`:
```bash
# Get your CA certificate:
echo | openssl s_client -connect YOUR-KEYCLOAK.com:443 -showcerts 2>/dev/null | openssl x509 -outform PEM

# Paste it into the configmap
```

#### Edit `08-httpproxy.yaml`:
```yaml
# Update domain:
fqdn: yossarian.YOUR-DOMAIN.com
```

#### Edit `09-certificate.yaml`:
```yaml
# Update issuer and domain:
issuerRef:
  name: YOUR-CLUSTER-ISSUER
dnsNames:
- yossarian.YOUR-DOMAIN.com
```

### Step 2: Deploy

```bash
# Apply in order (numbered files):
kubectl apply -f 01-namespace.yaml
kubectl apply -f 02-configmap.yaml
kubectl apply -f 03-secrets.yaml
kubectl apply -f 04-ca-bundle-configmap.yaml
kubectl apply -f 05-pvcs.yaml
kubectl apply -f 06-db-service-deployment.yaml
kubectl apply -f 07-app-deployment.yaml
kubectl apply -f 08-httpproxy.yaml
kubectl apply -f 09-certificate.yaml
kubectl apply -f 10-cronjob-ad-sync.yaml

# Or apply all at once:
kubectl apply -f .
```

### Step 3: Verify Deployment

```bash
# Check all resources
kubectl get all -n yossarian-go

# Check PVCs (should see 2 PVCs)
kubectl get pvc -n yossarian-go
# Expected:
# yossarian-db-pvc      Bound   5Gi
# yossarian-batch-pvc   Bound   100Gi

# Check pods are running
kubectl get pods -n yossarian-go
# Expected:
# yossarian-go-xxxxx              1/1   Running
# yossarian-db-service-xxxxx      1/1   Running

# Check logs
kubectl logs -n yossarian-go -l app=yossarian-go --tail=50
kubectl logs -n yossarian-go -l app=yossarian-db-service --tail=50

# Look for:
# - [BATCH] Background processor initialized ✅
# - Server starting on port 8080 ✅
# - Database service starting on port 8081 ✅
```

### Step 4: Test

```bash
# Access via ingress
https://yossarian.YOUR-DOMAIN.com

# Or port-forward for testing
kubectl port-forward -n yossarian-go svc/yossarian-go-service 8080:80

# Test health
curl http://localhost:8080/health
curl http://localhost:8081/health  # (requires separate port-forward)

# Test online mode (small file)
echo "Test from 192.168.1.1" > test.log
curl -F "file=@test.log" http://localhost:8080/upload

# Test batch mode (ZIP file)
zip test.zip test.log
curl -F "file=@test.zip" http://localhost:8080/upload
# Should return: {"status": "batch_queued", "job_id": "..."}
```

## 🔄 Upgrading from Previous Version

### If Upgrading from v0.9.x to v0.10.0:

```bash
# 1. Update images in deployment files
# Already updated to v0.10.0 in these files

# 2. Create new batch PVC
kubectl apply -f 05-pvcs.yaml

# 3. Update deployments (will restart pods)
kubectl apply -f 06-db-service-deployment.yaml
kubectl apply -f 07-app-deployment.yaml

# 4. Verify batch storage mounted
kubectl exec -n yossarian-go deployment/yossarian-go -- ls -la /data/jobs

# 5. Update configmap and secrets if needed
kubectl apply -f 02-configmap.yaml
kubectl apply -f 03-secrets.yaml

# 6. Restart pods to pick up changes
kubectl rollout restart deployment/yossarian-go -n yossarian-go
kubectl rollout restart deployment/yossarian-db-service -n yossarian-go
```

### If You Already Have Running Deployment:

```bash
# Option 1: Replace resources (careful - will restart pods)
kubectl replace -f .

# Option 2: Apply changes (safer - incremental updates)
kubectl apply -f .

# Option 3: Delete and recreate (cleanest - causes downtime)
kubectl delete namespace yossarian-go
kubectl apply -f .
```

## 🗂️ File Order & Purpose

| File | Purpose | Required |
|------|---------|----------|
| `01-namespace.yaml` | Creates namespace | ✅ |
| `02-configmap.yaml` | App configuration | ✅ |
| `03-secrets.yaml` | Passwords & secrets | ✅ |
| `04-ca-bundle-configmap.yaml` | Custom CA certs | Optional |
| `05-pvcs.yaml` | Storage (DB + Batch) | ✅ |
| `06-db-service-deployment.yaml` | Database service | ✅ |
| `07-app-deployment.yaml` | Main application | ✅ |
| `08-httpproxy.yaml` | Ingress (Contour) | Optional |
| `09-certificate.yaml` | TLS cert | Optional |
| `10-cronjob-ad-sync.yaml` | Daily AD sync | Optional |

## 🔍 Troubleshooting

### PVCs Not Binding
```bash
# Check if storageclass exists
kubectl get storageclass

# If using different storageclass, update in 05-pvcs.yaml:
storageClassName: your-storage-class-name
```

### Pods Not Starting
```bash
# Check events
kubectl get events -n yossarian-go --sort-by='.lastTimestamp'

# Describe pod
kubectl describe pod -n yossarian-go <pod-name>

# Check logs
kubectl logs -n yossarian-go <pod-name>
```

### Image Pull Failures
```bash
# If using private registry, create imagePullSecret:
kubectl create secret docker-registry ghcr-secret \
  --docker-server=ghcr.io \
  --docker-username=YOUR-USERNAME \
  --docker-password=YOUR-TOKEN \
  -n yossarian-go

# Add to deployments:
spec:
  template:
    spec:
      imagePullSecrets:
      - name: ghcr-secret
```

### Batch Jobs Not Processing
```bash
# Check batch storage exists
kubectl exec -n yossarian-go deployment/yossarian-go -- ls -la /data/jobs

# Check background processor
kubectl logs -n yossarian-go -l app=yossarian-go | grep BATCH

# Check job status
kubectl exec -n yossarian-go deployment/yossarian-db-service -- \
  curl http://localhost:8081/jobs/list/USERNAME
```

## 📊 Resource Requirements

### Minimum (Development)
- **App Pods**: 512Mi RAM, 250m CPU
- **DB Service**: 128Mi RAM, 100m CPU
- **Storage**: 5Gi (DB) + 10Gi (Batch)

### Recommended (Production)
- **App Pods**: 2Gi RAM, 1 CPU (for batch processing)
- **DB Service**: 512Mi RAM, 200m CPU
- **Storage**: 10Gi (DB) + 100-200Gi (Batch)

## 🔐 Security Notes

1. **Change default passwords** in `03-secrets.yaml`
2. **Use proper secrets management** (Vault, Sealed Secrets, etc.)
3. **Keep images updated** for security patches
4. **Enable network policies** if required
5. **Review RBAC** if needed

## 📚 Additional Resources

- **Main Repository**: https://github.com/kofadam/yossarian-go
- **Helm Chart**: Use the provided Helm chart for easier deployment
- **Documentation**: See project README.md

## 🆘 Support

For issues or questions:
- GitHub Issues: https://github.com/kofadam/yossarian-go/issues
- Check logs: `kubectl logs -n yossarian-go -l app=yossarian-go`
