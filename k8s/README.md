# Yossarian Go - Kubernetes Deployment Guide

Enterprise log sanitization system with MinIO-backed batch processing for Kubernetes.

**Version:** v0.13.3+ (Split Architecture)

---

## 📋 Prerequisites

### Required

- **Kubernetes cluster** (1.27+)
- **kubectl** configured and connected to your cluster
- **Storage**: Default StorageClass configured OR ability to specify custom StorageClass
- **Ingress controller**: EITHER Contour (HTTPProxy) OR Nginx/Traefik (Ingress)

### Optional

- **cert-manager** (for automatic TLS certificates)
- **OIDC provider** (Keycloak/Auth0/Azure AD) for multi-user mode
- **LDAP/Active Directory** for AD account sanitization

---

## 🚀 Quick Start (Local Testing)

**Get up and running in 2 minutes** with minimal configuration:

```bash
# 1. Apply quickstart configuration
kubectl apply -f 00-quickstart-local.yaml

# 2. Wait for pods to be ready
kubectl wait --for=condition=ready pod -l app=yossarian -n yossarian-go --timeout=120s

# 3. Access the application
# For minikube/kind:
kubectl port-forward -n yossarian-go svc/yossarian-frontend-local 8080:8080

# For cloud providers with NodePort support:
# Access at: http://<node-ip>:30080
```

**Default credentials:**
- Username: `Administrator`
- Password: `Yossarian123`

**What this includes:**
- ✅ Single-user mode (password authentication)
- ✅ No OIDC/SSO required
- ✅ No TLS/ingress (direct NodePort access)
- ✅ Non-persistent storage (emptyDir)
- ⚠️ **NOT for production** - Data will be lost on pod restart

---

## 🏗️ Production Deployment

### Step 1: Clone and Prepare

```bash
# Download manifests
git clone https://github.com/kofadam/yossarian-go.git
cd yossarian-go/k8s
```

### Step 2: Configure Secrets (REQUIRED)

Edit `03-secrets.yaml`:

```bash
# CRITICAL: Change default passwords!
vi 03-secrets.yaml
```

**Minimum required changes:**
```yaml
stringData:
  ADMIN_PASSWORD: "YourSecurePassword123!"  # CHANGE THIS
  LDAP_BIND_PASSWORD: "changeme"            # Only if using LDAP
  OIDC_CLIENT_SECRET: "changeme"            # Only if using OIDC
```

For MinIO password, edit `minio-secret`:
```yaml
stringData:
  password: "YourSecureMinIOPassword123!"  # CHANGE THIS
```

### Step 3: Configure Storage (if needed)

**If your cluster does NOT have a default StorageClass:**

Edit `04-pvcs.yaml` and specify your StorageClass:

```yaml
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 5Gi
  storageClassName: standard  # UNCOMMENT and set your StorageClass
```

Also edit `05-minio.yaml` line 74:

```yaml
volumeClaimTemplates:
  - metadata:
      name: data
    spec:
      storageClassName: standard  # UNCOMMENT and set your StorageClass
```

**Check available StorageClasses:**
```bash
kubectl get storageclass
```

### Step 4: Choose Authentication Mode

#### Option A: Single-User Mode (Default)

**For:** Local testing, single-administrator deployments

**Configuration:** Already set in `02-configmaps.yaml`:
```yaml
OIDC_ENABLED: "false"
```

**Credentials:** Set in `03-secrets.yaml`:
```yaml
ADMIN_PASSWORD: "Yossarian123"  # Change this!
```

**Access:** Login with username `Administrator` + your password

---

#### Option B: Multi-User Mode (OIDC/SSO)

**For:** Enterprise deployments with multiple users

**Prerequisites:**
- OIDC provider (Keycloak/Auth0/Azure AD/Google) configured
- Client ID and secret obtained
- Redirect URL registered: `https://yossarian-go.yourdomain.com/auth/oidc/callback`

**Configuration:** Edit `02-configmaps.yaml`:

```yaml
# Enable OIDC
OIDC_ENABLED: "true"

# Configure your OIDC provider
OIDC_CLIENT_ID: "yossarian-go"
OIDC_ISSUER_URL: "https://keycloak.example.com/realms/your-realm"
OIDC_REDIRECT_URL: "https://yossarian-go.example.com/auth/oidc/callback"
OIDC_LOGOUT_URL: "https://keycloak.example.com/realms/your-realm/protocol/openid-connect/logout"
AUTO_SSO_ENABLED: "true"
```

**And set client secret in `03-secrets.yaml`:**
```yaml
OIDC_CLIENT_SECRET: "your-client-secret-from-keycloak"
```

### Step 5: Choose Ingress Method

You must choose **EITHER** HTTPProxy (Contour) OR Ingress (Nginx/Traefik).

#### Option A: HTTPProxy (Contour)

**Use if:** Your cluster has Contour ingress controller

**Files needed:**
- `09b-httpproxy.yaml` - Ingress routing
- `10-certificate-certmanager.yaml` - TLS certificate (optional)

**Configure:**

1. Edit `09b-httpproxy.yaml`:
```yaml
spec:
  virtualhost:
    fqdn: yossarian-go.example.com  # CHANGE to your domain
```

2. **For TLS**, choose one of:

   **Option 1: cert-manager (recommended)**
   ```bash
   # Edit 10-certificate-certmanager.yaml
   vi 10-certificate-certmanager.yaml
   
   # Change:
   issuerRef:
     name: letsencrypt-prod  # Your ClusterIssuer name
   dnsNames:
     - yossarian-go.example.com  # Your domain
   ```

   **Option 2: Manual certificate**
   ```bash
   kubectl create secret tls yossarian-go-tls \
     --cert=path/to/tls.crt \
     --key=path/to/tls.key \
     -n yossarian-go
   ```

---

#### Option B: Standard Ingress (Nginx/Traefik)

**Use if:** Your cluster has Nginx, Traefik, or other standard ingress controller

**Files needed:**
- `09a-ingress.yaml` - Ingress routing
- `10-certificate-certmanager.yaml` - TLS certificate (optional)

**Configure:**

1. Edit `09a-ingress.yaml`:
```yaml
spec:
  ingressClassName: nginx  # Change to your ingress class
  tls:
    - hosts:
        - yossarian-go.example.com  # CHANGE to your domain
  rules:
    - host: yossarian-go.example.com  # CHANGE to your domain
```

2. **For automatic TLS via cert-manager:**
```yaml
metadata:
  annotations:
    cert-manager.io/cluster-issuer: "letsencrypt-prod"  # Your ClusterIssuer
```

3. **Or create manual certificate** (same as HTTPProxy Option 2 above)

### Step 6: Deploy

**Deploy in order:**

```bash
# 1. Namespace and base resources
kubectl apply -f 01-namespace.yaml
kubectl apply -f 02-configmaps.yaml
kubectl apply -f 03-secrets.yaml
kubectl apply -f 04-pvcs.yaml

# 2. Storage and databases
kubectl apply -f 05-minio.yaml
kubectl apply -f 06-db-service.yaml

# 3. Application services
kubectl apply -f 07-frontend.yaml
kubectl apply -f 08-worker.yaml

# 4. Ingress (choose ONE)
kubectl apply -f 09a-ingress.yaml      # For Nginx/Traefik
# OR
kubectl apply -f 09b-httpproxy.yaml    # For Contour

# 5. TLS certificate (optional)
kubectl apply -f 10-certificate-certmanager.yaml

# 6. Scheduled tasks (optional - for AD sync)
kubectl apply -f 11-cronjob-ad-sync.yaml
```

**Or apply all at once:**
```bash
# For standard Ingress:
kubectl apply -f 01-namespace.yaml,02-configmaps.yaml,03-secrets.yaml,04-pvcs.yaml,05-minio.yaml,06-db-service.yaml,07-frontend.yaml,08-worker.yaml,09a-ingress.yaml

# For HTTPProxy:
kubectl apply -f 01-namespace.yaml,02-configmaps.yaml,03-secrets.yaml,04-pvcs.yaml,05-minio.yaml,06-db-service.yaml,07-frontend.yaml,08-worker.yaml,09b-httpproxy.yaml
```

### Step 7: Verify Deployment

```bash
# Check all pods are running
kubectl get pods -n yossarian-go

# Expected output:
# NAME                                    READY   STATUS    RESTARTS
# minio-0                                 1/1     Running   0
# yossarian-db-service-xxx                1/1     Running   0
# yossarian-frontend-xxx                  1/1     Running   0
# yossarian-worker-xxx                    1/1     Running   0

# Check services
kubectl get svc -n yossarian-go

# Check ingress/httpproxy
kubectl get ingress -n yossarian-go      # For Ingress
kubectl get httpproxy -n yossarian-go    # For HTTPProxy

# Check TLS certificate (if using cert-manager)
kubectl get certificate -n yossarian-go
kubectl describe certificate yossarian-go-tls -n yossarian-go
```

### Step 8: Access Application

**Via Ingress/HTTPProxy:**
```
https://yossarian-go.example.com
```

**Via Port Forward (testing):**
```bash
kubectl port-forward -n yossarian-go svc/yossarian-frontend 8080:8080
# Access at: http://localhost:8080
```

**Default credentials (single-user mode):**
- Username: `Administrator`
- Password: `Yossarian123` (or your changed password)

---

## ⚙️ Optional: LDAP/AD Integration

**Purpose:** Enables sanitization of Active Directory usernames to USN tokens (e.g., `CORP\john.doe` → `USN123456789`)

**Prerequisites:**
- Active Directory server accessible from Kubernetes
- Service account with read access to AD
- LDAPS (port 636) or StartTLS enabled

**Configuration:**

1. **Get your DC CA certificate:**
```bash
echo | openssl s_client -connect dc01.example.com:636 -showcerts 2>/dev/null | \
  sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/p' > dc-ca.crt
```

2. **Edit `02-configmaps.yaml`:**
```yaml
# Uncomment and configure:
LDAP_SERVER: "ldaps://dc01.example.com:636"
LDAP_BIND_DN: "CN=svc-yossarian,DC=example,DC=com"
LDAP_SEARCH_BASE: "DC=example,DC=com"
DOMAIN_NETBIOS: "CORP"
DOMAIN_FQDN: "example.com"
```

3. **Add CA certificate to `02-configmaps.yaml`:**
```yaml
data:
  ca-bundle.crt: |
    -----BEGIN CERTIFICATE-----
    [Your DC CA certificate here]
    -----END CERTIFICATE-----
```

4. **Set bind password in `03-secrets.yaml`:**
```yaml
LDAP_BIND_PASSWORD: "your-service-account-password"
```

5. **Deploy and test:**
```bash
kubectl apply -f 02-configmaps.yaml,03-secrets.yaml
kubectl rollout restart deployment -n yossarian-go

# Test LDAP connection
kubectl exec -n yossarian-go deployment/yossarian-db-service -- \
  wget -qO- http://localhost:8081/ldap/test
```

6. **Trigger manual sync:**
```bash
kubectl exec -n yossarian-go deployment/yossarian-db-service -- \
  wget -qO- --post-data='' http://localhost:8081/ldap/sync-full
```

**Automatic daily sync** is configured via CronJob (`11-cronjob-ad-sync.yaml`)

---

## 🔍 Troubleshooting

### Pods Not Starting

```bash
# Check pod status
kubectl get pods -n yossarian-go

# View pod events
kubectl describe pod <pod-name> -n yossarian-go

# Check logs
kubectl logs -n yossarian-go deployment/yossarian-frontend
kubectl logs -n yossarian-go deployment/yossarian-worker
kubectl logs -n yossarian-go deployment/yossarian-db-service
```

### PVC Stuck in Pending

**Cause:** No default StorageClass or StorageClass not found

**Solution:**
```bash
# Check available StorageClasses
kubectl get storageclass

# Edit PVCs and specify StorageClass
vi 04-pvcs.yaml
vi 05-minio.yaml  # Line 74
```

### TLS Certificate Not Working

**For cert-manager:**
```bash
# Check certificate status
kubectl describe certificate yossarian-go-tls -n yossarian-go

# Check cert-manager logs
kubectl logs -n cert-manager deployment/cert-manager

# Check ACME challenge
kubectl get challenges -n yossarian-go
```

### OIDC Login Failing

1. **Verify OIDC configuration:**
```bash
kubectl get configmap yossarian-go-config -n yossarian-go -o yaml | grep OIDC
```

2. **Check redirect URL is registered in OIDC provider**

3. **Verify client secret:**
```bash
kubectl get secret yossarian-go-secrets -n yossarian-go -o yaml
```

4. **Check frontend logs:**
```bash
kubectl logs -n yossarian-go deployment/yossarian-frontend | grep OIDC
```

### Batch Jobs Not Processing

1. **Check worker is running:**
```bash
kubectl get pods -n yossarian-go -l mode=worker
```

2. **Check worker logs:**
```bash
kubectl logs -n yossarian-go deployment/yossarian-worker -f
```

3. **Check MinIO connectivity:**
```bash
kubectl exec -n yossarian-go deployment/yossarian-worker -- \
  wget -qO- http://minio:9000/minio/health/live
```

4. **Check job status in database:**
```bash
kubectl exec -n yossarian-go deployment/yossarian-db-service -- \
  wget -qO- http://localhost:8081/jobs/queued
```

---

## 🧹 Cleanup

**Remove everything:**
```bash
kubectl delete namespace yossarian-go
```

**Or remove components individually:**
```bash
kubectl delete -f 11-cronjob-ad-sync.yaml
kubectl delete -f 10-certificate-certmanager.yaml
kubectl delete -f 09a-ingress.yaml  # or 09b-httpproxy.yaml
kubectl delete -f 08-worker.yaml
kubectl delete -f 07-frontend.yaml
kubectl delete -f 06-db-service.yaml
kubectl delete -f 05-minio.yaml
kubectl delete -f 04-pvcs.yaml
kubectl delete -f 03-secrets.yaml
kubectl delete -f 02-configmaps.yaml
kubectl delete -f 01-namespace.yaml
```

**Note:** PVCs and their data will be preserved unless explicitly deleted.

---

## 📊 Architecture

### Components

- **Frontend** (3 replicas): Stateless web UI, handles uploads and user sessions
- **Worker** (1 replica): Processes batch jobs, downloads from MinIO
- **MinIO** (1 replica): Object storage for batch job files
- **DB Service** (1 replica): SQLite database with HTTP API for job queue and metadata

### Data Flow

```
User → Frontend → MinIO (input.zip)
                ↓
         Database (job record)
                ↓
Worker polls → Downloads from MinIO → Processes → Uploads results → MinIO
                ↓
User downloads ← Frontend ← MinIO (output.zip)
```

### Storage Requirements

- **MinIO**: 100Gi (batch job files, 8-hour retention)
- **Worker**: 50Gi (temporary processing space)
- **Database**: 5Gi (job metadata, AD cache)

---

## 🔐 Security Notes

### Default Credentials

⚠️ **CRITICAL:** Change default passwords before production deployment!

```yaml
# In 03-secrets.yaml
ADMIN_PASSWORD: "Yossarian123"  # CHANGE THIS!

# In minio-secret
password: "changeme-minio-password"  # CHANGE THIS!
```

### Authentication Modes

| Mode | When to Use | Security Level |
|------|-------------|----------------|
| **Single-user (password)** | Local testing, single admin | ⚠️ Basic |
| **Multi-user (OIDC/SSO)** | Production, multiple users | ✅ Enterprise |

### Network Policies

Consider adding NetworkPolicies to restrict pod-to-pod communication:
- Frontend → MinIO, DB Service
- Worker → MinIO, DB Service
- DB Service → LDAP (if configured)

---

## 📚 Additional Resources

- **GitHub**: https://github.com/kofadam/yossarian-go
- **Docker Images**: 
  - Frontend/Worker: `ghcr.io/kofadam/yossarian-go:latest`
  - DB Service: `ghcr.io/kofadam/yossarian-go-db-service:latest`
- **Architecture Docs**: See `ARCHITECTURE-v0.13.0.md` in repo

---

## 🆘 Support

**Issues:** https://github.com/kofadam/yossarian-go/issues

**Version:** v0.13.3+  
**Last Updated:** January 2026

---

## ✅ Quick Reference

| File | Purpose | Must Edit? |
|------|---------|------------|
| `00-quickstart-local.yaml` | Local testing (all-in-one) | No |
| `01-namespace.yaml` | Namespace creation | No |
| `02-configmaps.yaml` | App configuration | Yes (for OIDC/LDAP) |
| `03-secrets.yaml` | Passwords and secrets | **YES** |
| `04-pvcs.yaml` | Storage claims | Maybe (StorageClass) |
| `05-minio.yaml` | Object storage | Maybe (StorageClass) |
| `06-db-service.yaml` | Database service | No |
| `07-frontend.yaml` | Web UI | No |
| `08-worker.yaml` | Batch processor | No |
| `09a-ingress.yaml` | Standard ingress | Yes (domain) |
| `09b-httpproxy.yaml` | Contour ingress | Yes (domain) |
| `10-certificate-certmanager.yaml` | TLS cert | Yes (domain, issuer) |
| `11-cronjob-ad-sync.yaml` | AD sync schedule | No |

---

**🛡️ Yossarian Go - Making logs safe to share, at any scale**
