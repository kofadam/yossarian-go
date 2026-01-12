# Certificate Configuration Guide for Yossarian Go Helm Chart

## 📋 Summary of Changes

We've added comprehensive certificate extraction documentation and fixed the Helm chart to properly handle **two separate certificates**:

1. **OIDC Certificate** (`customCA.certificate`) - For Keycloak/Okta/Auth0 authentication
2. **AD/LDAP Certificate** (`ldap.caCert`) - For Active Directory LDAPS synchronization

## 🔧 What Was Fixed

### 1. **Separate Certificate Paths**
- **Frontend/Worker** use `CA_CERT_PATH` for OIDC authentication
- **Database Service** uses `DC_CA_CERT_PATH` for AD LDAPS sync
- Each component gets the correct certificate mounted

### 2. **Two ConfigMaps Created**
- `yossarian-go-ca-bundle` → OIDC certificate (if `customCA.enabled=true`)
- `yossarian-go-dc-ca-bundle` → AD LDAPS certificate (if `ldap.caCert` is set)

### 3. **Improved Documentation**
- Added OpenSSL commands to extract certificates
- Explained when each certificate is needed
- Provided troubleshooting commands
- Added example configurations

## 📝 How to Use

### Scenario 1: OIDC with Self-Signed Certificate (Keycloak)

```bash
# Extract Keycloak certificate
openssl s_client -showcerts -connect keycloak.company.com:443 </dev/null 2>/dev/null | \
  openssl x509 -outform PEM > oidc-ca.pem

# Verify certificate
openssl x509 -in oidc-ca.pem -text -noout | grep -E "Subject:|Issuer:|Not After"
```

**values.yaml:**
```yaml
customCA:
  enabled: true
  certificate: |
    -----BEGIN CERTIFICATE-----
    [paste oidc-ca.pem content]
    -----END CERTIFICATE-----

oidc:
  enabled: true
  issuerURL: "https://keycloak.company.com/realms/main"
  clientID: "yossarian-go"
  clientSecret: "your-secret"
  redirectURL: "https://yossarian.company.com/auth/oidc/callback"
```

### Scenario 2: Active Directory LDAPS Synchronization

```bash
# Extract Domain Controller certificate
openssl s_client -showcerts -connect dc.company.com:636 </dev/null 2>/dev/null | \
  openssl x509 -outform PEM > dc-ca.pem

# Verify certificate
openssl x509 -in dc-ca.pem -text -noout | grep -E "Subject:|Issuer:|Not After"
```

**values.yaml:**
```yaml
ldap:
  enabled: true
  server: "ldaps://dc.company.com:636"
  bindDN: "CN=svc-yossarian,OU=Service,DC=company,DC=com"
  bindPassword: "your-password"
  searchBase: "DC=company,DC=com"
  caCert: |
    -----BEGIN CERTIFICATE-----
    [paste dc-ca.pem content]
    -----END CERTIFICATE-----

domain:
  netbios: "COMPANY"
  fqdn: "company.com"
```

### Scenario 3: Both OIDC and LDAPS (Full Enterprise)

```yaml
# Extract both certificates first
customCA:
  enabled: true
  certificate: |
    -----BEGIN CERTIFICATE-----
    [Keycloak certificate]
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
    [Domain Controller certificate]
    -----END CERTIFICATE-----

domain:
  netbios: "COMPANY"
  fqdn: "company.com"
```

## 🔍 Verification Commands

### Check OIDC Certificate (Frontend/Worker)
```bash
# Verify certificate is mounted
kubectl exec -n yossarian-go deployment/yossarian-frontend -- \
  cat /etc/ssl/certs/ca-bundle.crt

# Check OIDC logs
kubectl logs -n yossarian-go deployment/yossarian-frontend | grep -i oidc
```

### Check LDAPS Certificate (Database Service)
```bash
# Verify DC certificate is mounted
kubectl exec -n yossarian-go deployment/yossarian-db-service -- \
  cat /etc/ssl/certs/ca-bundle.crt

# Test LDAPS connectivity
kubectl exec -n yossarian-go deployment/yossarian-db-service -- \
  curl -v telnet://dc.company.com:636

# Check LDAP sync logs
kubectl logs -n yossarian-go deployment/yossarian-db-service | grep -i ldap
```

### Verify Certificate Validity
```bash
# Check expiration
openssl x509 -in your-cert.pem -noout -enddate

# Test TLS connection
openssl s_client -connect dc.company.com:636 -CAfile dc-ca.pem </dev/null
```

## 🚨 Common Mistakes to Avoid

1. **Don't use the same certificate for both** - OIDC and LDAPS likely have different CAs
2. **Don't forget the pipe (`|`) in YAML** - Multi-line certificates need it
3. **Include BEGIN/END lines** - The full PEM format is required
4. **Check certificate expiration** - Expired certs will cause connection failures
5. **Use LDAPS (port 636), not LDAP (port 389)** - Plain LDAP doesn't need certificates

## 📊 Architecture Diagram

```
┌────────────────────────────────────────────────────────────┐
│                     Kubernetes Cluster                      │
│                                                             │
│  ┌──────────────────┐         ┌──────────────────┐         │
│  │ Frontend/Worker  │         │  Database Service│         │
│  │                  │         │                  │         │
│  │ Uses:            │         │ Uses:            │         │
│  │ CA_CERT_PATH     │         │ DC_CA_CERT_PATH  │         │
│  │ (OIDC cert)      │         │ (LDAPS cert)     │         │
│  └────────┬─────────┘         └────────┬─────────┘         │
│           │                            │                   │
│           ▼                            ▼                   │
│  ┌──────────────────┐         ┌──────────────────┐         │
│  │ ConfigMap:       │         │ ConfigMap:       │         │
│  │ ca-bundle        │         │ dc-ca-bundle     │         │
│  │ (Keycloak)       │         │ (AD DC)          │         │
│  └──────────────────┘         └──────────────────┘         │
│           │                            │                   │
│           ▼                            ▼                   │
│  ┌──────────────────┐         ┌──────────────────┐         │
│  │ Keycloak Server  │         │ Domain Controller│         │
│  │ (port 443)       │         │ (port 636)       │         │
│  └──────────────────┘         └──────────────────┘         │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## ✅ Files Modified in Helm Chart

1. **README.md** - Added comprehensive certificate extraction guide
2. **values.yaml** - Improved documentation for both certificates
3. **templates/configmap.yaml** - Added separate DC CA bundle ConfigMap
4. **templates/database.yaml** - Fixed to use dc-ca-bundle instead of ca-bundle

## 📦 Testing

```bash
# Test the chart with both certificates
helm template yossarian ./yossarian-go \
  --set customCA.enabled=true \
  --set customCA.certificate="$(cat oidc-ca.pem)" \
  --set ldap.enabled=true \
  --set ldap.caCert="$(cat dc-ca.pem)" \
  | grep -A 10 "kind: ConfigMap"

# Should show TWO ConfigMaps:
# 1. yossarian-ca-bundle (OIDC)
# 2. yossarian-dc-ca-bundle (LDAPS)
```

## 🎯 Next Steps

Now that certificates are properly documented and configured, we can proceed with:

1. ✅ Update chart version to 0.13.8
2. ✅ Add ServiceMonitor template for Prometheus
3. ✅ Update memory limits
4. ✅ Package and publish chart

---

**Generated:** January 12, 2026  
**Chart Version:** 0.13.8 (in progress)  
**Author:** Yossarian Go Team
