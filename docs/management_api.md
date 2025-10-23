## 📋 **Yossarian Go - Complete REST API Reference**

### **🏠 Main Application API** (Port 8080)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/` | Main web interface (HTML) |
| `GET` | `/health` | Application health check |
| `GET` | `/api/userinfo` | Current user authentication info |
| `POST` | `/upload` | **Upload and sanitize files** |
| `GET` | `/download/sanitized` | **Download all sanitized files (ZIP)** |
| `GET` | `/download/sanitized/single` | Download combined sanitized content |
| `GET` | `/download/sanitized/{filename}` | Download specific sanitized file |
| `GET` | `/mappings/csv` | **Download IP mappings audit report (CSV)** |

### **🔐 Authentication Endpoints** (Port 8080)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/admin/login` | Admin login page |
| `POST` | `/admin/login` | Admin password authentication |
| `GET` | `/admin/logout` | Admin logout |
| `GET` | `/auth/oidc/login` | **Enterprise SSO login** |
| `GET` | `/auth/oidc/callback` | OIDC callback handler |

### **⚙️ Admin Panel Endpoints** (Port 8080)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/admin` | **Admin dashboard** (requires auth) |
| `GET` | `/admin/ad-accounts` | AD account management |

### **🗄️ Database Service API** (Port 8081)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Database service health |
| `GET` | `/lookup/{account}` | **Lookup AD account USN mapping** |
| `GET` | `/ldap/status` | **LDAP configuration and account counts** |
| `GET` | `/ldap/test` | **Test LDAP connectivity** |
| `POST` | `/ldap/sync-limited` | Manual limited import (testing) |
| `POST` | `/ldap/sync-full` | **Manual full AD import** |
| `GET` | `/accounts/list` | **List all imported AD accounts** |
| `POST` | `/add-test-data` | Add test data (development) |

## 🔥 **Most Important Endpoints:**

### **For Regular Use:**
```bash
# Upload and sanitize files
curl -X POST -F "file=@logfile.log" http://localhost:8080/upload

# Download sanitized files
curl -O http://localhost:8080/download/sanitized

# Get audit trail
curl -O http://localhost:8080/mappings/csv
```

### **For Administration:**
```bash
# Check AD sync status
curl http://localhost:8081/ldap/status

# Import all AD accounts
curl -X POST http://localhost:8081/ldap/sync-full

# Test LDAP connectivity
curl http://localhost:8081/ldap/test

# List imported accounts
curl http://localhost:8081/accounts/list
```

### **For Health Monitoring:**
```bash
# Main app health
curl http://localhost:8080/health

# Database service health
curl http://localhost:8081/health
```

**Quick SQLite search commands:**

**1. Search for specific user/computer:**
```bash
kubectl exec -it deployment/yossarian-db-service -n yossarian-go -- sqlite3 /data/yossarian.db "SELECT * FROM ad_accounts WHERE account LIKE '%real-user%';"
```

**2. Search for computer accounts:**
```bash
kubectl exec -it deployment/yossarian-db-service -n yossarian-go -- sqlite3 /data/yossarian.db "SELECT * FROM ad_accounts WHERE account LIKE '%SERVER01%';"
```

**3. Count all entries:**
```bash
kubectl exec -it deployment/yossarian-db-service -n yossarian-go -- sqlite3 /data/yossarian.db "SELECT COUNT(*) FROM ad_accounts;"
```

**4. Show all computer accounts:**
```bash
kubectl exec -it deployment/yossarian-db-service -n yossarian-go -- sqlite3 /data/yossarian.db "SELECT * FROM ad_accounts WHERE account LIKE '%$' LIMIT 10;"
```

**5. Check if `real-user` exists in any format:**
```bash
kubectl exec -it deployment/yossarian-db-service -n yossarian-go -- sqlite3 /data/yossarian.db "SELECT * FROM ad_accounts WHERE UPPER(account) LIKE '%REAL-USER%';"
```

This will show if the user/computer is in the database and what USN it maps to.

**🛡️ The complete enterprise log sanitization API suite!**