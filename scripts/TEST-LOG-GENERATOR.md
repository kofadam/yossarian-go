# Yossarian Go - Test Log Generator

Generate realistic test log files with various sensitive patterns for testing Yossarian Go's sanitization capabilities.

## Quick Start

```bash
# Make executable
chmod +x generate-test-logs.sh

# Generate default test set (20 files × 10K lines = 200K total lines)
./generate-test-logs.sh

# Upload test-logs-bundle.zip to Yossarian Go
```

## Usage

```bash
./generate-test-logs.sh [OPTIONS]
```

### Options

| Option | Description | Default |
|--------|-------------|---------|
| `-f, --files NUM` | Number of files to generate | 20 |
| `-l, --lines NUM` | Lines per file | 10000 |
| `-o, --output DIR` | Output directory | test-logs |
| `-z, --zip` | Create ZIP archive | yes |
| `--no-zip` | Skip ZIP creation | - |
| `-h, --help` | Show help message | - |

### Examples

```bash
# Quick test (5 files, 1K lines each)
./generate-test-logs.sh -f 5 -l 1000

# Standard test (20 files, 10K lines each)
./generate-test-logs.sh

# Stress test (50 files, 50K lines each = 2.5M lines)
./generate-test-logs.sh -f 50 -l 50000

# Maximum stress test (100 files, 100K lines each = 10M lines)
./generate-test-logs.sh -f 100 -l 100000
```

## Pattern Coverage

The generator creates realistic log entries with these sensitive patterns:

| Pattern Type | Example | Detection |
|--------------|---------|-----------|
| **IP Addresses** | `192.168.1.100`, `10.0.50.25` | → `[IP-001]` |
| **AD Accounts (domain\\user)** | `CORP\john.doe` | → `USN123456` |
| **AD Accounts (UPN)** | `admin@example.com` | → `USN123456` |
| **Computer Accounts** | `WORKSTATION01$` | → `USN789012` |
| **JWT Tokens** | `eyJhbGciOiJIUzI1NiIs...` | → `[JWT-REDACTED]` |
| **Passwords (connection string)** | `Password=Secret123` | → `[PASSWORD-REDACTED]` |
| **Passwords (URL)** | `user:pass@host.com` | → `[PASSWORD-REDACTED]` |
| **Passwords (params)** | `password=MyP@ss` | → `[PASSWORD-REDACTED]` |
| **Private Keys** | `-----BEGIN RSA PRIVATE KEY-----` | → `[PRIVATE-KEY-REDACTED]` |
| **Sensitive Terms** | `ProjectApollo`, `ClientMegaCorp` | → `[SENSITIVE]` |
| **Server Names** | `SLLS-prd-dbserver01` | → `USN345678` |

## Expected Output

### File Generation
```
==============================================
🔧 Yossarian Go - Test Log Generator
==============================================
Files:          20
Lines per file: 10000
Total lines:    200000
Output:         test-logs/
==============================================

Generating test-logs/application-01.log... done (1.2M)
Generating test-logs/application-02.log... done (1.2M)
...
Generating test-logs/application-20.log... done (1.2M)

Creating ZIP archive... done (8.5M)

==============================================
✅ Generation Complete!
==============================================
Files generated: 20
Lines per file:  10000
Total lines:     200000
Time taken:      15s

📁 Log files:    test-logs/
📦 ZIP archive:  test-logs-bundle.zip
```

### Expected File Sizes

| Configuration | Total Lines | Raw Size | ZIP Size | Generation Time |
|---------------|-------------|----------|----------|-----------------|
| 5 × 1K | 5,000 | ~600 KB | ~200 KB | ~1s |
| 20 × 10K | 200,000 | ~24 MB | ~8 MB | ~15s |
| 50 × 50K | 2,500,000 | ~300 MB | ~100 MB | ~3 min |
| 100 × 100K | 10,000,000 | ~1.2 GB | ~400 MB | ~12 min |

## Testing Procedure

### 1. Generate Test Files
```bash
./generate-test-logs.sh
```

### 2. Upload to Yossarian Go
1. Open Yossarian Go web UI
2. ☑️ Enable "Generate detailed replacement report (CSV)"
3. Upload `test-logs-bundle.zip`
4. Click "🔒 Secure Files"

### 3. Monitor Processing
```bash
# If using Docker
docker logs -f yossarian-frontend 2>&1 | grep -E "PERF|INFO|Pattern"

# If using Kubernetes
kubectl logs -f -n yossarian-go -l app.kubernetes.io/component=worker
```

### 4. Expected Log Output
```
[INFO] File upload started: user=Administrator, files=1
[INFO] Detailed replacement report requested
[WORKER] Processing job batch-Administrator-20260129-...
[DEBUG] Pattern detection - IP addresses: 40000 total, 35000 unique
[DEBUG] Pattern detection - AD accounts: 20000 candidates
[DEBUG] Pattern detection - JWT tokens: 8000 found
[DEBUG] Pattern detection - Passwords: 12000 found
[PERF] Job completed in 45.2s
```

### 5. Verify Results

**Download and check:**
- `sanitized-*.zip` - All patterns should be replaced
- `*-ip-mappings.csv` - IP address mapping table
- `*-detailed-report.csv` - Full replacement audit log

**Detailed report columns:**
| Column | Description |
|--------|-------------|
| Category | Pattern type (IP_Address, AD_Account, etc.) |
| File | Source filename |
| Line | Line number in original file |
| Original | Original sensitive value |
| Sanitized | Replacement token |

## Performance Benchmarks

### Expected Processing Times

| File Size | Lines | Patterns | Expected Time |
|-----------|-------|----------|---------------|
| 1 MB | 10K | ~4K | 1-2s |
| 10 MB | 100K | ~40K | 5-10s |
| 50 MB | 500K | ~200K | 30-60s |
| 100 MB | 1M | ~400K | 1-2 min |

### Performance Indicators

✅ **Good Performance:**
- < 1 MB/sec processing rate
- Memory usage < 500 MB
- No timeout errors

⚠️ **Potential Issues:**
- Processing time > 2 min for 100K lines
- Memory usage > 1 GB
- Browser becomes unresponsive

## Troubleshooting

### Script Issues

**Permission denied:**
```bash
chmod +x generate-test-logs.sh
```

**awk not found:**
```bash
# Ubuntu/Debian
sudo apt install gawk

# RHEL/CentOS
sudo yum install gawk
```

**zip not found:**
```bash
# Ubuntu/Debian
sudo apt install zip

# RHEL/CentOS
sudo yum install zip
```

### Upload Issues

**File too large:**
- Default limit is 100 MB total upload
- Split into smaller ZIPs or increase `MAX_TOTAL_UPLOAD_SIZE_MB`

**Timeout during processing:**
- Large files may timeout with default Ingress settings
- Increase timeout in HTTPProxy/Ingress configuration

### Processing Issues

**Out of memory:**
- Reduce file size or number of files
- Increase worker memory limits in Helm values

**Patterns not detected:**
- Check that sensitive terms are configured in Admin Panel
- Verify AD accounts exist in database (if using AD lookup)

## Sample Output

### Original Log Entry
```
2026-01-15 14:32:01 INFO  [AuthService] User CORP\john.doe logged in from 192.168.1.100
```

### Sanitized Log Entry
```
2026-01-15 14:32:01 INFO  [AuthService] User USN123456789 logged in from [IP-001]
```

### Detailed Report Row
```csv
Category,File,Line,Original,Sanitized
AD_Account,application-01.log,1523,CORP\john.doe,USN123456789
IP_Address,application-01.log,1523,192.168.1.100,[IP-001]
```
