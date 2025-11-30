# Yossarian Go - Verbose Logging Guide

## Overview

Yossarian Go now includes comprehensive verbose logging to provide visibility into file processing, pattern detection, performance metrics, and security events. All logs are structured with prefixed levels for easy filtering and monitoring.

## Log Levels

Logs are prefixed with levels for easy filtering:

| Level | Purpose | Example |
|-------|---------|---------|
| `[INFO]` | Normal operations | `[INFO] File upload started: user=john.doe, files=1` |
| `[DEBUG]` | Detailed debugging info | `[DEBUG] File received: server.log (611251 bytes)` |
| `[PERF]` | Performance metrics | `[PERF] Sanitization completed: server.log in 2.8s (213.22 MB/sec)` |
| `[ERROR]` | Error conditions | `[ERROR] File upload failed: file too large` |
| `[WARN]` | Warning conditions | `[WARN] File skipped: binary.exe (binary content detected)` |
| `[AUDIT]` | Security/audit events | `[AUDIT] Upload completed: user=john.doe, files=1, patterns_found=937` |

## What Gets Logged

### File Upload & Processing
- File upload initiated with user identification
- File validation (size, type, binary detection)
- Processing start/completion with timing
- Pattern detection counts for each category
- Cache performance statistics (hits/misses)
- File storage and download availability

### Pattern Detection
- **IP Addresses**: Total occurrences and unique count
- **AD Accounts**: Candidates found, confirmed matches, cache statistics
- **JWT Tokens**: Count detected
- **Private Keys**: Count detected
- **Passwords**: Count detected
- **Sensitive Terms**: Organization-defined terms found
- **User Words**: Personal sensitive words from cookies

### ZIP File Processing
- ZIP detection and extraction timing
- Files extracted with individual sizes
- Per-file processing progress
- ZIP recreation and compression statistics
- Aggregate pattern counts across all files
- Processing rate and timing

### Performance Metrics
- Processing time per file
- Processing rate (MB/sec)
- Cache hit/miss ratios for AD lookups
- Overall upload processing time
- Individual pattern detection timing

### Security & Audit
- User authentication events (SSO login)
- File upload completions with pattern counts
- Download events (all files and individual)
- User activity tracking
- Access attempts and failures

### Error Tracking
- File validation failures (size, type)
- Binary file detection and skipping
- Database service connectivity issues
- AD lookup failures
- ZIP extraction errors

## Example Log Output

### File Processing
```
[INFO] File upload started: user=john.doe, files=1
[DEBUG] File received: server.log (611251 bytes)
[DEBUG] File type check: server.log - binary=false, archive=false
[INFO] Processing file: server.log (597.01 KB)
[PERF] Sanitization started: server.log
[DEBUG] Pattern detection - JWT tokens: 2 found
[DEBUG] Pattern detection - AD accounts: 1234 candidates, 856 confirmed (cache hit: 782, miss: 74)
[DEBUG] Pattern detection - Sensitive terms: 45 found
[DEBUG] Pattern detection - User words: 12 found
[DEBUG] Pattern detection - IP addresses: 3456 total occurrences, 22 unique
[PERF] Sanitization completed: server.log in 2.8s (213.22 MB/sec)
[INFO] Results - File: server.log, IPs: 22, AD: 856, JWT: 2, Keys: 0, Sensitive: 45, UserWords: 12, Total: 937
[INFO] Storing 1 files for download
[DEBUG] File stored for download: server.log (597.01 KB)
[INFO] Storage complete: 1 files stored (0.58 MB total)
[INFO] Total files available for download: 1
[INFO] ========== Upload Processing Complete ==========
[INFO] User: john.doe
[INFO] Files Processed: 1
[INFO] Total Size: 0.58 MB → 0.58 MB (0.5% reduction)
[INFO] IP Mappings Created: 22
[PERF] Overall Rate: 213.22 MB/sec
[AUDIT] Upload completed: user=john.doe, files=1, total_size_mb=0.58, patterns_found=937
[INFO] ===============================================
```

### ZIP Processing
```
[INFO] ZIP archive detected: logs.zip (15.23 MB)
[DEBUG] Extracting ZIP contents: logs.zip
[INFO] ZIP extraction complete: logs.zip - 25 files extracted (12.45 MB uncompressed) in 1.12s
[INFO] Processing ZIP contents: logs.zip (25 files)
[DEBUG] Processing file 1/25 in ZIP: server-1.log (2.34 KB)
[PERF] Sanitized 1/25: server-1.log (0.85s)
[DEBUG] Processing file 2/25 in ZIP: server-2.log (1.89 KB)
[PERF] Sanitized 2/25: server-2.log (0.72s)
...
[INFO] Recreating sanitized ZIP archive: logs.zip
[DEBUG] ZIP recreation completed in 1.23s
[INFO] ZIP archive created: logs.zip (11.89 MB sanitized, 12.45 MB original, 4.5% compression)
[INFO] ZIP processing summary: logs.zip
[INFO]   Files: 25 processed
[INFO]   Size: 12.45 MB → 11.89 MB (4.5% reduction)
[INFO]   Patterns: IPs=345, AD=123, JWT=2, Keys=0, Sensitive=45, UserWords=12
[PERF] Total processing time: 30.12s (0.41 MB/sec)
[AUDIT] ZIP processed: user=john.doe, file=logs.zip, files=25, total_patterns=527
```

### Authentication & Downloads
```
[INFO] Unauthenticated access detected, redirecting to SSO
[AUDIT] SSO login successful: user=john.doe, roles=[user]
[INFO] Download all ZIP requested: user=john.doe, files_available=1
[INFO] ZIP archive created for download: 11.89 MB (1 files)
[AUDIT] Download completed: user=john.doe, type=all_files_zip, size_mb=11.89, file_count=1
```

## Querying Logs in Grafana/Loki

### Prerequisites
Your logs are available in Loki/Grafana using these labels:
- `namespace="yossarian-go"`
- `pod` (for filtering main app vs db service)
- `container`
- `service_name`

### Essential LogQL Queries

#### All Yossarian Logs
```logql
{namespace="yossarian-go"}
```

#### Main Application Only (exclude DB service)
```logql
{namespace="yossarian-go", pod=~"yossarian-go-[^d].*"}
```

#### Database Service Only
```logql
{namespace="yossarian-go", pod=~"yossarian-go-db-.*"}
```

### Filter by Log Level

#### All INFO Logs
```logql
{namespace="yossarian-go"} |~ "\\[INFO\\]"
```

#### All ERROR Logs
```logql
{namespace="yossarian-go"} |~ "\\[ERROR\\]"
```

#### All Performance Metrics
```logql
{namespace="yossarian-go"} |~ "\\[PERF\\]"
```

#### All Audit Trail
```logql
{namespace="yossarian-go"} |~ "\\[AUDIT\\]"
```

#### All DEBUG (detailed)
```logql
{namespace="yossarian-go"} |~ "\\[DEBUG\\]"
```

#### All WARNINGS
```logql
{namespace="yossarian-go"} |~ "\\[WARN\\]"
```

### Monitoring Queries

#### File Processing Activity
```logql
{namespace="yossarian-go"} |~ "File upload started|Processing file"
```

#### Pattern Detection Details
```logql
{namespace="yossarian-go"} |~ "Pattern detection"
```

#### User Activity (Authentication)
```logql
{namespace="yossarian-go"} |~ "logged in successfully|OIDC:"
```

#### File Downloads
```logql
{namespace="yossarian-go"} |~ "Download.*requested|Download completed"
```

#### ZIP Processing
```logql
{namespace="yossarian-go"} |~ "ZIP archive|ZIP extraction|ZIP processing"
```

#### Upload Completions
```logql
{namespace="yossarian-go"} |~ "Upload Processing Complete"
```

#### Errors Only
```logql
{namespace="yossarian-go"} |~ "(?i)error|failed|failure"
```

### Performance Monitoring

#### Processing Times
```logql
{namespace="yossarian-go"} |~ "Sanitization completed.*in ([0-9.]+)s"
```

#### Cache Performance
```logql
{namespace="yossarian-go"} |~ "cache hit:|cache miss:"
```

#### Processing Rates
```logql
{namespace="yossarian-go"} |~ "Overall Rate:|MB/sec"
```

#### Slow Files (over 5 seconds)
```logql
{namespace="yossarian-go"} 
  |~ "Sanitization completed" 
  | regexp "in (?P<time>[0-9.]+)s"
  | time > 5
```

### User-Specific Queries

#### Activity by Specific User
```logql
{namespace="yossarian-go"} |~ "user=john.doe"
```

#### All Users' Upload Activity
```logql
{namespace="yossarian-go"} |~ "\\[AUDIT\\] Upload completed"
```

#### Anonymous Access (not logged in)
```logql
{namespace="yossarian-go"} |~ "user=anonymous"
```

### Database Service Queries

#### LDAP Sync Activity
```logql
{namespace="yossarian-go", pod=~".*db-.*"} |~ "LDAP sync|User search page|Computer search page"
```

#### LDAP Sync Completions
```logql
{namespace="yossarian-go", pod=~".*db-.*"} |~ "LDAP sync completed"
```

#### Account Counts
```logql
{namespace="yossarian-go", pod=~".*db-.*"} |~ "accounts synchronized"
```

#### AD Lookup Failures
```logql
{namespace="yossarian-go"} |~ "AD lookup failed"
```

### Troubleshooting Queries

#### All Errors and Warnings
```logql
{namespace="yossarian-go"} |~ "\\[(ERROR|WARN)\\]"
```

#### File Upload Failures
```logql
{namespace="yossarian-go"} |~ "File upload (failed|rejected)|exceeds.*limit"
```

#### Binary Files Skipped
```logql
{namespace="yossarian-go"} |~ "Skipping.*binary"
```

#### Large Files Rejected
```logql
{namespace="yossarian-go"} |~ "exceeds.*MB limit"
```

#### Database Service Connection Issues
```logql
{namespace="yossarian-go"} |~ "dial tcp.*yossarian-db-service|Service unavailable"
```

### Aggregate Statistics

#### Count Files Processed (Last Hour)
```logql
count_over_time({namespace="yossarian-go"} |~ "Upload completed" [1h])
```

#### Count Errors (Last Hour)
```logql
count_over_time({namespace="yossarian-go"} |~ "\\[ERROR\\]" [1h])
```

#### User Upload Activity (Logs Panel)
```logql
{namespace="yossarian-go"} 
  |~ "\\[AUDIT\\] Upload completed" 
  | regexp "user=(?P<user>[a-zA-Z0-9._-]+)"
```

*Note: Use "Logs" visualization in Grafana to see individual events with extracted user labels.*

### Real-Time Monitoring

#### Live File Processing
```logql
{namespace="yossarian-go"} |~ "Processing file|Sanitization (started|completed)"
```

#### Live Pattern Detection
```logql
{namespace="yossarian-go"} |~ "Pattern detection - (IPs|AD|JWT|Keys|Sensitive|UserWords)"
```

#### Live Audit Trail
```logql
{namespace="yossarian-go"} |~ "\\[AUDIT\\]"
```

### Combined Queries (Most Useful)

#### Complete File Processing Journey
```logql
{namespace="yossarian-go"} 
  |~ "File upload started|File received|Processing file|Sanitization|Results|Upload.*Complete"
```

#### Security Events
```logql
{namespace="yossarian-go"} 
  |~ "logged in|AUDIT|Authentication|SSO"
```

#### Performance Overview
```logql
{namespace="yossarian-go"} 
  |~ "\\[PERF\\]|MB/sec|processing time"
```

## Grafana Dashboard Panels

### Panel 1: Error Rate (Time Series)
**Query:**
```logql
sum(rate({namespace="yossarian-go"} |~ "\\[ERROR\\]" [5m]))
```
**Visualization:** Time series

### Panel 2: Files Processed (Counter)
**Query:**
```logql
sum(count_over_time({namespace="yossarian-go"} |~ "Upload completed" [5m]))
```
**Visualization:** Stat

### Panel 3: Active Users (Logs)
**Query:**
```logql
{namespace="yossarian-go"} 
  |~ "\\[AUDIT\\] Upload completed" 
  | regexp "user=(?P<user>[a-zA-Z0-9._-]+)"
```
**Visualization:** Logs (shows individual uploads with user labels)

### Panel 4: Log Level Distribution (Time Series)
**Query:**
```logql
sum by (level) (
  count_over_time(
    {namespace="yossarian-go"} 
      | regexp "\\[(?P<level>INFO|DEBUG|ERROR|WARN|PERF|AUDIT)\\]" [5m]
  )
)
```
**Visualization:** Time series (stacked)

### Panel 5: Recent File Processing (Logs)
**Query:**
```logql
{namespace="yossarian-go"} |~ "Processing file|Sanitization completed"
```
**Visualization:** Logs (shows recent processing activity)

## Performance Impact

The verbose logging has **negligible performance impact** (<1% overhead):

- **Logging overhead:** ~2ms per file
- **Typical file processing:** 2-3 seconds
- **Impact:** 0.08% (unmeasurable)

Logs are written to stdout (buffered, no disk I/O) and captured asynchronously by Kubernetes/Fluent Bit, ensuring no blocking on the processing path.

## Quick Reference

| What You Want | Query |
|---------------|-------|
| All logs | `{namespace="yossarian-go"}` |
| Only errors | `{namespace="yossarian-go"} \|~ "\\[ERROR\\]"` |
| Only performance | `{namespace="yossarian-go"} \|~ "\\[PERF\\]"` |
| Only audit | `{namespace="yossarian-go"} \|~ "\\[AUDIT\\]"` |
| File processing | `{namespace="yossarian-go"} \|~ "Processing file"` |
| User activity | `{namespace="yossarian-go"} \|~ "\\[AUDIT\\]"` |
| DB service | `{namespace="yossarian-go", pod=~".*db-.*"}` |

## Version

Verbose logging introduced in version **v0.9.51** (November 2025).

## Related Documentation

- [Main README](README.md) - Project overview and setup
- [Admin Guide](admin.html) - Admin panel documentation
- [API Documentation](docs/API.md) - API endpoints and usage

## Support

For issues or questions about logging:
1. Check existing logs in Grafana using queries above
2. Review error logs: `{namespace="yossarian-go"} |~ "\\[ERROR\\]"`
3. Open an issue with relevant log excerpts

## License

See main project [LICENSE](LICENSE) file.
