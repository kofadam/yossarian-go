#!/bin/bash
# =============================================================================
# Yossarian Go - Test Log Generator
# =============================================================================
# Generates realistic log files with various sensitive patterns for testing
# the sanitization capabilities of Yossarian Go.
#
# Usage:
#   ./generate-test-logs.sh [OPTIONS]
#
# Options:
#   -f, --files NUM      Number of files to generate (default: 20)
#   -l, --lines NUM      Lines per file (default: 10000)
#   -o, --output DIR     Output directory (default: test-logs)
#   -z, --zip            Create ZIP archive (default: yes)
#   -h, --help           Show this help message
#
# Examples:
#   ./generate-test-logs.sh                    # 20 files, 10K lines each
#   ./generate-test-logs.sh -f 5 -l 1000       # 5 files, 1K lines each
#   ./generate-test-logs.sh -f 50 -l 50000     # 50 files, 50K lines each (stress test)
# =============================================================================

set -e

# Default values
FILES=20
LINES_PER_FILE=10000
OUTPUT_DIR="test-logs"
CREATE_ZIP=true

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -f|--files)
            FILES="$2"
            shift 2
            ;;
        -l|--lines)
            LINES_PER_FILE="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -z|--zip)
            CREATE_ZIP=true
            shift
            ;;
        --no-zip)
            CREATE_ZIP=false
            shift
            ;;
        -h|--help)
            head -n 25 "$0" | tail -n 23
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Create output directory
mkdir -p "$OUTPUT_DIR"

echo "=============================================="
echo "🔧 Yossarian Go - Test Log Generator"
echo "=============================================="
echo "Files:          $FILES"
echo "Lines per file: $LINES_PER_FILE"
echo "Total lines:    $((FILES * LINES_PER_FILE))"
echo "Output:         $OUTPUT_DIR/"
echo "=============================================="
echo ""

START_TIME=$(date +%s)

for f in $(seq 1 $FILES); do
    filename="$OUTPUT_DIR/application-$(printf '%02d' $f).log"
    echo -n "Generating $filename... "
    
    # Generate all lines using awk (MUCH faster than bash loops)
    awk -v lines="$LINES_PER_FILE" -v seed="$RANDOM$f" '
    BEGIN {
        srand(seed)
        for (i = 1; i <= lines; i++) {
            # Generate timestamp
            h = int(rand() * 24)
            m = int(rand() * 60)
            s = int(rand() * 60)
            d = int(rand() * 28) + 1
            timestamp = sprintf("2026-01-%02d %02d:%02d:%02d", d, h, m, s)
            
            # Select pattern type (weighted distribution)
            pattern = int(rand() * 25)
            
            # Generate random IPs
            ip1 = sprintf("%d.%d.%d.%d", int(rand()*223)+1, int(rand()*256), int(rand()*256), int(rand()*256))
            ip2 = sprintf("10.%d.%d.%d", int(rand()*256), int(rand()*256), int(rand()*256))
            ip3 = sprintf("192.168.%d.%d", int(rand()*256), int(rand()*256))
            ip4 = sprintf("172.%d.%d.%d", int(rand()*16)+16, int(rand()*256), int(rand()*256))
            
            # Random numbers for variety
            usernum = int(rand() * 1000)
            portnum = int(rand() * 64000) + 1024
            reqid = int(rand() * 1000000)
            
            # Pattern selection with realistic log distribution
            if (pattern == 0) {
                # External IP connection
                print timestamp " INFO  [ConnectionHandler] Accepted connection from " ip1 ":" portnum
            }
            else if (pattern == 1) {
                # AD domain\user authentication
                print timestamp " DEBUG [AuthService] User CORP\\user" usernum " authenticated via Kerberos"
            }
            else if (pattern == 2) {
                # UPN format login
                print timestamp " INFO  [LoginModule] Login successful: admin" int(rand()*100) "@example.com from " ip1
            }
            else if (pattern == 3) {
                # JWT token in auth header
                print timestamp " DEBUG [TokenValidator] Validating token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlVzZXIiLCJpYXQiOjE1MTYyMzkwMjJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
            }
            else if (pattern == 4) {
                # Database connection string with password
                print timestamp " INFO  [DBPool] Connecting: Server=db-" int(rand()*10) ".internal;User=appuser;Password=Sup3rS3cr3t" int(rand()*1000) "!;Database=production"
            }
            else if (pattern == 5) {
                # Private key in error dump
                print timestamp " ERROR [CertManager] Failed to load key: -----BEGIN RSA PRIVATE KEY-----MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy3Z-----END RSA PRIVATE KEY-----"
            }
            else if (pattern == 6) {
                # Computer account
                print timestamp " DEBUG [DomainService] Computer account WORKSTATION" int(rand()*500) "$ authenticated to domain"
            }
            else if (pattern == 7) {
                # Password in URL
                print timestamp " WARN  [HTTPClient] Request to https://apiuser:s3cr3tP@ss" int(rand()*100) "@api.internal.corp/v2/resources"
            }
            else if (pattern == 8) {
                # Service account
                print timestamp " INFO  [Scheduler] Service svc_backup" int(rand()*10) " started scheduled job BackupTask_" reqid
            }
            else if (pattern == 9) {
                # Connection timeout with internal IP
                print timestamp " ERROR [NetworkManager] Connection timeout to " ip3 ":" portnum " after 30000ms"
            }
            else if (pattern == 10) {
                # Multiple IPs in routing
                print timestamp " DEBUG [Router] Routing packet: src=" ip1 " via=" ip2 " dst=" ip4
            }
            else if (pattern == 11) {
                # Sensitive project terms
                print timestamp " INFO  [ProjectManager] Processing ProjectApollo milestone for ClientMegaCorp - classified data sync"
            }
            else if (pattern == 12) {
                # Password in query params
                print timestamp " DEBUG [RequestLogger] POST /api/auth params: username=admin&password=MyP@ssw0rd" int(rand()*100) "!&remember=true"
            }
            else if (pattern == 13) {
                # Domain admin access
                print timestamp " WARN  [AuditLog] Elevated access: CORP\\domain.admin" int(rand()*5) " accessed restricted resource /admin/config"
            }
            else if (pattern == 14) {
                # Email notification
                print timestamp " INFO  [Notifier] Email sent to john.doe" int(rand()*100) "@company.internal regarding ticket #" reqid
            }
            else if (pattern == 15) {
                # Normal request log (no sensitive data)
                print timestamp " INFO  [RequestHandler] Processing request #" reqid " - status: 200 OK"
            }
            else if (pattern == 16) {
                # Stack trace (no sensitive data)
                print timestamp " ERROR [ExceptionHandler] NullPointerException at com.app.service.UserService.process(UserService.java:" int(rand()*500) ")"
            }
            else if (pattern == 17) {
                # Config with password
                print timestamp " DEBUG [ConfigLoader] Loaded: db.password=ChangeMe" int(rand()*1000) ", api.secret=sk-live-abc123xyz789"
            }
            else if (pattern == 18) {
                # Server hostname pattern
                print timestamp " INFO  [ClusterManager] Health check passed for SLLS-prd-dbserver" int(rand()*10) ".datacenter.internal"
            }
            else if (pattern == 19) {
                # Private IP health check
                print timestamp " DEBUG [HealthMonitor] Node " ip3 " responded in " int(rand()*100) "ms - healthy"
            }
            else if (pattern == 20) {
                # Mixed auth failure
                print timestamp " WARN  [SecurityAudit] Auth failure for CORP\\test.user" int(rand()*50) " from " ip1 " - invalid credentials"
            }
            else if (pattern == 21) {
                # Bearer token
                print timestamp " DEBUG [APIGateway] Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhdXRoLnNlcnZlci5jb20ifQ.signature_here"
            }
            else if (pattern == 22) {
                # JDBC connection
                print timestamp " INFO  [ConnectionFactory] JDBC URL: jdbc:postgresql://" ip2 ":5432/appdb?user=dbadmin&password=db_secret_" int(rand()*100)
            }
            else if (pattern == 23) {
                # Restricted document access
                print timestamp " WARN  [DocumentService] Accessing restricted document - classification: internal-only, confidential"
            }
            else {
                # Generic worker log
                print timestamp " INFO  [WorkerPool] Thread-" int(rand()*32) " completed task in " int(rand()*5000) "ms"
            }
        }
    }' > "$filename"
    
    # Get file size
    SIZE=$(ls -lh "$filename" | awk '{print $5}')
    echo "done ($SIZE)"
done

# Create ZIP archive
if [ "$CREATE_ZIP" = true ]; then
    echo ""
    echo -n "Creating ZIP archive... "
    ZIP_NAME="test-logs-bundle.zip"
    (cd "$OUTPUT_DIR" && zip -q "../$ZIP_NAME" *.log)
    ZIP_SIZE=$(ls -lh "$ZIP_NAME" | awk '{print $5}')
    echo "done ($ZIP_SIZE)"
fi

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

echo ""
echo "=============================================="
echo "✅ Generation Complete!"
echo "=============================================="
echo "Files generated: $FILES"
echo "Lines per file:  $LINES_PER_FILE"
echo "Total lines:     $((FILES * LINES_PER_FILE))"
echo "Time taken:      ${DURATION}s"
echo ""
echo "📁 Log files:    $OUTPUT_DIR/"
if [ "$CREATE_ZIP" = true ]; then
    echo "📦 ZIP archive:  $ZIP_NAME"
fi
echo ""
echo "Pattern Coverage:"
echo "  • IP addresses (public, private, mixed)"
echo "  • AD accounts (DOMAIN\\user, user@domain, user\$)"
echo "  • JWT tokens"
echo "  • Passwords (connection strings, URLs, params)"
echo "  • Private keys"
echo "  • Sensitive terms (ProjectApollo, ClientMegaCorp, etc.)"
echo "  • Server hostnames"
echo "=============================================="
