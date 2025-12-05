#!/bin/bash
# Generate 100K line stress test file

OUTPUT="stress-test-100k.log"
LINES=100000

echo "Generating $LINES line stress test file..."

> $OUTPUT

for i in $(seq 1 $LINES); do
    # Random pattern selection (more realistic distribution)
    PATTERN=$((RANDOM % 10))
    
    TIMESTAMP=$(date -d "2024-01-15 + $i seconds" +"%Y-%m-%d %H:%M:%S")
    
    case $PATTERN in
        0|1|2)  # 30% - Normal logs with IPs
            IP="192.168.$((RANDOM % 255)).$((RANDOM % 255))"
            echo "$TIMESTAMP INFO Server request from $IP processed successfully" >> $OUTPUT
            ;;
        3|4)    # 20% - AD Account access
            USERS=("john.doe" "jane.smith" "bob.wilson" "alice.johnson" "charlie.brown")
            USER=${USERS[$((RANDOM % 5))]}
            IP="10.0.$((RANDOM % 255)).$((RANDOM % 255))"
            echo "$TIMESTAMP INFO User CORP\\$USER logged in from $IP" >> $OUTPUT
            ;;
        5)      # 10% - Passwords
            PASS="Pass$(tr -dc A-Za-z0-9 </dev/urandom | head -c 8)"
            echo "$TIMESTAMP ERROR Database connection failed: password=$PASS" >> $OUTPUT
            ;;
        6)      # 10% - Sensitive terms
            PROJECTS=("ProjectApollo" "ProjectPhoenix" "SecretInitiative" "ConfidentialDeal")
            PROJ=${PROJECTS[$((RANDOM % 4))]}
            echo "$TIMESTAMP WARN $PROJ deadline approaching" >> $OUTPUT
            ;;
        7)      # 10% - JWT tokens
            TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.$(tr -dc A-Za-z0-9 </dev/urandom | head -c 40).$(tr -dc A-Za-z0-9 </dev/urandom | head -c 20)"
            echo "$TIMESTAMP DEBUG Auth token: $TOKEN" >> $OUTPUT
            ;;
        8)      # 10% - Email addresses (AD accounts)
            EMAILS=("john.doe@company.com" "jane.smith@company.com" "admin@company.com")
            EMAIL=${EMAILS[$((RANDOM % 3))]}
            echo "$TIMESTAMP INFO User $EMAIL accessed resource" >> $OUTPUT
            ;;
        9)      # 10% - Plain logs (no patterns)
            echo "$TIMESTAMP INFO Background task completed successfully" >> $OUTPUT
            ;;
    esac
    
    # Progress indicator
    if [ $((i % 10000)) -eq 0 ]; then
        echo "Progress: $i / $LINES lines"
    fi
done

echo "✅ Generated $OUTPUT"
ls -lh $OUTPUT
wc -l $OUTPUT