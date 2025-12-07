## **🔥 STRESS TEST FILE GENERATOR**

### **Option 1: Realistic Mixed Patterns (RECOMMENDED)**

This creates a file with varied patterns like real logs:

```bash
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
```

**Save as:** `generate-stress-test.sh`

**Run:**
```bash
chmod +x generate-stress-test.sh
./generate-stress-test.sh
```

**Expected output:**
```
Progress: 10000 / 100000 lines
Progress: 20000 / 100000 lines
...
Progress: 100000 / 100000 lines
✅ Generated stress-test-100k.log
-rw-r--r-- 1 user user 12M Dec  5 18:00 stress-test-100k.log
100000 stress-test-100k.log
```

---

### **Option 2: Maximum Pattern Density (EXTREME)**

Every line has multiple patterns (worst case):

```bash
#!/bin/bash
OUTPUT="extreme-stress-100k.log"
LINES=100000

echo "Generating EXTREME stress test with maximum patterns..."

> $OUTPUT

for i in $(seq 1 $LINES); do
    TIMESTAMP=$(date -d "2024-01-15 + $i seconds" +"%Y-%m-%d %H:%M:%S")
    IP1="192.168.$((RANDOM % 255)).$((RANDOM % 255))"
    IP2="10.0.$((RANDOM % 255)).$((RANDOM % 255))"
    USER="user$((RANDOM % 1000))"
    PASS="Pass$(tr -dc A-Za-z0-9 </dev/urandom | head -c 8)"
    TOKEN="eyJ$(tr -dc A-Za-z0-9 </dev/urandom | head -c 60)"
    
    echo "$TIMESTAMP ERROR CORP\\$USER at $IP1 failed auth password=$PASS token=$TOKEN ProjectApollo from $IP2" >> $OUTPUT
    
    if [ $((i % 10000)) -eq 0 ]; then
        echo "Progress: $i / $LINES"
    fi
done

echo "✅ Generated $OUTPUT"
ls -lh $OUTPUT
```

---

### **Option 3: Quick One-Liner (Simple)**

```bash
# Simple version - 100K lines with IPs and passwords
for i in {1..100000}; do 
    echo "2024-01-15 12:00:$((i % 60)) INFO User CORP\\user$i at 192.168.$((i % 255)).$((i % 255)) password=Pass$i"; 
done > stress-test-100k.log

ls -lh stress-test-100k.log
```

---

## **📊 EXPECTED FILE SIZES**

| Lines  | Patterns | Approx Size | Processing Time |
|--------|----------|-------------|-----------------|
| 100K   | Mixed    | ~10-15 MB   | 10-15 seconds   |
| 100K   | Dense    | ~20-25 MB   | 20-30 seconds   |
| 500K   | Mixed    | ~50-75 MB   | 60-90 seconds   |

---

## **🧪 TESTING PROCEDURE**

### **Step 1: Generate File**
```bash
./generate-stress-test.sh
```

### **Step 2: Upload to Yossarian**
1. Go to `http://localhost:8080` (or your work instance)
2. ✅ **Check** "Generate detailed replacement report (CSV)"
3. Upload `stress-test-100k.log`
4. Click "🔒 Sanitize Files"

### **Step 3: Monitor Performance**

**Watch Docker logs:**
```bash
docker logs -f yossarian-test | grep -E "PERF|INFO|Detailed"
```

**Expected log output:**
```
[INFO] File upload started: user=anonymous, files=1
[INFO] Detailed replacement report requested by user=anonymous
[PERF] Sanitization started: stress-test-100k.log
[DEBUG] Pattern detection - IP addresses: 30000 total occurrences, 65535 unique
[DEBUG] Pattern detection - AD accounts: 20000 candidates, 18000 confirmed
[DEBUG] Pattern detection - Passwords: 10000 found
[DEBUG] Pattern detection - JWT tokens: 10000 found
[PERF] Sanitization completed: stress-test-100k.log in 12.45s (1.20 MB/sec)
[INFO] Detailed report generated: 68000 replacements, 8.5 MB
```

### **Step 4: Verify Results**

**Check detailed CSV:**
- Download detailed report
- Open in Excel/LibreOffice
- Verify row count: ~68,000+ rows (excluding header)
- Check categories: IP_Address, AD_Account, Password, JWT_Token, Sensitive_Term

**Performance metrics to track:**
- Processing time (should be 10-20 seconds for 100K lines)
- Memory usage
- CSV generation time
- Download size

---

## **🎯 PERFORMANCE EXPECTATIONS**

### **With Detailed Report Enabled:**
```
File Size: 12 MB (100K lines)
Processing Time: ~15 seconds
Patterns Found: ~60,000-70,000
CSV Size: ~6-8 MB
Memory Usage: +20-30 MB
Rate: ~0.8 MB/sec
```

### **Without Detailed Report:**
```
File Size: 12 MB (100K lines)
Processing Time: ~14 seconds
Patterns Found: ~60,000-70,000
CSV Size: N/A
Memory Usage: Baseline
Rate: ~0.85 MB/sec
```

**Overhead: ~6-8% (as expected)**

---

## **📈 STRESS TEST SCENARIOS**

### **Scenario 1: Typical Enterprise Logs**
```bash
./generate-stress-test.sh  # Mixed patterns, realistic
```

### **Scenario 2: Worst Case (Dense Patterns)**
```bash
# Every line has 5+ patterns
./generate-extreme-stress.sh
```

### **Scenario 3: Maximum File Size**
```bash
# Generate 500K lines (~50MB)
sed -i 's/LINES=100000/LINES=500000/' generate-stress-test.sh
./generate-stress-test.sh
```

### **Scenario 4: Multiple Files**
```bash
# Generate 10 files of 10K lines each
for i in {1..10}; do
    head -n 10000 stress-test-100k.log > stress-test-part-$i.log
done

# Upload all 10 files at once
```

---

## **🐛 WHAT TO WATCH FOR**

### **Performance Issues:**
- ⚠️ Processing time > 30 seconds
- ⚠️ Browser becomes unresponsive
- ⚠️ Memory usage > 200MB

### **Functional Issues:**
- ⚠️ CSV file corrupted or incomplete
- ⚠️ Missing line numbers
- ⚠️ Incorrect pattern categorization
- ⚠️ Progress bar stuck

### **Success Indicators:**
- ✅ Processing completes in 15-20 seconds
- ✅ CSV downloads successfully
- ✅ All patterns detected
- ✅ Line numbers accurate
- ✅ No browser errors

---

## **💡 BONUS: Comparison Test**

```bash
# Generate 3 sizes for comparison
for SIZE in 10000 50000 100000; do
    sed "s/LINES=100000/LINES=$SIZE/" generate-stress-test.sh > gen-$SIZE.sh
    chmod +x gen-$SIZE.sh
    ./gen-$SIZE.sh
done

# Test each and compare times
```