# Yossarian Go API Integration Guide

> **Version:** v0.13.17+  
> **Last Updated:** January 2025

This guide explains how to integrate Yossarian Go into your automated pipelines, CI/CD workflows, and log processing systems using the REST API.

---

## Table of Contents

1. [Overview](#overview)
2. [Authentication](#authentication)
3. [Quick Start](#quick-start)
4. [API Endpoints](#api-endpoints)
5. [Complete Pipeline Example](#complete-pipeline-example)
6. [Error Handling](#error-handling)
7. [Rate Limits & Best Practices](#rate-limits--best-practices)
8. [Troubleshooting](#troubleshooting)

---

## Overview

Yossarian Go provides a REST API for automated log sanitization. The API supports:

- **Single file processing** - Upload a file, get sanitized content immediately
- **Batch processing** - Upload ZIP archives, process asynchronously, download results
- **Job management** - Track progress, cancel jobs, download reports
- **Reports** - IP mappings, processing summaries

### Architecture

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│   Client    │────▶│   Frontend   │────▶│   Worker    │
│  (curl/SDK) │     │   (API)      │     │ (Processor) │
└─────────────┘     └──────────────┘     └─────────────┘
                           │                    │
                           ▼                    ▼
                    ┌──────────────┐     ┌─────────────┐
                    │  DB Service  │     │    MinIO    │
                    │  (Metadata)  │     │  (Storage)  │
                    └──────────────┘     └─────────────┘
```

---

## Authentication

### API Key Authentication (Recommended for Automation)

API keys provide stateless authentication for automated systems. Create keys via the Admin Panel (Admin → API Keys).

**Header Format:**
```
X-API-Key: yoss_<64 hex characters>
```

**Example:**
```bash
curl -H "X-API-Key: yoss_a1b2c3d4e5f6..." https://yossarian.example.com/upload
```

### API Key Scopes

| Scope | Permissions |
|-------|-------------|
| `read` | Download sanitized files, reports, job status |
| `write` | Upload files, create jobs, cancel jobs, delete jobs |
| `admin` | Access other users' jobs (for service accounts) |

### Creating an API Key

1. Navigate to **Admin Panel** → **API Keys**
2. Click **Create New Key**
3. Enter a name (e.g., "Jenkins Pipeline")
4. Select scopes: `read`, `write` (and `admin` if needed)
5. Set expiration (optional)
6. **Copy the key immediately** - it's only shown once!

### Session Authentication (Browser)

For interactive use, the API also accepts session cookies from browser login. This is not recommended for automation.

---

## Quick Start

### 1. Set Up Your API Key

```bash
export API_KEY="yoss_your_api_key_here"
export YOSSARIAN_URL="https://yossarian.example.com"
```

### 2. Sanitize a Single File

```bash
curl -X POST "$YOSSARIAN_URL/upload" \
  -H "X-API-Key: $API_KEY" \
  -F "file=@/path/to/logfile.log"
```

**Response:**
```json
{
  "files": [{
    "filename": "logfile.log",
    "original_size": 1024,
    "sanitized_size": 980,
    "total_ips": 5,
    "ad_accounts": 2,
    "jwt_tokens": 1,
    "sanitized_content": "Log entry: IP [IP-001] user USN123456789..."
  }],
  "total_files": 1,
  "status": "completed"
}
```

### 3. Process a Batch (ZIP Archive)

```bash
# Upload ZIP file
JOB_RESPONSE=$(curl -s -X POST "$YOSSARIAN_URL/upload" \
  -H "X-API-Key: $API_KEY" \
  -F "file=@logs.zip")

JOB_ID=$(echo "$JOB_RESPONSE" | jq -r '.job_id')
echo "Job created: $JOB_ID"
```

### 4. Poll for Completion

```bash
while true; do
  STATUS=$(curl -s -H "X-API-Key: $API_KEY" \
    "$YOSSARIAN_URL/api/jobs/status/$JOB_ID" | jq -r '.status')
  
  echo "Status: $STATUS"
  
  if [ "$STATUS" = "completed" ] || [ "$STATUS" = "failed" ]; then
    break
  fi
  
  sleep 5
done
```

### 5. Download Results

```bash
curl -H "X-API-Key: $API_KEY" \
  "$YOSSARIAN_URL/jobs/download/$JOB_ID" \
  -o sanitized-output.zip
```

---

## API Endpoints

### File Upload

#### `POST /upload`

Upload files for sanitization.

**Request:**
- Content-Type: `multipart/form-data`
- Field: `file` (can be repeated for multiple files)
- Optional: `generate_detailed_report=true` for line-by-line replacement tracking

**Single File Response:**
```json
{
  "files": [{
    "filename": "app.log",
    "original_size": 2048,
    "sanitized_size": 1920,
    "processing_time": "0.15s",
    "total_ips": 12,
    "ad_accounts": 5,
    "jwt_tokens": 0,
    "private_keys": 0,
    "sensitive_terms": 3,
    "sanitized_content": "...",
    "status": "sanitized"
  }],
  "total_files": 1,
  "total_original": 2048,
  "total_sanitized": 1920,
  "total_ip_mappings": 12,
  "status": "completed"
}
```

**ZIP File Response (Batch Job Created):**
```json
{
  "job_id": "batch-username-20260129-121340",
  "status": "queued",
  "total_files": 15,
  "message": "Batch job submitted successfully"
}
```

---

### Job Management

#### `GET /api/jobs/status/{job_id}`

Get job status and details.

**Response:**
```json
{
  "job_id": "batch-username-20260129-121340",
  "username": "username",
  "status": "completed",
  "total_files": 15,
  "processed_files": 15,
  "created_at": "2026-01-29T12:13:40Z",
  "started_at": "2026-01-29T12:13:42Z",
  "completed_at": "2026-01-29T12:14:15Z",
  "error_message": null
}
```

**Status Values:**
| Status | Description |
|--------|-------------|
| `queued` | Job is waiting to be processed |
| `processing` | Worker is actively processing files |
| `completed` | All files processed successfully |
| `failed` | Processing failed (see `error_message`) |
| `cancelled` | Job was cancelled by user |

---

#### `GET /api/jobs/list`

List all jobs for the authenticated user.

**Response:**
```json
{
  "jobs": [
    {
      "job_id": "batch-username-20260129-121340",
      "status": "completed",
      "total_files": 15,
      "processed_files": 15,
      "created_at": "2026-01-29T12:13:40Z"
    }
  ],
  "total": 1
}
```

---

#### `POST /api/jobs/cancel/{job_id}`

Cancel a queued or processing job.

**Response:**
```json
{
  "status": "cancelled",
  "job_id": "batch-username-20260129-121340",
  "message": "Job cancelled successfully"
}
```

---

#### `DELETE /api/jobs/delete/{job_id}`

Delete a job and all associated files.

**Response:**
```json
{
  "status": "deleted",
  "job_id": "batch-username-20260129-121340",
  "message": "Job and all associated files deleted successfully"
}
```

---

### Downloads

#### `GET /jobs/download/{job_id}`

Download the sanitized output ZIP for a completed batch job.

**Response:** Binary ZIP file

**Headers:**
```
Content-Type: application/zip
Content-Disposition: attachment; filename="sanitized-batch-xxx.zip"
```

---

#### `GET /jobs/reports/{job_id}/ip-mappings.csv`

Download the IP address mapping report.

**Response:**
```csv
original_ip,placeholder,timestamp
10.0.0.1,[IP-001],2026-01-29T12:13:42Z
192.168.1.100,[IP-002],2026-01-29T12:13:42Z
```

---

#### `GET /jobs/reports/{job_id}/summary.json`

Download the processing summary.

**Response:**
```json
{
  "job_id": "batch-username-20260129-121340",
  "timestamp": "2026-01-29T12:14:15Z",
  "total_files": 15,
  "processing_time": "33.5s",
  "patterns_found": {
    "ip_addresses": 127,
    "ad_accounts": 45,
    "jwt_tokens": 3,
    "private_keys": 0,
    "passwords": 2,
    "sensitive_terms": 18,
    "user_words": 0
  },
  "total_patterns": 195
}
```

---

### Utility Endpoints

#### `GET /health`

Health check endpoint.

**Response:**
```json
{
  "status": "ok",
  "service": "yossarian-go",
  "version": "v0.13.17",
  "build_time": "2026-01-29_12:00:00",
  "commit": "abc1234"
}
```

---

#### `GET /mappings/csv`

Download current session's IP mappings (for single-file processing).

---

## Complete Pipeline Example

### Bash Script

```bash
#!/bin/bash
set -e

# Configuration
API_KEY="${YOSSARIAN_API_KEY:?Missing API key}"
BASE_URL="${YOSSARIAN_URL:-https://yossarian.example.com}"
INPUT_FILE="$1"
OUTPUT_DIR="${2:-.}"

if [ -z "$INPUT_FILE" ]; then
  echo "Usage: $0 <input.zip> [output_dir]"
  exit 1
fi

echo "📤 Uploading $INPUT_FILE..."

# Upload and get job ID
RESPONSE=$(curl -s -X POST "$BASE_URL/upload" \
  -H "X-API-Key: $API_KEY" \
  -F "file=@$INPUT_FILE")

JOB_ID=$(echo "$RESPONSE" | jq -r '.job_id // empty')

if [ -z "$JOB_ID" ]; then
  # Single file processing - content is in response
  echo "$RESPONSE" | jq -r '.files[0].sanitized_content' > "$OUTPUT_DIR/sanitized-output.txt"
  echo "✅ Single file processed. Output: $OUTPUT_DIR/sanitized-output.txt"
  exit 0
fi

echo "📋 Job created: $JOB_ID"

# Poll for completion
echo "⏳ Waiting for processing..."
while true; do
  STATUS_RESPONSE=$(curl -s -H "X-API-Key: $API_KEY" \
    "$BASE_URL/api/jobs/status/$JOB_ID")
  
  STATUS=$(echo "$STATUS_RESPONSE" | jq -r '.status')
  PROCESSED=$(echo "$STATUS_RESPONSE" | jq -r '.processed_files')
  TOTAL=$(echo "$STATUS_RESPONSE" | jq -r '.total_files')
  
  echo "   Status: $STATUS ($PROCESSED/$TOTAL files)"
  
  case "$STATUS" in
    completed)
      break
      ;;
    failed)
      ERROR=$(echo "$STATUS_RESPONSE" | jq -r '.error_message')
      echo "❌ Job failed: $ERROR"
      exit 1
      ;;
    cancelled)
      echo "⚠️ Job was cancelled"
      exit 1
      ;;
  esac
  
  sleep 3
done

# Download results
echo "📥 Downloading results..."
curl -s -H "X-API-Key: $API_KEY" \
  "$BASE_URL/jobs/download/$JOB_ID" \
  -o "$OUTPUT_DIR/sanitized-$JOB_ID.zip"

echo "📥 Downloading IP mappings..."
curl -s -H "X-API-Key: $API_KEY" \
  "$BASE_URL/jobs/reports/$JOB_ID/ip-mappings.csv" \
  -o "$OUTPUT_DIR/ip-mappings-$JOB_ID.csv"

echo "📥 Downloading summary..."
curl -s -H "X-API-Key: $API_KEY" \
  "$BASE_URL/jobs/reports/$JOB_ID/summary.json" \
  -o "$OUTPUT_DIR/summary-$JOB_ID.json"

# Show summary
echo ""
echo "✅ Processing complete!"
echo "   Files: $TOTAL"
echo "   Patterns found: $(jq '.total_patterns' "$OUTPUT_DIR/summary-$JOB_ID.json")"
echo ""
echo "📁 Output files:"
echo "   - $OUTPUT_DIR/sanitized-$JOB_ID.zip"
echo "   - $OUTPUT_DIR/ip-mappings-$JOB_ID.csv"
echo "   - $OUTPUT_DIR/summary-$JOB_ID.json"
```

**Usage:**
```bash
export YOSSARIAN_API_KEY="yoss_..."
export YOSSARIAN_URL="https://yossarian.example.com"

./sanitize.sh logs.zip ./output/
```

---

### Python Script

```python
#!/usr/bin/env python3
"""
Yossarian Go API Client
Sanitize log files via the REST API.
"""

import os
import sys
import time
import json
import requests
from pathlib import Path

class YossarianClient:
    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers['X-API-Key'] = api_key
    
    def upload(self, file_path: str) -> dict:
        """Upload a file for sanitization."""
        with open(file_path, 'rb') as f:
            response = self.session.post(
                f"{self.base_url}/upload",
                files={'file': (Path(file_path).name, f)}
            )
        response.raise_for_status()
        return response.json()
    
    def get_job_status(self, job_id: str) -> dict:
        """Get status of a batch job."""
        response = self.session.get(
            f"{self.base_url}/api/jobs/status/{job_id}"
        )
        response.raise_for_status()
        return response.json()
    
    def wait_for_completion(self, job_id: str, poll_interval: int = 3) -> dict:
        """Poll until job completes."""
        while True:
            status = self.get_job_status(job_id)
            
            if status['status'] == 'completed':
                return status
            elif status['status'] in ('failed', 'cancelled'):
                raise Exception(f"Job {status['status']}: {status.get('error_message', '')}")
            
            print(f"  Status: {status['status']} ({status['processed_files']}/{status['total_files']})")
            time.sleep(poll_interval)
    
    def download_result(self, job_id: str, output_path: str):
        """Download the sanitized output ZIP."""
        response = self.session.get(
            f"{self.base_url}/jobs/download/{job_id}",
            stream=True
        )
        response.raise_for_status()
        
        with open(output_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
    
    def download_report(self, job_id: str, report_type: str, output_path: str):
        """Download a report (ip-mappings.csv, summary.json)."""
        response = self.session.get(
            f"{self.base_url}/jobs/reports/{job_id}/{report_type}"
        )
        response.raise_for_status()
        
        with open(output_path, 'wb') as f:
            f.write(response.content)
    
    def cancel_job(self, job_id: str) -> dict:
        """Cancel a queued or processing job."""
        response = self.session.post(
            f"{self.base_url}/api/jobs/cancel/{job_id}"
        )
        response.raise_for_status()
        return response.json()


def main():
    # Configuration from environment
    api_key = os.environ.get('YOSSARIAN_API_KEY')
    base_url = os.environ.get('YOSSARIAN_URL', 'https://yossarian.example.com')
    
    if not api_key:
        print("Error: YOSSARIAN_API_KEY environment variable required")
        sys.exit(1)
    
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <input_file> [output_dir]")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else '.'
    
    # Create client
    client = YossarianClient(base_url, api_key)
    
    print(f"📤 Uploading {input_file}...")
    result = client.upload(input_file)
    
    # Check if it's a batch job or immediate result
    if 'job_id' in result:
        job_id = result['job_id']
        print(f"📋 Batch job created: {job_id}")
        
        print("⏳ Waiting for processing...")
        status = client.wait_for_completion(job_id)
        
        # Download results
        output_zip = f"{output_dir}/sanitized-{job_id}.zip"
        mappings_csv = f"{output_dir}/ip-mappings-{job_id}.csv"
        summary_json = f"{output_dir}/summary-{job_id}.json"
        
        print("📥 Downloading results...")
        client.download_result(job_id, output_zip)
        client.download_report(job_id, 'ip-mappings.csv', mappings_csv)
        client.download_report(job_id, 'summary.json', summary_json)
        
        # Show summary
        with open(summary_json) as f:
            summary = json.load(f)
        
        print(f"\n✅ Processing complete!")
        print(f"   Files: {summary['total_files']}")
        print(f"   Patterns found: {summary['total_patterns']}")
        print(f"\n📁 Output files:")
        print(f"   - {output_zip}")
        print(f"   - {mappings_csv}")
        print(f"   - {summary_json}")
    
    else:
        # Single file - content in response
        output_file = f"{output_dir}/sanitized-output.txt"
        content = result['files'][0]['sanitized_content']
        
        with open(output_file, 'w') as f:
            f.write(content)
        
        print(f"✅ Single file processed: {output_file}")
        print(f"   IPs replaced: {result['files'][0].get('total_ips', 0)}")


if __name__ == '__main__':
    main()
```

**Usage:**
```bash
pip install requests

export YOSSARIAN_API_KEY="yoss_..."
export YOSSARIAN_URL="https://yossarian.example.com"

python yossarian_client.py logs.zip ./output/
```

---

### Jenkins Pipeline

```groovy
pipeline {
    agent any
    
    environment {
        YOSSARIAN_URL = 'https://yossarian.example.com'
        YOSSARIAN_API_KEY = credentials('yossarian-api-key')
    }
    
    stages {
        stage('Collect Logs') {
            steps {
                sh 'zip -r logs.zip /var/log/myapp/'
            }
        }
        
        stage('Sanitize Logs') {
            steps {
                script {
                    // Upload logs
                    def uploadResponse = sh(
                        script: """
                            curl -s -X POST "${YOSSARIAN_URL}/upload" \
                                -H "X-API-Key: ${YOSSARIAN_API_KEY}" \
                                -F "file=@logs.zip"
                        """,
                        returnStdout: true
                    )
                    
                    def jobId = readJSON(text: uploadResponse).job_id
                    echo "Job ID: ${jobId}"
                    
                    // Poll for completion
                    def status = 'queued'
                    while (status == 'queued' || status == 'processing') {
                        sleep 5
                        def statusResponse = sh(
                            script: """
                                curl -s -H "X-API-Key: ${YOSSARIAN_API_KEY}" \
                                    "${YOSSARIAN_URL}/api/jobs/status/${jobId}"
                            """,
                            returnStdout: true
                        )
                        status = readJSON(text: statusResponse).status
                        echo "Status: ${status}"
                    }
                    
                    if (status != 'completed') {
                        error "Sanitization failed: ${status}"
                    }
                    
                    // Download results
                    sh """
                        curl -H "X-API-Key: ${YOSSARIAN_API_KEY}" \
                            "${YOSSARIAN_URL}/jobs/download/${jobId}" \
                            -o sanitized-logs.zip
                    """
                    
                    env.SANITIZED_FILE = 'sanitized-logs.zip'
                }
            }
        }
        
        stage('Upload to Support Portal') {
            steps {
                // Upload sanitized logs to vendor support
                sh 'curl -X POST https://support.vendor.com/upload -F "file=@${SANITIZED_FILE}"'
            }
        }
    }
    
    post {
        always {
            archiveArtifacts artifacts: 'sanitized-*.zip', allowEmptyArchive: true
        }
    }
}
```

---

## Error Handling

### HTTP Status Codes

| Code | Meaning |
|------|---------|
| 200 | Success |
| 400 | Bad request (invalid input) |
| 401 | Unauthorized (missing or invalid API key) |
| 403 | Forbidden (insufficient scope or wrong owner) |
| 404 | Not found (job or file doesn't exist) |
| 500 | Internal server error |

### Error Response Format

```json
{
  "error": "unauthorized",
  "message": "Session expired or invalid"
}
```

### Common Errors

**Invalid API Key:**
```json
{
  "error": "unauthorized",
  "message": "Invalid API key"
}
```

**Insufficient Scope:**
```json
{
  "error": "forbidden",
  "message": "API key does not have 'write' scope"
}
```

**Job Not Found:**
```json
{
  "error": "not_found",
  "message": "Job not found"
}
```

**Access Denied (Wrong Owner):**
```json
{
  "error": "forbidden",
  "message": "Access denied"
}
```

---

## Rate Limits & Best Practices

### Limits

| Limit | Default Value |
|-------|---------------|
| Max upload size (total) | 100 MB |
| Max single file size | 50 MB |
| Max files per upload | 10 |
| Job retention | 8 hours |

### Best Practices

1. **Use batch processing** for multiple files - upload as ZIP
2. **Poll with reasonable intervals** - 3-5 seconds is sufficient
3. **Download results promptly** - jobs are deleted after 8 hours
4. **Store API keys securely** - use secret managers, not code
5. **Use appropriate scopes** - principle of least privilege
6. **Handle errors gracefully** - implement retry logic

### Retry Logic

```python
import time
from requests.exceptions import RequestException

def upload_with_retry(client, file_path, max_retries=3):
    for attempt in range(max_retries):
        try:
            return client.upload(file_path)
        except RequestException as e:
            if attempt < max_retries - 1:
                wait = 2 ** attempt  # Exponential backoff
                print(f"Retry {attempt + 1} after {wait}s: {e}")
                time.sleep(wait)
            else:
                raise
```

---

## Troubleshooting

### "Session expired" Error

**Cause:** API key is invalid or expired.

**Solution:**
1. Verify the API key is correct
2. Check if the key has expired (Admin → API Keys)
3. Create a new key if needed

### Job Stuck in "Processing"

**Cause:** Worker may be overloaded or crashed.

**Solution:**
1. Check worker health: `GET /health` on worker service
2. Cancel the job and retry
3. Check worker logs for errors

### Empty ZIP Output

**Cause:** All files were binary or unsupported.

**Solution:**
1. Ensure files are text-based (`.log`, `.txt`, `.json`, etc.)
2. Check if files contain actual content

### "Access Denied" on Download

**Cause:** API key doesn't own the job.

**Solution:**
1. Verify you're using the same API key that created the job
2. Use an API key with `admin` scope for cross-user access

### Large File Upload Timeout

**Cause:** Network timeout on large uploads.

**Solution:**
1. Increase client timeout
2. Use chunked uploads (split into smaller ZIPs)
3. Check server's `MAX_TOTAL_UPLOAD_SIZE_MB` setting

---

## Support

- **API Documentation:** `/docs/` (Swagger UI)
- **GitHub Issues:** [github.com/kofadam/yossarian-go/issues](https://github.com/kofadam/yossarian-go/issues)
- **Version:** Check `/health` endpoint for current version

---

*🛡️ Yossarian Go - Making logs safe to share, at any scale*
