# Code Scan - Source Code Sanitization Guide

Remove secrets, credentials, and sensitive data from source code before sharing with external vendors, customers, or public repositories.

## Overview

Code Scan is designed for developers and security teams who need to share code without exposing sensitive information. Unlike log sanitization which uses anonymized tokens (`[IP-001]`), Code Scan replaces secrets with safe placeholder values that maintain code syntax validity.

## What Gets Detected & Sanitized

| Category | Examples | Safe Replacement |
|----------|----------|------------------|
| **Internal URLs** | `http://192.168.1.100:8080/api` | `http://example.com:8080/api` |
| **IP Addresses** | `10.0.0.50`, `172.16.0.1` | `192.0.2.x` (RFC 5737) |
| **Passwords** | `"password": "Secret123"` | `"password": "CHANGE_ME_PASSWORD"` |
| **Connection Strings** | `redis://:pass@host:6379` | `redis://:CHANGE_ME_PASSWORD@host:6379` |
| **AWS Access Keys** | `AKIAIOSFODNN7EXAMPLE` | `[AWS-KEY-REDACTED]` |
| **AWS Secret Keys** | `wJalrXUtnFEMI/K7MDENG...` | `[AWS-SECRET-REDACTED]` |
| **Stripe Keys** | `sk_live_...`, `sk_test_...` | `[STRIPE-KEY-REDACTED]` |
| **GitHub Tokens** | `ghp_xxxx...` | `[GITHUB-TOKEN-REDACTED]` |
| **Slack Tokens** | `xoxb-...` | `[SLACK-TOKEN-REDACTED]` |
| **OpenAI Keys** | `sk-proj-...` | `[OPENAI-KEY-REDACTED]` |
| **SendGrid Keys** | `SG.xxx.yyy` | `[SENDGRID-KEY-REDACTED]` |
| **JWT Secrets** | `JWT_SECRET = "..."` | `JWT_SECRET = "[SECRET-REDACTED]"` |
| **Generic Secrets** | `jwtSecret`, `api_secret`, `secret_key` | `[SECRET-REDACTED]` |
| **Private Keys** | `-----BEGIN RSA PRIVATE KEY-----` | Safe placeholder PEM |
| **JWT Tokens** | `eyJhbGciOiJ...` | Safe placeholder JWT |
| **Location Coordinates** | `37.7749, -122.4194` | `0.0000, 0.0000` |
| **Geo URIs** | `geo:37.7749,-122.4194` | `geo:0.0000,0.0000` |
| **Coordinate Objects** | `{ lat: 37.7749, lng: -122.4194 }` | `{ lat: 0.0000, lng: 0.0000 }` |

## Supported File Types

### Source Code
`.go`, `.py`, `.js`, `.ts`, `.jsx`, `.tsx`, `.java`, `.cs`, `.c`, `.cpp`, `.h`, `.hpp`, `.rb`, `.php`, `.swift`, `.kt`, `.scala`, `.rs`, `.r`, `.pl`, `.pm`, `.sh`, `.bash`, `.ps1`, `.psm1`, `.vb`, `.fs`, `.lua`, `.groovy`, `.dart`

### Configuration Files
`.env`, `.yaml`, `.yml`, `.json`, `.xml`, `.toml`, `.ini`, `.conf`, `.cfg`, `.properties`, `.tf`, `.hcl`

### Other
`.sql`, `.graphql`, `.html`, `.htm`, `.css`, `.scss`, `.sass`, `.less`, `.vue`, `.svelte`, `.md`, `.rst`, `.txt`

### Archives
`.zip`, `.tar.gz`, `.tgz` — Processed as batch jobs with directory structure preserved

## Scan Modes

### 1. Report Only
Scan and detect secrets without modifying code. Useful for auditing what would be found before sanitizing.

### 2. Sanitize with Safe Values
Replace detected secrets with safe placeholder values. The sanitized code remains syntactically valid and can often still be executed (though API calls will fail with placeholder credentials).

### 3. Sanitize + Generate Report
Replace secrets AND generate a detailed CSV report showing:
- Pattern type
- File name
- Line number
- Original value
- Replacement value

## Usage

### Web Interface

1. Navigate to **Code Scan** panel
2. Drag & drop files or click to browse
3. Select scan mode
4. Click **Scan & Sanitize Code**
5. Review results and download sanitized files

### Archive Processing

For ZIP or tar.gz files:
1. Upload the archive to Code Scan
2. Job is automatically queued for batch processing
3. You'll be redirected to **My Jobs** panel
4. Download the sanitized archive when complete

### API Integration

```bash
# Upload code for sanitization
curl -X POST "https://yossarian.example.com/upload" \
  -H "X-API-Key: $API_KEY" \
  -F "file=@project.zip" \
  -F "mode=code" \
  -F "code_scan_mode=sanitize_safe"

# Check job status
curl -H "X-API-Key: $API_KEY" \
  "https://yossarian.example.com/api/jobs/status/$JOB_ID"

# Download sanitized code
curl -H "X-API-Key: $API_KEY" \
  "https://yossarian.example.com/jobs/download/$JOB_ID" \
  -o sanitized-project.zip
```

**API Parameters:**
- `mode=code` — Enable code scanning mode
- `code_scan_mode` — One of: `report_only`, `sanitize_safe`, `sanitize_report`

## Example: Before & After

### Python Config (Before)
```python
DATABASE_CONFIG = {
    "host": "192.168.10.50",
    "password": "Pr0duct10n_P@ssw0rd!",
}

AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

OFFICE_LOCATION = { lat: 37.7749, lng: -122.4194 }
```

### Python Config (After)
```python
DATABASE_CONFIG = {
    "host": "192.0.2.1",
    "password": "CHANGE_ME_PASSWORD",
}

AWS_ACCESS_KEY = "[AWS-KEY-REDACTED]"
AWS_SECRET_KEY = "[AWS-SECRET-REDACTED]"

OFFICE_LOCATION = { lat: 0.0000, lng: 0.0000 }
```

### JavaScript Config (Before)
```javascript
const config = {
  database: {
    host: '192.168.1.100',
    password: 'DbSecret123!'
  },
  apis: {
    stripe: { secretKey: 'sk_live_EXAMPLE_KEY_REPLACE_ME' },
    github: { token: 'ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' }
  },
  services: {
    auth: 'http://10.0.0.15:8080/api/auth'
  }
};
```

### JavaScript Config (After)
```javascript
const config = {
  database: {
    host: '192.0.2.1',
    password: 'CHANGE_ME_PASSWORD'
  },
  apis: {
    stripe: { secretKey: '[STRIPE-KEY-REDACTED]' },
    github: { token: '[GITHUB-TOKEN-REDACTED]' }
  },
  services: {
    auth: 'http://example.com:8080/api/auth'
  }
};
```

## Best Practices

1. **Always review** sanitized output before sharing
2. **Use Report Only** first to audit what will be detected
3. **Add custom words** in "My Words" for organization-specific terms
4. **Keep archives organized** — directory structure is preserved
5. **Test sanitized code** locally if possible before sending to vendors

## Limitations

- Generic variable names without keywords (e.g., `TOKEN = "abc"`) may not be detected
- Some edge cases like command-line passwords (`--password=xxx`) require specific patterns
- Binary files are passed through unchanged
- Very large files (>50MB) may be rejected

## Version

Code Scan was introduced in Yossarian Go v0.13.19 and enhanced in v0.13.20.
