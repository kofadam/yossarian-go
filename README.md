# Yossarian Go - Enterprise Log Sanitization System

🛡️ **Air-gapped log sanitization with Material Design UI**

## Overview

Enterprise-grade log sanitization system built in Go, designed for air-gapped environments. Handles 100MB+ files with comprehensive pattern detection and zero data retention.

## Features

### 🔍 Pattern Detection
- **IP Addresses** → `[IP-ADDRESS-REDACTED]` with consistent mapping
- **AD Accounts** → USN format (`CORP\user` → `USN123456789`)
- **JWT Tokens** → `[JWT-REDACTED]`
- **Private Keys** → `[PRIVATE-KEY-REDACTED]`
- **Sensitive Terms** → `[SENSITIVE]` (organization-defined)
- **User Words** → `[USER-SENSITIVE]` (personal cookie-stored)

### 🎨 Material Design UI
- Multi-file upload (up to 10 files, 50MB each)
- Drag & drop + click-to-browse
- Real-time progress tracking
- Comprehensive results dashboard
- Downloadable sanitized files and audit reports

### 🔒 Security & Compliance
- **Zero persistence** - all processing in-memory
- **Air-gap ready** - no external dependencies
- **Audit trails** - complete IP mapping exports
- **Session-based auth** - secure admin panel
  
<img width="1402" height="993" alt="image" src="https://github.com/user-attachments/assets/88a14f1f-d9b0-4afd-909b-21c554df5777" />


## Quick Start

### Docker Deployment
```bash
# Build and run
docker-compose up --build

# Access the application
http://localhost:8080        # Main interface
http://localhost:8080/admin  # Admin panel (password: admin123)
