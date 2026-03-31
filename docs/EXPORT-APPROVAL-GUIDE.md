# Export Approval & Digital Signatures Guide

## Overview

Yossarian Go includes an export approval workflow that ensures every sanitized file leaving your organization has been reviewed and approved by an authorized security officer. Each approved export carries two independent digital signatures — one proving the file was scanned, and one proving it was approved — creating a verifiable chain of custody.

This process satisfies the common enterprise requirement for **dual attestation** — one person prepares the files, a second person reviews and approves them before export.

---

## How It Works

### The Workflow

The export process follows three steps:

**Step 1 — Scan (Technical Staff)**
A team member uploads log files or source code to Yossarian. The system scans and sanitizes the files, removing IP addresses, usernames, passwords, tokens, and other sensitive information. Once processing completes, the system automatically generates a **scan attestation** — a digitally signed record proving that these specific files were scanned by Yossarian. This is **signature #1**. The job then enters a "Pending Approval" state.

**Step 2 — Review & Approve (Security Officer)**
A security officer opens the **Approval Queue** in Yossarian's interface. They can review what was scanned — the submitter's identity, the number of files, when the job was created and completed, and what patterns were detected. The security officer may also download a preview of the sanitized files to verify the output.

When satisfied, the security officer clicks **Approve for Export**. At this point, Yossarian generates an **approval attestation** — a digitally signed record that references the scan attestation and confirms the security officer reviewed and approved the export. This is **signature #2**.

**Step 3 — Download & Share (Technical Staff)**
The original submitter returns to **My Jobs** and sees the job is now marked as "Approved." They download the sanitized ZIP file — this is the clean file that gets shared with the external party. The attestations (signatures) remain in the system as internal audit records and are not included in the download.

---

## Two Signatures, Not One

The system produces two independent signatures that form a chain:

| Signature | Created When | Created By | What It Proves |
|-----------|-------------|------------|----------------|
| Scan Attestation | At scan completion | The system (automatically) | "These files were scanned by Yossarian" |
| Approval Attestation | At approval | Security officer (manually) | "I reviewed and approved these files for export" |

The approval attestation includes a hash of the scan attestation, creating a cryptographic chain. This means:

- If someone modifies the sanitized files after scanning but before approval, the scan attestation's file hash will not match — and the chain breaks.
- If someone modifies the scan attestation itself, the approval attestation's reference hash will not match — and the chain breaks.
- Neither attestation can be forged without the server's private key.

---

## Roles

### Who Can Upload and Scan?
Any authenticated user with the **user** or **admin** role can upload files and create sanitization jobs.

### Who Can Approve?
Only users with the **security-officer** role (or **admin** role) can access the Approval Queue and approve jobs. This role is assigned in Keycloak under the `yossarian-go` client roles.

To configure this:
1. Open Keycloak Admin Console
2. Navigate to your realm → Clients → `yossarian-go` → Roles
3. Create a role named `security-officer`
4. Assign this role to the appropriate users under their Role Mappings

### Can the Same Person Scan and Approve?
Technically, yes — if someone has both the user and security-officer roles. However, both attestations clearly record the identities involved, so auditors can verify whether dual attestation was properly followed. Your organization's policy should define whether self-approval is acceptable.

---

## The Attestations

### Scan Attestation

Created automatically when a job completes. Contains:

- **scanner** and **scanner_version** — which version of Yossarian performed the scan
- **scanned_by** — who submitted the files
- **scanned_at** — when the scan completed
- **total_files** — how many files were processed
- **detections** — counts of each type of sensitive content found and removed (IP addresses, passwords, tokens, etc.)
- **file_hash** — SHA-256 hash of the sanitized output ZIP, computed at scan time

The scan attestation is signed with the server's ECDSA private key. The signature file is stored alongside it.

### Approval Attestation

Created when a security officer approves a job. Contains:

- **approved_by** — the security officer's identity
- **approved_at** — when the approval occurred
- **role** — confirms the approver had the security-officer role
- **scan_attestation_hash** — SHA-256 hash of the scan attestation, linking this approval to that specific scan

The approval attestation is also signed with the server's ECDSA private key.

---

## Digital Signatures

### Why They Cannot Be Forged

The signatures are based on **ECDSA with the P-256 curve and SHA-256 hashing** — the same standard used in TLS certificates, code signing, and government systems. The security relies on a key pair:

- **Private key** — stored only in Yossarian's database, never exported, never leaves the server. Used to create signatures.
- **Public key** — freely distributable. Used to verify signatures.

Without the private key, it is computationally infeasible to create a valid signature. Even if someone obtains the signed files and the public key, they cannot produce a new signature that would pass verification.

### How Keys Are Managed

When the first approval is made, Yossarian automatically generates an ECDSA P-256 key pair. The private key is stored in the database and the public key is available for export through the UI or API.

If the database is ever lost or rebuilt, a new key pair is generated automatically. Old exports remain verifiable as long as the corresponding public key was saved. It is recommended to save the public key when it is first generated and store it alongside your security documentation.

### Exporting the Public Key

The public key can be obtained in two ways:

**From the UI:** Navigate to the Approvals panel and click **Load Public Key**. The key is displayed in PEM format with a Copy button.

**From the API:**
```
GET /api/signing-key/public
```

This returns the public key in PEM format along with its fingerprint and key ID.

---

## Verifying an Export

### Method 1 — Yossarian Verify Panel (Recommended)

The simplest way to verify. No technical knowledge required.

1. Log in to Yossarian
2. Open the **Verify** tab in the sidebar
3. Select the job you want to verify from the dropdown
4. Click **Verify**

The system performs all five checks server-side and displays clear pass/fail results:

| Check | What It Verifies |
|-------|-----------------|
| File Integrity | The output ZIP file exists and is readable |
| Scan Signature | The scan attestation is cryptographically signed by Yossarian |
| File Hash Match | The output file hash matches the value recorded at scan time |
| Approval Signature | The approval attestation is cryptographically signed |
| Chain of Custody | The approval attestation correctly references the scan attestation |

If all checks pass, you will see **ALL CHECKS PASSED** in green. If any check fails, the specific failure is highlighted with an explanation.

### Method 2 — Command-Line Verification (OpenSSL)

For advanced users or external auditors who want to verify independently. Requires OpenSSL and the public key.

**Prerequisites:**
- OpenSSL (available on Linux, macOS, and Windows via Git Bash or WSL)
- The public key from Yossarian (saved as `public.pem`)
- The attestation files downloaded from the Reports section in My Jobs

**Verify the scan attestation:**

```bash
# Decode the base64 signature
base64 -d scan-attestation.sig > scan-attestation.sig.der

# Verify the signature
openssl dgst -sha256 -verify public.pem -signature scan-attestation.sig.der scan-attestation.json
```

A successful verification prints: `Verified OK`

**Verify the approval attestation:**

```bash
base64 -d approval-attestation.sig > approval-attestation.sig.der
openssl dgst -sha256 -verify public.pem -signature approval-attestation.sig.der approval-attestation.json
```

**Verify the file has not been modified:**

```bash
sha256sum sanitized.zip
```

Compare the output with the `file_hash.value` field in `scan-attestation.json`. They should match exactly.

**Verify the chain of custody:**

```bash
sha256sum scan-attestation.json
```

Compare the output with the `scan_attestation_hash.value` field in `approval-attestation.json`. They should match exactly.

---

## What Gets Downloaded

The download button in My Jobs always provides just the **sanitized ZIP file** — the clean file ready to share externally.

The attestations (scan attestation, approval attestation, and their signatures) are internal audit documents. They are available from the **Reports** section of each job in My Jobs, but they are not included in the download and should not be shared with external parties.

| What | Where | Who Sees It |
|------|-------|-------------|
| Sanitized ZIP | Download button | External parties (vendors, support teams) |
| Scan Attestation + Signature | Reports section | Internal only (auditors, security officers) |
| Approval Attestation + Signature | Reports section | Internal only (auditors, security officers) |
| Public Key | Approvals panel | Anyone who needs to verify |

---

## Frequently Asked Questions

**Can I download files before they are approved?**
Yes. The sanitized ZIP is always available for download. However, before approval, there is only a scan attestation — no approval attestation exists yet.

**What happens if I lose the public key?**
You can always retrieve the current public key from Yossarian's UI or API. If the database was rebuilt and a new key was generated, the old public key is needed to verify old exports. It is good practice to save the public key when it is first generated.

**Can approvals be revoked?**
No. Once approved, the attestation is permanently signed. If a mistake is discovered, the recommended approach is to delete the job and re-process the files.

**Does the signature encrypt the files?**
No. The digital signature proves that the files were scanned and approved — it does not encrypt the content. If encryption is also required, apply it separately after download.

**What if two people need to approve?**
The current implementation supports a single approver. If your policy requires two approvals, this can be implemented in a future version.

**Is the private key exportable?**
No. The private key is stored in the database and is only accessible by the Yossarian server process. It cannot be downloaded through the UI or API. Only the public key is exportable.

---

## API Reference

For automation and CI/CD integration, the following endpoints are available:

| Endpoint | Method | Role Required | Description |
|----------|--------|---------------|-------------|
| `/api/jobs/approve` | POST | security-officer, admin | Approve a job and generate signed attestation |
| `/api/jobs/pending-approval` | GET | security-officer, admin | List all jobs awaiting approval |
| `/api/jobs/verify/{job_id}` | GET | Any authenticated user | Run all verification checks server-side |
| `/api/signing-key/public` | GET | Any authenticated user | Get the public verification key |

### Approve a Job

```bash
curl -X POST https://yossarian.example.com/api/jobs/approve \
  -H "Content-Type: application/json" \
  -H "X-API-Key: yoss_your_api_key_here" \
  -d '{"job_id": "batch-john.doe-20260331-141500"}'
```

### List Pending Approvals

```bash
curl https://yossarian.example.com/api/jobs/pending-approval \
  -H "X-API-Key: yoss_your_api_key_here"
```

### Verify a Job

```bash
curl https://yossarian.example.com/api/jobs/verify/batch-john.doe-20260331-141500 \
  -H "X-API-Key: yoss_your_api_key_here"
```

### Get Public Key

```bash
curl https://yossarian.example.com/api/signing-key/public \
  -H "X-API-Key: yoss_your_api_key_here"
```
