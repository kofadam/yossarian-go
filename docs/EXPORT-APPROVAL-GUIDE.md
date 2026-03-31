# Export Approval & Digital Signatures Guide

## Overview

Yossarian Go includes an export approval workflow that ensures every sanitized file leaving your organization has been reviewed and approved by an authorized security officer. Each approved export is accompanied by a digitally signed manifest that provides cryptographic proof of the approval chain.

This process satisfies the common enterprise requirement for **dual attestation** — one person prepares the files, a second person reviews and approves them before export.

---

## How It Works

### The Workflow

The export process follows three steps:

**Step 1 — Scan (Technical Staff)**
A team member uploads log files or source code to Yossarian. The system scans and sanitizes the files, removing IP addresses, usernames, passwords, tokens, and other sensitive information. Once processing completes, the job enters a "Pending Approval" state.

**Step 2 — Review & Approve (Security Officer)**
A security officer opens the **Approval Queue** in Yossarian's interface. They can review what was scanned — the submitter's identity, the number of files, when the job was created and completed, and what patterns were detected. The security officer may also download a preview of the sanitized files to verify the output.

When satisfied, the security officer clicks **Approve for Export**. At this point, Yossarian:
- Records the approver's identity and timestamp
- Computes a SHA-256 hash of the sanitized ZIP file
- Generates a manifest containing all scan and approval details
- Signs the manifest with the server's ECDSA private key
- Bundles everything together for download

**Step 3 — Download & Share (Technical Staff)**
The original submitter returns to **My Jobs** and sees the job is now marked as "Approved." The download button changes to **Download Approved Export**, and the resulting ZIP file now contains three items:

| File | Description |
|------|-------------|
| `sanitized.zip` | The sanitized files, ready to share externally |
| `manifest.json` | A record of who scanned, who approved, what was detected, and the file hash |
| `manifest.sig` | The digital signature proving the manifest is authentic |

The `sanitized.zip` is what gets shared with the external party. The `manifest.json` and `manifest.sig` serve as proof that the proper review process was followed.

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
Technically, yes — if someone has both the user and security-officer roles. However, the manifest clearly records both identities, so auditors can verify whether dual attestation was properly followed. Your organization's policy should define whether self-approval is acceptable.

---

## The Manifest

The manifest is a JSON file that captures the complete chain of custody. Here is an example:

```json
{
  "version": "1.0",
  "job_id": "batch-john.doe-20260331-141500",
  "scan": {
    "scanner": "yossarian-go",
    "scanner_version": "v0.13.22",
    "scanned_by": "john.doe",
    "scanned_at": "2026-03-31T14:20:00Z",
    "total_files": 45,
    "detections": {
      "ip_addresses": 128,
      "ad_accounts": 34,
      "passwords": 12,
      "jwt_tokens": 3,
      "private_keys": 0,
      "sensitive_terms": 7,
      "user_words": 0
    }
  },
  "approval": {
    "approved_by": "security.officer",
    "approved_at": "2026-03-31T15:05:00Z",
    "role": "security-officer"
  },
  "file_hash": {
    "algorithm": "SHA-256",
    "value": "a1b2c3d4e5f6..."
  },
  "signing_key": {
    "key_id": "yoss-1a2b3c4d",
    "fingerprint": "SHA256:abc123..."
  }
}
```

### What Each Section Means

**scan** — Records which version of Yossarian performed the scan, who submitted the files, when, how many files were processed, and what types of sensitive content were found and removed.

**approval** — Records who approved the export and when. The role confirms they had the authority to approve.

**file_hash** — A SHA-256 hash of the `sanitized.zip` file. If anyone modifies the ZIP after approval, the hash will no longer match, and the signature verification will fail.

**signing_key** — Identifies which key was used to sign the manifest. The key ID and fingerprint allow recipients to confirm they are verifying against the correct public key.

---

## Digital Signatures

### What Is Being Signed?

Yossarian uses **ECDSA with the P-256 curve and SHA-256 hashing** to sign the manifest. This is a widely supported, industry-standard algorithm used in TLS certificates, code signing, and government systems.

The signature covers the entire `manifest.json` file. This means any change to the manifest — altering the approver name, changing detection counts, modifying the file hash — will cause signature verification to fail.

### How Keys Are Managed

When the first approval is made, Yossarian automatically generates an ECDSA P-256 key pair:
- The **private key** is stored in Yossarian's database and never leaves the server
- The **public key** is available for export through the UI or API

If the database is ever lost or rebuilt, a new key pair is generated automatically. Old exports remain verifiable as long as the corresponding public key was saved (which is why distributing the public key to stakeholders is recommended).

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

Recipients of an approved export can verify its authenticity using standard tools. No access to Yossarian or your internal network is required — only the public key and the files from the export bundle.

### Prerequisites
- OpenSSL (available on Linux, macOS, and Windows via Git Bash or WSL)
- The public key from Yossarian (saved as `public.pem`)
- The three files from the approved export: `sanitized.zip`, `manifest.json`, `manifest.sig`

### Verification Steps

**1. Extract the approved export ZIP**

The downloaded file (e.g., `approved-batch-john.doe-20260331-141500.zip`) contains three files. Extract them into a folder.

**2. Decode the signature**

The signature file is base64-encoded. Decode it first:

```bash
base64 -d manifest.sig > manifest.sig.der
```

**3. Verify the signature**

```bash
openssl dgst -sha256 -verify public.pem -signature manifest.sig.der manifest.json
```

A successful verification prints:

```
Verified OK
```

If the manifest has been tampered with, or if the wrong public key is used, OpenSSL will print:

```
Verification Failure
```

**4. (Optional) Verify the file hash**

To confirm the sanitized ZIP hasn't been modified since approval:

```bash
sha256sum sanitized.zip
```

Compare the output with the `file_hash.value` field in `manifest.json`. They should match exactly.

---

## Frequently Asked Questions

**Can I download files before they're approved?**
Yes. The sanitized ZIP is always available for download. However, before approval, the download contains only the sanitized files — no manifest or signature is included. After approval, the download is a bundle containing the sanitized ZIP plus the signed manifest.

**What happens if I lose the public key?**
You can always retrieve the current public key from Yossarian's UI or API. If the database was rebuilt and a new key was generated, the old public key is needed to verify old exports. It's good practice to save the public key whenever it's first generated and store it alongside your security documentation.

**Can approvals be revoked?**
The current version does not support revoking an approval. Once approved, the manifest is permanently signed. If a mistake is discovered, the recommended approach is to delete the job and re-process the files.

**Does this replace file-level encryption?**
No. The digital signature proves that the files were scanned and approved — it does not encrypt the content. The sanitized files are readable by anyone who has them. If encryption is also required, apply it separately after download.

**What if two people need to approve?**
The current implementation supports a single approver. If your policy requires two approvals, this can be implemented in a future version. Contact the development team to discuss requirements.

**Is the private key exportable?**
No. The private key is stored in the database and is only accessible by the Yossarian server process. It cannot be downloaded through the UI or API. Only the public key is exportable.

---

## API Reference

For automation and CI/CD integration, the following endpoints are available:

| Endpoint | Method | Role Required | Description |
|----------|--------|---------------|-------------|
| `/api/jobs/approve` | POST | security-officer, admin | Approve a job and generate signed manifest |
| `/api/jobs/pending-approval` | GET | security-officer, admin | List all jobs awaiting approval |
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

### Get Public Key

```bash
curl https://yossarian.example.com/api/signing-key/public \
  -H "X-API-Key: yoss_your_api_key_here"
```
