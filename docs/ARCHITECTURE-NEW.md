# yossarian-go architecture

This document describes what `yossarian-go` is, how it is built, and how it
behaves. It is grounded in the source as it exists in the repository at the
time of writing — every non-obvious claim is anchored to a file and line so
it can be verified mechanically. Where the code is internally inconsistent,
or where behavior differs from what the project's own documentation claims,
this document says so explicitly rather than smoothing it over.

This is a description, not a specification. It captures the system as it
*is*, not as it *should be*. Recommendations belong to the audit that
follows this document.

## 1. Purpose and scope

### 1.1 What yossarian-go is

`yossarian-go` is a log and source-code sanitization service. A user
uploads files (individual files or archives); the service detects sensitive
patterns (IP addresses, Active Directory accounts, JWTs, private keys,
passwords, API keys for several known providers, GPS coordinates,
caller-supplied keywords, organization-defined sensitive terms, internal
URLs); it replaces those patterns with placeholder values; it returns
the sanitized output along with reports describing what was replaced.

The service is designed to run inside a customer's Kubernetes cluster,
behind a corporate identity provider (Keycloak/OIDC), with optional
integration to Active Directory for richer AD-account substitution.

### 1.2 What it promises (and what it does not)

The sanitization contract is **best-effort**. The service does not
guarantee that every sensitive value in the input is detected and removed.
The user is expected to review output before sharing it externally. The
detection rules are pattern-based (regex), not semantic, and are tuned for
the customer's most common log and code formats.

The service additionally produces **post-hoc verifiable attestations**: a
scan attestation signed at job completion describing what was processed
and what was detected, and an approval attestation signed by a security
officer when a job is approved. These are **records**, not gates: a user
can download a sanitized output before approval, and approval after the
fact does not change what is downloadable. The attestations exist so that
later questions ("was this file sanitized? by whom? when? was the export
authorized?") can be answered cryptographically.

### 1.3 Scope of this document

In scope: the two Go binaries (`main.go`, `db-service.go`), the front-end
SPA (`index.html`, `admin.html`), and the sample Kubernetes manifests in
the repository.

Out of scope: the production Kubernetes manifests (which are
customer-confidential and not in this repository), the surrounding
cluster configuration (Keycloak realm definitions, Contour `HTTPProxy`
policies, Loki/Prometheus pipelines), and the AD/LDAP source-of-truth.
Where production behavior depends on platform configuration that is not
in this repo, this document says so and does not attempt to characterize it.

## 2. Actors and trust boundaries

### 2.1 Human actors

The system recognizes three human actor classes:

- **User.** Uploads logs or code, downloads sanitized output, downloads
  reports for their own jobs.
- **Security Officer.** Approves completed jobs. Approval produces a
  signed approval attestation; it does not gate download.
- **Admin.** Operates the system: manages organization-level sensitive
  terms, manages API keys, triggers AD/LDAP sync, configures
  organization settings.

### 2.2 Non-human principals

These are not actors in the threat-model sense (they are not adversaries),
but they are distinct trust principals that this document refers to by
name throughout:

| Principal | What it does | How it authenticates outbound |
|---|---|---|
| `yossarian-frontend` | Serves the SPA, terminates user requests, runs the regular-path sanitization pipeline, calls `db-service` and MinIO | API key / OIDC token verification with Keycloak; plain HTTP to db-service |
| `yossarian-worker` | Runs the batch sanitization pipeline | Plain HTTP to db-service; MinIO credentials from secret |
| `yossarian-db-service` | Owns the SQLite database; performs LDAP sync; mediates structured-data access | LDAP bind to AD DC (configurable); no inbound auth (see 2.3) |
| `MinIO` | Object storage for archives, outputs, reports, and attestation files | Static access key/secret |
| `Keycloak` | Identity provider for OIDC | N/A (it is the IdP) |
| `AD-sync CronJob` | Periodically POSTs to db-service to refresh the AD-account cache | Same network trust as everything else in the namespace |

### 2.3 Trust boundaries

There are three trust boundaries in this system:

1. **The cluster ingress.** Everything outside is untrusted; everything
   reaching the `yossarian-frontend` pods through Contour is the
   external-attacker-or-legitimate-user surface.

2. **The user's identity claim.** Once a request crosses the ingress with
   a valid session cookie or API key, the principal it represents (the
   `username` claim) is taken as authoritative. There is no
   request-level re-verification against Keycloak after session
   establishment.

3. **The Keycloak boundary.** OIDC token signatures are verified at
   callback time (`main.go:868`). Token claims, including `roles`, are
   trusted thereafter for the lifetime of the local session.

What is **not** a boundary, by design (per project intent confirmed by the
maintainer):

- The Kubernetes namespace. Anything reachable inside `yossarian-go`'s
  namespace is trusted. `db-service` does not authenticate inbound
  requests; MinIO is reachable on its cluster service; the AD-sync
  CronJob simply POSTs.
- The frontend ↔ worker boundary. They run the same binary in
  different modes (`MODE=frontend` vs `MODE=worker`), share access to
  MinIO and db-service, and route registration is identical
  (`main.go:5172-5239` is unconditional). A worker pod also exposes the
  full HTTP UI surface; it is simply not behind the ingress.

The implication of (2.3) is that the security of the system rests on
network-level isolation of the namespace, which must be enforced by the
platform (NetworkPolicy or equivalent). The repository's sample manifests
do not include such a policy.

## 3. Components and their responsibilities

### 3.1 Frontend pod (`MODE=frontend`)

- Serves the SPA (`/`, `homeHandler` at `main.go:3061`).
- Terminates user requests for upload, download, listing, approval,
  verification, admin operations.
- Performs OIDC code exchange and session establishment.
- Performs sanitization on the **regular path** (in-process, see §4).
- Verifies attestation signatures (`jobVerifyAPIHandler`,
  `main.go:3764`).
- Proxies admin operations to `db-service` (e.g. `proxySensitiveAdd`,
  `main.go:2932`).

Sample deployment uses `replicas: 3` (`07-frontend.yaml:30`). All session
state lives in process-local maps (`adminSessions`, `sessionUsers`,
`sessionRoles`, `sessionTokens`, `sessionTokenExpiry` at
`main.go:91-95`). HTTPProxy uses cookie-based session affinity
(`09b-httpproxy.yaml:22-29`) to keep a user pinned to one pod for the
session's lifetime.

### 3.2 Worker pod (`MODE=worker`)

Same binary, same registered routes; the only mode-conditional code is
the worker startup at `main.go:5242-5263`. It starts:

- `startBatchWorker` (`main.go:4457`): a 5-second polling loop that
  asks `db-service` for the next queued job (`/batch/next`) and
  processes it via `processBatchJobFromMinIO` (`main.go:4496`).
- `cleanupOldJobsWorker` (`main.go:4842`): runs every 6 hours, deletes
  MinIO objects and database rows for old jobs.

There is no per-pod concurrency. Inside one worker pod,
`processBatchJobFromMinIO` runs jobs serially (the polling loop is a
single goroutine). Horizontal scaling is achieved by running multiple
worker replicas, which compete via the database for the next queued job.

### 3.3 db-service pod

Single-replica deployment (`06-db-service.yaml:29`) on a ReadWriteOnce
PVC. Owns:

- The SQLite database at `/data/yossarian.db` (`db-service.go:26`).
- Tables: `ad_accounts`, `sensitive_terms`, `org_settings`,
  `batch_jobs`, `api_keys`, `signing_keys` (`db-service.go:48-104`).
  Schema is created with `CREATE TABLE IF NOT EXISTS`; column additions
  are handled by repeated `ALTER TABLE ADD COLUMN` migrations
  (`db-service.go:112-130`) whose errors are tolerated when they
  indicate the column already exists.
- LDAP bind credentials and the LDAP sync logic (`syncLDAPAccounts`,
  `db-service.go:186`).
- ECDSA signing keys (loaded into `main.go` on first use, see §7.5).

`db-service` exposes 35 HTTP routes on port 8081 (`db-service.go:1674-1714`).
None authenticate the inbound caller. Trust is namespace-scoped.

### 3.4 MinIO

Object storage for:

- Job inputs: `{username}/{job_id}/input.zip`
- Job outputs: `{username}/{job_id}/output.zip`
- Reports: `{username}/{job_id}/reports/{file}` where `{file}` is one of
  `ip-mappings.csv`, `summary.json`, `detailed-report.csv`,
  `scan-attestation.json`, `scan-attestation.sig`,
  `approval-attestation.json`, `approval-attestation.sig`.

The bucket is created on first use if absent (`ensureBucket`,
`main.go:4278`). The deployment uses static access-key/secret-key
credentials from Kubernetes secrets.

### 3.5 Topology

```
            ┌──────────────────────────────────────────────────┐
            │ Cluster ingress (Contour HTTPProxy, TLS, cookie  │
            │ session affinity, 300s timeouts)                 │
            └──────────────────────────────────────────────────┘
                                │
                                ▼
            ┌──────────────────────────────────────────────────┐
            │ yossarian-frontend ×3                            │
            │  - Serves SPA, regular-path sanitization,        │
            │    verify endpoint, admin proxies                │
            │  - Per-pod in-memory session/AD/IP state         │
            └──────────────────────────────────────────────────┘
                       │                        │
                       │ HTTP (no auth)         │ S3-compat
                       ▼                        ▼
            ┌──────────────────────┐  ┌────────────────────────┐
            │ yossarian-db-service │  │ MinIO                  │
            │  SQLite on RWO PVC   │  │  RWO PVC               │
            │  AD/LDAP outbound    │  │  {user}/{job}/...      │
            └──────────────────────┘  └────────────────────────┘
                       ▲                        ▲
                       │ HTTP                   │ S3-compat
                       │                        │
            ┌──────────────────────┐            │
            │ yossarian-worker ×N  │────────────┘
            │  Batch pipeline      │
            │  Cleanup task        │
            └──────────────────────┘

            ┌──────────────────────┐
            │ AD-sync CronJob      │── HTTP POST ──▶ db-service
            │  Daily 01:00         │
            └──────────────────────┘
```

## 4. The two sanitization paths

This is the most important section in the document. The service implements
sanitization twice, by two different code paths, with two different
security postures. Both paths are wired up in the production routes; both
are reachable from the SPA.

### 4.1 The batch (archive) path

**Trigger.** A user uploads a file with extension `.zip`, `.tgz`, or
filename ending in `.tar.gz`, while running in `MODE=frontend`
(`main.go:2079-2196`).

**Flow.**

1. The frontend pod streams the archive bytes to MinIO at
   `{username}/{job_id}/input.zip`.
2. The frontend pod creates a `batch_jobs` row in db-service with
   `status='queued'`, recording username, file count, scan mode, and
   detailed-report flag.
3. The frontend returns immediately with the job ID.
4. A worker pod's polling loop picks up the queued job via
   `/batch/next` and calls `processBatchJobFromMinIO`.
5. The worker downloads the archive, extracts it (zip or tar.gz, both
   in-memory), iterates files, calls `sanitizeText` or `sanitizeCodeFile`
   on each, writes the sanitized content into a new in-memory zip
   (`main.go:4651-4735`), uploads `output.zip` to MinIO.
6. The worker generates and uploads the IP-mappings CSV, the summary
   JSON, and (if requested) the detailed-replacement CSV.
7. The worker computes the SHA-256 of `output.zip`, calls
   `generateScanAttestation` to produce a JSON attestation including
   that hash, signs it with the ECDSA private key, and uploads both
   the JSON and the base64 signature to MinIO.
8. The worker calls `db-service` to set `status='completed'`. The
   db-service `jobUpdateHandler` simultaneously sets
   `approval_status='pending'` (`db-service.go:935`).

**Auth on upload:** session cookie or API key with `write` scope
(`main.go:1992, 2014`).

**Auth on download (`jobDownloadHandler`, `main.go:3174`):** session
cookie or API key with `read` scope, plus an ownership check
(`username == jobInfo.Username` or has `admin` role/scope,
`main.go:3241`). **Approval status is not consulted.**

**Auth on report download (`jobReportsDownloadHandler`,
`main.go:3284`):** same — session/API key + ownership; approval not
consulted.

### 4.2 The regular path

**Trigger.** A user uploads anything that is not a `.zip` / `.tgz` /
`.tar.gz` archive — including a single `.log` file or a code file
(`main.go:2199` onward).

**Flow.**

1. The frontend pod reads each file in-process, calls `sanitizeText` or
   `sanitizeCodeFile` on the contents.
2. Sanitized output is stored in **process-global** maps:
   `lastSanitizedContent` (string), `lastSanitizedFilename` (string),
   `lastSanitizedFiles` (`map[string]string`)
   (`main.go:88-90, 2205-2207`).
3. The HTTP response returns rendering data to the SPA. The SPA then
   renders download links pointing at the global-state endpoints
   (`index.html:3332, 3341, 4013, 4022`).

**Auth on upload:** same as batch path — session cookie or API key.

**Auth on download:** **none.** Four endpoints serve from the global
state:

| Endpoint | Handler | What it returns | Auth |
|---|---|---|---|
| `/download/sanitized` | `downloadAllZipHandler` (`main.go:2420`) | All `lastSanitizedFiles` as a zip | None |
| `/download/sanitized/single` | `downloadHandler` (`main.go:2351`) | `lastSanitizedContent` | None |
| `/download/sanitized/{filename}` | `individualFileHandler` (`main.go:2476`) | `lastSanitizedFiles[filename]` | None |
| `/download/detailed-report` | `downloadDetailedReportHandler` (`main.go:2362`) | `detailedReplacements` (CSV including original pre-sanitization content) | None |

Each of these handlers reads a cookie *only* to attribute a username for
audit logging (`main.go:2422-2429`); absence of a cookie produces an
"anonymous" log entry and proceeds with the request. There is no
ownership check, no completion check, no approval check, and no rejection
path on auth failure. Whichever frontend pod the request lands on returns
that pod's last-processed regular-path data.

### 4.3 Why both exist; what posture differences look like

The regular path predates the batch path. The regular path was the
original synchronous-upload-and-respond flow; the batch path was added
to support large archives without holding the HTTP connection open for
minutes. Both code paths still exist; nothing in the code retires the
regular path when the batch path is taken.

Practical posture summary:

| Property | Batch path | Regular path |
|---|---|---|
| Persistence | MinIO, namespaced per `{user, job_id}` | Process-global, last-write-wins |
| Cross-pod consistency | Yes (object store) | No (per-pod state) |
| Cross-user isolation | Yes (path-prefix + ownership check) | No (any caller wins) |
| Cleanup | Worker, 8h after completion (see §8.3) | None; lives until pod restart or next overwrite |
| Auth on download | Yes (session/API key + ownership) | No |
| Attestation generated | Yes (scan + approval) | No |
| Detailed report sensitivity | Same content, served only to owner | Same content, served to anyone |

The detailed report on the regular path is the highest-sensitivity output
in the system, because it contains pre-sanitization values verbatim
alongside the sanitized replacements. It is served unauthenticated.

## 5. Authentication and authorization

### 5.1 Three identity sources

**OIDC (Keycloak).** Initiated at `/auth/oidc/login` (`main.go:819`),
completed at `/auth/oidc/callback` (`main.go:835`). The callback verifies
the ID token signature against Keycloak's published keys
(`main.go:868-873`), extracts `preferred_username`, `email`, `name`, and
roles from `resource_access.yossarian-go.roles` (preferred) or
`realm_access.roles` (fallback) (`main.go:880-906`). A new session is
created with an 8-hour `Yossarian` expiry independent of the Keycloak
token expiry (`main.go:921`); both expiries are stored
(`main.go:925-929`) and the earlier of the two terminates the session.

**Password.** A single-string password held in the `ADMIN_PASSWORD`
environment variable, with a hard-coded fallback of `"admin123"` in
`main.go:5165`. Compared at `main.go:2760` with the `==` operator (not
constant-time). On match, a 30-minute session is created with hard-coded
roles `["admin", "user"]` (`main.go:2766`). Password authentication is
intended for single-user mode (`OIDC_ENABLED=false`).

**API key.** A header `X-API-Key` validated by db-service via a SHA-256
hash lookup against the `api_keys` table (`db-service.go:1582-1591`).
Validation returns `username` and a comma-separated `scopes` string
(typically `"read,write"` or `"admin"`). `validateAPIKey`
(`main.go:1091`) makes a fresh HTTP request to db-service for every
authentication; results are not cached.

### 5.2 Two role vocabularies

OIDC and password sessions use **roles** (`admin`, `user`,
`security-officer`, etc., as defined in Keycloak). API keys use
**scopes** (`read`, `write`, `admin`). These vocabularies are reconciled
ad-hoc per handler:

| Handler | OIDC/password check | API-key check |
|---|---|---|
| `uploadHandler` | session present | scope `write` |
| `jobDownloadHandler` | session present, owner-or-`admin` role | scope `read`, owner-or-`admin` scope |
| `jobReportsDownloadHandler` | session present, owner-or-`admin` role | scope `read`, owner-or-`admin` scope |
| `jobApproveAPIHandler` | role `security-officer` or `admin` | (same `hasRole` check; will fail for API keys, see below) |
| `jobVerifyAPIHandler` | session present | scope check absent (any valid key) |
| `adminRequired` (admin proxies) | `isValidAdminSession` | not supported |

The asymmetry on `jobApproveAPIHandler` is worth noting: the role check
at `main.go:3561` is `hasRole(r, "security-officer") || hasRole(r, "admin")`.
`hasRole` reads roles from `sessionRoles[cookie.Value]`
(`main.go:1064-1081`); it has no knowledge of API-key scopes. An API
key with scope `admin` cannot approve a job; only an OIDC session with
the right role can. Whether this is intentional is unclear from the code.

A second asymmetry: a password-login admin is granted `["admin", "user"]`
unconditionally (`main.go:2766`). The role `security-officer` is never
granted to a password admin, but the `|| hasRole(r, "admin")` clause
means a password admin can approve any job. Combined with the absence
of a separation-of-duties check, this means a password admin who also
happens to be the uploader can approve their own job (see §7.7 for the
proposed remediation).

### 5.3 Session storage

All session state is in five process-local Go maps protected by a single
`sessionMutex`:

```
adminSessions      map[sessionID] -> expiry time
sessionUsers       map[sessionID] -> username
sessionRoles       map[sessionID] -> []role
sessionTokens      map[sessionID] -> raw OIDC ID token
sessionTokenExpiry map[sessionID] -> token expiry time
```

Consequences:

- Sessions do not survive a frontend pod restart.
- Sessions do not roam across frontend pods. The HTTPProxy session
  affinity (`09b-httpproxy.yaml:22-29`) is the load-balancer-side
  workaround. A cookie-affinity miss appears to the user as an
  unexpected logout.
- Memory grows with active sessions; there is no eviction other than
  the explicit `delete()` calls in `isValidAdminSession`.

### 5.4 What is unauthenticated

| Endpoint | Handler | Status |
|---|---|---|
| `/health` | `mainHealthHandler` | Intentional; for probes |
| `/metrics` | `promhttp.Handler` | Exposed on the same FQDN as the app via the HTTPProxy. Anyone reaching the ingress can scrape Prometheus metrics, including session counts, queue depth, AD cache hit rates, and per-pattern detection counts. |
| `/api/config` | `configLimitsHandler` | Returns upload limits |
| `/api/userinfo` | `userInfoHandler` | Returns the caller's identity if authenticated, an unauthenticated stub otherwise |
| `/api/org-settings/public` | `proxyOrgSettingsPublic` | Returns disclaimer text and docs URL — explicitly designed as public |
| `/api/tour/` | `tourContentHandler` | Returns onboarding content |
| `/debug` | `debugHandler` | Returns template metadata only (`main.go:1977-1983`) |
| `/download/sanitized` | `downloadAllZipHandler` | Regular-path output. See §4.2. |
| `/download/sanitized/single` | `downloadHandler` | Regular-path output. See §4.2. |
| `/download/sanitized/{filename}` | `individualFileHandler` | Regular-path output. See §4.2. |
| `/download/detailed-report` | `downloadDetailedReportHandler` | Regular-path detailed report. See §4.2. |
| `/clear-download-cache` | `clearDownloadCacheHandler` | Mutation of the regular-path global state |
| `/auth/oidc/login`, `/auth/oidc/callback` | OIDC handlers | Necessarily unauthenticated |
| `/admin/login` | `adminLoginHandler` | Necessarily unauthenticated |

The four regular-path download endpoints and the detailed-report
endpoint are unauthenticated by accident of the regular-path design, not
by intent.

## 6. Sanitization rules

### 6.1 Patterns

All patterns are regex-based, defined as package-level globals in
`main.go:526-589`. Detection produces both a count (in the per-job stats
map) and, optionally, an entry in the global `detailedReplacements`
slice.

| Category | Regex / approach | Replacement (log path) | Replacement (code path) |
|---|---|---|---|
| Private key blocks | `-----BEGIN[^-]*KEY-----[\s\S]*?-----END[^-]*KEY-----` | `[PRIVATE-KEY-REDACTED]` | A canned RFC-formatted placeholder (`safePrivateKey`) |
| JWT | `eyJ[A-Za-z0-9+/=]+\.[...]\.[...]` | `[JWT-REDACTED]` | A canned valid-shaped JWT (`safeJWT`) |
| Password (config / connection-string) | `(?i)(:([^:@\s]{3,50})@\|password["':=\s]+["']?([^"',\s]{3,50})["']?)` | `[PASSWORD-REDACTED]` (whole-match replacement) | Structure-preserving replacement that keeps the key/quote/separator and replaces only the value (`main.go:1576-1611`) |
| AD account | A complex regex matching `DOMAIN\user`, `user@dom`, `user$`, plus customer-specific server prefixes (`adRegex`, `main.go:529`) | Looked up via db-service `/lookup/`; replaced with USN if found, kept verbatim otherwise | Same |
| Server-prefix accounts | Built dynamically from `SERVER_PREFIXES` env, matched word-bounded | Same as AD account | Same |
| Sensitive terms | Built dynamically from `SENSITIVE_TERMS` env + `sensitive_terms` DB table | Per-term custom replacement, default `[SENSITIVE]` | Same |
| User words | From the `sensitive_words` cookie (comma-separated, 3+ chars) | `[USER-SENSITIVE]` | Same (passed in by the caller; in batch path, currently passed as `nil`, see §6.4) |
| IP address (IPv4) | `\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b` | `[IP-NNN]`, where NNN is sequentially assigned per unique IP and recorded in `ipMappings` (`main.go:1466-1487`) | Pseudo-random RFC 5737 TEST-NET-1 placeholder |
| Internal URL | `https?://(?:localhost\|127.0.0.1\|10.\*\|192.168.\*\|172.16-31.\*)...` | Replaced only in code mode (`main.go:1494-1511`); not redacted in log mode | `[INTERNAL-URL-REDACTED]` (or, in `replaceInternalURLPreservingPath`, structure-preserving) |
| AWS access key | `AKIA[0-9A-Z]{16}` | **Not detected in log mode** | `[AWS-KEY-REDACTED]` |
| AWS secret | Key/quote/value pattern around `aws_secret_access_key` etc. | **Not detected in log mode** | Structure-preserving replacement |
| Generic `*_secret` / `*_key` | `(?i)(jwt_secret\|...)["'\s:=]+["']?([^"'\s,]{10,100})["']?` | **Not detected in log mode** | Structure-preserving replacement |
| Stripe key | `sk_(live\|test)_[a-zA-Z0-9]{24,}` | **Not detected in log mode** | `[STRIPE-KEY-REDACTED]` |
| GitHub token | `ghp_[a-zA-Z0-9]{36}` | **Not detected in log mode** | `[GITHUB-TOKEN-REDACTED]` |
| Slack token | `xox[baprs]-[0-9a-zA-Z-]{10,80}` | **Not detected in log mode** | `[SLACK-TOKEN-REDACTED]` |
| OpenAI key | `sk-(?:proj-)?[a-zA-Z0-9]{32,}` | **Not detected in log mode** | `[OPENAI-KEY-REDACTED]` |
| SendGrid key | `SG\.[a-zA-Z0-9_-]{20,30}\.[a-zA-Z0-9_-]{40,50}` | **Not detected in log mode** | `[SENDGRID-KEY-REDACTED]` |
| GPS coordinates (decimal, DMS, geo URI, JSON object) | Multiple regex patterns | **Not detected in log mode** | `0.0000, 0.0000` (Null Island) |
| Hebrew text | Documented in project memory as TODO; **not implemented** | — | — |
| LDAP DN content | Documented in project memory as TODO; **not implemented** | — | — |

### 6.2 Path-specific coverage

The log path (`sanitizeText`, `main.go:1263`) and the code path
(`sanitizeCodeFile`, `main.go:1517`) are two separate ~250-line
functions with no shared core. They overlap in the categories above the
"Not detected in log mode" rows and diverge below. A change to a pattern
that should apply to both paths must be made in both places. The
post-processing on the password regex is one example of an existing
divergence: log mode replaces the entire match, code mode preserves
structure.

The log path does not detect provider-specific API keys or GPS
coordinates. If a log file contains a leaked AWS key, the key passes
through verbatim. This may be intentional (logs typically do not contain
literal API keys) but is undocumented in the user-facing material.

### 6.3 AD account lookup

The AD-account detection regex matches a wide superset of strings; the
db-service `/lookup/{account}` call distinguishes real AD accounts from
false positives (`db-service.go:385-400`). Lookups are cached
in-process in `adLookupCache` (`main.go:122`). The cache holds both
positive and negative results: a string identified as not-an-AD-account
is also cached, so it isn't re-queried for the rest of the job.

Critical concurrency note (`main.go:1264-1265`): `sanitizeText` acquires
`mapMutex` (the IP-mapping mutex) for the entire function duration,
including the network round-trip to db-service inside the AD callback.
The same mutex protects `ipMappings` and is used as a meta-lock around
all sanitization. Combined with the worker's serial job model, this
means a worker pod processes exactly one file at a time, with all
db-service round-trips serialized.

The AD cache is cleared at the start of each batch job
(`main.go:4506-4508`). It is not cleared in the regular path; entries
accumulate for the lifetime of the frontend pod.

### 6.4 User words and organization terms

Three distinct levers exist for adding patterns:

- **`SENSITIVE_TERMS` env / configmap**, loaded at process start
  (`loadSensitiveTerms`, `main.go:625`).
- **`sensitive_terms` DB table**, also loaded at process start, merged
  with the env-derived list. New terms added through the admin UI are
  written to this table by `db-service`. **The frontend caches the
  merged list at startup**; `loadSensitiveTermsFromConfigMap`
  (`main.go:698`) is the only mechanism for re-reading, and it is not
  called by any startup or runtime code path I can locate. New terms
  added by an admin take effect on the next pod restart.
- **`sensitive_words` cookie**, applied per-request as `userWords` in
  the regular path. In the batch path, `userWords` is passed as `nil`
  (`main.go:4680, 4682`); per-job custom keywords are not supported.

### 6.5 What "best-effort" means

The contract a user receives is:

- The detected categories above are searched for, with the regexes
  shown.
- Anything detected is replaced with the corresponding placeholder.
- Anything not matching the regex passes through unchanged.

The user is expected to inspect the output. The `detailed-report.csv`
serves as the primary inspection artifact: it lists every replacement
made, with line numbers and original content.

The contract does **not** include:

- Detection of structural sensitivity (e.g. tabular data where one
  column contains usernames without LDAP/AD format).
- Detection of obfuscated or encoded sensitive material (base64 of a
  password, a JWT split across lines).
- Detection of natural-language secrets ("my password is hunter2").
- Hebrew text or LDAP DN content embedded in log lines (planned per
  project memory; not implemented).

### 6.6 Code present but not active

`commentRegex` is declared at `main.go:533` (commented out) and
referenced once in a commented-out call at `main.go:1283`. It is dead
code suggesting comment-block redaction was once considered.

A duplicate `adCacheHits.Inc()` call exists at `main.go:1354-1355`
inside `sanitizeText`. AD cache hits are over-counted by a factor of
two in the log path. The code path has only one call.

## 7. The attestation system

### 7.1 Purpose

The attestation system produces post-hoc verifiable records of who
sanitized what and who approved its export. **It is a record-keeping
mechanism, not an access-control mechanism.** A user can download a
sanitized output before approval; approval after the fact does not
change download behavior. The attestations exist so questions about
provenance can be answered cryptographically months later.

This intent is not currently documented anywhere user-visible. The UI
surfaces a "pending approval" state and an "approval queue", which
together suggest gating; the code does not gate.

### 7.2 Scan attestation

Generated by the worker after `output.zip` is uploaded to MinIO
(`main.go:4817-4832`). Constructed by `generateScanAttestation`
(`main.go:256-301`). Contains:

| Field | Value |
|---|---|
| `type` | `"scan_attestation"` |
| `version` | `"2.0"` |
| `job_id` | The job ID |
| `scanner` | `"yossarian-go"` |
| `scanner_version` | `Version` constant compiled into the binary |
| `scanned_by` | The username that uploaded the job |
| `scanned_at` | RFC3339 timestamp at attestation generation |
| `total_files` | File count |
| `detections` | The full per-pattern stats map |
| `file_hash.algorithm` | `"SHA-256"` |
| `file_hash.value` | Hex SHA-256 of the entire `output.zip` |
| `signing_key.key_id` | The key ID (`yoss-{8-hex}`, derived from the public key SHA-256) |
| `signing_key.fingerprint` | `SHA256:{base64}` of the public key DER |

The JSON is then ECDSA-signed (P-256) over its SHA-256 hash
(`signManifest`, `main.go:237-253`). The signature is written as a
base64 string into a sibling `.sig` file in MinIO.

### 7.3 Approval attestation

Generated when a security officer approves a job
(`jobApproveAPIHandler`, `main.go:3545-3694`). Constructed by
`generateApprovalAttestation` (`main.go:304-349`). Contains:

| Field | Value |
|---|---|
| `type` | `"approval_attestation"` |
| `version` | `"2.0"` |
| `job_id` | The job ID |
| `approved_by` | The username from the approver's session |
| `approved_at` | RFC3339 timestamp |
| `role` | `"security-officer"` (literal) |
| `scan_attestation_hash.algorithm` | `"SHA-256"` |
| `scan_attestation_hash.value` | Hex SHA-256 of the scan attestation JSON, **as currently stored in MinIO at approval time** |
| `signing_key.*` | Same as scan attestation |

The hash chain in `scan_attestation_hash` is the only mechanism
linking the approval to a specific scan. If the scan attestation
file is missing from MinIO at approval time (e.g. a job that predates
dual-attestation), an empty `{}` is hashed instead
(`main.go:3633-3634`), producing an approval attestation that does not
chain to anything. The approval is still recorded as `signed: true`
in the response.

### 7.4 Verify endpoint

`jobVerifyAPIHandler` (`main.go:3764-4037`) performs five checks and
returns a structured result:

| Check | What it does | Failure mode |
|---|---|---|
| `file_integrity` | SHA-256 of `output.zip` from MinIO | `failed` if MinIO read errors; `skipped` covers no other case |
| `scan_signature` | ECDSA verify of scan attestation against current public key | `failed` if signature invalid; **`skipped` if any intermediate read or decode fails silently** |
| `file_hash_match` | Compare computed hash with `file_hash.value` from attestation | `failed` if mismatch; `skipped` if either input absent |
| `approval_signature` | ECDSA verify of approval attestation | Only run if `approval_status='approved'`; otherwise `skipped` |
| `chain_integrity` | Compare current scan-attestation hash with `scan_attestation_hash.value` from approval | Same conditional as above; `failed` if mismatch |

The aggregate `overall` is computed (`main.go:4003-4023`) as:

- `passed` if all checks (incl. approval-related, when applicable) are `passed`.
- `failed` if any check is `failed`.
- `partial` otherwise — i.e. when any check is `skipped` and none is
  `failed`.

The `partial` state is reachable through silent intermediate failures
inside the verify handler: if MinIO returns an error when fetching the
signature file, or if base64 decoding fails, or if the signing-key load
fails, the handler reaches `else { /* nothing */ }` branches
(`main.go:3904-3909`) that leave the check as `"skipped"`. A
verify call against a corrupted or partially-deleted attestation will
return `overall: "partial"` rather than `failed`. A reviewer who
glances at the UI may misread this as a soft warning.

The verifier fetches the signing key via `getOrCreateSigningKey`, which
returns the **private** key (`main.go:3879, 3949`). Verification only
needs the public key. The private key is being retrieved on a
verification path.

### 7.5 Signing key lifecycle

A single ECDSA P-256 keypair is used for the entire system. The key is
**lazily generated** the first time any pod (frontend or worker) calls
`getOrCreateSigningKey`. The flow is:

1. Acquire `signingKeyMutex`. If the in-memory `signingKey` is non-nil,
   return it.
2. GET `/signing-key/get` from db-service. If a key exists, parse the
   PEM, cache it, return.
3. Otherwise, generate a new ECDSA P-256 key. Encode private and public
   to PEM. Compute key ID as `yoss-` + first 8 hex chars of the public
   key SHA-256. POST `/signing-key/store` to db-service with the new
   keypair.
4. Cache locally and return.

**The `INSERT OR REPLACE` on storage** (`db-service.go:1110-1112`) is
the key concern. If two pods race on first-key-creation (e.g., a
frontend and a worker both starting up simultaneously, with db-service
returning 404 to both because no key exists yet), both will generate
distinct keys, both will POST `/signing-key/store`, and the second POST
silently overwrites the first. Any attestations the first pod signed
between its store and the second pod's overwrite would now verify
against a different key than the one in the database. The cached
private key in the first pod's memory remains usable for that pod's
lifetime, producing signatures that the verifier cannot validate.

The mutex `signingKeyMutex` is process-local; it does not coordinate
across pods.

The key has no rotation mechanism. The schema supports an `active`
column on `signing_keys` (`db-service.go:103`), but no code path
implements rotation: the `active` flag is set to 1 on insert and never
toggled. There is no user-facing rotation endpoint, no emergency
rotation procedure, no key escrow, no backup mechanism beyond the PVC
itself.

The PVC is RWO (`04-pvcs.yaml`) with a single-replica db-service. PVC
loss is signing-key loss, which is verifiability loss for every
attestation ever produced.

### 7.6 What approval enforces

Repeated for emphasis because it conflicts with what one would assume
from the feature name: **approval does not gate downloads.** The
approval workflow:

- Sets `approval_status` from `'pending'` to `'approved'` in the
  database.
- Generates and stores the approval attestation and signature.
- Logs `[APPROVAL]`.

It does not:

- Block any download endpoint.
- Block any report endpoint.
- Block any verify endpoint.
- Notify the user.
- Notify the uploader.

Every job is auto-marked `'pending'` on completion
(`db-service.go:935`). There is no path that produces a job which does
not require approval, because `db-service.go` writes that string
unconditionally as part of the status-to-completed transition.

### 7.7 Separation of duties

The approval handler does not check whether the approver and the
uploader are the same person (`main.go:3545-3694`). The maintainer's
intent is that this should be enforced. The check would be a comparison
of `username` (the approver, taken from the auth context) against
`jobInfo.Username` (the uploader, fetched from db-service). This is
not currently in the code.

## 8. Storage and data lifecycle

### 8.1 SQLite schema

Source: `db-service.go:48-104`, with column-level migrations at lines
112-130.

```
ad_accounts(account PK, usn)                 -- the AD lookup cache
sensitive_terms(id PK, term U, replacement, created_at)
org_settings(key PK, value, updated_at, updated_by)
batch_jobs(job_id PK, username, status,      -- status: queued|processing|
           total_files, processed_files,        completed|failed|cancelled
           created_at, started_at, completed_at,
           input_path, output_path,
           error_message,
           scan_mode, code_scan_mode,        -- added by migration
           generate_detailed_report,
           approval_status,                  -- none|pending|approved
           approved_by, approved_at,
           manifest_json, manifest_signature)
api_keys(id PK, key_hash U, key_prefix, name,
         username, scopes, created_at,
         expires_at, last_used_at, is_active)
signing_keys(key_id PK, private_key_pem,
             public_key_pem, created_at, active)
```

### 8.2 MinIO object layout

```
{username}/{job_id}/
  input.zip                          # original archive
  output.zip                         # sanitized archive
  reports/
    ip-mappings.csv                  # IP -> placeholder mapping
    summary.json                     # processing summary
    detailed-report.csv              # per-replacement record (if requested)
    scan-attestation.json            # signed scan record
    scan-attestation.sig             # base64 ECDSA signature
    approval-attestation.json        # signed approval record (if approved)
    approval-attestation.sig         # base64 ECDSA signature
```

The path-prefix convention (`{username}/{job_id}/`) is the only
isolation between users at the object layer. There is no MinIO-side
ACL: any caller with the bucket credentials can read any object. The
isolation is enforced exclusively in `main.go`'s download handlers.

### 8.3 Cleanup

`cleanupOldJobsWorker` (`main.go:4842-4897`) runs every 6 hours
(`main.go:5250`) and deletes:

- `{username}/{job_id}/input.zip`
- `{username}/{job_id}/output.zip`
- The `batch_jobs` row

It does **not** delete the `reports/` subdirectory. Attestations,
signatures, IP mappings, summaries, and detailed reports remain in
MinIO indefinitely. The retention claim in this codebase is mixed:
the log message says `"8-hour retention"` (`main.go:4843`); project
documentation has historically said `48-hour retention`. The actual
cutoff is **8 hours** (`main.go:4845`). Combined with the 6-hour
cleanup cadence, jobs persist between 8 and 14 hours.

`deleteFromMinIO` errors are not checked in cleanup (`main.go:4883-4884`).
A failed delete leaves orphaned MinIO objects whose `batch_jobs` row
has been removed. There is no orphan reaper.

In-process state on the regular path (`lastSanitizedContent`,
`lastSanitizedFiles`, `lastSanitizedFilename`, `detailedReplacements`)
is never cleaned up. It is overwritten on the next regular-path upload
to that pod, or freed when the pod is destroyed.

## 9. Configuration surface

### 9.1 Environment variables

| Variable | Default | Read by | Notes |
|---|---|---|---|
| `MODE` | `"frontend"` | main.go | `"frontend"` or `"worker"` |
| `PORT` | `"8080"` | main.go | |
| `ADMIN_PASSWORD` | `"admin123"` (hard-coded fallback in main.go:5165) | main.go | Default issued with logged warning |
| `MINIO_ENDPOINT`, `MINIO_ACCESS_KEY`, `MINIO_SECRET_KEY`, `MINIO_BUCKET`, `MINIO_USE_SSL` | various | main.go | `MINIO_BUCKET` defaults to `"yossarian-jobs"` |
| `WORKER_POLL_INTERVAL` | 5 (seconds) | main.go | |
| `MAX_TOTAL_UPLOAD_SIZE_MB` | 100 | main.go | |
| `MAX_FILE_SIZE_MB` | 50 | main.go | |
| `MAX_ZIP_FILE_SIZE_MB` | 10 | main.go | |
| `MAX_FILE_COUNT` | 10 | main.go | |
| `OIDC_ENABLED`, `OIDC_ISSUER_URL`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `OIDC_REDIRECT_URL` | unset | main.go | |
| `AUTO_SSO_ENABLED` | `false` | main.go | If true, anonymous home-page hits redirect to OIDC |
| `AD_SERVICE_URL` | `"http://yossarian-db-service:8081"` | main.go | |
| `CA_CERT_PATH` | unset | main.go | Custom CA bundle for outbound HTTPS |
| `LDAP_SERVER`, `LDAP_BIND_DN`, `LDAP_BIND_PASSWORD`, `LDAP_SEARCH_BASE` | unset | db-service.go | |
| `LDAP_SYNC_INTERVAL` | 3600 (seconds) | db-service.go | Read but unused (LDAP sync is manual/cron-driven, see §3.3) |
| `DC_CA_CERT_PATH` | unset | db-service.go | CA for LDAPS |
| `SENSITIVE_TERMS` | unset | main.go | Comma-separated, merged with DB terms at startup |
| `SERVER_PREFIXES` | unset | main.go | Comma-separated; used to build `serverRegex` for AD-account-style server names |

### 9.2 ConfigMap-driven settings

The sample `02-configmaps.yaml` provides all of the above except
secrets. `02-configmaps-tour.yaml` provides the onboarding tour content
served at `/api/tour/`. `custom-ca-bundle` is a separate ConfigMap
mounted at `/etc/ssl/certs/ca-bundle.crt` for Keycloak and DC TLS.

The maintainer has noted (project memory) that in production these
values come from ConfigMaps that allow no-rebuild updates. In code, this
is true for the values listed above only; `SENSITIVE_TERMS` is read at
startup and the cached merged list does not refresh — see §6.4.

### 9.3 Secrets and their default values in samples

The sample `03-secrets.yaml` ships with:

- `ADMIN_PASSWORD: "Yossarian123"`
- `LDAP_BIND_PASSWORD: "changeme"`
- `OIDC_CLIENT_SECRET: "changeme"`
- `minio-secret.password: "changeme-minio-password"`

These are convenience defaults intended to be replaced before any real
deployment. The fallback in `main.go` is a different default
(`"admin123"`), which means an empty-secret `ADMIN_PASSWORD` produces a
different password than a missing-secret deployment.

### 9.4 What requires a restart vs hot-reload

- Restart required: every environment variable, the OIDC provider
  configuration, `SENSITIVE_TERMS`, `SERVER_PREFIXES`, the
  `custom-ca-bundle` ConfigMap (Go reads it once at startup).
- Hot reload via the admin UI: organization settings (disclaimer text,
  docs URL) are served fresh from db-service per request via
  `proxyOrgSettingsPublic`. Sensitive terms added through the admin UI
  are written to the database immediately, but the in-memory cache is
  not invalidated; new terms apply only after restart.

## 10. Deployment posture

### 10.1 Sample manifests vs production manifests

The Kubernetes manifests in this repository are **samples**. The
maintainer has indicated that the production manifests are
customer-confidential and not in this repo. Findings about manifest
content (default passwords, `imagePullPolicy: Always`, missing
`NetworkPolicy`, missing `securityContext`, no `runAsNonRoot`,
no `readOnlyRootFilesystem`) apply unambiguously to the samples. They
**may or may not** apply to the production manifests; this document
cannot characterize what it cannot see.

### 10.2 Container image lineage

Two Dockerfiles, both based on `golang:1.23-alpine` builders and
`alpine:latest` runtimes. Notable details:

- `Dockerfile:23` runs `go mod tidy` during the build. This can mutate
  `go.mod` and `go.sum` at build time, breaking reproducibility: a
  build today is not byte-identical to a build last week from the same
  commit.
- The frontend image installs `wget` (`Dockerfile:32`) which is not
  used by the running binary or the manifests' `httpGet` probes.
- Neither Dockerfile sets a `USER` directive; both run as root.
- Both images are tagged `:latest` by the build scripts and consumed
  via `imagePullPolicy: Always` in the sample manifests, defeating
  pinned-version determinism. The maintainer has noted this as a known
  anti-pattern (project memory).
- Versions disagree across artifacts: `main.go:72` declares
  `Version = "v0.13.0"`; `build.sh:4` defaults to `v0.7.0`;
  `build-db-service.sh:2` defaults to `v0.8.8`. The compiled-in
  `Version` is the only one used at runtime; the script defaults are
  overridden in practice by the first script argument.

### 10.3 Network exposure

A single HTTPProxy at `09b-httpproxy.yaml` exposes everything on the
frontend service under one FQDN with no path-level ACLs. `/metrics` and
`/debug` share the FQDN with the application. There is no separate
internal-only ingress for operational endpoints.

`db-service` and MinIO are `ClusterIP` services. There is no
NetworkPolicy in the sample manifests restricting which pods may talk
to them. With the per-maintainer trust model ("anyone in the cluster"),
this is consistent — but the trust assumption depends on the platform
or production manifests enforcing the namespace boundary, which this
repository does not characterize.

### 10.4 What we assume the platform provides

This document assumes, without proving, that the deployment
environment provides:

- Namespace isolation enforced by NetworkPolicy or equivalent.
- TLS termination at the ingress with a trusted certificate.
- Backups for the db-service PVC and the MinIO PVC.
- Monitoring and alerting on the Prometheus metrics surface.
- Image scanning and pinned image references in production manifests.

Where these assumptions fail, every "trust the namespace" decision
in this codebase becomes a security decision visible to anything that
can route into the namespace.

## 11. Failure modes

### 11.1 Sanitization failures

A regex that matches nothing produces a stat count of zero and silent
pass-through of any sensitive content the regex was supposed to catch.
The user-facing signal is the absence of a category in the report, not
a failure. False negatives are visible only on review.

A regex that matches too greedily (e.g., the AD-account regex matches
many strings that are not AD accounts) is mitigated by the db-service
lookup: a non-match leaves the original text in place. The cost is a
db-service round-trip per false-positive candidate.

`sanitizeText` and `sanitizeCodeFile` propagate no errors. Any panic
inside a regex callback (`ReplaceAllStringFunc`) would terminate the
goroutine, killing the request or job; standard Go HTTP-server recovery
applies but no application-level handler is registered.

### 11.2 Verification failures

Per §7.4: verification can return `partial` for genuinely failed
states. A user trusting only the `overall` field may interpret a
partial as benign.

Verification fetches the **current** signing key from db-service
(`main.go:3879, 3949`). If the key has rotated (which currently can
only happen via the `INSERT OR REPLACE` race in §7.5) all historical
attestations against the old key now report `failed` on
`scan_signature` and `approval_signature`, even though the original
signatures were valid.

### 11.3 db-service unavailable

- `validateAPIKey` returns an error; the caller treats this as
  authentication failure (`main.go:1142`). API-key auth fails open in
  no observed code path; failure is closed.
- AD-account lookup fails silently, returning empty string
  (`lookupADAccount` returning empty is the "not an AD account"
  signal). A db-service outage during sanitization causes all
  AD-account candidates to pass through verbatim — sensitive material
  may leak.
- Job creation fails; the upload returns a 500.
- Worker polling logs an error and retries on the next tick.
- Signing-key fetch fails; if the in-process cache is populated, signing
  continues. If the cache is empty, a new key is generated locally,
  and the `INSERT OR REPLACE` path becomes a possibility.
- Status updates (`updateJobStatus`) are best-effort and do not propagate
  errors to the caller; a database-stale-state can result.

### 11.4 MinIO unavailable

- Frontend uploads return 500 to the user.
- Worker job processing returns an error from the polling function;
  the job is marked `failed` via `/batch/{job_id}/fail`.
- Verification's `file_integrity` check is `failed` — but
  `scan_signature` may be `skipped`, leading to an `overall: partial`
  (see §7.4).
- Cleanup attempts proceed regardless; failed deletes are silent.

### 11.5 Pod restart and scale-zero

- All session state on a frontend pod is lost on restart. Affected
  users are silently logged out and must re-authenticate.
- All in-process AD cache, IP-mapping, and regular-path output state
  on a frontend pod is lost. Outstanding regular-path download links
  become 404 (because `lastSanitizedFiles` is empty after restart).
- Cookie-based session affinity may direct a returning user to a
  different pod after a restart, where their session does not exist.
- `db-service` is RWO; scaling to zero requires explicit scale-down
  (per maintainer's project memory) to avoid Multi-Attach errors.

### 11.6 Signing-key race

Described in §7.5. The collapse mode is silent: signatures are
produced, stored, and logged as success; verification later fails. The
gap between signing and the verification revealing the failure can be
arbitrarily long.

### 11.7 Concurrency model

A worker pod processes one batch job at a time. Within a job, files
are processed serially (`main.go:4667-4735`). The frontend serializes
all sanitization through `mapMutex` (§6.3), so simultaneous regular-path
uploads on a single frontend pod are processed in series.

`detailedReplacements` is a single process-global slice. Two
simultaneous regular-path uploads to the same frontend pod would
interleave their replacements, producing a corrupted detailed report.
The mutex on `detailedReplacements` prevents concurrent writes to the
slice itself but does not isolate the per-job logical content.

## 12. Observability

### 12.1 Prometheus metrics

Defined at `main.go:423-523`. All metrics are exposed at the
unauthenticated `/metrics` endpoint on the same FQDN as the app.

| Metric | Type | Labels | What it reveals |
|---|---|---|---|
| `yossarian_ad_cache_hits_total` | Counter | — | AD lookup cache effectiveness |
| `yossarian_ad_cache_misses_total` | Counter | — | Same |
| `yossarian_active_sessions` | Gauge | — | Concurrent active users |
| `yossarian_batch_jobs_total` | Counter | `status` | Job throughput by status |
| `yossarian_batch_job_queue_depth` | Gauge | — | Queue backlog |
| `yossarian_batch_processing_duration_seconds` | Histogram | — | Per-job processing time |
| `yossarian_batch_files_processed_total` | Counter | — | File volume |
| `yossarian_batch_patterns_detected_total` | Counter | `pattern_type` | **Per-category detection counts** |
| `yossarian_minio_operations_total` | Counter | `operation` | Object-store usage |
| `yossarian_minio_operation_duration_seconds` | Histogram | `operation` | Same |
| `yossarian_minio_operation_errors_total` | Counter | `operation` | Same |

The `batch_patterns_detected_total{pattern_type=...}` metric is the
most operationally useful and the most informative side-channel: an
external observer can infer which categories of sensitive content the
customer's data tends to contain, and watch real-time trends.

### 12.2 Logs

Logs go to standard output. Notable patterns:

- `[INFO]`, `[WARN]`, `[ERROR]`, `[DEBUG]` prefixes throughout `main.go`.
- `[AUDIT]` events on download handlers (regular path's audit logs use
  the literal username `"anonymous"` when no cookie is present).
- `[SECURITY]` events on cross-user access denials
  (`main.go:3242, 3355`).
- AD account lookups, IP replacements, and counts are logged at DEBUG
  when non-zero. The original account name is logged in the AD case.

The `[DEBUG]` log entries for AD account candidates (`main.go:1382-1383`)
include the candidate count but not the candidate strings; the per-replacement
record (`recordReplacement`) is held only in memory until the detailed
report is written.

### 12.3 Audit trail beyond log rotation

The `detailed-report.csv` is the durable per-job audit artifact. It
contains every replacement made, with category, file, line, original
value, and replacement. It is **stored in MinIO and not cleaned up**
(per §8.3, `reports/` is exempt from the cleanup task). The retention
policy on these files is therefore "indefinite", which has both audit
value (records preserved) and a privacy concern (the original
sensitive values are preserved in plaintext indefinitely, accessible
to anyone with MinIO credentials).

## 13. Open questions and known gaps

This section is the document's deliberate honesty: things that are
either incomplete, internally inconsistent, or undocumented in the
code itself.

**Hebrew text and LDAP DN redaction.** Project memory describes both
features as implemented. They are not implemented in the code in this
repository (verified by exhaustive grep across `main.go`, `db-service.go`,
and `index.html`). `sanitizeText` does not contain Hebrew Unicode-range
matching; it does not contain LDAP-DN line matching. The narrative
section of project memory and its TODO list disagree; the TODO list is
the truthful record.

**The regular path and the legacy download endpoints.** The maintainer
described these as dead code. They are not dead. The SPA links to them
from `index.html:3332, 3341, 4013, 4022`. They are reachable and
unauthenticated.

**Approval as record vs. approval as gate.** The code implements
record-keeping; the UI language ("pending approval", "approval queue")
suggests gating. Either the UI language needs to change or the code
needs to gate. Per the maintainer's stated intent, the UI language
should change.

**Separation of duties.** Confirmed missing by the maintainer.
`jobApproveAPIHandler` accepts approval from the uploader.

**Signing key rotation, escrow, and backup.** No mechanism exists.
The single-key, single-PVC, lazy-generation, `INSERT OR REPLACE` model
is the current state. The maintainer is open to changing this.

**`go mod tidy` in Dockerfile.** Reproducibility hole; `go.sum` at the
commit is not authoritative for what compiles.

**Default `:latest` tags and `imagePullPolicy: Always`.** Maintainer
has flagged this as a known anti-pattern in project memory; the build
scripts and sample manifests still encourage it.

**Three version sources.** `main.go`, `build.sh`, `build-db-service.sh`
each declare a different default version string.

**Mutex misuse.** `mapMutex` (declared as protecting `ipMappings`) is
acquired across the entire body of `sanitizeText`, including
network calls. The naming and the actual responsibility have drifted.

**Duplicate `adCacheHits.Inc()`.** `main.go:1354-1355`. Cache hit
metric is over-counted by 2× in the log path.

**`commentRegex` dead code.** `main.go:533, 1283`. Suggests an
abandoned feature.

**Two role vocabularies.** OIDC roles and API-key scopes do not
reconcile cleanly. `jobApproveAPIHandler` cannot be invoked with an
API key today, regardless of scope.

**Verifier silently degrades.** `jobVerifyAPIHandler` returns
`overall: partial` for states that include silent intermediate
failures, not just "not yet approved". The semantic of `partial` is
ambiguous.

**Cleanup retention.** Code says 8 hours; project memory says 48
hours; the worker log message says 8 hours. The code is the truthful
record.

**Reports are not cleaned up.** Per §8.3, `reports/` survives the
cleanup task. Including the `detailed-report.csv` containing original
sensitive values in plaintext, indefinitely, in MinIO.

**Manifest assumptions.** No NetworkPolicy, no Pod-level
`securityContext`, no `runAsNonRoot`, no `readOnlyRootFilesystem`, no
resource quotas in the sample manifests. Production may differ.

This list is not the audit. It is the set of things the document writer
believes the audit will need to address. The audit will produce the
prioritized findings.
