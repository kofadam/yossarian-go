# Claude Code project rules for yossarian-go

## Critical rules
- NEVER write or modify code without explicit permission from kof.
  This includes "small fixes", "obvious improvements", and bugs you spot
  during reviews. Note them, do not act on them.
- NEVER commit, push, or run git operations without explicit permission.
- ALWAYS use FIND/REPLACE blocks for proposed changes. Show exact
  existing code with surrounding context, then exact new code. Never
  rewrite entire functions or files.
- NEVER use `:latest` image tags or `imagePullPolicy: Always` in
  manifests. Always pin to explicit versions.
- ALWAYS use word-boundary matching in regex patterns to prevent false
  positives.

## Scope
- The Kubernetes manifests in this repo are SAMPLES. The production
  manifests are customer-confidential and not available. Do not
  recommend changes that assume production matches the samples.
- yossarian-go is a security-relevant log/code sanitization tool going
  to production after a 2-month beta. Findings should be actionable
  pre-launch, not theoretical.
- The sanitization contract is best-effort, not guaranteed. A "value
  slipped through" is not automatically a P0; a "tool silently failed
  while presenting output as successful" is.

## Workflow
- Use zsh syntax in any shell commands.
- Feature branches per task. Never commit directly to main.
- Ask before creating or modifying files. Never guess or assume.
- If something is unclear, ask kof rather than inferring.

## Key facts about the codebase
- Two binaries: main.go (frontend+worker, mode-selected) and db-service.go.
- Three actors: User, Security Officer, Admin.
- Trust model: anyone in the cluster namespace is trusted by design.
  db-service has no inbound auth on purpose.
- Project state is captured in docs/ARCHITECTURE-NEW.md (currently
  pending verification by Claude Code).
