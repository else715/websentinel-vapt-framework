# WebSentinel implementation roadmap

WebSentinel is an assessment workspace for security work on systems the operator is authorized to assess. The implementation is incremental: first establish scope and evidence handling, then add bounded scanner integrations, and only then expand reporting and deployment.

## Product guardrails

- Register a project and its authorized target scope before creating scan jobs.
- Keep scanner execution behind a project scope check and record the exact target, options, operator confirmation, timestamps, and result.
- Never build shell command strings. Invoke installed tools with argument arrays, strict timeouts, output limits, and a low-privilege account.
- Treat tool output as unverified observations. A human reviewer confirms findings and severity before a report calls them validated.
- Treat RAG output as a cited draft. Never let generated text alter finding status, invent evidence, or treat vulnerability presence as proof of adversary behavior.
- Bind the development server to localhost. Before shared or remote use, add authentication, CSRF protection, secure secret storage, and deployment isolation.
- Start with passive discovery and conservative scan profiles. Require a separate explicit action for active vulnerability checks.

## Milestones

### 0. Foundation and scope controls (1–2 days)

- FastAPI app, SQLite schema, configuration, health endpoint, local dashboard.
- Projects and targets with canonicalization, validation, and an explicit authorization acknowledgment.
- Audit trail for scope changes and scan-job creation.
- **Exit:** an operator can create a project, register an in-scope host, and see it persisted after restart.

### 1. MVP workflow (3–5 days)

- Target inventory, scan history, finding list, severity counts, and HTML report export.
- Job model with queued/running/completed/failed/cancelled states and normalized error handling.
- Report includes scope, timestamps, tools/options, raw-versus-validated status, findings, and remediation notes.
- **Exit:** an operator can manage a small assessment and export an honest report, including when no scanner is installed.

### 2. Passive discovery (3–5 days)

- Optional Subfinder integration for registered root domains; validate and de-duplicate returned hostnames.
- Optional httpx probing for discovered hosts, with conservative rate, timeout, and result caps.
- Store assets and provenance. Newly discovered hosts are candidates; they do not automatically expand scan scope.
- **Exit:** discovered assets are reviewable and must be explicitly approved into scope.

Implementation status: Subfinder jobs are scoped to a registered domain, use a five-minute limit and retain output. Results are candidate assets. httpx runs only over registered/approved targets with a low rate and private-IP exclusions. Both adapters record result state, output provenance, and target-specific inventory.

### 3. Bounded infrastructure and endpoint inventory (4–6 days)

- Nmap integration using a conservative scan profile and explicit approved host/IP scope.
- Technology and security-header inventory from HTTP responses.
- Optional Katana crawling with depth, request, duration, and same-origin limits.
- **Exit:** inventory results are reproducible, attributable to a job, and constrained to approved scope.

### 4. Vulnerability scanner adapters (5–8 days)

- Nuclei adapter first, initially limited to reviewed templates and conservative rate/time limits.
- ZAP baseline/passive mode next; active mode requires explicit per-job confirmation and a designated test environment.
- Normalize alerts while retaining original tool output and template/rule identifiers.
- **Exit:** scans cannot run without scope validation; alerts remain unverified until reviewed.

### 5. Validation and risk review (3–5 days)

- Finding lifecycle: unreviewed, confirmed, false positive, accepted, remediated, retest-needed.
- Severity and CVSS fields with source attribution; no automatic promotion of scanner alerts to confirmed issues.
- OWASP mapping is advisory and versioned. Manual assessment notes cover categories scanners cannot reliably establish.
- **Exit:** reviewers can explain and reproduce every reported confirmed issue.

### 6. Reporting and retest comparison (3–5 days)

- HTML reports, then optional PDF export after layout review.
- Compare assessment runs using stable finding fingerprints; show new, fixed, recurring, and changed findings.
- Evidence metadata and controlled file references; redact secrets and sensitive response data.
- **Exit:** reports clearly distinguish tool alerts from validated findings and summarize scope limitations.

### 7. Hardening and deployment (5–8 days)

- Authentication and role checks, CSRF protections, audit-log review, backup/migration strategy.
- Isolated worker processes/containers, egress controls, resource limits, scanner version pinning, and secret handling.
- Integration tests with local lab fixtures; deployment guide and recovery procedure.
- **Exit:** deployment checklist is met before exposing the service beyond localhost.

## Delivery sequence

Milestones 0–4 are implemented as local app workflows with scanner tools invoked only when installed and explicitly launched for approved targets. The RAG report-drafting foundation is also in place. Next, add mapping-pack version/update workflow, integration fixtures, authenticated scans, and deployment hardening.

### RAG report drafting (started alongside Milestone 1)

- Import Nuclei JSONL and OWASP ZAP JSON while retaining original output and a content hash.
- Retrieve from a curated, locally stored OWASP Top 10:2025 and ATT&CK mapping pack using SQLite keyword search.
- Ask a local Ollama model to draft summaries, remediation, and mapping rationales with retrieved source references.
- Keep all imports unreviewed. A vulnerability finding alone does not establish an ATT&CK technique; T1190 is only a conditional suggestion when confirmed evidence records observed exploitation.
- **Next:** broader parser coverage, mapping-pack update/version workflow, report citation polish, and integration fixtures.

## Initial data model

- `projects`: name, description, created timestamp.
- `targets`: project, canonical hostname/IP, target kind, authorization acknowledgment, in-scope flag, created timestamp.
- `scans`: project, target, scan type, state, options summary, timestamps, safe error summary.
- `findings`: scan, title, asset, severity, status, description, evidence reference, remediation, source.
- `scanner_imports`: scan, tool/format, filename, SHA-256, retained raw output, import timestamp.
- `mapping_documents`: versioned framework reference snippets and official source URLs used by local retrieval.
- `audit_events`: action, project/target references, timestamp, concise metadata.

## Estimates

For one developer, an MVP foundation and reporting workflow is roughly 1–2 weeks. A guarded, useful scanner platform is roughly 4–7 additional weeks depending on scanner integration and deployment requirements. Estimates exclude procurement, external authorization processes, and manual penetration testing.
