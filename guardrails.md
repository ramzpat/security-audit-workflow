# AGY Security Auditor - Guardrails

These guardrails enforce non-negotiable safety policies, sandbox containment, and data integrity boundaries across all audit runs.

## 1. Execution Safety & Sandboxing
- **Network Isolation**: Absolute ban on external network calls. Only isolated loopback is permitted when validating local client-server interactions.
- **Environment Sanitation**: Empty allowlisted execution environments with dummy credentials and paths. Ambient host variables and secrets are never exposed to target processes.
- **Read-Only Target Source**: The repository under review is mounted or accessed read-only. Target-controlled builds/tests execute solely in assigned disposable scratch directories.
- **Resource Constraints**: Hard bounds on execution time, CPU, memory, child processes, file descriptors, and disk usage.

## 2. Benign Scope & Ethical Boundaries
- **No External Probing**: Never scan, probe, or interact with external servers, deployed production services, third-party APIs, or live control planes.
- **No Denial-of-Service / Exhaustion**: Never execute disruptive tests against shared hosts or production infrastructure.
- **Fictitious Credentials**: Use only dummy tokens, mocked certificates, and synthetic identities.

## 3. Write Isolation & File Ownership
- **Parent-Only State Ownership**: Only the parent orchestrator modifies canonical run state (`run-metadata.json`, `architecture.md`, `coverage-ledger.json`, `findings.json`, `REPORT.md`, `FINDINGS-DETAIL.md`, `NEEDS-VALIDATION.md`).
- **Subagent Scratch Isolation**: Subagents write exclusively inside their allocated directory `<output-dir>/agents/<agent-id>/scratch/`.
- **Artifact Promotion**: Promotion from scratch to retained artifacts is executed solely by trusted parent-side logic verifying path safety, link count, and byte boundaries.

## 4. Verdict Discipline & Anti-Hallucination
- **No Self-Confirmation**: A hunter subagent cannot mark its own candidate as `confirmed`.
- **Blocked Leads**: If an exploit candidate requires external services or unavailable sandbox capabilities to reproduce, classify it as `needs_validation` with the exact missing requirement.
- **Zero Checklist Inflation**: Missing best practices that have no direct exploit path or where upstream controls prevent abuse must be reported as hardening notes, not vulnerabilities.
