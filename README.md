# AGY Security Auditor Project

An enterprise-grade security auditor agent project built for the Antigravity (AGY) ecosystem, implementing the **8-Component Harness² Specification** (Google Research / Northwestern University, arXiv:2610.14224) and seeded with the **[Cloudflare Security Audit Skill](https://github.com/cloudflare/security-audit-skill)**.

## Architecture: The 8-Component Harness²

This project structures agent capabilities into 8 modular, editable harness components:

| Component | File / Location | Description |
|-----------|-----------------|-------------|
| **1. System Prompt** | [`systemprompt.md`](./systemprompt.md) | Defines core security auditor persona, operating modes, and multi-phase lifecycle. |
| **2. Guardrails** | [`guardrails.md`](./guardrails.md) | Enforces execution safety, sandbox isolation, ethical boundaries, and write isolation. |
| **3. Memory** | [`LongTermMEMORY.md`](./LongTermMEMORY.md) | Persistent audit memory, fingerprint ledger, and multi-run incremental coverage. |
| **4. Tool Guidance** | [`tool_guidance.md`](./tool_guidance.md) | Usage protocols for file exploration, command running, subagent delegation, and validation. |
| **5. Subagents** | [`sub_agents/`](./sub_agents/) | Modular delegated agents (`reconnaissance`, `hunter`, `verifier`, `critic`, `reporter`). |
| **6. Skills** | [`skills/security-audit/`](./skills/security-audit/) | Cloudflare security audit skill and 14 attack-class & reconnaissance guides. |
| **7. Scripts** | [`scripts/`](./scripts/) | Zero-dependency validators (`validate-findings.cjs`, `validate-coverage-ledger.cjs`) and test runner. |
| **8. Plugins** | [`plugins/security-auditor/`](./plugins/security-auditor/) & [`plugin/`](./plugin/) | AGY plugin manifest, lifecycle hooks, and TypeScript configuration bindings. |

## Workflow Phases

The auditor executes a six-phase adversarial process:

```
[Phase 1: Reconnaissance] -> [Phase 2: Coverage-Led Hunting]
                                      │
[Phase 4: Structured Output] <- [Phase 3: Adversarial Validation]
       │
[Phase 5: Record Verification] -> [Phase 6: Target-Neutral Reporting]
```

1. **Reconnaissance**: Map architecture, trust boundaries, and input surfaces into `architecture.md` and `coverage-ledger.json`.
2. **Coverage-Led Hunting**: Dispatch isolated hunter agents to examine specific ledger units and attack classes.
3. **Candidate Validation**: Fresh, independent verifiers attempt to disprove candidate findings.
4. **Structured Output**: Produce machine-validated JSON records (`findings.json`).
5. **Independent Record Verification**: Fresh agents verify final source claims before publication.
6. **Reporting**: Generate target-neutral deliverables (`REPORT.md`, `FINDINGS-DETAIL.md`, `NEEDS-VALIDATION.md`).

## Quick Start & Verification

Run the complete validation and test suite (validators, Discord webhook formatter, lifecycle hooks, and Python SDK harness):

```bash
./scripts/run-audit.sh test
```

## Running an Audit

### 1. In AGY (CLI / IDE)
To trigger an audit within AGY, launch the agent in the target codebase:

```bash
# Guidance mode
"Analyze authentication flow in ./src/auth"

# Full audit mode
"Security audit this codebase, output to ./audit-results"
```

### 2. Portable Antigravity SDK Server Runner (`harness/`)
The runner can audit server service configurations (Docker/Compose, systemd units, Nginx/Caddy proxies, application repos) and dispatch Rich Embed reports to Discord via webhook:

```bash
# 1. Setup per-server environment and config
cp .env.example .env && chmod 600 .env
cp config/server-audit.example.yaml config/server-audit.yaml

# 2. Run offline dry-run (generates validated artifacts + Discord payload preview)
./scripts/run-audit.sh run-server-audit --config config/server-audit.yaml --dry-run

# 3. Run and dispatch report to Discord webhook
./scripts/run-audit.sh run-server-audit --config config/server-audit.yaml --send-discord
```

