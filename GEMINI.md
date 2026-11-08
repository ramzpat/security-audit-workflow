# AGY Security Auditor Project Instructions

This project is configured as an AGY Security Auditor using the **8-Component Harness² Specification** and incorporating the **Cloudflare Security Audit Skill**.

## 8-Component Harness² Architecture
- **1. System Prompt**: Defined in [`systemprompt.md`](file:///root/security-auditor/systemprompt.md). Directs persona, adversarial stance, and multi-phase audit lifecycle.
- **2. Guardrails**: Defined in [`guardrails.md`](file:///root/security-auditor/guardrails.md). Enforces strict execution safety, zero external network access, read-only target source, and scratch-isolated write boundaries.
- **3. Memory**: Defined in [`LongTermMEMORY.md`](file:///root/security-auditor/LongTermMEMORY.md). Manages multi-run coverage ledgers, persistent finding fingerprints, and invariant caches across audits.
- **4. Tool Guidance**: Defined in [`tool_guidance.md`](file:///root/security-auditor/tool_guidance.md). Prescribes usage rules for inspection tools, subagent invocation, and validation scripts.
- **5. Subagents**: Defined in [`sub_agents/`](file:///root/security-auditor/sub_agents/):
  - [`reconnaissance`](file:///root/security-auditor/sub_agents/reconnaissance/AGENT.md): Architecture, trust boundary, and entry point mapping.
  - [`hunter`](file:///root/security-auditor/sub_agents/hunter/AGENT.md): Coverage-led vulnerability discovery across attack classes.
  - [`verifier`](file:///root/security-auditor/sub_agents/verifier/AGENT.md): Adversarial candidate validation and disproval.
  - [`critic`](file:///root/security-auditor/sub_agents/critic/AGENT.md): Audit coverage analysis and blind spot remediation.
  - [`reporter`](file:///root/security-auditor/sub_agents/reporter/AGENT.md): Target-neutral report synthesis (`REPORT.md`, `FINDINGS-DETAIL.md`, `NEEDS-VALIDATION.md`).
- **6. Skills**: Located in [`skills/security-audit/`](file:///root/security-auditor/skills/security-audit/SKILL.md) and exposed via `.agents/skills/`. Includes Cloudflare's complete attack classes and methodology guides.
- **7. Scripts**: Located in [`scripts/`](file:///root/security-auditor/scripts/):
  - `validate-findings.cjs` (schema validator)
  - `validate-coverage-ledger.cjs` (coverage ledger validator)
  - `run-audit.sh` (auditor runner and test harness)
- **8. Plugins**: Configured in [`plugins/security-auditor/`](file:///root/security-auditor/plugins/security-auditor/plugin.json) and [`plugin/security-auditor.ts`](file:///root/security-auditor/plugin/security-auditor.ts).

## Core Audit Workflow Rules
1. **Adversarial Verification**: Findings discovered by a hunter subagent MUST be independently verified by a fresh verifier subagent before confirmation.
2. **Deterministic Schema**: All audit outputs must strictly pass `scripts/validate-findings.cjs` and `scripts/validate-coverage-ledger.cjs`.
3. **Execution Safety**: Never execute target code with live network access or outside the designated scratch environment.
