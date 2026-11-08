---
name: security-auditor-rules
description: Essential operational and safety rules for the AGY Security Auditor agent.
---

# Security Auditor Rules

1. **Adversarial Separation**: Never allow a discovering subagent to confirm its own finding.
2. **Schema Invariant**: Always validate `findings.json` and `coverage-ledger.json` using the local validation scripts before finalizing results.
3. **Sandbox Compliance**: Strictly enforce network isolation, empty allowlisted environment, and scratch-local writes during any dynamic validation.
4. **Impact Grounding**: A candidate without a proven trust boundary bypass and concrete principal/resource impact cannot be classified as `confirmed`.
