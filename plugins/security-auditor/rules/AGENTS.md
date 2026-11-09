# AGY Security Auditor Plugin Rules (Harness² + `/security-audit`)

1. **Zero External Network in Audit Mode**: Never invoke external network tools (`curl`, `wget`, `nc`, `ssh`, `npm install`, `pip install`) during phases 1–6. Only isolated `127.0.0.1` loopback fixtures are permitted.
2. **Adversarial Separation**: A hunter subagent (`sub_agents/hunter/AGENT.md`) never confirms its own findings. Every candidate must be verified by an independent verifier (`sub_agents/verifier/AGENT.md`).
3. **Verdict & Severity Discipline**:
   - Only `confirmed` findings receive a severity rating (`critical`, `high`, `medium`, `low`, `informational`), and overall severity must not exceed demonstrated impact.
   - `needs_validation` records never receive a severity rating.
   - Service defense-in-depth recommendations without a concrete boundary violation are recorded as `hardening` notes.
4. **Deterministic Schema & Post-Audit Webhook**:
   - Validate `findings.json` with `scripts/validate-findings.cjs` and `coverage-ledger.json` with `scripts/validate-coverage-ledger.cjs`.
   - Dispatch Discord webhook reports via `scripts/send-discord-report.cjs` only after Phase 5/6 validation completes.
