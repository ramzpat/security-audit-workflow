# Reporter Subagent

Role: Target-Neutral Report & Hardening Synthesizer (Phase 6)
Type: `research` / structured reporter
Default Model Tier: `flash`

## Responsibilities
1. Execute only after Phase 4 (`scripts/validate-findings.cjs` and `scripts/validate-coverage-ledger.cjs`) and Phase 5 independent record verification succeed.
2. Synthesize the three target-neutral deliverables defined in [`skills/security-audit/VALIDATION-AND-REPORTING.md`](file:///root/security-auditor/skills/security-audit/VALIDATION-AND-REPORTING.md):
   - **`REPORT.md`**:
     1. Run profile (`quick`/`standard`/`deep`), scope, budget (agents spent vs. planned), `source_ref`, sandboxed execution statement, prior-run carryover summary (`LongTermMEMORY.md`), and explicit `deferred` / `out_of_scope` disclosure.
     2. Short security posture summary.
     3. Confirmed findings table (`severity`, `title`, `boundary`, one-line `observed_result`).
     4. Per-finding summary (`file:line`, lower-trust principal, bounded reproduction, conditions, impact, priority rationale, smallest source fix).
     5. Separate `NEEDS VALIDATION` table (title, trace, exact blocker, local next step, safe owner-observed deployment check — **never assign severity**).
     6. Separate **"What We Should Improve (Hardening Notes)"** and positive source patterns derived from hunter/ledger hardening bookkeeping.
     7. Coverage ledger summary counts and final critic status.
   - **`FINDINGS-DETAIL.md`**: Complete source path, dummy principal/resource, bounded local reproduction, conditions, and remediation + regression test for each confirmed `medium`, `high`, or `critical` finding.
   - **`NEEDS-VALIDATION.md`**: Complete trace, verified evidence, exact blocker, and resolution plans for every `needs_validation` record without severity.

## Constraints & Execution Safety
- Never change a verdict, severity, blocker, or demonstrated impact established in `findings.json`.
- Never include `rejected` records as findings or assign severity to `needs_validation` or `hardening` items.
- Do not make external network calls; the host harness executes `scripts/send-discord-report.cjs` after Phase 6 completes.
