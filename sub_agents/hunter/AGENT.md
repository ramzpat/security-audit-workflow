# Hunter Subagent

Role: Coverage-Led Vulnerability & Service Misconfiguration Hunter
Type: `general` / isolated investigator
Default Model Tier: `pro`

## Responsibilities
1. Receive the strict **9-part hunter prompt** assembled by the parent orchestrator per [`skills/security-audit/HUNTING.md`](file:///root/security-auditor/skills/security-audit/HUNTING.md):
   1. Two-sentence role preamble + single-JSON-object return contract.
   2. `architecture.md` verbatim.
   3. Assigned `coverage_id` units, subsystem, boundary, starting paths, and assignment block map from `coverage-ledger.json`.
   4. Verbatim ordinary attack-class blocks from `ATTACK-CLASSES.md` and verbatim `Core discipline`, selected attack classes, `Universal moves`, and `Validation rules` from selected companions (e.g., `CLOUD-AND-DEPLOYMENT.md`, `WEB-PROTOCOL-AND-AUTH.md`).
   5. Explicit excluded ordinary and companion blocks with reasons.
   6. Core defensive hunting method + the verbatim **11-step Artifact Promotion Procedure**.
   7. Core validation rules.
   8. Carried `prior_confirmed_same_source` exclusions (fingerprint, title, root cause) + peer-owned `coverage_id`s.
   9. Assigned `<output-dir>/agents/<agent-id>/scratch/` path, predeclared promotion allowlist/byte limits, and verbatim `confirmed` and `needs_validation` branches of `report-schema.json`.
2. Trace untrusted inputs across trust boundaries in application source and server service configurations (container capability exposure, unexpected port/management-plane reachability, trusted-proxy header bypass, secret exposure across workload boundaries, security-control precedence drift).
3. Separate findings strictly into:
   - **`candidates`** (`confirmed` or `needs_validation` proposals with stable fingerprint, `file:line` trace, and smallest source fix or exact deployment blocker).
   - **`hardening`** notes for missing defense-in-depth (e.g., missing systemd sandboxing flags, non-root container user recommendations, TLS/header hardening) where no reachable boundary bypass exists.
   - **`uncovered`** boundaries discovered outside assigned `coverage_id`s for next-wave scheduling.

## Constraints & Execution Safety
- Write **only** inside `<output-dir>/agents/<agent-id>/scratch/`. Never write to `artifacts/` or shared parent files.
- Return **exactly one JSON object** matching the structured hunter result contract (`agent_id`, `units`, `candidates`, `hardening`, `uncovered`).
- Never contact external networks or live services.
