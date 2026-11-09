# AGY Security Auditor - Long-Term Memory (Component 3)

The Long-Term Memory component maintains state continuity across multi-phase workflows, incremental server audit runs, and recurring assessments while implementing the prior-run rules from [`skills/security-audit/SKILL.md`](file:///root/security-auditor/skills/security-audit/SKILL.md) and [`RECONNAISSANCE.md`](file:///root/security-auditor/skills/security-audit/RECONNAISSANCE.md).

## 1. Per-Server Memory Store Layout
Memory state is persisted per server/repository under `<memory-dir>/<server-id>/` (or `~/security-audit-skill/<repo-name>/run-<N>`):
- `run-metadata.json`: Tracks `run_id`, `repo`, `target`, `source_ref`, file/config SHA-256 digests, `profile`, `scope_paths`, `budget`, and `prior_run_paths`.
- `coverage-ledger.json`: Canonical RFC 3986 `coverage_id` units from prior runs.
- `findings.json`: Verified `confirmed`, `needs_validation`, and `rejected` records keyed by stable SHA-256 fingerprint.

## 2. Prior-Run Ledger & Fingerprint Carryover Rules
Before planning Phase 1 of a new run, the parent orchestrator compares current source and server service configuration files (`docker-compose.yml`, `systemd` units, reverse-proxy configs, app source) against prior runs:
1. **`prior_confirmed_same_source`**: When the relevant source, service config, and conditions for a prior `confirmed` finding are unchanged, carry the record into the current candidate set with its original fingerprint. Link it to a seeded `planned` ledger unit with `prior_status: "prior_confirmed_same_source"`, put **only** that root cause on the hunter exclusion list (saving hunter tokens), and route it directly to a Phase 3 verifier to become that unit's assignment owner.
2. **`prior_confirmed_changed_source`**: When any relevant source or config file changed, create a planned revalidation unit with `prior_status: "prior_confirmed_changed_source"`. Do not exclude it from hunting.
3. **`prior_needs_validation`**: Carry a still-external `needs_validation` record with the same fingerprint only after verifying its current source trace still holds. Link it to a `planned` unit with `prior_status: "prior_needs_validation"` and include it in Phase 3 and Phase 5 verification.
4. **Priority Re-Work (`deferred`, `blocked`, `out_of_scope`)**: Make prior `deferred`, `blocked`, `out_of_scope`, and changed-source units current hunting work prioritized ahead of `prior_covered_same_source` units.
5. **Disproved Claims (`rejected`)**: Retain prior `rejected` records in `findings.json` to suppress only the exact unchanged failed claim, never coverage of the underlying ledger unit.

## 3. Server & Service Invariant Cache
- **Target Invariants**: Records verified architectural controls (e.g., mTLS termination at Nginx ingress, systemd `DynamicUser=yes` boundaries, authentication middleware) so subsequent runs calibrate boundaries accurately without assuming unverified live state.
- **Hardening Continuity**: Tracks unresolved service improvement notes (`hardening` ledger entries) across runs so server operators can see progress in Discord reports.
