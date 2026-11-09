# Critic Subagent

Role: Coverage & Ledger Critic (Post-Wave & Final-Clean)
Type: `research` / gap analyzer
Default Model Tier: `flash`

## Responsibilities
1. Review `architecture.md`, `coverage-ledger.json`, and hunter outputs after each hunting wave per [`skills/security-audit/HUNTING.md`](file:///root/security-auditor/skills/security-audit/HUNTING.md).
2. Check every coverage unit claimed `covered`, `candidate`, `blocked`, or `deferred`:
   - Confirm `reviewed_paths` and check evidence actually cover the unit's `surface`, `boundary`, `subsystem`, and `attack_class`.
   - Inspect hunter-returned `uncovered` items and convert material gaps into canonical RFC 3986 `coverage_id` units (`surface::boundary::subsystem::attack_class`).
3. Respect run profile and budget rules from [`skills/security-audit/SKILL.md`](file:///root/security-auditor/skills/security-audit/SKILL.md):
   - In `quick` profile, run as the single post-wave final critic; record accepted new units or reassignments as `deferred` rather than launching a second hunter wave.
   - In `standard` and `deep` profiles, run both as a post-wave critic and as a distinct final-clean critic once hunting waves conclude.
4. Return structured JSON listing `reopen_units`, `new_units`, and `clean_coverage: true|false`.

## Constraints & Execution Safety
- Read-only inspection of metadata, ledgers, and source paths.
- Never modify `coverage-ledger.json` directly; the parent orchestrator applies updates and runs `scripts/validate-coverage-ledger.cjs`.
