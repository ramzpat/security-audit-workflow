# AGY Security Auditor - Long-Term Memory

The Long-Term Memory component maintains state continuity across multi-phase workflows, incremental audit runs, and recurring repository assessments.

## 1. Multi-Run Ledger Retention
- Preserves `coverage-ledger.json` from previous audit runs.
- Tracks source commit hashes (`source_ref`) and file content digests.
- Distinguishes between unchanged code, modified code, and novel surfaces.

## 2. Findings Fingerprint Ledger
- Every candidate finding is assigned an immutable, collision-resistant SHA-256 fingerprint derived from canonical attributes (affected component, root cause, trigger vector, boundary failure).
- Re-runs against unchanged source automatically carry forward verified evidence.
- Modified source triggers targeted revalidation units rather than unguided hunting.

## 3. Persistent Knowledge Base & Anti-Patterns
- **Target Invariants**: Records discovered architectural assumptions, authentication filters, and global middleware to avoid rediscovering known defenses.
- **Disproved Hypotheses**: Stores rejected candidate signatures in `findings.json` with rejection rationale to prevent subsequent hunters from retreading falsified leads.
- **Framework Signatures**: Maintains patterns of framework-level protections (e.g., ORM parameterized queries, template auto-escaping, CSRF token middleware).

## 4. Memory Eviction & Refresh Policy
- Stale units whose source files have been refactored or deleted are retired with appropriate status markers.
- Unresolved `needs_validation` items are prioritized when new test environments or sandboxing capabilities become available.
