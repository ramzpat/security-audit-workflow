# AGY Security Auditor - Tool Guidance

This guidance instructs the auditor and subagents on the precise, correct, and efficient use of tools across the audit lifecycle.

## 1. Code Exploration & Inspection Tools
- **`read_file`**:
  - Always read in bounded chunks (e.g., 100-300 lines) with explicit line ranges.
  - Review import statements, routing tables, and interface definitions first before diving into implementation details.
- **`run_command`**:
  - Use for read-only static analysis, AST search, `git log`, `grep`, `find`, or file tree inspection.
  - Ensure timeouts and synchronous execution waits (`WaitMsBeforeAsync: 5000-10000`) for short commands.
  - Never run arbitrary remote scripts or package managers (`npm install`, `pip install`, `curl | bash`).

## 2. Orchestration & Subagent Delegation Tools
- **`invoke_subagent`**:
  - Use when delegating specialized roles: `reconnaissance`, `hunter`, `verifier`, `critic`, and `reporter`.
  - Provide concise, actionable prompts including the target repository path, specific coverage units, attack classes, and expected return structure.
  - Maintain agent isolation: verifier subagents must be invoked in clean, fresh contexts without the hunter's chain-of-thought.

## 3. Deterministic Validation Scripts
- **Findings Validation**:
  - Execute: `node scripts/validate-findings.cjs <path/to/findings.json>`
  - Run whenever modifying candidate records, during Phase 4 structured output, and after Phase 5 independent verification.
- **Coverage Ledger Validation**:
  - Execute: `node scripts/validate-coverage-ledger.cjs <path/to/coverage-ledger.json>`
  - Run immediately after Phase 1 initialization and after each wave of ledger updates.

## 4. Sandbox Execution Protocols
- When executing local tests or proof-of-concept reproductions:
  - Operate strictly within assigned subagent scratch directory (`scratch/`).
  - Strip ambient environment variables; provide only explicitly required allowlisted variables.
  - Use mock servers on localhost loopback (`127.0.0.1`) only.
