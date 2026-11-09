#!/usr/bin/env bash
set -euo pipefail

# Security Auditor Harness² Runner Script
# Supports validation of audit artifacts (findings.json, coverage-ledger.json),
# Discord webhook report dispatching, portable server audit runs, and test suites.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

usage() {
  cat <<EOF
Usage: $(basename "$0") <command> [args...]

Commands:
  test                               Run all unit tests (validators, Discord formatter, hooks, SDK harness)
  validate-findings <path>           Validate findings.json against report-schema.json
  validate-ledger <path>             Validate coverage-ledger.json
  send-discord <run-dir> [flags...]  Format and dispatch Discord webhook report from <run-dir>
  run-server-audit [flags...]        Run the portable Antigravity SDK server audit pipeline
  help                               Show this help message
EOF
}

cmd="${1:-help}"

case "$cmd" in
  test)
    echo "=== Running findings validator tests ==="
    node "$SCRIPT_DIR/validate-findings.test.cjs"
    echo "=== Running coverage-ledger validator tests ==="
    node "$SCRIPT_DIR/validate-coverage-ledger.test.cjs"
    echo "=== Running Discord webhook formatter & loopback tests ==="
    node "$SCRIPT_DIR/send-discord-report.test.cjs"
    echo "=== Running Harness² lifecycle hook tests ==="
    node "$SCRIPT_DIR/hooks/hooks.test.cjs"
    echo "=== Running Python SDK Harness² & /security-audit tests ==="
    python3 -m unittest "$PROJECT_ROOT/harness/test_harness.py"
    echo "=== All validation, Discord, hook, and harness tests passed successfully ==="
    ;;
  validate-findings)
    if [ -z "${2:-}" ]; then
      echo "Error: Path to findings.json required" >&2
      exit 1
    fi
    node "$SCRIPT_DIR/validate-findings.cjs" "$2"
    ;;
  validate-ledger)
    if [ -z "${2:-}" ]; then
      echo "Error: Path to coverage-ledger.json required" >&2
      exit 1
    fi
    node "$SCRIPT_DIR/validate-coverage-ledger.cjs" "$2"
    ;;
  send-discord)
    shift
    node "$SCRIPT_DIR/send-discord-report.cjs" "$@"
    ;;
  run-server-audit)
    shift
    PYTHONPATH="$PROJECT_ROOT${PYTHONPATH:+:$PYTHONPATH}" python3 -m harness.run_server_audit "$@"
    ;;
  help|--help|-h)
    usage
    ;;
  *)
    echo "Unknown command: $cmd" >&2
    usage
    exit 1
    ;;
esac
