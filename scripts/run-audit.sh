#!/usr/bin/env bash
set -euo pipefail

# Security Auditor Harness Runner Script
# Supports validation of audit artifacts (findings.json, coverage-ledger.json)
# and running test suites.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

usage() {
  cat <<EOF
Usage: $(basename "$0") <command> [args...]

Commands:
  test                      Run unit tests for findings and coverage validators
  validate-findings <path>  Validate findings.json against report-schema.json
  validate-ledger <path>    Validate coverage-ledger.json
  help                      Show this help message
EOF
}

cmd="${1:-help}"

case "$cmd" in
  test)
    echo "=== Running findings validator tests ==="
    node "$SCRIPT_DIR/validate-findings.test.cjs"
    echo "=== Running coverage-ledger validator tests ==="
    node "$SCRIPT_DIR/validate-coverage-ledger.test.cjs"
    echo "=== All validation tests passed successfully ==="
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
  help|--help|-h)
    usage
    ;;
  *)
    echo "Unknown command: $cmd" >&2
    usage
    exit 1
    ;;
esac
