#!/usr/bin/env node
'use strict';

/**
 * AGY Security Auditor — Harness² Component 8 Stop Validator Gate Hook
 *
 * Enforces SKILL.md terminal state requirement when AUDIT_OUTPUT_DIR is set:
 * "Do not end the run before one of exactly two terminal states:
 *  (a) all Phase 6 artifacts are written and both validators pass, or
 *  (b) run_status: 'incomplete' is recorded with its exact reason and the gap is disclosed in the report."
 */

const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

function evaluateStopGate(hookInput = {}, outputDir = process.env.AUDIT_OUTPUT_DIR) {
  if (!outputDir || !fs.existsSync(outputDir)) {
    return { decision: 'allow' };
  }

  const terminationReason = hookInput.terminationReason || 'NO_TOOL_CALL';
  // Only block normal turn completion; do not loop on hard errors or user cancellation
  if (terminationReason !== 'NO_TOOL_CALL') {
    return { decision: 'allow' };
  }

  const metadataPath = path.join(outputDir, 'run-metadata.json');
  if (!fs.existsSync(metadataPath)) {
    return { decision: 'allow' };
  }

  let metadata;
  try {
    metadata = JSON.parse(fs.readFileSync(metadataPath, 'utf8'));
  } catch (err) {
    return {
      decision: 'continue',
      reason: `Harness² Stop Gate: run-metadata.json in ${outputDir} is invalid JSON (${err.message}). Fix it before ending the audit.`,
    };
  }

  if (metadata.run_status === 'incomplete') {
    if (!metadata.incomplete_reason || typeof metadata.incomplete_reason !== 'string') {
      return {
        decision: 'continue',
        reason:
          'Harness² Stop Gate: run_status is "incomplete" but incomplete_reason is missing in run-metadata.json.',
      };
    }
    return { decision: 'allow' };
  }

  if (metadata.run_status !== 'complete') {
    return {
      decision: 'continue',
      reason: `Harness² Stop Gate: Audit run in ${outputDir} has run_status="${metadata.run_status}". Complete all 6 phases and set run_status="complete" (or set run_status="incomplete" with incomplete_reason) before stopping.`,
    };
  }

  const findingsPath = path.join(outputDir, 'findings.json');
  const ledgerPath = path.join(outputDir, 'coverage-ledger.json');
  const reportPath = path.join(outputDir, 'REPORT.md');

  for (const reqFile of [findingsPath, ledgerPath, reportPath]) {
    if (!fs.existsSync(reqFile)) {
      return {
        decision: 'continue',
        reason: `Harness² Stop Gate: Missing required deliverable ${path.basename(reqFile)} in ${outputDir}.`,
      };
    }
  }

  const scriptsDir = path.resolve(__dirname, '..');
  const valFindings = spawnSync(
    process.execPath,
    [path.join(scriptsDir, 'validate-findings.cjs'), findingsPath],
    { encoding: 'utf8' }
  );
  if (valFindings.status !== 0) {
    return {
      decision: 'continue',
      reason: `Harness² Stop Gate: findings.json failed schema validation:\n${(valFindings.stderr || valFindings.stdout || '').trim()}`,
    };
  }

  const valLedger = spawnSync(
    process.execPath,
    [path.join(scriptsDir, 'validate-coverage-ledger.cjs'), ledgerPath],
    { encoding: 'utf8' }
  );
  if (valLedger.status !== 0) {
    return {
      decision: 'continue',
      reason: `Harness² Stop Gate: coverage-ledger.json failed validation:\n${(valLedger.stderr || valLedger.stdout || '').trim()}`,
    };
  }

  return { decision: 'allow' };
}

function main() {
  let raw = '';
  try {
    raw = fs.readFileSync(0, 'utf8');
  } catch (_) {
    process.stdout.write(JSON.stringify({ decision: 'allow' }) + '\n');
    return;
  }

  let hookInput = {};
  try {
    if (raw.trim()) hookInput = JSON.parse(raw);
  } catch (_) {
    // ignore
  }

  const result = evaluateStopGate(hookInput, process.env.AUDIT_OUTPUT_DIR);
  process.stdout.write(JSON.stringify(result) + '\n');
}

if (require.main === module) {
  main();
}

module.exports = { evaluateStopGate };
