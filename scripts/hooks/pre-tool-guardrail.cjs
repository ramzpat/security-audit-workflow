#!/usr/bin/env node
'use strict';

/**
 * AGY Security Auditor — Harness² Component 2 & 8 PreToolUse Guardrail Hook
 *
 * Enforces guardrails.md and SKILL.md Universal Execution Safety on `run_command`:
 * - Blocks external network probing/transfer tools (curl, wget, nc, ncat, ssh, scp, sftp, telnet)
 *   unless explicitly targeting isolated loopback (127.0.0.1 / localhost).
 * - Blocks package installation / remote dependency fetching (npm install, pip install,
 *   apt/apt-get install, cargo install, go get) during audit runs.
 */

const fs = require('node:fs');

function evaluateCommand(commandLine) {
  const cmd = String(commandLine || '').trim();
  if (!cmd) {
    return { decision: 'allow' };
  }

  // Block package manager installations / network fetches per SKILL.md & tool_guidance.md
  const pkgInstallPattern =
    /(?:^|[;&|]\s*)(?:sudo\s+)?(?:npm\s+(?:install|i|ci)|pnpm\s+(?:install|add)|yarn\s+(?:install|add)|pip3?\s+install|apt(?:-get)?\s+install|apk\s+add|cargo\s+install|go\s+get)\b/i;
  if (pkgInstallPattern.test(cmd)) {
    return {
      decision: 'deny',
      reason:
        'Harness² Guardrail Violation: Installing dependencies or fetching remote packages is prohibited during security audits (guardrails.md / SKILL.md).',
    };
  }

  // Block remote shell / transfer tools unconditionally
  const remoteAccessPattern = /(?:^|[;&|]\s*)(?:sudo\s+)?(?:ssh|scp|sftp|rsync\s+[^\n]*:|nc|ncat|netcat|socat|telnet|nmap|masscan)\b/i;
  if (remoteAccessPattern.test(cmd)) {
    return {
      decision: 'deny',
      reason:
        'Harness² Guardrail Violation: External network probing and remote shell tools are strictly prohibited (guardrails.md).',
    };
  }

  // Check curl / wget: only allow isolated loopback (127.0.0.1 or localhost)
  const httpClientPattern = /(?:^|[;&|]\s*)(?:curl|wget)\b([^\n;&|]*)/gi;
  let match;
  while ((match = httpClientPattern.exec(cmd)) !== null) {
    const argsSegment = match[1] || '';
    const urls = argsSegment.match(/https?:\/\/[^\s"']+/gi) || [];
    if (urls.length === 0) {
      return {
        decision: 'deny',
        reason:
          'Harness² Guardrail Violation: curl/wget without an explicit http://127.0.0.1 or http://localhost loopback URL is prohibited.',
      };
    }
    for (const u of urls) {
      const isLoopback = /^http:\/\/(?:127\.0\.0\.1|localhost|\[::1\])(?::\d+)?(?:\/|$)/i.test(u);
      if (!isLoopback) {
        return {
          decision: 'deny',
          reason: `Harness² Guardrail Violation: External network call to "${u}" is prohibited during audit execution. Only 127.0.0.1/localhost loopback is permitted.`,
        };
      }
    }
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

  if (!raw.trim()) {
    process.stdout.write(JSON.stringify({ decision: 'allow' }) + '\n');
    return;
  }

  try {
    const input = JSON.parse(raw);
    const toolName = input && input.toolCall && input.toolCall.name;
    const args = (input && input.toolCall && input.toolCall.args) || {};

    if (toolName === 'run_command') {
      const result = evaluateCommand(args.CommandLine);
      process.stdout.write(JSON.stringify(result) + '\n');
      return;
    }
  } catch (_) {
    // Fall through to allow if payload cannot be parsed
  }

  process.stdout.write(JSON.stringify({ decision: 'allow' }) + '\n');
}

if (require.main === module) {
  main();
}

module.exports = { evaluateCommand };
