#!/usr/bin/env node
'use strict';

const assert = require('node:assert/strict');
const http = require('node:http');
const {
  DISCORD_LIMITS,
  embedCharCount,
  buildDiscordPayload,
  sendWebhookRequest,
} = require('./send-discord-report.cjs');

async function runTests() {
  let passed = 0;

  // Test 1: Standard payload generation & /security-audit skill compliance
  {
    const metadata = {
      server_id: 'prod-eu-west-01',
      repo: 'server-services',
      profile: 'quick',
      run_status: 'complete',
      source_ref: 'a1b2c3d',
      budget: 12,
      agents_spent: 9,
    };

    const findings = [
      {
        fingerprint: 'fp-confirmed-1',
        verdict: 'confirmed',
        title: 'Unauthenticated Admin Socket Exposed via Nginx Proxy',
        description: 'Nginx location /admin forwards to internal socket without auth.',
        root_cause: 'Missing auth_request directive on /admin proxy block.',
        intended_behavior: 'Admin endpoints require mTLS or internal session token.',
        conditions: ['Request sent to /admin/metrics'],
        trace: [
          { file: 'nginx/conf.d/app.conf', line: 42, role: 'entrypoint', description: 'location /admin' },
          { file: 'services/admin/server.py', line: 88, role: 'sink', description: 'executes admin action' },
        ],
        evidence: [{ file: 'nginx/conf.d/app.conf', line: 42, description: 'proxy_pass without auth' }],
        execution: {
          interface: 'HTTP GET /admin/metrics',
          input: 'GET /admin/metrics HTTP/1.1',
          observed_result: 'Returns 200 OK with internal tenant tokens.',
        },
        remediation: {
          summary: 'Add auth_request /internal-auth and restrict /admin to internal subnet.',
        },
        severity: {
          likelihood: 'high',
          impact: 'critical',
          overall: 'critical',
        },
        confidence: 'high',
      },
      {
        fingerprint: 'fp-nv-1',
        verdict: 'needs_validation',
        title: 'Docker Host Socket Mount Reachability',
        description: 'Worker service mounts /var/run/docker.sock.',
        claimed_root_cause: 'Container may escalate to host root if worker queue accepts untrusted jobs.',
        trace: [{ file: 'docker-compose.yml', line: 19, role: 'entrypoint', description: 'volumes: /var/run/docker.sock' }],
        evidence: [{ file: 'docker-compose.yml', line: 19, description: 'socket mount' }],
        blockers: ['Production Redis queue ACLs are managed outside repository'],
        validation_plan: {
          deployment: 'Inspect Redis ACLs on prod-eu-west-01 to verify whether untrusted services can push to worker queue.',
        },
      },
    ];

    const ledger = [
      {
        coverage_id: 'nginx::auth::profile%2Fquick%2Fall-in-scope-subsystems::WEB-PROTOCOL-AND-AUTH.md%23Trusted-proxy',
        status: 'candidate',
        prior_status: 'prior_confirmed_same_source',
      },
      {
        coverage_id: 'docker::host::profile%2Fquick%2Fall-in-scope-subsystems::CLOUD-AND-DEPLOYMENT.md%23Host',
        status: 'deferred',
      },
    ];

    const hardeningNotes = [
      'systemd/app.service: Add ProtectSystem=strict and NoNewPrivileges=true.',
      'Dockerfile: Run node process as non-root USER 1001.',
    ];

    const payload = buildDiscordPayload({
      metadata,
      findings,
      ledger,
      hardeningNotes,
      mentionRoleId: '987654321',
    });

    assert.ok(payload.content.includes('<@&987654321>'), 'Should mention role on Critical finding');
    assert.ok(payload.content.length <= DISCORD_LIMITS.MAX_CONTENT_LEN);
    assert.equal(payload.embeds.length, 4, 'Should have Posture, Confirmed, Needs Validation, and Hardening embeds');

    // Verify partial pass disclosure for quick profile
    assert.ok(
      payload.embeds[0].description.includes('partial pass'),
      'Quick profile must disclose partial pass in Embed 1'
    );

    // Verify Needs Validation embed NEVER assigns a severity badge
    const nvEmbed = payload.embeds[2];
    assert.ok(nvEmbed.title.includes('No Severity Assigned'));
    const nvFieldText = JSON.stringify(nvEmbed.fields);
    assert.ok(!/\[CRITICAL\]|\[HIGH\]|\[MEDIUM\]|\[LOW\]/.test(nvFieldText), 'Needs validation must never carry severity badges');

    passed++;
  }

  // Test 2: 6,000-char & 10-embed ceiling clamping under heavy finding load
  {
    const hugeFindings = Array.from({ length: 35 }, (_, idx) => ({
      fingerprint: `fp-huge-${idx}`,
      verdict: 'confirmed',
      title: `High Severity Boundary Bypass #${idx} `.repeat(4),
      description: 'X'.repeat(600),
      root_cause: 'Y'.repeat(500),
      execution: { observed_result: 'Z'.repeat(500) },
      remediation: { summary: 'R'.repeat(500) },
      trace: [{ file: `services/svc-${idx}/handler.ts`, line: idx + 10 }],
      severity: { overall: 'high', impact: 'high', likelihood: 'high' },
    }));

    const payload = buildDiscordPayload({
      metadata: { server_id: 'stress-server', profile: 'deep', run_status: 'complete' },
      findings: hugeFindings,
      ledger: [],
      hardeningNotes: Array.from({ length: 20 }, (_, i) => `Hardening item #${i}: ` + 'H'.repeat(300)),
    });

    assert.ok(payload.embeds.length <= DISCORD_LIMITS.MAX_EMBEDS, 'Must not exceed 10 embeds');
    const totalChars = payload.embeds.reduce((acc, e) => acc + embedCharCount(e), 0);
    assert.ok(
      totalChars <= DISCORD_LIMITS.MAX_TOTAL_EMBED_CHARS,
      `Total embed chars (${totalChars}) must be <= ${DISCORD_LIMITS.MAX_TOTAL_EMBED_CHARS}`
    );
    passed++;
  }

  // Test 3: Local loopback (127.0.0.1) multipart webhook delivery
  {
    let receivedContentType = '';
    let receivedBody = '';

    const server = http.createServer((req, res) => {
      receivedContentType = req.headers['content-type'] || '';
      const chunks = [];
      req.on('data', (c) => chunks.push(c));
      req.on('end', () => {
        receivedBody = Buffer.concat(chunks).toString('utf8');
        res.writeHead(204);
        res.end();
      });
    });

    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = server.address().port;

    try {
      const payload = buildDiscordPayload({
        metadata: { server_id: 'loopback-test' },
        findings: [],
        ledger: [],
        hardeningNotes: ['Enable UFW loopback rules'],
      });

      const response = await sendWebhookRequest(
        `http://127.0.0.1:${port}/api/webhooks/test/token`,
        payload,
        [{ filename: 'REPORT.md', content: '# Executive Report\nAll clear.' }]
      );

      assert.equal(response.statusCode, 204);
      assert.ok(receivedContentType.startsWith('multipart/form-data; boundary='));
      assert.ok(receivedBody.includes('name="payload_json"'));
      assert.ok(receivedBody.includes('filename="REPORT.md"'));
      assert.ok(receivedBody.includes('# Executive Report'));
      passed++;
    } finally {
      server.close();
    }
  }

  console.log(`send-discord-report.test.cjs: ${passed}/3 tests passed.`);
}

runTests().catch((err) => {
  console.error(err);
  process.exit(1);
});
