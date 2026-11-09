#!/usr/bin/env node
'use strict';

/**
 * AGY Security Auditor — Deterministic Discord Webhook Dispatcher (Component 7)
 *
 * Transforms validated audit run outputs (run-metadata.json, findings.json,
 * coverage-ledger.json, REPORT.md, FINDINGS-DETAIL.md, NEEDS-VALIDATION.md)
 * into Discord Rich Embeds + multipart file attachments while strictly enforcing:
 *   1. Discord API payload bounds (<=2000 char content, <=10 embeds, <=6000 total
 *      embed chars, <=1024 char field values, <=256 char titles/field names).
 *   2. /security-audit skill reporting rules (only confirmed findings get severity;
 *      needs_validation records NEVER receive severity; hardening notes are separated;
 *      partial/quick/scoped/incomplete runs explicitly disclose coverage status).
 */

const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const https = require('node:https');
const { spawnSync } = require('node:child_process');

const DISCORD_LIMITS = {
  MAX_CONTENT_LEN: 2000,
  MAX_EMBEDS: 10,
  MAX_TOTAL_EMBED_CHARS: 6000,
  MAX_TITLE_LEN: 256,
  MAX_DESC_LEN: 4096,
  MAX_FIELDS: 25,
  MAX_FIELD_NAME_LEN: 256,
  MAX_FIELD_VALUE_LEN: 1024,
  MAX_FOOTER_LEN: 2048,
};

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'informational'];

const SEVERITY_COLORS = {
  critical: 0xed4245,      // Red
  high: 0xf26522,          // Orange
  medium: 0xfee75c,        // Yellow
  low: 0x3498db,           // Blue
  informational: 0x95a5a6, // Grey
  clean: 0x57f287,         // Green
  needs_validation: 0x9b59b6, // Purple (no severity rating)
  hardening: 0x1abc9c,     // Teal
};

const SEVERITY_BADGES = {
  critical: '[CRITICAL]',
  high: '[HIGH]',
  medium: '[MEDIUM]',
  low: '[LOW]',
  informational: '[INFO]',
};

function truncate(str, maxLen, suffix = '...') {
  const s = String(str ?? '');
  if (s.length <= maxLen) return s;
  return s.slice(0, Math.max(0, maxLen - suffix.length)) + suffix;
}

function embedCharCount(embed) {
  let total = 0;
  if (embed.title) total += embed.title.length;
  if (embed.description) total += embed.description.length;
  if (embed.author && embed.author.name) total += embed.author.name.length;
  if (embed.footer && embed.footer.text) total += embed.footer.text.length;
  if (Array.isArray(embed.fields)) {
    for (const f of embed.fields) {
      total += (f.name ? f.name.length : 0) + (f.value ? f.value.length : 0);
    }
  }
  return total;
}

function sanitizeEmbed(rawEmbed) {
  const embed = {};
  if (rawEmbed.title) embed.title = truncate(rawEmbed.title, DISCORD_LIMITS.MAX_TITLE_LEN);
  if (rawEmbed.description) embed.description = truncate(rawEmbed.description, DISCORD_LIMITS.MAX_DESC_LEN);
  if (typeof rawEmbed.color === 'number') embed.color = rawEmbed.color;
  if (rawEmbed.timestamp) embed.timestamp = rawEmbed.timestamp;
  if (rawEmbed.footer && rawEmbed.footer.text) {
    embed.footer = { text: truncate(rawEmbed.footer.text, DISCORD_LIMITS.MAX_FOOTER_LEN) };
  }
  if (Array.isArray(rawEmbed.fields) && rawEmbed.fields.length > 0) {
    embed.fields = rawEmbed.fields.slice(0, DISCORD_LIMITS.MAX_FIELDS).map((f) => ({
      name: truncate(f.name || 'Detail', DISCORD_LIMITS.MAX_FIELD_NAME_LEN),
      value: truncate(f.value || '-', DISCORD_LIMITS.MAX_FIELD_VALUE_LEN),
      inline: Boolean(f.inline),
    }));
  }
  return embed;
}

function clampEmbedsToBudget(embeds, maxTotalChars = DISCORD_LIMITS.MAX_TOTAL_EMBED_CHARS) {
  const clamped = [];
  let usedChars = 0;

  for (const raw of embeds.slice(0, DISCORD_LIMITS.MAX_EMBEDS)) {
    const e = sanitizeEmbed(raw);
    let cost = embedCharCount(e);

    if (usedChars + cost <= maxTotalChars) {
      clamped.push(e);
      usedChars += cost;
      continue;
    }

    // Try trimming fields to fit within remaining character budget
    const remaining = maxTotalChars - usedChars;
    if (remaining < 250) break;

    const baseCost =
      (e.title ? e.title.length : 0) +
      (e.description ? e.description.length : 0) +
      (e.footer && e.footer.text ? e.footer.text.length : 0);

    if (baseCost >= remaining) {
      e.fields = [];
      e.description = truncate(e.description || '', Math.max(60, remaining - (e.title ? e.title.length : 0) - 80));
      if (embedCharCount(e) <= remaining) {
        clamped.push(e);
      }
      break;
    }

    if (Array.isArray(e.fields)) {
      const keptFields = [];
      let fieldBudget = remaining - baseCost - 80;
      for (const f of e.fields) {
        const fCost = f.name.length + f.value.length;
        if (fCost <= fieldBudget) {
          keptFields.push(f);
          fieldBudget -= fCost;
        } else {
          keptFields.push({
            name: 'Truncated',
            value: 'Additional items omitted to fit Discord 6,000-character embed limit. See attached Markdown reports.',
            inline: false,
          });
          break;
        }
      }
      e.fields = keptFields;
    }
    clamped.push(e);
    break;
  }

  return clamped;
}

function extractHardeningFromReport(reportMd) {
  if (!reportMd) return [];
  const lines = reportMd.split(/\r?\n/);
  const notes = [];
  let inHardening = false;
  for (const line of lines) {
    if (/^#{1,4}\s+.*(hardening|what we should improve|improvements)/i.test(line)) {
      inHardening = true;
      continue;
    }
    if (inHardening && /^#{1,4}\s+/.test(line)) {
      break;
    }
    if (inHardening) {
      const m = line.match(/^\s*[-*]\s+(.+)/);
      if (m && m[1].trim()) {
        notes.push(m[1].trim());
      }
    }
  }
  return notes;
}

function formatTraceSummary(record) {
  if (Array.isArray(record.trace) && record.trace.length > 0) {
    const first = record.trace[0];
    const last = record.trace[record.trace.length - 1];
    const firstRef = `${first.file}:${first.line}`;
    const lastRef = `${last.file}:${last.line}`;
    return firstRef === lastRef ? `\`${firstRef}\`` : `\`${firstRef}\` -> \`${lastRef}\``;
  }
  if (Array.isArray(record.evidence) && record.evidence.length > 0) {
    const ev = record.evidence[0];
    return `\`${ev.file}:${ev.line}\``;
  }
  return '`source`';
}

function getOverallSeverity(record) {
  if (!record || !record.severity) return 'informational';
  return record.severity.overall_severity || record.severity.overall || 'informational';
}

function getRemediationSummary(record) {
  if (!record || !record.remediation) {
    return 'Enforce security invariant at the last trusted decision point.';
  }
  return (
    record.remediation.strategy ||
    record.remediation.summary ||
    'Enforce security invariant at the last trusted decision point.'
  );
}

function buildDiscordPayload({
  metadata = {},
  findings = [],
  ledger = [],
  hardeningNotes = [],
  serverId,
  mentionRoleId,
}) {
  const effectiveServerId = serverId || metadata.server_id || metadata.repo || 'server-target';
  const profile = metadata.profile || 'standard';
  const runStatus = metadata.run_status || 'complete';
  const sourceRef = metadata.source_ref || 'HEAD';

  const confirmed = findings
    .filter((f) => f && f.verdict === 'confirmed')
    .sort((a, b) => {
      const sA = SEVERITY_ORDER.indexOf(getOverallSeverity(a));
      const sB = SEVERITY_ORDER.indexOf(getOverallSeverity(b));
      return (sA === -1 ? 99 : sA) - (sB === -1 ? 99 : sB);
    });

  const needsValidation = findings.filter((f) => f && f.verdict === 'needs_validation');
  const rejected = findings.filter((f) => f && f.verdict === 'rejected');

  const sevCounts = { critical: 0, high: 0, medium: 0, low: 0, informational: 0 };
  for (const c of confirmed) {
    const sev = getOverallSeverity(c);
    if (sevCounts[sev] !== undefined) sevCounts[sev] += 1;
  }

  const ledgerCounts = {
    covered: 0,
    candidate: 0,
    blocked: 0,
    deferred: 0,
    out_of_scope: 0,
    planned: 0,
    in_progress: 0,
    prior_carried: 0,
  };
  for (const unit of ledger) {
    if (unit && unit.status && ledgerCounts[unit.status] !== undefined) {
      ledgerCounts[unit.status] += 1;
    }
    if (unit && unit.prior_status === 'prior_confirmed_same_source') {
      ledgerCounts.prior_carried += 1;
    }
  }

  let highestSeverity = 'clean';
  for (const sev of SEVERITY_ORDER) {
    if (sevCounts[sev] > 0) {
      highestSeverity = sev;
      break;
    }
  }

  const shouldMention =
    mentionRoleId && (sevCounts.critical > 0 || sevCounts.high > 0)
      ? `<@&${mentionRoleId}> `
      : '';

  const content = truncate(
    `${shouldMention}**AGY Security Audit Report** — Server: \`${effectiveServerId}\` | Profile: \`${profile}\` | Status: \`${runStatus.toUpperCase()}\``,
    DISCORD_LIMITS.MAX_CONTENT_LEN
  );

  const embeds = [];

  // Embed 1: Posture, Profile, Memory & Coverage Summary
  const isPartialPass =
    profile === 'quick' ||
    runStatus === 'incomplete' ||
    (Array.isArray(metadata.scope_paths) && metadata.scope_paths.length > 0) ||
    ledgerCounts.deferred > 0 ||
    ledgerCounts.out_of_scope > 0;

  const partialDisclosure = isPartialPass
    ? `\n**Coverage Notice**: This run is a **partial pass** (` +
      [
        profile === 'quick' ? 'profile: quick' : null,
        runStatus === 'incomplete' ? `incomplete: ${metadata.incomplete_reason || 'budget_exhausted'}` : null,
        ledgerCounts.deferred > 0 ? `${ledgerCounts.deferred} deferred units` : null,
        ledgerCounts.out_of_scope > 0 ? `${ledgerCounts.out_of_scope} out-of-scope units` : null,
      ]
        .filter(Boolean)
        .join(', ') +
      ').'
    : '\n**Coverage Notice**: Full in-scope pass verified by coverage critic.';

  const budgetLine =
    metadata.budget != null
      ? `${metadata.agents_spent ?? '-'} / ${metadata.budget} subagent calls`
      : `${metadata.agents_spent ?? 'standard'} (unbounded)`;

  embeds.push({
    title: `Security Audit Posture — ${effectiveServerId}`,
    description:
      `Source Ref: \`${sourceRef}\` | Execution Policy: \`sandboxed-source-and-local-only\`` +
      partialDisclosure,
    color: SEVERITY_COLORS[highestSeverity] || SEVERITY_COLORS.clean,
    fields: [
      {
        name: 'Confirmed Findings',
        value:
          `Critical: **${sevCounts.critical}** | High: **${sevCounts.high}**\n` +
          `Medium: **${sevCounts.medium}** | Low: **${sevCounts.low}** | Info: **${sevCounts.informational}**`,
        inline: true,
      },
      {
        name: 'Verification & Memory',
        value:
          `Needs Validation: **${needsValidation.length}**\n` +
          `Disproved (Rejected): **${rejected.length}**\n` +
          `Prior Carried: **${ledgerCounts.prior_carried}**`,
        inline: true,
      },
      {
        name: 'Coverage Ledger & Budget',
        value:
          `Units: **${ledger.length}** (Covered: ${ledgerCounts.covered}, Candidate: ${ledgerCounts.candidate}, Blocked: ${ledgerCounts.blocked}, Deferred: ${ledgerCounts.deferred})\n` +
          `Budget: ${budgetLine}`,
        inline: false,
      },
    ],
    footer: {
      text: 'Harness² + /security-audit Skill | Zero external network during audit',
    },
    timestamp: new Date().toISOString(),
  });

  // Embed 2: Confirmed Findings (Only confirmed records receive severity!)
  if (confirmed.length > 0) {
    const confirmedFields = confirmed.slice(0, 8).map((c) => {
      const sev = getOverallSeverity(c);
      const badge = SEVERITY_BADGES[sev] || '[CONFIRMED]';
      const trace = formatTraceSummary(c);
      const fix = getRemediationSummary(c);
      const observed =
        (c.execution && c.execution.observed_result) || c.root_cause || c.description;

      return {
        name: `${badge} ${c.title || c.fingerprint}`,
        value:
          `**Location**: ${trace}\n` +
          `**Result**: ${truncate(observed, 260)}\n` +
          `**Fix**: ${truncate(fix, 260)}`,
        inline: false,
      };
    });

    if (confirmed.length > 8) {
      confirmedFields.push({
        name: `+${confirmed.length - 8} More Confirmed Findings`,
        value: 'See attached `REPORT.md` and `FINDINGS-DETAIL.md` for complete source traces and reproductions.',
        inline: false,
      });
    }

    embeds.push({
      title: `Confirmed Boundary Violations (${confirmed.length})`,
      description: 'Independently verified by adversarial Phase 3 & Phase 5 verifiers.',
      color: SEVERITY_COLORS[highestSeverity] || SEVERITY_COLORS.high,
      fields: confirmedFields,
    });
  }

  // Embed 3: Needs Validation Leads (Strictly NO severity assigned per SKILL.md Anti-Pattern #9)
  if (needsValidation.length > 0) {
    const nvFields = needsValidation.slice(0, 5).map((nv) => {
      const trace = formatTraceSummary(nv);
      const blocker = Array.isArray(nv.blockers) ? nv.blockers.join('; ') : 'External deployment fact required';
      const plan =
        (nv.validation_plan && (nv.validation_plan.deployment || nv.validation_plan.local)) ||
        'Inspect active deployment configuration.';
      return {
        name: `[NEEDS VALIDATION] ${nv.title || nv.fingerprint}`,
        value:
          `**Trace**: ${trace}\n` +
          `**Blocker**: ${truncate(blocker, 240)}\n` +
          `**Safe Check**: ${truncate(plan, 240)}`,
        inline: false,
      };
    });

    embeds.push({
      title: `Needs Validation Leads (${needsValidation.length}) — No Severity Assigned`,
      description:
        'Source-grounded hypotheses blocked on unobserved deployment/runtime facts. Do not treat as confirmed vulnerabilities until validated.',
      color: SEVERITY_COLORS.needs_validation,
      fields: nvFields,
    });
  }

  // Embed 4: What We Should Improve (Server & Service Hardening Notes)
  if (hardeningNotes.length > 0) {
    const bulletText = hardeningNotes
      .slice(0, 10)
      .map((item, idx) => `${idx + 1}. ${truncate(item, 280)}`)
      .join('\n');

    embeds.push({
      title: `What We Should Improve — Service Hardening (${hardeningNotes.length})`,
      description:
        'Defense-in-depth and server service configuration improvements (no direct boundary bypass observed):\n\n' +
        truncate(bulletText, 3500),
      color: SEVERITY_COLORS.hardening,
    });
  }

  return {
    content,
    embeds: clampEmbedsToBudget(embeds),
  };
}

function buildMultipartBody(payloadObj, attachments = []) {
  const boundary = '----AGYSecurityAuditorBoundary' + Date.now().toString(16);
  const chunks = [];

  const pushStr = (s) => chunks.push(Buffer.from(s, 'utf8'));

  pushStr(`--${boundary}\r\n`);
  pushStr('Content-Disposition: form-data; name="payload_json"\r\n');
  pushStr('Content-Type: application/json\r\n\r\n');
  pushStr(JSON.stringify(payloadObj));
  pushStr('\r\n');

  attachments.forEach((att, idx) => {
    pushStr(`--${boundary}\r\n`);
    pushStr(
      `Content-Disposition: form-data; name="files[${idx}]"; filename="${path.basename(att.filename)}"\r\n`
    );
    pushStr('Content-Type: text/markdown; charset=utf-8\r\n\r\n');
    chunks.push(Buffer.isBuffer(att.content) ? att.content : Buffer.from(String(att.content), 'utf8'));
    pushStr('\r\n');
  });

  pushStr(`--${boundary}--\r\n`);
  return {
    boundary,
    body: Buffer.concat(chunks),
  };
}

function sendWebhookRequest(webhookUrl, payloadObj, attachments = [], maxRetries = 2) {
  return new Promise((resolve, reject) => {
    const parsedUrl = new URL(webhookUrl);
    const transport = parsedUrl.protocol === 'https:' ? https : http;

    const useMultipart = attachments.length > 0;
    let bodyBuf;
    let contentType;

    if (useMultipart) {
      const mp = buildMultipartBody(payloadObj, attachments);
      bodyBuf = mp.body;
      contentType = `multipart/form-data; boundary=${mp.boundary}`;
    } else {
      bodyBuf = Buffer.from(JSON.stringify(payloadObj), 'utf8');
      contentType = 'application/json';
    }

    const req = transport.request(
      {
        protocol: parsedUrl.protocol,
        hostname: parsedUrl.hostname,
        port: parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80),
        path: parsedUrl.pathname + parsedUrl.search,
        method: 'POST',
        headers: {
          'Content-Type': contentType,
          'Content-Length': bodyBuf.length,
          'User-Agent': 'AGY-Security-Auditor-Harness2/1.0',
        },
        timeout: 15000,
      },
      (res) => {
        const resChunks = [];
        res.on('data', (c) => resChunks.push(c));
        res.on('end', () => {
          const responseBody = Buffer.concat(resChunks).toString('utf8');
          if (res.statusCode >= 200 && res.statusCode < 300) {
            resolve({ statusCode: res.statusCode, body: responseBody });
            return;
          }
          if (res.statusCode === 429 && maxRetries > 0) {
            let retryMs = 1000;
            try {
              const parsed = JSON.parse(responseBody);
              if (parsed.retry_after) {
                retryMs = Math.ceil(Number(parsed.retry_after) * 1000);
              }
            } catch (_) {
              // fallback
            }
            setTimeout(() => {
              sendWebhookRequest(webhookUrl, payloadObj, attachments, maxRetries - 1).then(resolve, reject);
            }, Math.min(retryMs, 5000));
            return;
          }
          reject(new Error(`Discord webhook failed with HTTP ${res.statusCode}: ${responseBody}`));
        });
      }
    );

    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy(new Error('Discord webhook request timed out'));
    });
    req.write(bodyBuf);
    req.end();
  });
}

function loadRunDirectory(runDir, options = {}) {
  const findingsPath = path.join(runDir, 'findings.json');
  const ledgerPath = path.join(runDir, 'coverage-ledger.json');
  const metadataPath = path.join(runDir, 'run-metadata.json');
  const hardeningPath = path.join(runDir, 'hardening.json');
  const reportPath = path.join(runDir, 'REPORT.md');

  if (!fs.existsSync(findingsPath)) {
    throw new Error(`Missing findings.json in ${runDir}`);
  }
  if (!fs.existsSync(ledgerPath)) {
    throw new Error(`Missing coverage-ledger.json in ${runDir}`);
  }

  if (!options.skipValidate) {
    const valFindingsScript = path.join(__dirname, 'validate-findings.cjs');
    const valLedgerScript = path.join(__dirname, 'validate-coverage-ledger.cjs');

    const r1 = spawnSync(process.execPath, [valFindingsScript, findingsPath], { encoding: 'utf8' });
    if (r1.status !== 0) {
      throw new Error(`findings.json failed schema validation:\n${r1.stderr || r1.stdout}`);
    }
    const r2 = spawnSync(process.execPath, [valLedgerScript, ledgerPath], { encoding: 'utf8' });
    if (r2.status !== 0) {
      throw new Error(`coverage-ledger.json failed validation:\n${r2.stderr || r2.stdout}`);
    }
  }

  const findings = JSON.parse(fs.readFileSync(findingsPath, 'utf8'));
  const ledger = JSON.parse(fs.readFileSync(ledgerPath, 'utf8'));
  const metadata = fs.existsSync(metadataPath)
    ? JSON.parse(fs.readFileSync(metadataPath, 'utf8'))
    : {};

  let hardeningNotes = [];
  if (fs.existsSync(hardeningPath)) {
    const h = JSON.parse(fs.readFileSync(hardeningPath, 'utf8'));
    if (Array.isArray(h)) hardeningNotes = h.map((item) => (typeof item === 'string' ? item : item.summary || item.title || JSON.stringify(item)));
  } else if (Array.isArray(metadata.hardening_notes)) {
    hardeningNotes = metadata.hardening_notes;
  } else if (fs.existsSync(reportPath)) {
    hardeningNotes = extractHardeningFromReport(fs.readFileSync(reportPath, 'utf8'));
  }

  const attachments = [];
  if (options.attachFiles !== false) {
    for (const fname of ['REPORT.md', 'FINDINGS-DETAIL.md', 'NEEDS-VALIDATION.md']) {
      const fpath = path.join(runDir, fname);
      if (fs.existsSync(fpath)) {
        const stat = fs.statSync(fpath);
        if (stat.isFile() && stat.size > 0 && stat.size <= 8 * 1024 * 1024) {
          attachments.push({
            filename: fname,
            content: fs.readFileSync(fpath),
          });
        }
      }
    }
  }

  return { metadata, findings, ledger, hardeningNotes, attachments };
}

async function main() {
  const args = process.argv.slice(2);
  let runDir = null;
  let webhookUrl = process.env.DISCORD_WEBHOOK_URL || '';
  let serverId = process.env.SERVER_ID || '';
  let mentionRoleId = process.env.DISCORD_MENTION_ROLE || '';
  let dryRun = false;
  let skipValidate = false;
  let noAttach = false;
  let outputPayloadPath = '';

  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--dry-run') dryRun = true;
    else if (a === '--skip-validate') skipValidate = true;
    else if (a === '--no-attach') noAttach = true;
    else if (a === '--webhook-url' && args[i + 1]) webhookUrl = args[++i];
    else if (a === '--server-id' && args[i + 1]) serverId = args[++i];
    else if (a === '--mention-role' && args[i + 1]) mentionRoleId = args[++i];
    else if (a === '--output-payload' && args[i + 1]) outputPayloadPath = args[++i];
    else if (!a.startsWith('--') && !runDir) runDir = a;
  }

  if (!runDir) {
    console.error(
      'Usage: node scripts/send-discord-report.cjs <run-dir> [--webhook-url <url>] [--server-id <id>] [--dry-run] [--output-payload <path>]'
    );
    process.exit(1);
  }

  const loaded = loadRunDirectory(path.resolve(runDir), {
    skipValidate,
    attachFiles: !noAttach,
  });

  const payload = buildDiscordPayload({
    metadata: loaded.metadata,
    findings: loaded.findings,
    ledger: loaded.ledger,
    hardeningNotes: loaded.hardeningNotes,
    serverId,
    mentionRoleId,
  });

  if (outputPayloadPath) {
    fs.writeFileSync(path.resolve(outputPayloadPath), JSON.stringify(payload, null, 2), 'utf8');
  }

  if (dryRun) {
    console.log(JSON.stringify(payload, null, 2));
    return;
  }

  if (!webhookUrl) {
    throw new Error('DISCORD_WEBHOOK_URL environment variable or --webhook-url flag is required when not in --dry-run mode.');
  }

  const res = await sendWebhookRequest(webhookUrl, payload, loaded.attachments);
  console.log(`Discord report dispatched successfully (HTTP ${res.statusCode}).`);
}

if (require.main === module) {
  main().catch((err) => {
    console.error(`Error: ${err.message}`);
    process.exit(1);
  });
}

module.exports = {
  DISCORD_LIMITS,
  SEVERITY_COLORS,
  embedCharCount,
  clampEmbedsToBudget,
  buildDiscordPayload,
  buildMultipartBody,
  sendWebhookRequest,
  loadRunDirectory,
};
