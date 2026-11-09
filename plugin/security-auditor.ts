/**
 * AGY Security Auditor Harness² Plugin & SDK Manifest (Component 8)
 *
 * Unifies the Google 8-Component Harness² Specification with the
 * `/security-audit` skill, model-tier routing, deterministic hooks,
 * and post-audit Discord webhook reporting.
 */

export type AuditProfile = 'quick' | 'standard' | 'deep';
export type ModelTier = 'inherit' | 'flash_lite' | 'flash' | 'pro';

export interface SubagentModelTiers {
  orchestrator: ModelTier;
  reconnaissance: ModelTier;
  hunter: ModelTier;
  critic: ModelTier;
  verifierPhase3: ModelTier;
  verifierPhase5: ModelTier;
  reporter: ModelTier;
}

export interface DiscordReportConfig {
  enabled: boolean;
  webhookUrlEnv: string;
  mentionRoleId?: string;
  attachFiles?: string[];
}

export interface AuditorConfig {
  serverId: string;
  repoName: string;
  repoPath: string;
  outputDir?: string;
  memoryDir?: string;
  mode: 'guidance' | 'full';
  profile: AuditProfile;
  scopePaths?: string[];
  budget?: number | null;
  companions?: string[];
  llmProvider?: 'gemini' | 'vertex' | 'openai-compatible';
  apiKeyEnv?: string;
  baseUrl?: string;
  modelTiers: SubagentModelTiers;
  discord?: DiscordReportConfig;
}

export interface HarnessComponents {
  systemPrompt: string;
  guardrails: string;
  longTermMemory: string;
  toolGuidance: string;
  subAgents: Record<'reconnaissance' | 'hunter' | 'verifier' | 'critic' | 'reporter', string>;
  skills: {
    main: string;
    reconnaissance: string;
    hunting: string;
    validationAndReporting: string;
    attackClasses: string;
    reportSchema: string;
    companions: string[];
  };
  scripts: {
    validateFindings: string;
    validateCoverageLedger: string;
    sendDiscordReport: string;
    runAudit: string;
    preToolHook: string;
    stopHook: string;
  };
  plugins: string[];
}

export const DefaultModelTiers: SubagentModelTiers = {
  orchestrator: 'pro',
  reconnaissance: 'flash',
  hunter: 'pro',
  critic: 'flash',
  verifierPhase3: 'pro',
  verifierPhase5: 'flash',
  reporter: 'flash',
};

export const SecurityAuditorHarness: HarnessComponents = {
  systemPrompt: 'systemprompt.md',
  guardrails: 'guardrails.md',
  longTermMemory: 'LongTermMEMORY.md',
  toolGuidance: 'tool_guidance.md',
  subAgents: {
    reconnaissance: 'sub_agents/reconnaissance/AGENT.md',
    hunter: 'sub_agents/hunter/AGENT.md',
    verifier: 'sub_agents/verifier/AGENT.md',
    critic: 'sub_agents/critic/AGENT.md',
    reporter: 'sub_agents/reporter/AGENT.md',
  },
  skills: {
    main: 'skills/security-audit/SKILL.md',
    reconnaissance: 'skills/security-audit/RECONNAISSANCE.md',
    hunting: 'skills/security-audit/HUNTING.md',
    validationAndReporting: 'skills/security-audit/VALIDATION-AND-REPORTING.md',
    attackClasses: 'skills/security-audit/ATTACK-CLASSES.md',
    reportSchema: 'skills/security-audit/report-schema.json',
    companions: [
      'skills/security-audit/CLOUD-AND-DEPLOYMENT.md',
      'skills/security-audit/WEB-PROTOCOL-AND-AUTH.md',
      'skills/security-audit/PROTOCOLS-RPC-AND-MESSAGING.md',
      'skills/security-audit/DATA-ISOLATION-AND-LIFECYCLE.md',
      'skills/security-audit/SUPPLY-CHAIN-AND-RELEASE.md',
      'skills/security-audit/RESOURCE-EXHAUSTION-AND-AVAILABILITY.md',
      'skills/security-audit/AI-AND-LLM.md',
      'skills/security-audit/CLIENT-SIDE.md',
      'skills/security-audit/DESKTOP-MOBILE-AND-LOCAL-IPC.md',
      'skills/security-audit/MEMORY-SAFETY-AND-BINARY.md',
    ],
  },
  scripts: {
    validateFindings: 'scripts/validate-findings.cjs',
    validateCoverageLedger: 'scripts/validate-coverage-ledger.cjs',
    sendDiscordReport: 'scripts/send-discord-report.cjs',
    runAudit: 'scripts/run-audit.sh',
    preToolHook: 'scripts/hooks/pre-tool-guardrail.cjs',
    stopHook: 'scripts/hooks/stop-validator-gate.cjs',
  },
  plugins: [
    'plugins/security-auditor/plugin.json',
    'plugins/security-auditor/hooks.json',
  ],
};

export default SecurityAuditorHarness;
