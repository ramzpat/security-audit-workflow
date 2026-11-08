/**
 * AGY Security Auditor Harness² Plugin
 *
 * Provides lifecycle event hooks and tool orchestration for the
 * 8-component security audit harness.
 */

export interface AuditorConfig {
  outputDir?: string;
  repoPath: string;
  mode: 'guidance' | 'full';
  profile?: string;
  budget?: number;
}

export interface HarnessComponents {
  systemPrompt: string;
  guardrails: string;
  longTermMemory: string;
  toolGuidance: string;
  subAgents: string[];
  skills: string[];
  scripts: string[];
  plugins: string[];
}

export const SecurityAuditorHarness: HarnessComponents = {
  systemPrompt: 'systemprompt.md',
  guardrails: 'guardrails.md',
  longTermMemory: 'LongTermMEMORY.md',
  toolGuidance: 'tool_guidance.md',
  subAgents: [
    'sub_agents/reconnaissance/AGENT.md',
    'sub_agents/hunter/AGENT.md',
    'sub_agents/verifier/AGENT.md',
    'sub_agents/critic/AGENT.md',
    'sub_agents/reporter/AGENT.md'
  ],
  skills: ['skills/security-audit/SKILL.md'],
  scripts: [
    'scripts/validate-findings.cjs',
    'scripts/validate-coverage-ledger.cjs',
    'scripts/run-audit.sh'
  ],
  plugins: ['plugins/security-auditor/plugin.json']
};

export default SecurityAuditorHarness;
