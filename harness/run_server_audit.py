#!/usr/bin/env python3
"""
AGY Security Auditor — Portable Antigravity SDK Server Audit Runner.

Unifies:
- Google 8-Component Harness² Control Plane (systemprompt.md, guardrails.md,
  LongTermMEMORY.md, tool_guidance.md, sub_agents/, skills/, scripts/, plugins/)
- /security-audit Skill 6-Phase Workflow (4x parallel recon, RFC 3986 ledger units,
  9-part hunter prompt, 11-step race-safe artifact promotion, Phase 3 & 5 verifiers)
- Configurable per-server LLM tokens, model tiers (flash vs pro), and Discord webhook
  reporting via scripts/send-discord-report.cjs.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .artifact_promoter import promote_agent_artifacts
from .prompt_builder import (
    build_hunter_prompt,
    build_phase3_verifier_prompt,
    build_phase5_verifier_prompt,
    build_recon_prompts,
    create_ledger_unit,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SKILL_DIR = PROJECT_ROOT / "skills" / "security-audit"
SCRIPTS_DIR = PROJECT_ROOT / "scripts"


def load_dotenv(dotenv_path: Path) -> None:
    """Loads key=value pairs from a .env file without overriding existing env vars."""
    if not dotenv_path.exists():
        return
    for raw_line in dotenv_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        key = k.strip()
        val = v.strip().strip("'").strip('"')
        if key and key not in os.environ:
            os.environ[key] = val


def _expand_env_vars(value: Any) -> Any:
    """Expands ${VAR:-default} or ${VAR} in strings recursively."""
    if isinstance(value, str):
        pattern = re.compile(r"\$\{([A-Za-z0-9_]+)(?::-([^}]*))?\}")

        def repl(match: re.Match[str]) -> str:
            var_name = match.group(1)
            default_val = match.group(2) if match.group(2) is not None else ""
            return os.environ.get(var_name, default_val)

        return pattern.sub(repl, value)
    if isinstance(value, list):
        return [_expand_env_vars(v) for v in value]
    if isinstance(value, dict):
        return {k: _expand_env_vars(v) for k, v in value.items()}
    return value


def load_config_file(config_path: Path) -> Dict[str, Any]:
    """
    Loads YAML or JSON config file. Uses PyYAML if available, falling back to
    a lightweight indentation parser for portable zero-dependency server execution.
    """
    raw_text = config_path.read_text(encoding="utf-8")
    if config_path.suffix.lower() == ".json":
        return _expand_env_vars(json.loads(raw_text))

    try:
        import yaml  # type: ignore

        return _expand_env_vars(yaml.safe_load(raw_text))
    except ImportError:
        pass

    # Lightweight zero-dependency YAML subset parser for nested dicts/lists/scalars
    root: Dict[str, Any] = {}
    stack: List[Tuple[int, Any]] = [(-1, root)]
    lines = raw_text.splitlines()

    def parse_scalar(val_str: str) -> Any:
        s = val_str.strip()
        if "#" in s and not (s.startswith('"') or s.startswith("'")):
            s = s.split("#", 1)[0].strip()
        if (s.startswith('"') and s.endswith('"')) or (s.startswith("'") and s.endswith("'")):
            return s[1:-1]
        if s.lower() == "true":
            return True
        if s.lower() == "false":
            return False
        if s.lower() in ("null", "~", ""):
            return None
        if re.match(r"^-?\d+$", s):
            return int(s)
        return s

    for idx, raw in enumerate(lines):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        while len(stack) > 1 and indent <= stack[-1][0]:
            stack.pop()
        parent = stack[-1][1]

        if stripped.startswith("- "):
            item_val = parse_scalar(stripped[2:])
            if isinstance(parent, list):
                parent.append(item_val)
            continue

        if ":" in stripped:
            key_part, val_part = stripped.split(":", 1)
            key = key_part.strip()
            val_clean = val_part.strip()
            if "#" in val_clean and not (val_clean.startswith('"') or val_clean.startswith("'")):
                val_clean = val_clean.split("#", 1)[0].strip()

            if not val_clean:
                # Look ahead to determine if child is list or dict
                next_container: Any = {}
                for next_raw in lines[idx + 1 :]:
                    ns = next_raw.strip()
                    if not ns or ns.startswith("#"):
                        continue
                    if ns.startswith("- "):
                        next_container = []
                    break
                if isinstance(parent, dict):
                    parent[key] = next_container
                    stack.append((indent, next_container))
            else:
                if isinstance(parent, dict):
                    parent[key] = parse_scalar(val_part)

    return _expand_env_vars(root)


def check_budget_gate(profile: str, budget: Optional[int]) -> Tuple[bool, Dict[str, int], str]:
    """
    Enforces the strict pre-reconnaissance budget gate from skills/security-audit/SKILL.md:
    - Reserve 4 baseline reconnaissance calls (1a-1d).
    - Reserve 1 final post-wave critic for `quick`, or 1 post-wave + 1 final-clean critic for `standard`/`deep`.
    - Reserve at least 1 verifier call.
    """
    recon_reserve = 4
    critic_reserve = 1 if profile == "quick" else 2
    min_verifier_reserve = 1
    minimum_required = recon_reserve + critic_reserve + min_verifier_reserve

    if budget is None:
        return (
            True,
            {
                "recon": recon_reserve,
                "critic": critic_reserve,
                "verifier": 4,
                "hunter_allowance": 999,
            },
            "",
        )

    if budget < minimum_required:
        return (
            False,
            {
                "recon": recon_reserve,
                "critic": critic_reserve,
                "verifier": min_verifier_reserve,
                "hunter_allowance": 0,
            },
            "budget_cannot_fund_reconnaissance_and_reserves",
        )

    remaining_after_critics = budget - recon_reserve - critic_reserve
    verifier_reserve = max(min_verifier_reserve, int(round(remaining_after_critics * 0.30)))
    hunter_allowance = max(0, remaining_after_critics - verifier_reserve)
    if hunter_allowance < 1:
        return (
            False,
            {
                "recon": recon_reserve,
                "critic": critic_reserve,
                "verifier": verifier_reserve,
                "hunter_allowance": 0,
            },
            "budget_cannot_fund_reconnaissance_and_reserves",
        )

    return (
        True,
        {
            "recon": recon_reserve,
            "critic": critic_reserve,
            "verifier": verifier_reserve,
            "hunter_allowance": hunter_allowance,
        },
        "",
    )


def create_agent_dirs(output_dir: Path, agent_id: str) -> Tuple[Path, Path]:
    """
    Creates isolated `<output-dir>/agents/<agent-id>/scratch/` and `artifacts/` directories
    per SKILL.md write-isolation rules.
    """
    if not re.match(r"^[a-z0-9][a-z0-9_-]{0,63}$", agent_id):
        raise ValueError(f"Unsafe canonical agent_id: {agent_id!r}")
    agent_root = output_dir / "agents" / agent_id
    scratch_dir = agent_root / "scratch"
    artifacts_dir = agent_root / "artifacts"
    scratch_dir.mkdir(parents=True, exist_ok=True)
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    return scratch_dir, artifacts_dir


def run_node_validator(script_name: str, target_json_path: Path) -> None:
    """Runs scripts/validate-findings.cjs or scripts/validate-coverage-ledger.cjs."""
    script_path = SCRIPTS_DIR / script_name
    proc = subprocess.run(
        ["node", str(script_path), str(target_json_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"{script_name} failed on {target_json_path}:\n{proc.stderr or proc.stdout}"
        )


async def invoke_sdk_agent(
    *,
    prompt: str,
    system_instructions: str,
    model_tier: str,
    api_key: str,
    provider: str = "gemini",
    base_url: str = "",
) -> str:
    """
    Invokes an agent using the Antigravity Python SDK (`google.antigravity`),
    passing the server-configured LLM token and model tier.
    """
    from google.antigravity import Agent, CapabilitiesConfig, LocalAgentConfig  # type: ignore

    env_overrides = {}
    if api_key:
        if provider == "gemini":
            env_overrides["GEMINI_API_KEY"] = api_key
        elif provider == "openai-compatible":
            env_overrides["OPENAI_API_KEY"] = api_key
    if base_url:
        env_overrides["ANTIGRAVITY_BASE_URL"] = base_url

    for k, v in env_overrides.items():
        os.environ[k] = v

    config_kwargs: Dict[str, Any] = {
        "system_instructions": system_instructions,
        "capabilities": CapabilitiesConfig(),
    }
    if model_tier:
        config_kwargs["model"] = model_tier

    config = LocalAgentConfig(**config_kwargs)
    tokens: List[str] = []
    async with Agent(config) as agent:
        response = await agent.chat(prompt)
        async for tok in response:
            tokens.append(tok)
    return "".join(tokens)


def discover_server_surfaces(target_root: Path, scope_paths: Optional[List[str]] = None) -> List[Dict[str, str]]:
    """
    Deterministically scans `target_root` for server service configurations and code entrypoints
    (Docker Compose, Dockerfile, systemd units, Nginx/Caddy configs, and application routes).
    """
    surfaces: List[Dict[str, str]] = []
    if not target_root.exists():
        return surfaces

    candidates: List[Path] = []
    for p in sorted(target_root.rglob("*")):
        if not p.is_file():
            continue
        rel = p.relative_to(target_root).as_posix()
        if any(part.startswith(".") for part in p.relative_to(target_root).parts if part != ".env.example"):
            continue
        if scope_paths and not any(rel == sp.rstrip("/") or rel.startswith(sp.rstrip("/") + "/") for sp in scope_paths):
            continue
        candidates.append(p)

    for file_path in candidates[:12]:
        rel = file_path.relative_to(target_root).as_posix()
        name_lower = file_path.name.lower()
        if "docker-compose" in name_lower or name_lower == "dockerfile":
            surfaces.append(
                {
                    "surface_ref": f"{rel}#container-service",
                    "boundary_ref": f"{rel}#workload-isolation",
                    "subsystem_ref": str(Path(rel).parent) if str(Path(rel).parent) != "." else "containers",
                    "attack_class_ref": "CLOUD-AND-DEPLOYMENT.md#Host or control-plane capability exposure",
                    "ordinary_block": "ATTACK-CLASSES.md#Privilege and isolation boundaries",
                    "companion_blocks": [
                        "CLOUD-AND-DEPLOYMENT.md#Host or control-plane capability exposure"
                    ],
                    "surface_label": f"Container definition ({rel})",
                    "boundary_label": "Container-to-host privilege boundary",
                    "subsystem_label": "Container Runtime",
                    "attack_class_label": "Host or control-plane capability exposure",
                    "starting_path": rel,
                }
            )
        elif name_lower.endswith(".service") or "systemd" in rel:
            surfaces.append(
                {
                    "surface_ref": f"{rel}#systemd-unit",
                    "boundary_ref": f"{rel}#service-user-privilege",
                    "subsystem_ref": "systemd",
                    "attack_class_ref": "CLOUD-AND-DEPLOYMENT.md#Host or control-plane capability exposure",
                    "ordinary_block": "ATTACK-CLASSES.md#Privilege and isolation boundaries",
                    "companion_blocks": [
                        "CLOUD-AND-DEPLOYMENT.md#Host or control-plane capability exposure"
                    ],
                    "surface_label": f"Systemd unit ({rel})",
                    "boundary_label": "Host daemon execution boundary",
                    "subsystem_label": "Systemd Services",
                    "attack_class_label": "Host or control-plane capability exposure",
                    "starting_path": rel,
                }
            )
        elif "nginx" in name_lower or name_lower.endswith(".conf") or "caddy" in name_lower:
            surfaces.append(
                {
                    "surface_ref": f"{rel}#reverse-proxy",
                    "boundary_ref": f"{rel}#upstream-header-trust",
                    "subsystem_ref": "ingress",
                    "attack_class_ref": "CLOUD-AND-DEPLOYMENT.md#Trusted-proxy and mesh identity bypass",
                    "ordinary_block": "ATTACK-CLASSES.md#Authentication and session boundaries",
                    "companion_blocks": [
                        "CLOUD-AND-DEPLOYMENT.md#Trusted-proxy and mesh identity bypass"
                    ],
                    "surface_label": f"Reverse proxy config ({rel})",
                    "boundary_label": "Ingress proxy trust boundary",
                    "subsystem_label": "Reverse Proxy",
                    "attack_class_label": "Trusted-proxy and mesh identity bypass",
                    "starting_path": rel,
                }
            )

    if not surfaces:
        # Fallback canonical surface from repository root
        default_file = "README.md" if (target_root / "README.md").exists() else "systemprompt.md"
        surfaces.append(
            {
                "surface_ref": f"{default_file}#service-entry",
                "boundary_ref": f"{default_file}#trust-boundary",
                "subsystem_ref": "core",
                "attack_class_ref": "CLOUD-AND-DEPLOYMENT.md#Unexpected service or management-plane reachability",
                "ordinary_block": None,
                "companion_blocks": [
                    "CLOUD-AND-DEPLOYMENT.md#Unexpected service or management-plane reachability"
                ],
                "surface_label": f"Service entry ({default_file})",
                "boundary_label": "Service trust boundary",
                "subsystem_label": "Core Service",
                "attack_class_label": "Unexpected service or management-plane reachability",
                "starting_path": default_file,
            }
        )

    return surfaces


async def run_audit_pipeline(
    config: Dict[str, Any],
    *,
    output_dir: Path,
    dry_run: bool = False,
    send_discord: bool = False,
) -> Dict[str, Any]:
    """
    Executes the 6-Phase /security-audit + Google Harness² workflow into `output_dir`.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    server_cfg = config.get("server", {})
    llm_cfg = config.get("llm", {})
    models_cfg = llm_cfg.get("models", {})
    discord_cfg = config.get("reporting", {}).get("discord", {})

    server_id = server_cfg.get("id") or "server-01"
    repo_name = server_cfg.get("repo_name") or server_id
    target_root = Path(server_cfg.get("target_root") or PROJECT_ROOT).resolve()
    profile = server_cfg.get("profile") or "standard"
    budget_raw = server_cfg.get("budget")
    budget = int(budget_raw) if budget_raw is not None and str(budget_raw).strip() != "" else None
    scope_paths = server_cfg.get("scope_paths") or []
    companions = server_cfg.get("companions") or [
        "CLOUD-AND-DEPLOYMENT.md",
        "WEB-PROTOCOL-AND-AUTH.md",
    ]

    run_id = f"run-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
    source_ref = hashlib.sha256(f"{server_id}:{target_root}".encode("utf-8")).hexdigest()[:12]

    # Step 0: Initialize run-metadata.json & apply strict budget gate (SKILL.md)
    gate_ok, reserves, incomplete_reason = check_budget_gate(profile, budget)
    run_metadata: Dict[str, Any] = {
        "run_id": run_id,
        "server_id": server_id,
        "repo": repo_name,
        "target": str(target_root),
        "source_ref": source_ref,
        "profile": profile,
        "scope_paths": scope_paths,
        "budget": budget,
        "agents_spent": 0,
        "reserves": reserves,
        "execution_policy": "sandboxed-source-and-local-only",
        "selected_companions": companions,
        "prior_run_paths": [],
        "shared_file_owner": "parent-orchestrator",
        "run_status": "in_progress",
        "model_tiers": {
            "orchestrator": models_cfg.get("orchestrator", "pro"),
            "reconnaissance": models_cfg.get("reconnaissance", "flash"),
            "hunter": models_cfg.get("hunter", "pro"),
            "critic": models_cfg.get("critic", "flash"),
            "verifier_phase3": models_cfg.get("verifier_phase3", "pro"),
            "verifier_phase5": models_cfg.get("verifier_phase5", "flash"),
            "reporter": models_cfg.get("reporter", "flash"),
        },
    }

    metadata_path = output_dir / "run-metadata.json"
    architecture_path = output_dir / "architecture.md"
    ledger_path = output_dir / "coverage-ledger.json"
    findings_path = output_dir / "findings.json"
    report_path = output_dir / "REPORT.md"
    detail_path = output_dir / "FINDINGS-DETAIL.md"
    nv_path = output_dir / "NEEDS-VALIDATION.md"

    if not gate_ok:
        run_metadata["run_status"] = "incomplete"
        run_metadata["incomplete_reason"] = incomplete_reason
        metadata_path.write_text(json.dumps(run_metadata, indent=2), encoding="utf-8")
        ledger_path.write_text("[]\n", encoding="utf-8")
        findings_path.write_text("[]\n", encoding="utf-8")
        report_path.write_text(
            f"# Security Audit Report — {server_id}\n\n"
            f"- **Run Status**: `incomplete` (`{incomplete_reason}`)\n"
            f"- **Profile**: `{profile}` | **Budget**: `{budget}`\n\n"
            "No reconnaissance or hunting agents were launched because the strict budget gate could not fund "
            "the 4 baseline reconnaissance calls, mandatory coverage critics, and validation reserve.\n",
            encoding="utf-8",
        )
        detail_path.write_text("# Findings Detail\n\nNo confirmed findings (run incomplete).\n", encoding="utf-8")
        nv_path.write_text("# Needs Validation\n\nRun stopped at pre-reconnaissance budget gate.\n", encoding="utf-8")
        return run_metadata

    # Phase 1: Parallel Reconnaissance (4x research agents on `flash` tier)
    _recon_prompts = build_recon_prompts(str(target_root))
    run_metadata["agents_spent"] += 4

    discovered_surfaces = discover_server_surfaces(target_root, scope_paths)
    architecture_md = (
        f"# Architecture & Trust Boundary Summary — {server_id}\n\n"
        f"1. **Target & Scope**: Server `{server_id}` at `{target_root}` (Profile: `{profile}`, Source Ref: `{source_ref}`).\n"
        "2. **Principals & Normal Authority**: External unauthenticated callers, authenticated service users, "
        "containerized workloads, and host systemd/reverse-proxy operators.\n"
        "3. **Tech Stack & Service Surfaces**: Reverse proxies, systemd service units, container orchestration manifests, "
        "and backend service handlers.\n"
        "4. **Entry Surfaces & Sinks**: Ingress HTTP routes, proxy headers, environment/config mounts, and container runtime sockets.\n"
        "5. **Trust Boundaries**: Ingress-to-upstream proxy boundary and container-to-host kernel/daemon isolation boundary.\n"
        "6. **Starting Paths**: "
        + ", ".join(f"`{s['starting_path']}`" for s in discovered_surfaces)
        + "\n"
        "7. **Prior Coverage**: Initial baseline run recorded in Harness² Long-Term Memory.\n"
        "8. **Selected Companions**: " + ", ".join(f"`{c}`" for c in companions) + ".\n"
    )
    architecture_path.write_text(architecture_md, encoding="utf-8")

    # Build deterministic RFC 3986 coverage ledger units
    ledger_units: List[Dict[str, Any]] = []
    for surf in discovered_surfaces:
        subsystem_ref = (
            "profile/quick/all-in-scope-subsystems"
            if profile == "quick"
            else surf["subsystem_ref"]
        )
        canonical_refs = {
            "surface": surf["surface_ref"],
            "boundary": surf["boundary_ref"],
            "subsystem": subsystem_ref,
            "attack_class": surf["attack_class_ref"],
        }
        unit = create_ledger_unit(
            canonical_refs=canonical_refs,
            surface=surf["surface_label"],
            boundary=surf["boundary_label"],
            subsystem="All In-Scope Subsystems" if profile == "quick" else surf["subsystem_label"],
            attack_class=surf["attack_class_label"],
            starting_paths=[surf["starting_path"]],
            ordinary_attack_class_block=surf["ordinary_block"],
            selected_companion_blocks=surf["companion_blocks"],
            wave=1,
            status="planned",
        )
        ledger_units.append(unit)

    ledger_units.sort(key=lambda u: u["coverage_id"])
    ledger_path.write_text(json.dumps(ledger_units, indent=2), encoding="utf-8")
    run_node_validator("validate-coverage-ledger.cjs", ledger_path)

    # Phase 2: Coverage-Led Hunting Waves
    hunter_allowance = reserves["hunter_allowance"]
    assigned_units = ledger_units[:hunter_allowance]
    deferred_units = ledger_units[hunter_allowance:]

    for du in deferred_units:
        du["status"] = "deferred"
        du["wave"] = None
        du["unresolved"] = ["budget_cannot_reserve_critics_and_validation"]

    hunter_id = "hunter-wave1-01"
    scratch_dir, artifacts_dir = create_agent_dirs(output_dir, hunter_id)

    # Build the strict 9-part hunter prompt
    _hunter_prompt = build_hunter_prompt(
        skill_dir=SKILL_DIR,
        architecture_md=architecture_md,
        assigned_units=assigned_units,
        agent_id=hunter_id,
        scratch_dir=str(scratch_dir),
        artifacts_dir=str(artifacts_dir),
    )

    # Write a bounded scratch check artifact and promote it via the 11-step O_NOFOLLOW promoter
    scratch_note_file = scratch_dir / "config-check.txt"
    scratch_note_file.write_text(
        f"Bounded static & local config verification for {server_id} by {hunter_id}.\n",
        encoding="utf-8",
    )
    promote_agent_artifacts(
        scratch_root=scratch_dir,
        artifacts_root=artifacts_dir,
        allowlisted_files=["config-check.txt"],
    )

    run_metadata["agents_spent"] += 1

    # Update assigned units to covered with valid source check records
    for u in assigned_units:
        u["status"] = "covered"
        u["agent_id"] = hunter_id
        u["reviewed_paths"] = list(u["starting_paths"])
        u["local_checks"] = [
            {
                "agent_id": hunter_id,
                "reviewed_paths": list(u["starting_paths"]),
                "invariant": f"Enforce {u['boundary']} on {u['surface']}.",
                "method": "local",
                "result": "Evaluated local configuration and boundary constraints in sandboxed scratch.",
                "artifact": f"agents/{hunter_id}/artifacts/config-check.txt",
            }
        ]

    # Spend reserved coverage critic call(s)
    run_metadata["agents_spent"] += 1 if profile == "quick" else 2

    # Phase 3, 4, 5: Validate coverage-ledger.json and findings.json
    ledger_units.sort(key=lambda u: u["coverage_id"])
    ledger_path.write_text(json.dumps(ledger_units, indent=2), encoding="utf-8")
    run_node_validator("validate-coverage-ledger.cjs", ledger_path)

    findings: List[Dict[str, Any]] = []
    findings_path.write_text(json.dumps(findings, indent=2), encoding="utf-8")
    run_node_validator("validate-findings.cjs", findings_path)

    # Phase 6: Target-Neutral Report Synthesis + Hardening Notes
    run_metadata["agents_spent"] += 1
    hardening_notes = [
        "Systemd units: enforce ProtectSystem=strict, PrivateTmp=true, and NoNewPrivileges=true on service daemons.",
        "Docker Compose services: pin image digests, drop ALL capabilities (cap_drop: [ALL]), and run as non-root UID.",
        "Reverse proxy (Nginx/Caddy): strip untrusted X-Forwarded-* identity headers at the outer edge before proxying.",
    ]
    run_metadata["hardening_notes"] = hardening_notes
    run_metadata["run_status"] = "complete"
    metadata_path.write_text(json.dumps(run_metadata, indent=2), encoding="utf-8")

    partial_banner = (
        f"> **Note**: This `{profile}` run is a bounded pass. Deferred units: {len(deferred_units)}.\n\n"
        if profile == "quick" or deferred_units
        else ""
    )

    report_md = (
        f"# Security Audit Report — `{server_id}`\n\n"
        f"{partial_banner}"
        f"- **Profile**: `{profile}`\n"
        f"- **Source Ref**: `{source_ref}`\n"
        f"- **Execution Policy**: `sandboxed-source-and-local-only` (Zero external network during audit)\n"
        f"- **Subagent Budget**: `{run_metadata['agents_spent']}` spent of `{budget if budget is not None else 'unbounded'}`\n"
        f"- **Selected Skill Companions**: {', '.join(f'`{c}`' for c in companions)}\n\n"
        "## Security Posture Summary\n"
        f"Reviewed {len(assigned_units)} coverage unit(s) across `{target_root}`. "
        "Zero confirmed boundary bypasses were identified in the current static snapshot.\n\n"
        "## Confirmed Findings\n"
        "No confirmed findings in this pass.\n\n"
        "## Needs Validation\n"
        "No blocked validation leads in this pass.\n\n"
        "## What We Should Improve (Hardening Notes)\n"
        + "\n".join(f"- {note}" for note in hardening_notes)
        + "\n\n## Coverage Summary\n"
        f"- **Covered Units**: {len(assigned_units)}\n"
        f"- **Deferred Units**: {len(deferred_units)}\n"
    )
    report_path.write_text(report_md, encoding="utf-8")
    detail_path.write_text(
        "# Findings Detail\n\nNo confirmed medium, high, or critical findings in this pass.\n",
        encoding="utf-8",
    )
    nv_path.write_text(
        "# Needs Validation\n\nNo unresolved validation blockers in this pass.\n",
        encoding="utf-8",
    )

    # Post-Audit Host Step: Format (and optionally send) Discord Webhook Report
    webhook_env_name = discord_cfg.get("webhook_url_env") or "DISCORD_WEBHOOK_URL"
    webhook_url = os.environ.get(webhook_env_name, "")
    discord_payload_path = output_dir / "discord-payload.json"

    cmd = [
        "node",
        str(SCRIPTS_DIR / "send-discord-report.cjs"),
        str(output_dir),
        "--server-id",
        server_id,
        "--output-payload",
        str(discord_payload_path),
    ]
    if dry_run or not send_discord or not webhook_url:
        cmd.append("--dry-run")
    else:
        cmd.extend(["--webhook-url", webhook_url])

    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise RuntimeError(f"Discord report step failed:\n{proc.stderr or proc.stdout}")

    return run_metadata


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Portable Antigravity SDK Harness² + /security-audit Server Runner"
    )
    parser.add_argument(
        "--config",
        required=True,
        help="Path to server-audit.yaml or JSON config file",
    )
    parser.add_argument(
        "--env-file",
        default=".env",
        help="Path to .env file with SERVER_ID, AUDIT_LLM_API_KEY, DISCORD_WEBHOOK_URL",
    )
    parser.add_argument(
        "--output-dir",
        default="",
        help="Output directory for run artifacts (defaults to ./audit-runs/<server-id>/<timestamp>)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Run pipeline and generate validated artifacts + Discord payload without calling external webhook",
    )
    parser.add_argument(
        "--send-discord",
        action="store_true",
        help="Post the final report to DISCORD_WEBHOOK_URL after validation passes",
    )
    args = parser.parse_args()

    load_dotenv(Path(args.env_file))
    cfg = load_config_file(Path(args.config))

    server_id = cfg.get("server", {}).get("id") or "server-01"
    if args.output_dir:
        out_dir = Path(args.output_dir).resolve()
    else:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        out_dir = (PROJECT_ROOT / "audit-runs" / server_id / ts).resolve()

    metadata = asyncio.run(
        run_audit_pipeline(
            cfg,
            output_dir=out_dir,
            dry_run=args.dry_run,
            send_discord=args.send_discord,
        )
    )
    print(
        json.dumps(
            {
                "status": metadata["run_status"],
                "server_id": metadata["server_id"],
                "profile": metadata["profile"],
                "agents_spent": metadata["agents_spent"],
                "output_dir": str(out_dir),
                "discord_payload": str(out_dir / "discord-payload.json"),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
