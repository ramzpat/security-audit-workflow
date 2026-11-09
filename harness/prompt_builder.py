#!/usr/bin/env python3
"""
Deterministic Prompt & Ledger Builder for the /security-audit Skill and Google Harness².

Implements:
1. RFC 3986 percent-encoded canonical coverage_id generation matching validate-coverage-ledger.cjs.
2. Verbatim block extraction from ATTACK-CLASSES.md, CLOUD-AND-DEPLOYMENT.md, and companion skill files.
3. Exact 9-part Hunter prompt assembly (HUNTING.md) including the 11-step promotion block.
4. Recon 1a-1d (RECONNAISSANCE.md) and Phase 3 / Phase 5 Verifier prompts (VALIDATION-AND-REPORTING.md).
"""

from __future__ import annotations

import json
import re
import unicodedata
from pathlib import Path
from typing import Any, Dict, List, Optional

UNRESERVED_BYTES = set(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
)

PROMOTION_PROCEDURE_BLOCK = """Artifact promotion procedure (trusted parent-side code only):
Reference only for you: the parent performs these steps; you never perform them.

Before execution, the parent opens and retains trusted, non-inheritable directory
descriptors for the agent's scratch/ and artifacts/ roots, and records an allowlist
of expected scratch-relative artifact files plus explicit per-file and cumulative
byte limits. Never pass those descriptors to the agent or sandbox. After the sandbox
and all its processes terminate, trusted parent-side code promotes each allowlisted
file separately:

1. Validate the declared relative path: reject absolute, empty, `.`, `..`, or
   symlinked components.
2. Walk each parent component from the retained scratch-root descriptor with
   no-follow directory-relative operations; never reopen by path.
3. Open the leaf no-follow and nonblocking.
4. Verify with `fstat` that it is a regular file with link count exactly one and
   within the recorded per-file and cumulative byte limits.
5. Enforce those limits again while reading from that descriptor.
6. Copy exactly the verified size, repeat `fstat`, and reject a changed identity,
   type, link count, or size.
7. For the destination, walk every parent component from the retained
   artifacts-root descriptor with no-follow directory-relative operations; require
   each existing component to be a real directory, and create any missing directory
   exclusively before reopening and verifying it no-follow.
8. Create the leaf exclusively without following links, verify that the opened
   destination is a regular file with link count exactly one, and copy from the
   verified source descriptor without reopening either path.
9. Use equivalent race-safe APIs on non-POSIX systems.
10. Never recursively copy or glob scratch, extract an archive into artifacts, or
    open or promote a symlink, FIFO, socket, device, directory, hard-linked file,
    changing file, or file that exceeds its bound.
11. If any check is unavailable, cannot be enforced, or fails, discard the scratch
    entry; if it is decisive evidence, retain `needs_validation` with the exact
    promotion blocker."""

CORE_HUNTING_METHOD_BLOCK = """## Defensive vulnerability-finding method

Your goal is to find source-grounded security invariant failures and the smallest fix,
not to expand harm beyond the boundary result. Stay within source review and bounded local execution.
Do not contact deployed endpoints, provider APIs, registries, identity systems,
message brokers, shared services, or other users. Use local dummy data only.

READ THE CODE AT DEPTH. Follow each assigned input through parsing, identity,
authorization, normalization, state, derived copies, and the final sink. Read sibling,
legacy, batch, retry, cancellation, migration, and error paths that produce the same
effect. Compare sibling controls for equivalence, not only presence, and compare what
one component guarantees with what the next component assumes.

WORK FROM A CONCRETE INVARIANT:
1. Name the lower-trust principal and starting capability.
2. Name the accepted value, action, state transition, or resource selector.
3. Locate the control that should reject, bind, isolate, limit, or revoke it.
4. Trace the exact source path after that decision.
5. Stop at the smallest affected dummy record, wrong return value, process-integrity
   effect, or locally observable shared-resource effect.
6. State a source-level change and regression case that enforce the invariant."""

CORE_VALIDATION_RULES_BLOCK = """## Core validation rules

- Only `confirmed` records receive severity (`critical`, `high`, `medium`, `low`, `informational`).
  Overall severity must never exceed demonstrated impact.
- `needs_validation` means a source-grounded boundary hypothesis is blocked on an external or
  deployment fact. It never receives a severity rating.
- Missing defense-in-depth with no reachable boundary violation must be returned under `hardening`,
  not `candidates`."""


def encode_canonical_ref(ref: str) -> str:
    """
    Encodes a canonical reference string using Unicode NFC and RFC 3986 percent-encoding
    matching scripts/validate-coverage-ledger.cjs.
    """
    if not isinstance(ref, str) or not ref or ref != ref.strip():
        raise ValueError(f"Invalid canonical reference: {ref!r}")
    normalized = unicodedata.normalize("NFC", ref)
    if normalized != ref:
        raise ValueError(f"Canonical reference must be Unicode NFC: {ref!r}")
    raw_bytes = normalized.encode("utf-8")
    out: List[str] = []
    for b in raw_bytes:
        if b in UNRESERVED_BYTES:
            out.append(chr(b))
        else:
            out.append(f"%{b:02X}")
    return "".join(out)


def canonical_coverage_id(canonical_refs: Dict[str, str]) -> str:
    """
    Builds the canonical RFC 3986 coverage_id:
    surface::boundary::subsystem::attack_class[::lifecycle]
    """
    parts = [
        encode_canonical_ref(canonical_refs["surface"]),
        encode_canonical_ref(canonical_refs["boundary"]),
        encode_canonical_ref(canonical_refs["subsystem"]),
        encode_canonical_ref(canonical_refs["attack_class"]),
    ]
    if "lifecycle" in canonical_refs and canonical_refs["lifecycle"] is not None:
        parts.append(encode_canonical_ref(canonical_refs["lifecycle"]))
    return "::".join(parts)


def create_ledger_unit(
    *,
    canonical_refs: Dict[str, str],
    surface: str,
    boundary: str,
    subsystem: str,
    attack_class: str,
    starting_paths: List[str],
    ordinary_attack_class_block: Optional[str],
    selected_companion_blocks: Optional[List[str]] = None,
    excluded_blocks: Optional[List[Dict[str, str]]] = None,
    prior_status: str = "new",
    wave: Optional[int] = 1,
    status: str = "planned",
    agent_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Creates a schema-valid coverage ledger unit."""
    unit: Dict[str, Any] = {
        "coverage_id": canonical_coverage_id(canonical_refs),
        "canonical_refs": dict(canonical_refs),
        "surface": surface,
        "boundary": boundary,
        "subsystem": subsystem,
        "attack_class": attack_class,
        "starting_paths": list(starting_paths),
        "ordinary_attack_class_block": ordinary_attack_class_block,
        "selected_companion_blocks": list(selected_companion_blocks or []),
        "excluded_blocks": list(
            excluded_blocks
            or [
                {
                    "block": "CLIENT-SIDE.md#DOM and browser boundaries",
                    "reason": "Server-side service target does not execute browser DOM code.",
                }
            ]
        ),
        "prior_status": prior_status,
        "attempts": [],
        "wave": wave,
        "status": status,
        "agent_id": agent_id,
        "reviewed_paths": [],
        "local_checks": [],
        "result_fingerprints": [],
        "unresolved": [],
    }
    return unit


def extract_markdown_block(skill_dir: Path, block_ref: str) -> str:
    """
    Extracts a verbatim block from a skill markdown file by `FILE.md#HeadingOrBoldName`.
    """
    if "#" not in block_ref:
        file_name, section_name = block_ref, ""
    else:
        file_name, section_name = block_ref.split("#", 1)

    file_path = skill_dir / file_name
    if not file_path.exists():
        raise FileNotFoundError(f"Skill file not found: {file_path}")

    text = file_path.read_text(encoding="utf-8")
    if not section_name:
        return text.strip()

    lines = text.splitlines()
    # Try matching markdown heading first: ^#{1,6}\s+<section_name>
    heading_re = re.compile(
        r"^(#{1,6})\s+" + re.escape(section_name) + r"(?:\s+\(.*\))?\s*$"
    )
    for i, line in enumerate(lines):
        m = heading_re.match(line)
        if m:
            level = len(m.group(1))
            collected = [line]
            for j in range(i + 1, len(lines)):
                next_heading = re.match(r"^(#{1,6})\s+", lines[j])
                if next_heading and len(next_heading.group(1)) <= level:
                    break
                collected.append(lines[j])
            return "\n".join(collected).strip()

    # Try matching bold attack-class block: **<section_name>**
    bold_marker = f"**{section_name}**"
    for i, line in enumerate(lines):
        if line.strip() == bold_marker or line.strip().startswith(bold_marker):
            collected = [line]
            for j in range(i + 1, len(lines)):
                if lines[j].strip().startswith("**") or re.match(r"^#{1,6}\s+", lines[j]):
                    break
                collected.append(lines[j])
            return "\n".join(collected).strip()

    return f"<!-- Block {block_ref} from {file_name} -->\n" + "\n".join(lines[:40])


def load_schema_branches(skill_dir: Path) -> Dict[str, Any]:
    """Loads confirmed, needs_validation, and rejected branches from report-schema.json."""
    schema_path = skill_dir / "report-schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    one_of = schema.get("items", {}).get("oneOf", [])
    branches: Dict[str, Any] = {}
    for branch in one_of:
        verdict = (
            branch.get("properties", {}).get("verdict", {}).get("const")
        )
        if verdict:
            branches[verdict] = branch
    return branches


def build_recon_prompts(target_path: str) -> Dict[str, str]:
    """
    Returns the 4 parallel reconnaissance prompts (Agents 1a, 1b, 1c, 1d)
    defined in RECONNAISSANCE.md.
    """
    return {
        "recon-1a": (
            f"Read the target at {target_path}. Do not use network access. Return:\n"
            "1. Product type, users, operators, and ordinary trust-sensitive actions.\n"
            "2. Languages, frameworks, build system, runtimes, and locally visible deployment models "
            "(Docker/Compose, systemd units, Nginx/Caddy reverse proxies, app services).\n"
            "3. Repository-relative entry points and subsystem boundaries.\n"
            "4. Exact build and test commands that could run offline with local dependencies, their expected "
            "write locations, and the target-controlled inputs they process. Do not run them during reconnaissance.\n"
            "5. Comparable software or protocol visible from local documentation and dependencies.\n"
            "6. Missing local toolchains or runtime facts that limit bounded execution.\n"
            "Return only source facts with repository-relative file:line references."
        ),
        "recon-1b": (
            f"Read all source at {target_path} that establishes identity, authorization, isolation, and privilege. Map:\n"
            "1. Each lower-trust principal and the actions it has by design.\n"
            "2. Authentication or peer identity at each entry surface.\n"
            "3. Per-resource authorization and tenant/owner scope.\n"
            "4. Process, container, workload, CI, plugin, model/tool, or local-IPC authority.\n"
            "5. Privilege changes, confirmation, revocation, recovery, and fallback paths.\n"
            "6. Which controls are source-visible and which depend on an unobserved deployment fact.\n"
            "Return trust boundaries and control locations with repository-relative file:line references. Do not infer live reachability."
        ),
        "recon-1c": (
            f"Inventory every source-visible place at {target_path} where external or lower-trust input enters:\n"
            "- HTTP/browser, RPC/message/protocol, files/archive/document, CLI/env/config, container mounts, "
            "cloud events/IAM selectors, model context/tool arguments, and local IPC.\n"
            "For each surface, follow major transformations, stored or derived copies, and security-relevant sinks. "
            "Record source-visible limits and parallel paths to the same effect.\n"
            "Return repository-relative paths and line numbers. Be complete, but do not execute or send inputs."
        ),
        "recon-1d": (
            f"Read tests, build definitions, manifests, packaging, and maintained environment overlays at {target_path}. Return:\n"
            "1. Small offline tests or existing fixtures that could validate trust boundaries with dummy data inside the required OS-enforced sandbox.\n"
            "2. Processes that could use an isolated loopback network namespace without external or shared dependencies.\n"
            "3. Commands that would fetch dependencies, publish artifacts, contact paid/provider APIs, or affect shared state; mark them prohibited.\n"
            "4. Deployed controls and attachments that source cannot establish and therefore require needs_validation if decisive.\n"
            "5. The final active source path for each deployment mode only where the repository selects it deterministically.\n"
            "6. Whether the local platform can enforce an empty allowlisted environment, no external network, read-only target mounts, and scratch-only writes.\n"
            "7. Whether trusted parent-side code can promote predeclared scratch files with 11-step O_NOFOLLOW descriptor traversal."
        ),
    }


def build_hunter_prompt(
    *,
    skill_dir: Path,
    architecture_md: str,
    assigned_units: List[Dict[str, Any]],
    agent_id: str,
    scratch_dir: str,
    artifacts_dir: str,
    prior_exclusions: Optional[List[Dict[str, str]]] = None,
    peer_coverage_ids: Optional[List[str]] = None,
    max_file_bytes: int = 262144,
    max_cumulative_bytes: int = 1048576,
) -> str:
    """
    Constructs the exact 9-part hunter prompt required by skills/security-audit/HUNTING.md.
    """
    schema_branches = load_schema_branches(skill_dir)

    # Collect unique ordinary & companion blocks across assigned units
    ordinary_blocks: List[str] = []
    companion_files: List[str] = []
    companion_blocks: List[str] = []
    excluded_map: List[Dict[str, str]] = []

    for unit in assigned_units:
        ob = unit.get("ordinary_attack_class_block")
        if ob and ob not in ordinary_blocks:
            ordinary_blocks.append(ob)
        for cb in unit.get("selected_companion_blocks", []):
            if cb not in companion_blocks:
                companion_blocks.append(cb)
            comp_file = cb.split("#", 1)[0]
            if comp_file not in companion_files:
                companion_files.append(comp_file)
        for ex in unit.get("excluded_blocks", []):
            if ex not in excluded_map:
                excluded_map.append(ex)

    verbatim_blocks_text: List[str] = []
    for ob in ordinary_blocks:
        verbatim_blocks_text.append(f"### Ordinary Block: {ob}\n" + extract_markdown_block(skill_dir, ob))

    for cf in companion_files:
        for req_section in ["Core discipline", "Universal moves", "Validation rules"]:
            ref = f"{cf}#{req_section}"
            verbatim_blocks_text.append(f"### Companion Required Section: {ref}\n" + extract_markdown_block(skill_dir, ref))

    for cb in companion_blocks:
        verbatim_blocks_text.append(f"### Companion Attack Class: {cb}\n" + extract_markdown_block(skill_dir, cb))

    part1 = (
        "## Part 1: Role Preamble\n"
        "Your goal is to find source-grounded security invariant failures in your assigned coverage units. "
        "You must return exactly one JSON object matching the structured-result contract at the end of this prompt."
    )
    part2 = f"## Part 2: Architecture Summary (`architecture.md`)\n{architecture_md.strip()}"
    part3 = (
        "## Part 3: Assigned Coverage Units & Assignment Block Map\n"
        + json.dumps(
            [
                {
                    "coverage_id": u["coverage_id"],
                    "subsystem": u["subsystem"],
                    "boundary": u["boundary"],
                    "starting_paths": u["starting_paths"],
                    "ordinary_attack_class_block": u.get("ordinary_attack_class_block"),
                    "selected_companion_blocks": u.get("selected_companion_blocks", []),
                }
                for u in assigned_units
            ],
            indent=2,
        )
    )
    part4 = "## Part 4: Verbatim Selected Attack-Class & Companion Blocks\n" + "\n\n".join(verbatim_blocks_text)
    part5 = "## Part 5: Explicit Excluded Blocks & Reasons\n" + json.dumps(excluded_map, indent=2)
    part6 = (
        "## Part 6: Core Hunting Method & Promotion Procedure\n"
        f"{CORE_HUNTING_METHOD_BLOCK}\n\n{PROMOTION_PROCEDURE_BLOCK}"
    )
    part7 = f"## Part 7: Core Validation Rules\n{CORE_VALIDATION_RULES_BLOCK}"
    part8 = (
        "## Part 8: Prior Confirmed Exclusions & Peer-Owned Coverage IDs\n"
        + json.dumps(
            {
                "prior_confirmed_same_source_exclusions": prior_exclusions or [],
                "peer_owned_coverage_ids": peer_coverage_ids or [],
            },
            indent=2,
        )
    )
    part9 = (
        "## Part 9: Scratch Isolation, Agent ID & Structured Output Contract\n"
        f"- Canonical `agent_id`: `{agent_id}`\n"
        f"- Assigned writable `scratch/` directory: `{scratch_dir}`\n"
        f"- Parent-owned `artifacts/` directory (do NOT write directly): `{artifacts_dir}`\n"
        f"- Per-file promotion limit: `{max_file_bytes}` bytes; cumulative limit: `{max_cumulative_bytes}` bytes\n\n"
        "Return ONLY a single JSON object with keys `agent_id`, `units`, `candidates`, `hardening`, and `uncovered`.\n"
        "Each item in `candidates` must conform verbatim to either the `confirmed` or `needs_validation` branch of `report-schema.json`:\n"
        + json.dumps(
            {
                "confirmed_branch": schema_branches.get("confirmed", {}),
                "needs_validation_branch": schema_branches.get("needs_validation", {}),
            },
            indent=2,
        )
    )

    return "\n\n".join([part1, part2, part3, part4, part5, part6, part7, part8, part9])


def build_phase3_verifier_prompt(
    *,
    skill_dir: Path,
    candidate: Dict[str, Any],
    architecture_md: str,
    verifier_id: str,
    scratch_dir: str,
    artifacts_dir: str,
    merge_phase5: bool = False,
) -> str:
    """
    Constructs the Phase 3 Candidate Verifier prompt (and merges Phase 5 checks when profile=='quick').
    """
    schema_branches = load_schema_branches(skill_dir)
    quick_notice = (
        "\nNOTE (`quick` profile): Perform both Phase 3 candidate validation AND Phase 5 independent record "
        "verification (verify every repository-relative path, positive line number, severity cap `overall <= impact`, "
        "and non-destructive validation plan) in this pass."
        if merge_phase5
        else ""
    )
    return (
        "You did not write this candidate. Try to refute it from repository source and bounded local evidence. "
        "Do not contact deployed endpoints or external/shared services.\n"
        f"{quick_notice}\n\n"
        f"- Verifier `agent_id`: `{verifier_id}`\n"
        f"- Writable `scratch/`: `{scratch_dir}`\n"
        f"- Parent-owned `artifacts/`: `{artifacts_dir}`\n\n"
        f"### Promotion Procedure\n{PROMOTION_PROCEDURE_BLOCK}\n\n"
        f"### Architecture Context\n{architecture_md.strip()}\n\n"
        f"### Candidate Under Adversarial Review\n{json.dumps(candidate, indent=2)}\n\n"
        "Return ONLY one JSON object:\n"
        '`{"decision": "confirmed|needs_validation|rejected", "record": { ... }}`\n'
        "where `record` strictly matches one of these `report-schema.json` branches:\n"
        + json.dumps(schema_branches, indent=2)
    )


def build_phase5_verifier_prompt(
    *,
    skill_dir: Path,
    record: Dict[str, Any],
    verifier_id: str,
) -> str:
    """Constructs the Phase 5 Independent Record Verifier prompt."""
    schema_branches = load_schema_branches(skill_dir)
    return (
        f"Independent Phase 5 Record Verification (`agent_id`: `{verifier_id}`).\n"
        "Verify every repository-relative trace/evidence path, positive line number, condition, "
        "severity calibration (`overall_severity` <= `impact.score`), remediation strategy, or "
        "`needs_validation` blocker and non-destructive validation plan.\n\n"
        f"### Record Under Verification\n{json.dumps(record, indent=2)}\n\n"
        "Return ONLY one JSON object:\n"
        '`{"decision": "verified", "fingerprint": "..."}` or '
        '`{"decision": "replace", "reason": "...", "record": { ... }}`\n'
        "Schema branches:\n"
        + json.dumps(schema_branches, indent=2)
    )
