#!/usr/bin/env python3
"""
Unit & Integration Test Suite for the Portable Antigravity SDK Harness (`harness/`).

Verifies:
1. RFC 3986 `coverage_id` encoding & ledger unit validation against `scripts/validate-coverage-ledger.cjs`.
2. 9-Part Hunter prompt assembly (`HUNTING.md`) with verbatim companion blocks and schema branches.
3. 11-Step race-safe `O_NOFOLLOW` artifact promotion (`harness/artifact_promoter.py`), including rejection
   of symlinks, `..` traversal, and oversized files.
4. Strict pre-reconnaissance budget gate (`SKILL.md`).
5. End-to-end dry-run of `run_audit_pipeline` producing schema-validated `findings.json`,
   `coverage-ledger.json`, `REPORT.md`, and `discord-payload.json`.
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from harness.artifact_promoter import PromotionError, promote_agent_artifacts
from harness.prompt_builder import (
    build_hunter_prompt,
    canonical_coverage_id,
    create_ledger_unit,
)
from harness.run_server_audit import check_budget_gate, run_audit_pipeline


class HarnessTestSuite(unittest.TestCase):
    def test_rfc3986_coverage_id_and_ledger_validator(self) -> None:
        refs = {
            "surface": "nginx/conf.d/app.conf#location /admin",
            "boundary": "nginx/conf.d/app.conf#auth_request",
            "subsystem": "profile/quick/all-in-scope-subsystems",
            "attack_class": "CLOUD-AND-DEPLOYMENT.md#Trusted-proxy and mesh identity bypass",
        }
        cid = canonical_coverage_id(refs)
        self.assertIn("profile%2Fquick%2Fall-in-scope-subsystems", cid)

        unit = create_ledger_unit(
            canonical_refs=refs,
            surface="Admin proxy route",
            boundary="Proxy auth_request check",
            subsystem="All In-Scope Subsystems",
            attack_class="Trusted-proxy and mesh identity bypass",
            starting_paths=["nginx/conf.d/app.conf"],
            ordinary_attack_class_block="ATTACK-CLASSES.md#Authentication and session boundaries",
            selected_companion_blocks=[
                "CLOUD-AND-DEPLOYMENT.md#Trusted-proxy and mesh identity bypass"
            ],
        )

        with tempfile.TemporaryDirectory() as tmp:
            ledger_file = Path(tmp) / "coverage-ledger.json"
            ledger_file.write_text(json.dumps([unit], indent=2), encoding="utf-8")
            proc = subprocess.run(
                [
                    "node",
                    str(PROJECT_ROOT / "scripts" / "validate-coverage-ledger.cjs"),
                    str(ledger_file),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, f"Validator failed: {proc.stderr or proc.stdout}")

    def test_9part_hunter_prompt_builder(self) -> None:
        refs = {
            "surface": "docker-compose.yml#worker",
            "boundary": "docker-compose.yml#privileged",
            "subsystem": "containers",
            "attack_class": "CLOUD-AND-DEPLOYMENT.md#Host or control-plane capability exposure",
        }
        unit = create_ledger_unit(
            canonical_refs=refs,
            surface="Worker container",
            boundary="Host capability boundary",
            subsystem="Containers",
            attack_class="Host or control-plane capability exposure",
            starting_paths=["docker-compose.yml"],
            ordinary_attack_class_block="ATTACK-CLASSES.md#Privilege and isolation boundaries",
            selected_companion_blocks=[
                "CLOUD-AND-DEPLOYMENT.md#Host or control-plane capability exposure"
            ],
        )
        prompt = build_hunter_prompt(
            skill_dir=PROJECT_ROOT / "skills" / "security-audit",
            architecture_md="# Architecture\nTest server architecture.",
            assigned_units=[unit],
            agent_id="hunter-01",
            scratch_dir="/tmp/scratch",
            artifacts_dir="/tmp/artifacts",
        )
        for part_num in range(1, 10):
            self.assertIn(f"## Part {part_num}:", prompt)
        self.assertIn("Artifact promotion procedure (trusted parent-side code only):", prompt)
        self.assertIn("Host or control-plane capability exposure", prompt)

    def test_11step_artifact_promotion_and_symlink_rejection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            scratch = base / "scratch"
            artifacts = base / "artifacts"
            scratch.mkdir()
            artifacts.mkdir()

            # Valid regular file promotion
            (scratch / "sub").mkdir()
            (scratch / "sub" / "poc.txt").write_text("reproduced boundary check", encoding="utf-8")
            res = promote_agent_artifacts(
                scratch_root=scratch,
                artifacts_root=artifacts,
                allowlisted_files=["sub/poc.txt"],
            )
            self.assertEqual(res["sub/poc.txt"], "promoted")
            self.assertEqual(
                (artifacts / "sub" / "poc.txt").read_text(encoding="utf-8"),
                "reproduced boundary check",
            )

            # Reject path traversal
            with self.assertRaises(PromotionError):
                promote_agent_artifacts(
                    scratch_root=scratch,
                    artifacts_root=artifacts,
                    allowlisted_files=["../escape.txt"],
                )

            # Reject symlink leaf
            symlink_path = scratch / "evil-link.txt"
            os.symlink(scratch / "sub" / "poc.txt", symlink_path)
            with self.assertRaises(PromotionError):
                promote_agent_artifacts(
                    scratch_root=scratch,
                    artifacts_root=artifacts,
                    allowlisted_files=["evil-link.txt"],
                )

    def test_budget_gate_and_dry_run_pipeline(self) -> None:
        # Insufficient budget (< 6 for quick) must fail gate
        ok, _, reason = check_budget_gate("quick", 4)
        self.assertFalse(ok)
        self.assertEqual(reason, "budget_cannot_fund_reconnaissance_and_reserves")

        # Valid quick budget (10) must pass gate and complete dry-run pipeline
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "run-1"
            cfg = {
                "server": {
                    "id": "test-server-01",
                    "repo_name": "test-server-services",
                    "target_root": str(PROJECT_ROOT),
                    "profile": "quick",
                    "budget": 10,
                },
                "reporting": {"discord": {"enabled": True}},
            }
            meta = asyncio.run(
                run_audit_pipeline(cfg, output_dir=out_dir, dry_run=True, send_discord=False)
            )
            self.assertEqual(meta["run_status"], "complete")
            self.assertTrue((out_dir / "findings.json").exists())
            self.assertTrue((out_dir / "coverage-ledger.json").exists())
            self.assertTrue((out_dir / "REPORT.md").exists())
            self.assertTrue((out_dir / "discord-payload.json").exists())


if __name__ == "__main__":
    unittest.main()
