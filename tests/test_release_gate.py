from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scripts.check_release_gate import load_gate, main, release_status


ROOT = Path(__file__).resolve().parents[1]


class ReleaseGateTests(unittest.TestCase):
    @staticmethod
    def _write_project(path: Path, version: str) -> None:
        path.write_text(
            f'[project]\nname = "synthetic-release-gate"\nversion = "{version}"\n',
            encoding="utf-8",
        )

    def test_repository_is_deliberately_blocked_before_publication(self) -> None:
        gate = load_gate(ROOT / "release/release-gate.json")
        ready, blockers = release_status(gate, "0.5.0.dev0")

        self.assertFalse(ready)
        self.assertIn("publication_authorized", blockers)
        self.assertIn("approved_feature_scope_complete", blockers)
        self.assertIn("english_italian_public_surface_complete", blockers)
        self.assertIn("stable_version", blockers)

    def test_ready_requires_every_gate_and_a_stable_version(self) -> None:
        gate = {
            "schema_version": 1,
            "approved_feature_scope_complete": True,
            "cross_platform_packages_verified": True,
            "english_italian_public_surface_complete": True,
            "license_selected": True,
            "publication_authorized": True,
            "sanitized_assets_approved": True,
            "security_review_complete": True,
        }

        self.assertEqual(release_status(gate, "1.0.0"), (True, []))
        self.assertFalse(release_status(gate, "1.0.0rc1")[0])

    def test_require_blocked_fails_if_gate_opens_prematurely(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            gate_path = root / "gate.json"
            project_path = root / "pyproject.toml"
            gate_path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "approved_feature_scope_complete": True,
                        "cross_platform_packages_verified": True,
                        "english_italian_public_surface_complete": True,
                        "license_selected": True,
                        "publication_authorized": True,
                        "sanitized_assets_approved": True,
                        "security_review_complete": True,
                    }
                ),
                encoding="utf-8",
            )
            self._write_project(project_path, "1.0.0")

            self.assertEqual(
                main(
                    [
                        "--gate",
                        str(gate_path),
                        "--project",
                        str(project_path),
                        "--require-blocked",
                    ]
                ),
                1,
            )

    def test_require_blocked_accepts_an_explicitly_blocked_gate(self) -> None:
        self.assertEqual(main(["--require-blocked"]), 0)

    def test_unknown_or_non_boolean_fields_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "gate.json"
            path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "approved_feature_scope_complete": False,
                        "cross_platform_packages_verified": False,
                        "english_italian_public_surface_complete": False,
                        "license_selected": False,
                        "publication_authorized": "yes",
                        "sanitized_assets_approved": False,
                        "security_review_complete": False,
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaises(ValueError):
                load_gate(path)


if __name__ == "__main__":
    unittest.main()
