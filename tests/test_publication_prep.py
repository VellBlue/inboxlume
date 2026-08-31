from __future__ import annotations

import re
import tomllib
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.package_desktop import (
    SUPPORTED_SYSTEMS,
    pyinstaller_command,
    worker_pyinstaller_command,
)


ROOT = Path(__file__).resolve().parents[1]


class PublicationPreparationTests(unittest.TestCase):
    def test_supported_python_metadata_matches_tested_versions(self) -> None:
        metadata = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")

        self.assertEqual(metadata["project"]["requires-python"], ">=3.11,<3.14")
        self.assertEqual(
            {
                item.rsplit(" :: ", 1)[-1]
                for item in metadata["project"]["classifiers"]
                if item.startswith("Programming Language :: Python :: 3.")
            },
            {"3.11", "3.12", "3.13"},
        )
        self.assertIn('python: ["3.11", "3.12", "3.13"]', ci)
        self.assertIn("python-version: ${{ matrix.python }}", ci)

    def test_external_actions_are_immutably_pinned_with_version_comments(self) -> None:
        action_line = re.compile(
            r"^\s*(?:-\s*)?uses:\s*(\S+?)(?:\s+#\s*(\S.*))?\s*$"
        )
        sha = re.compile(r"[0-9a-f]{40}")
        workflows = sorted((ROOT / ".github/workflows").glob("*.yml"))

        self.assertTrue(workflows)
        for workflow in workflows:
            for line_number, line in enumerate(
                workflow.read_text(encoding="utf-8").splitlines(), start=1
            ):
                if "uses:" not in line:
                    continue
                match = action_line.match(line)
                self.assertIsNotNone(match, f"{workflow.name}:{line_number}")
                assert match is not None
                action, separator, reference = match.group(1).rpartition("@")
                if action.startswith("./"):
                    continue
                self.assertEqual(separator, "@", f"{workflow.name}:{line_number}")
                self.assertIsNotNone(
                    sha.fullmatch(reference),
                    f"{workflow.name}:{line_number}",
                )
                self.assertRegex(
                    match.group(2) or "",
                    r"^v\S+$",
                    f"{workflow.name}:{line_number}",
                )

    def test_ci_fails_if_the_release_gate_opens(self) -> None:
        ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        package_smoke = (ROOT / ".github/workflows/package-smoke.yml").read_text(
            encoding="utf-8"
        )

        command = "python scripts/check_release_gate.py --require-blocked"
        self.assertIn(command, ci)
        self.assertIn(command, package_smoke)
        self.assertIn("python scripts/smoke_packaged_worker.py", package_smoke)

    def test_site_uses_only_local_assets_and_has_no_tracking(self) -> None:
        index = (ROOT / "docs/index.html").read_text(encoding="utf-8")
        italian = (ROOT / "docs/it/index.html").read_text(encoding="utf-8")
        css = (ROOT / "docs/assets/site.css").read_text(encoding="utf-8")

        self.assertIn('<html lang="en">', index)
        self.assertIn('<html lang="it">', italian)
        for page in (index, italian):
            self.assertNotIn("http://", page)
            self.assertNotIn("https://", page)
            without_privacy_notice = page.casefold().replace("no analytics", "").replace(
                "nessun analytics", ""
            )
            self.assertNotIn("analytics", without_privacy_notice)
        self.assertNotIn("@import", css)
        for asset in (
            "docs/assets/site.css",
            "docs/assets/favicon.svg",
            "docs/assets/architecture.svg",
            "docs/assets/inboxlume-settings.png",
            "docs/assets/inboxlume-settings-it.png",
            "docs/it/ARTICLE.md",
        ):
            self.assertTrue((ROOT / asset).is_file(), asset)

    def test_ci_contains_no_publication_or_artifact_upload_step(self) -> None:
        workflows = list((ROOT / ".github/workflows").glob("*.yml"))
        self.assertEqual({path.name for path in workflows}, {"ci.yml", "package-smoke.yml"})
        forbidden = (
            "actions/upload-artifact",
            "actions/deploy-pages",
            "gh release",
            "pypa/gh-action-pypi-publish",
            "softprops/action-gh-release",
        )
        payload = "\n".join(path.read_text(encoding="utf-8") for path in workflows)
        for token in forbidden:
            self.assertNotIn(token, payload)

    def test_packaging_command_is_argument_only_and_scoped_per_system(self) -> None:
        with patch("pathlib.Path.is_file", return_value=True):
            for system_name, target in SUPPORTED_SYSTEMS.items():
                with self.subTest(system=system_name):
                    command = pyinstaller_command(system_name, "/synthetic/python")
                    self.assertEqual(command[:3], ["/synthetic/python", "-m", "PyInstaller"])
                    self.assertNotIn("shell=True", command)
                    self.assertIn(str(ROOT / "release/staging" / target), command)
                    self.assertEqual(command[-1], str(ROOT / "packaging/launch_inboxlume.py"))
                    worker = worker_pyinstaller_command(
                        system_name, "/synthetic/python"
                    )
                    self.assertIn("InboxLumeWorker", worker)
                    self.assertIn("--onefile", worker)
                    self.assertTrue(
                        any("mlx_email_worker.py:benchmarks" in item for item in worker)
                    )
                    self.assertEqual(
                        worker[-1],
                        str(ROOT / "packaging/launch_inboxlume_worker.py"),
                    )

    def test_wheel_installs_the_mlx_worker_data_file(self) -> None:
        metadata = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))

        self.assertEqual(
            metadata["tool"]["setuptools"]["data-files"]["benchmarks"],
            ["benchmarks/mlx_email_worker.py"],
        )


if __name__ == "__main__":
    unittest.main()
