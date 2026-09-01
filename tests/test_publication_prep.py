from __future__ import annotations

import re
import struct
import tomllib
import unittest
from pathlib import Path
from urllib.parse import urlsplit
from unittest.mock import patch

from scripts.package_desktop import (
    SUPPORTED_SYSTEMS,
    pyinstaller_command,
    worker_pyinstaller_command,
)
from scripts.render_public_articles import ARTICLES, _document


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
        pages = {
            ROOT / "docs/index.html": '<html lang="en">',
            ROOT / "docs/it/index.html": '<html lang="it">',
            ROOT / "docs/article.html": '<html lang="en">',
            ROOT / "docs/it/article.html": '<html lang="it">',
            ROOT / "docs/engineering-log.html": '<html lang="en">',
            ROOT / "docs/it/engineering-log.html": '<html lang="it">',
        }
        css = (ROOT / "docs/assets/site.css").read_text(encoding="utf-8")
        canonical_urls = {
            ROOT / "docs/index.html": "https://vellblue.github.io/inboxlume/",
            ROOT / "docs/it/index.html": "https://vellblue.github.io/inboxlume/it/",
            ROOT / "docs/article.html": "https://vellblue.github.io/inboxlume/article.html",
            ROOT / "docs/it/article.html": "https://vellblue.github.io/inboxlume/it/article.html",
            ROOT / "docs/engineering-log.html": (
                "https://vellblue.github.io/inboxlume/engineering-log.html"
            ),
            ROOT / "docs/it/engineering-log.html": (
                "https://vellblue.github.io/inboxlume/it/engineering-log.html"
            ),
        }

        for path, language_marker in pages.items():
            page = path.read_text(encoding="utf-8")
            self.assertIn(language_marker, page)
            self.assertNotIn("http://", page)
            self.assertIn(f'<link rel="canonical" href="{canonical_urls[path]}">', page)
            self.assertIn(
                '<meta property="og:image" content="https://vellblue.github.io/inboxlume/assets/og-card.png">',
                page,
            )
            self.assertIn('<meta property="og:image:width" content="1200">', page)
            self.assertIn('<meta property="og:image:height" content="630">', page)
            self.assertIn('<meta property="og:image:alt" content=', page)
            self.assertIn('<meta name="twitter:card" content="summary_large_image">', page)
            self.assertIn(
                '<meta name="twitter:image" content="https://vellblue.github.io/inboxlume/assets/og-card.png">',
                page,
            )
            for source in re.findall(r'src="([^"]+)"', page):
                self.assertFalse(urlsplit(source).scheme, f"{path}: remote asset {source}")
            folded = page.casefold()
            self.assertNotIn("<script", folded)
            self.assertNotIn("google-analytics", folded)
            self.assertNotIn("googletagmanager", folded)
            for reference in re.findall(r'(?:href|src)="([^"]+)"', page):
                parsed = urlsplit(reference)
                if parsed.scheme or not parsed.path:
                    continue
                target = path.parent / parsed.path
                self.assertTrue(target.exists(), f"{path}: missing {reference}")

        for homepage in (ROOT / "docs/index.html", ROOT / "docs/it/index.html"):
            content = homepage.read_text(encoding="utf-8")
            self.assertIn("article.html", content)
            self.assertIn("engineering-log.html", content)
        self.assertNotIn("@import", css)
        for asset in (
            "docs/assets/site.css",
            "docs/assets/favicon.svg",
            "docs/assets/architecture.svg",
            "docs/assets/inboxlume-settings.png",
            "docs/assets/inboxlume-settings-it.png",
            "docs/assets/og-card.png",
            "docs/it/ARTICLE.md",
            "docs/article.html",
            "docs/it/article.html",
            "docs/engineering-log.html",
            "docs/it/engineering-log.html",
            "scripts/render_public_articles.py",
            "scripts/build_og_card.py",
        ):
            self.assertTrue((ROOT / asset).is_file(), asset)

        card = (ROOT / "docs/assets/og-card.png").read_bytes()
        self.assertEqual(card[:8], b"\x89PNG\r\n\x1a\n")
        self.assertEqual(struct.unpack(">II", card[16:24]), (1200, 630))

    def test_static_articles_match_their_markdown_sources(self) -> None:
        for article in ARTICLES:
            self.assertEqual(
                article.output.read_text(encoding="utf-8"),
                _document(article),
            )

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

    def test_apache_license_is_declared_and_complete(self) -> None:
        metadata = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        license_text = (ROOT / "LICENSE").read_text(encoding="utf-8")
        notice = (ROOT / "NOTICE").read_text(encoding="utf-8")

        self.assertEqual(metadata["build-system"]["requires"], ["setuptools>=77"])
        self.assertEqual(metadata["project"]["license"], "Apache-2.0")
        self.assertEqual(metadata["project"]["license-files"], ["LICENSE", "NOTICE"])
        self.assertIn("Grant of Patent License", license_text)
        self.assertIn("APPENDIX: How to apply the Apache License", license_text)
        self.assertIn("Copyright 2026 VellBlue", notice)
        self.assertNotRegex(notice, r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+")


if __name__ == "__main__":
    unittest.main()
