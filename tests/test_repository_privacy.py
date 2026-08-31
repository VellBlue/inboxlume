from __future__ import annotations

import shutil
import subprocess
import sys
import unittest
from pathlib import Path

from scripts.audit_repository_privacy import (
    SECRET_SIGNATURES,
    binary_metadata_findings,
    history_email_is_public,
)


ROOT = Path(__file__).resolve().parents[1]


class RepositoryPrivacyTests(unittest.TestCase):
    def test_common_publication_secret_formats_are_detected(self) -> None:
        samples = {
            "github_token": "ghp_" + "A" * 36,
            "github_fine_grained_token": "github_pat_" + "A" * 24,
            "openai_api_key": "sk-" + "A" * 24,
            "google_client_secret": "GOCSPX-" + "A" * 24,
            "stripe_live_key": "sk_" + "live_" + "A" * 24,
            "slack_token": "xoxb-" + "A" * 24,
        }
        for expected, sample in samples.items():
            matches = {
                name for name, pattern in SECRET_SIGNATURES if pattern.search(sample)
            }
            with self.subTest(expected=expected):
                self.assertIn(expected, matches)

    def test_embedded_image_exif_is_rejected(self) -> None:
        png_with_exif = (
            b"\x89PNG\r\n\x1a\n"
            + (0).to_bytes(4, "big")
            + b"eXIf"
            + b"\x00\x00\x00\x00"
        )
        self.assertIn(
            "metadati_exif_immagine",
            binary_metadata_findings(png_with_exif),
        )

    def test_public_history_accepts_only_noreply_identities(self) -> None:
        self.assertTrue(
            history_email_is_public(
                "134018609+VellBlue" + "@" + "users.noreply.github.com"
            )
        )
        self.assertTrue(history_email_is_public("noreply" + "@" + "anthropic.com"))
        self.assertFalse(history_email_is_public("owner" + "@" + "example.net"))

    @unittest.skipUnless(shutil.which("git"), "git non disponibile")
    def test_private_runtime_artifacts_are_ignored(self) -> None:
        private_paths = (
            "data/private.sqlite3",
            "data/private.sqlite3-wal",
            "secrets/oauth.json",
            "client_secret_personal.json",
            "credentials-personal.json",
            "token-personal.json",
            "settings.json",
            "config/accounts.local.json",
            ".env",
            "mail-guardian.log",
        )
        for private_path in private_paths:
            with self.subTest(path=private_path):
                result = subprocess.run(
                    ["git", "check-ignore", "--no-index", "--quiet", private_path],
                    cwd=ROOT,
                    check=False,
                )
                self.assertEqual(result.returncode, 0)

    @unittest.skipUnless(shutil.which("git"), "git non disponibile")
    def test_all_commit_candidates_pass_privacy_audit(self) -> None:
        result = subprocess.run(
            [sys.executable, "scripts/audit_repository_privacy.py"],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout)


if __name__ == "__main__":
    unittest.main()
