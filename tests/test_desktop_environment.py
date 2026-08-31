from __future__ import annotations

import unittest
from pathlib import Path

from unittest.mock import patch

from inboxlume.tls_trust import TlsTrustUnavailable
from scripts.check_desktop_environment import (
    certificate_store_available,
    environment_errors,
    python_version_supported,
)


class DesktopEnvironmentTests(unittest.TestCase):
    def test_supported_python_range_matches_project_metadata(self) -> None:
        self.assertTrue(python_version_supported((3, 11)))
        self.assertTrue(python_version_supported((3, 13)))
        self.assertFalse(python_version_supported((3, 10)))
        self.assertFalse(python_version_supported((3, 14)))

    def test_a_machine_without_any_authority_is_reported_before_the_app_opens(
        self,
    ) -> None:
        with patch(
            "inboxlume.tls_trust.default_tls_context",
            side_effect=TlsTrustUnavailable("archivio vuoto"),
        ):
            self.assertFalse(certificate_store_available())
            errors = environment_errors(Path(__file__).resolve().parents[1])

        # Without this the provider reports an unreachable account, and the
        # user looks for a mailbox problem that does not exist.
        self.assertTrue(any("certificati" in error for error in errors), errors)

    def test_a_repairable_environment_is_accepted(self) -> None:
        # The preflight must accept what the providers accept, so an empty
        # interpreter store that the bundle repairs is not an error.
        self.assertTrue(certificate_store_available())
        errors = environment_errors(Path(__file__).resolve().parents[1])

        self.assertFalse(any("certificati" in error for error in errors), errors)

if __name__ == "__main__":
    unittest.main()
