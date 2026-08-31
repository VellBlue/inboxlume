from __future__ import annotations

import unittest
from pathlib import Path

from unittest.mock import patch

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

    def test_an_empty_certificate_store_is_reported_before_the_app_opens(self) -> None:
        class EmptyStoreContext:
            @staticmethod
            def cert_store_stats() -> dict[str, int]:
                return {"x509_ca": 0, "x509": 0, "crl": 0}

        with patch(
            "scripts.check_desktop_environment.ssl.create_default_context",
            return_value=EmptyStoreContext(),
        ):
            self.assertFalse(certificate_store_available())
            errors = environment_errors(Path(__file__).resolve().parents[1])

        # Without this the provider reports an unreachable account, and the
        # user looks for a mailbox problem that does not exist.
        self.assertTrue(
            any("certificati" in error for error in errors),
            errors,
        )

    def test_a_populated_certificate_store_is_accepted(self) -> None:
        class PopulatedStoreContext:
            @staticmethod
            def cert_store_stats() -> dict[str, int]:
                return {"x509_ca": 150, "x509": 150, "crl": 0}

        with patch(
            "scripts.check_desktop_environment.ssl.create_default_context",
            return_value=PopulatedStoreContext(),
        ):
            self.assertTrue(certificate_store_available())


if __name__ == "__main__":
    unittest.main()
