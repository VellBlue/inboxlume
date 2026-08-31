from __future__ import annotations

import shutil
import ssl
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from inboxlume.tls_trust import (
    TlsTrustUnavailable,
    default_tls_context,
    fallback_certificate_bundle,
    https_handler,
)


def _empty_store_context() -> ssl.SSLContext:
    """A real verifying context that carries no authorities at all."""

    return ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)


def _real_bundle() -> Path:
    bundle = fallback_certificate_bundle()
    if bundle is None:
        raise unittest.SkipTest("nessun archivio di certificati su questa macchina")
    return bundle


class TlsTrustTests(unittest.TestCase):
    def test_the_interpreter_store_is_preferred_when_it_has_authorities(self) -> None:
        with patch("inboxlume.tls_trust.fallback_certificate_bundle") as fallback:
            context = default_tls_context()

        # A machine whose own store carries administrator decisions must keep
        # using it; the bundle is a repair, not a replacement.
        fallback.assert_not_called()
        self.assertGreater(context.cert_store_stats()["x509_ca"], 0)

    def test_an_empty_store_is_repaired_from_the_bundle(self) -> None:
        bundle = _real_bundle()
        with (
            patch(
                "inboxlume.tls_trust.ssl.create_default_context",
                side_effect=_empty_store_context,
            ),
            patch(
                "inboxlume.tls_trust.fallback_certificate_bundle",
                return_value=bundle,
            ),
        ):
            context = default_tls_context()

        self.assertGreater(context.cert_store_stats()["x509_ca"], 0)

    def test_no_authority_anywhere_is_an_error_not_a_silent_downgrade(self) -> None:
        with (
            patch(
                "inboxlume.tls_trust.ssl.create_default_context",
                side_effect=_empty_store_context,
            ),
            patch(
                "inboxlume.tls_trust.fallback_certificate_bundle",
                return_value=None,
            ),
            self.assertRaises(TlsTrustUnavailable),
        ):
            default_tls_context()

    def test_an_unreadable_bundle_is_an_error_not_a_silent_downgrade(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "assente.pem"
            with (
                patch(
                    "inboxlume.tls_trust.ssl.create_default_context",
                    side_effect=_empty_store_context,
                ),
                patch(
                    "inboxlume.tls_trust.fallback_certificate_bundle",
                    return_value=missing,
                ),
                self.assertRaises(TlsTrustUnavailable),
            ):
                default_tls_context()

    def test_a_bundle_without_authorities_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            empty = Path(directory) / "vuoto.pem"
            empty.write_text("", encoding="utf-8")
            with (
                patch(
                    "inboxlume.tls_trust.ssl.create_default_context",
                    side_effect=_empty_store_context,
                ),
                patch(
                    "inboxlume.tls_trust.fallback_certificate_bundle",
                    return_value=empty,
                ),
                self.assertRaises(TlsTrustUnavailable),
            ):
                default_tls_context()

    def test_every_context_verifies_the_certificate_and_the_hostname(self) -> None:
        bundle = _real_bundle()
        contexts = [default_tls_context()]
        with (
            patch(
                "inboxlume.tls_trust.ssl.create_default_context",
                side_effect=_empty_store_context,
            ),
            patch(
                "inboxlume.tls_trust.fallback_certificate_bundle",
                return_value=bundle,
            ),
        ):
            contexts.append(default_tls_context())

        for index, context in enumerate(contexts):
            with self.subTest(context=index):
                self.assertTrue(context.check_hostname)
                self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
                self.assertGreaterEqual(
                    context.minimum_version, ssl.TLSVersion.TLSv1_2
                )

    def test_the_packaged_bundle_is_preferred_over_a_system_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            packaged = Path(directory) / "packaged.pem"
            packaged.write_text("", encoding="utf-8")
            system = Path(directory) / "system.pem"
            system.write_text("", encoding="utf-8")
            with (
                patch(
                    "inboxlume.tls_trust._packaged_bundle",
                    return_value=packaged,
                ),
                patch(
                    "inboxlume.tls_trust.SYSTEM_CERTIFICATE_BUNDLES",
                    (system,),
                ),
            ):
                self.assertEqual(fallback_certificate_bundle(), packaged)

    def test_a_system_path_is_used_when_nothing_is_packaged(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            absent = Path(directory) / "assente.pem"
            system = Path(directory) / "system.pem"
            shutil.copyfile(_real_bundle(), system)
            with (
                patch("inboxlume.tls_trust._packaged_bundle", return_value=None),
                patch(
                    "inboxlume.tls_trust.SYSTEM_CERTIFICATE_BUNDLES",
                    (absent, system),
                ),
            ):
                self.assertEqual(fallback_certificate_bundle(), system)

    def test_no_bundle_anywhere_reports_nothing_rather_than_guessing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            absent = Path(directory) / "assente.pem"
            with (
                patch("inboxlume.tls_trust._packaged_bundle", return_value=None),
                patch(
                    "inboxlume.tls_trust.SYSTEM_CERTIFICATE_BUNDLES",
                    (absent,),
                ),
            ):
                self.assertIsNone(fallback_certificate_bundle())

    def test_the_https_handler_carries_the_verified_context(self) -> None:
        handler = https_handler()
        context = getattr(handler, "_context", None)

        self.assertIsInstance(context, ssl.SSLContext)
        assert context is not None
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)


if __name__ == "__main__":
    unittest.main()
