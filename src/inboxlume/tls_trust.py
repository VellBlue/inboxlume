"""Certificate authority material for provider connections.

The interpreter's own trust store is always preferred: it carries the machine's
own decisions, including any authority an administrator added and any the
platform later distrusted.  A bundled fallback applies only when that store is
empty, which is what a framework Python installed without its certificate step
leaves behind, and what a packaged build on a machine with no system bundle can
also produce.

Without the fallback every provider connection fails verification even against
a genuine certificate, and the provider reports it as an unreachable account,
which sends the user looking for a mailbox problem that does not exist.

Verification itself is never relaxed here: a context without authorities is an
error, never an unverified connection.
"""

from __future__ import annotations

import ssl
import urllib.request
from pathlib import Path


class TlsTrustUnavailable(RuntimeError):
    """No authority material is available to verify a provider certificate."""


# Consulted only when the interpreter carries no store of its own.
SYSTEM_CERTIFICATE_BUNDLES: tuple[Path, ...] = (
    Path("/etc/ssl/cert.pem"),  # macOS
    Path("/etc/ssl/certs/ca-certificates.crt"),  # Debian, Ubuntu
    Path("/etc/pki/tls/certs/ca-bundle.crt"),  # Fedora, RHEL
    Path("/etc/ssl/ca-bundle.pem"),  # openSUSE
)


def _authority_count(context: ssl.SSLContext) -> int:
    try:
        return int(context.cert_store_stats().get("x509_ca", 0))
    except (OSError, ValueError):
        return 0


def _packaged_bundle() -> Path | None:
    try:
        import certifi
    except ImportError:
        return None
    try:
        bundle = Path(certifi.where())
    except (OSError, ValueError):
        return None
    return bundle if bundle.is_file() else None


def fallback_certificate_bundle() -> Path | None:
    """Locate authority material for an interpreter that carries none."""

    packaged = _packaged_bundle()
    if packaged is not None:
        return packaged
    for candidate in SYSTEM_CERTIFICATE_BUNDLES:
        if candidate.is_file():
            return candidate
    return None


def default_tls_context() -> ssl.SSLContext:
    """Build the verifying context every provider connection must use."""

    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    if _authority_count(context) > 0:
        return context
    bundle = fallback_certificate_bundle()
    if bundle is None:
        raise TlsTrustUnavailable(
            "nessun archivio di certificati disponibile per verificare il provider"
        )
    try:
        context.load_verify_locations(cafile=str(bundle))
    except (OSError, ssl.SSLError) as exc:
        raise TlsTrustUnavailable(
            "archivio di certificati locale non leggibile"
        ) from exc
    if _authority_count(context) == 0:
        raise TlsTrustUnavailable("archivio di certificati locale vuoto")
    return context


def https_handler() -> urllib.request.HTTPSHandler:
    """Return an HTTPS handler bound to the verified context."""

    return urllib.request.HTTPSHandler(context=default_tls_context())
