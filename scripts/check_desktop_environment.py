#!/usr/bin/env python3
"""Fail fast when the source desktop runtime is stale or unsupported."""

from __future__ import annotations

import argparse
import importlib.metadata
import importlib.util
import ssl
import sys
import tomllib
from pathlib import Path


MINIMUM_PYTHON = (3, 11)
MAXIMUM_PYTHON_EXCLUSIVE = (3, 14)


def python_version_supported(version: tuple[int, int]) -> bool:
    return MINIMUM_PYTHON <= version < MAXIMUM_PYTHON_EXCLUSIVE


def certificate_store_available() -> bool:
    """Report whether a provider certificate can be verified at all.

    This asks the application's own trust module, so the preflight accepts
    exactly what the providers will accept: the interpreter's store when it has
    one, and the bundled fallback when it does not.  A framework Python
    installed without its certificate step leaves an empty store, and every
    provider connection then fails verification against a genuine certificate.
    """

    try:
        from inboxlume.tls_trust import default_tls_context
    except ImportError:
        try:
            context = ssl.create_default_context()
        except (OSError, ssl.SSLError):
            return False
        return context.cert_store_stats().get("x509_ca", 0) > 0
    try:
        default_tls_context()
    except (OSError, RuntimeError, ssl.SSLError):
        return False
    return True


def environment_errors(project_root: Path) -> tuple[str, ...]:
    errors: list[str] = []
    version = sys.version_info[:2]
    if not python_version_supported(version):
        errors.append(
            "Python non supportato: serve una versione da 3.11 a 3.13"
        )

    source_root = project_root / "src"
    if not (source_root / "inboxlume" / "__init__.py").is_file():
        errors.append("sorgenti InboxLume non trovati")
    elif str(source_root) not in sys.path:
        sys.path.insert(0, str(source_root))

    # Checked after the sources are importable so the preflight can ask the
    # application's own trust module rather than guess on its behalf.
    if not certificate_store_available():
        errors.append(
            "archivio certificati TLS assente: nessun provider e verificabile"
        )

    try:
        metadata = tomllib.loads(
            (project_root / "pyproject.toml").read_text(encoding="utf-8")
        )
        expected_version = str(metadata["project"]["version"])
    except (KeyError, OSError, tomllib.TOMLDecodeError, UnicodeError):
        errors.append("metadati del progetto non leggibili")
        expected_version = ""
    try:
        installed_version = importlib.metadata.version("inboxlume")
    except importlib.metadata.PackageNotFoundError:
        errors.append("pacchetto InboxLume non installato nel venv")
    else:
        if expected_version and installed_version != expected_version:
            errors.append(
                "pacchetto InboxLume nel venv non allineato ai sorgenti"
            )

    for module_name in ("inboxlume", "PySide6", "keyring"):
        if importlib.util.find_spec(module_name) is None:
            errors.append(f"modulo richiesto non disponibile: {module_name}")

    if importlib.util.find_spec("PySide6") is not None:
        try:
            from PySide6.QtCore import QLibraryInfo

            plugin_root = Path(
                QLibraryInfo.path(QLibraryInfo.LibraryPath.PluginsPath)
            )
            platform_plugins = plugin_root / "platforms"
            if not platform_plugins.is_dir() or not any(
                platform_plugins.glob("libq*.dylib")
            ):
                errors.append("plugin grafici Qt non disponibili")
        except (ImportError, OSError, RuntimeError):
            errors.append("runtime Qt non importabile")

    return tuple(dict.fromkeys(errors))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("project_root", type=Path)
    args = parser.parse_args(argv)
    errors = environment_errors(args.project_root.resolve())
    for error in errors:
        print(f"- {error}", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
