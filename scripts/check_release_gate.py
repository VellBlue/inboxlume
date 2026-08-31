#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_GATE = ROOT / "release" / "release-gate.json"
REQUIRED_GATES = (
    "approved_feature_scope_complete",
    "cross_platform_packages_verified",
    "english_italian_public_surface_complete",
    "license_selected",
    "sanitized_assets_approved",
    "security_review_complete",
)
EXPECTED_FIELDS = {"schema_version", "publication_authorized", *REQUIRED_GATES}


def load_gate(path: Path) -> dict[str, Any]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("release gate non leggibile") from exc
    if not isinstance(raw, dict) or set(raw) != EXPECTED_FIELDS:
        raise ValueError("campi release gate mancanti o sconosciuti")
    if raw["schema_version"] != 1:
        raise ValueError("versione release gate non supportata")
    if any(not isinstance(raw[name], bool) for name in EXPECTED_FIELDS - {"schema_version"}):
        raise ValueError("i gate di release devono essere booleani")
    return raw


def release_status(gate: Mapping[str, Any], version: str) -> tuple[bool, list[str]]:
    blockers = [name for name in REQUIRED_GATES if not gate[name]]
    if not gate["publication_authorized"]:
        blockers.append("publication_authorized")
    normalized = version.casefold()
    if any(marker in normalized for marker in ("dev", "a", "b", "rc")):
        blockers.append("stable_version")
    return not blockers, blockers


def project_version(path: Path) -> str:
    import tomllib

    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
        value = raw["project"]["version"]
    except (OSError, UnicodeDecodeError, KeyError, TypeError, tomllib.TOMLDecodeError) as exc:
        raise ValueError("versione progetto non leggibile") from exc
    if not isinstance(value, str) or not value.strip():
        raise ValueError("versione progetto non valida")
    return value.strip()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verifica locale che una release InboxLume sia autorizzata.",
    )
    parser.add_argument("--gate", type=Path, default=DEFAULT_GATE)
    parser.add_argument("--project", type=Path, default=ROOT / "pyproject.toml")
    parser.add_argument(
        "--require-ready",
        action="store_true",
        help="restituisce errore finché tutti i gate non sono esplicitamente aperti",
    )
    parser.add_argument(
        "--require-blocked",
        action="store_true",
        help="restituisce errore se la pubblicazione risulta autorizzata",
    )
    args = parser.parse_args(argv)
    if args.require_ready and args.require_blocked:
        parser.error("--require-ready e --require-blocked sono incompatibili")
    try:
        gate = load_gate(args.gate)
        ready, blockers = release_status(gate, project_version(args.project))
    except ValueError as exc:
        print(f"Release gate NON VALIDO: {exc}", file=sys.stderr)
        return 2

    if ready:
        print("Release gate APERTO: la pubblicazione è stata autorizzata esplicitamente.")
        return 1 if args.require_blocked else 0
    print(
        "Release gate BLOCCATO: " + ", ".join(sorted(blockers)) + "."
    )
    return 1 if args.require_ready else 0


if __name__ == "__main__":
    raise SystemExit(main())
