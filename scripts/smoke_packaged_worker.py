#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import platform
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[1]


def packaged_worker_path(system_name: str) -> Path:
    if system_name == "Darwin":
        return (
            ROOT
            / "release/staging/macos/InboxLume.app/Contents/MacOS/InboxLumeWorker"
        )
    if system_name == "Windows":
        return ROOT / "release/staging/windows/InboxLume/InboxLumeWorker.exe"
    if system_name == "Linux":
        return ROOT / "release/staging/linux/InboxLume/InboxLumeWorker"
    raise ValueError(f"unsupported package smoke platform: {system_name}")


def validate_synthetic_receipt(event: Mapping[str, Any]) -> None:
    if event.get("type") != "local_threat_backtest":
        raise ValueError("invalid packaged worker receipt field: type")
    required_booleans = {
        "synthetic_corpus_only": True,
        "reads_mailbox": False,
        "uses_network": False,
        "changes_mailbox": False,
        "authorizes_actions": False,
        "stored_plaintext": False,
    }
    for name, expected in required_booleans.items():
        if event.get(name) is not expected:
            raise ValueError(f"invalid packaged worker receipt field: {name}")
    cases = event.get("cases")
    if not isinstance(cases, dict):
        raise ValueError("packaged worker did not report synthetic fixture cases")
    total = cases.get("total")
    malicious = cases.get("malicious")
    benign = cases.get("benign")
    if (
        isinstance(total, bool)
        or not isinstance(total, int)
        or total <= 0
        or isinstance(malicious, bool)
        or not isinstance(malicious, int)
        or isinstance(benign, bool)
        or not isinstance(benign, int)
        or malicious <= 0
        or benign <= 0
        or malicious + benign != total
    ):
        raise ValueError("packaged worker synthetic fixture counts are invalid")


def main() -> int:
    worker = packaged_worker_path(platform.system())
    if not worker.is_file():
        raise SystemExit("packaged worker is missing")
    environment = os.environ.copy()
    for name in (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ):
        environment.pop(name, None)
    environment.update(
        {
            "HF_HUB_OFFLINE": "1",
            "TRANSFORMERS_OFFLINE": "1",
            "NO_PROXY": "*",
            "no_proxy": "*",
        }
    )
    with tempfile.TemporaryDirectory(prefix="inboxlume-package-smoke-") as directory:
        isolated_root = Path(directory)
        environment.update(
            {
                "INBOXLUME_SETTINGS_PATH": str(
                    isolated_root / "synthetic-settings-do-not-create.json"
                ),
                "XDG_CONFIG_HOME": str(isolated_root / "xdg-config"),
                "APPDATA": str(isolated_root / "appdata"),
                "LOCALAPPDATA": str(isolated_root / "local-appdata"),
            }
        )
        completed = subprocess.run(
            [
                str(worker),
                "desktop-worker",
                "threat-backtest",
                "--backend",
                "heuristic",
            ],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
            env=environment,
            cwd=isolated_root,
        )
        if any(isolated_root.iterdir()):
            raise SystemExit("package smoke unexpectedly wrote local account state")
    if completed.returncode != 0:
        raise SystemExit("packaged worker smoke failed")
    events = []
    for line in completed.stdout.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(event, dict):
            events.append(event)
    if not events:
        raise SystemExit("packaged worker did not return its synthetic receipt")
    try:
        validate_synthetic_receipt(events[-1])
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    print("Packaged worker synthetic smoke passed; no account was accessed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
