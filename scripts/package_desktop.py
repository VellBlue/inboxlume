#!/usr/bin/env python3
from __future__ import annotations

import argparse
import platform
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ENTRYPOINT = ROOT / "packaging" / "launch_inboxlume.py"
WORKER_ENTRYPOINT = ROOT / "packaging" / "launch_inboxlume_worker.py"
MLX_WORKER = ROOT / "benchmarks" / "mlx_email_worker.py"
ASSETS = ROOT / "build" / "release-assets"
SUPPORTED_SYSTEMS = {"Darwin": "macos", "Windows": "windows", "Linux": "linux"}


def icon_for(system_name: str) -> Path:
    names = {
        "Darwin": "InboxLume.icns",
        "Windows": "InboxLume.ico",
        "Linux": "InboxLume-512.png",
    }
    try:
        return ASSETS / names[system_name]
    except KeyError as exc:
        raise ValueError(f"sistema non supportato: {system_name}") from exc


def pyinstaller_command(
    system_name: str,
    executable: str,
    *,
    require_assets: bool = True,
) -> list[str]:
    if system_name not in SUPPORTED_SYSTEMS:
        raise ValueError(f"sistema non supportato: {system_name}")
    icon = icon_for(system_name)
    if require_assets:
        for required in (ENTRYPOINT, ROOT / "src/inboxlume/default_policy.json", icon):
            if not required.is_file():
                raise FileNotFoundError(f"asset packaging mancante: {required.name}")
    target = SUPPORTED_SYSTEMS[system_name]
    return [
        executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--windowed",
        "--onedir",
        "--name",
        "InboxLume",
        "--paths",
        str(ROOT / "src"),
        "--collect-data",
        "inboxlume",
        "--collect-submodules",
        "keyring.backends",
        "--icon",
        str(icon),
        "--distpath",
        str(ROOT / "release" / "staging" / target),
        "--workpath",
        str(ROOT / "build" / "pyinstaller" / target),
        "--specpath",
        str(ROOT / "build" / "pyinstaller-spec" / target),
        str(ENTRYPOINT),
    ]


def packaged_worker_directory(system_name: str) -> Path:
    if system_name not in SUPPORTED_SYSTEMS:
        raise ValueError(f"sistema non supportato: {system_name}")
    target = ROOT / "release" / "staging" / SUPPORTED_SYSTEMS[system_name]
    if system_name == "Darwin":
        return target / "InboxLume.app" / "Contents" / "MacOS"
    return target / "InboxLume"


def worker_pyinstaller_command(
    system_name: str,
    executable: str,
    *,
    require_assets: bool = True,
) -> list[str]:
    if system_name not in SUPPORTED_SYSTEMS:
        raise ValueError(f"sistema non supportato: {system_name}")
    if require_assets:
        for required in (
            WORKER_ENTRYPOINT,
            MLX_WORKER,
            ROOT / "src/inboxlume/default_policy.json",
        ):
            if not required.is_file():
                raise FileNotFoundError(f"asset packaging mancante: {required.name}")
    target = SUPPORTED_SYSTEMS[system_name]
    return [
        executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--console",
        "--onefile",
        "--name",
        "InboxLumeWorker",
        "--paths",
        str(ROOT / "src"),
        "--collect-data",
        "inboxlume",
        "--collect-submodules",
        "keyring.backends",
        "--add-data",
        f"{MLX_WORKER}:benchmarks",
        "--distpath",
        str(packaged_worker_directory(system_name)),
        "--workpath",
        str(ROOT / "build" / "pyinstaller-worker" / target),
        "--specpath",
        str(ROOT / "build" / "pyinstaller-spec" / target),
        str(WORKER_ENTRYPOINT),
    ]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Prepara un pacchetto desktop locale senza pubblicarlo.",
    )
    parser.add_argument(
        "--build",
        action="store_true",
        help="esegue PyInstaller; senza questo flag valida soltanto la configurazione",
    )
    parser.add_argument(
        "--system",
        choices=tuple(SUPPORTED_SYSTEMS),
        default=platform.system(),
        help=argparse.SUPPRESS,
    )
    args = parser.parse_args(argv)
    commands = (
        pyinstaller_command(
            args.system,
            sys.executable,
            require_assets=args.build,
        ),
        worker_pyinstaller_command(
            args.system,
            sys.executable,
            require_assets=args.build,
        ),
    )
    if args.build and shutil.which("pyinstaller") is None:
        try:
            import PyInstaller  # noqa: F401
        except ModuleNotFoundError as exc:
            raise SystemExit(
                "PyInstaller non disponibile: installa il profilo packaging"
            ) from exc
    if not args.build:
        print(
            f"Configurazione {SUPPORTED_SYSTEMS[args.system]} valida. "
            "Nessun pacchetto creato o pubblicato."
        )
        return 0
    for command in commands:
        completed = subprocess.run(command, cwd=ROOT, check=False)
        if completed.returncode != 0:
            return completed.returncode
    print(
        f"Pacchetto unsigned creato in release/staging/"
        f"{SUPPORTED_SYSTEMS[args.system]}. Nessun upload eseguito."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
