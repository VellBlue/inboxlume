#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from build_icns import build_icns


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "macos" / "InboxLumeIcon.png"
OUTPUT = ROOT / "build" / "release-assets"
SIZES = (16, 32, 48, 64, 128, 256, 512)


def prepare(source: Path, output: Path) -> tuple[Path, Path, Path]:
    try:
        from PIL import Image
    except ModuleNotFoundError as exc:
        raise RuntimeError(
            "Pillow non disponibile: installa il profilo packaging"
        ) from exc
    if not source.is_file():
        raise FileNotFoundError("icona sorgente InboxLume non disponibile")
    output.mkdir(parents=True, exist_ok=True)
    iconset = output / "InboxLume.iconset"
    iconset.mkdir(parents=True, exist_ok=True)

    with Image.open(source) as original:
        image = original.convert("RGBA")
        if image.width != image.height or image.width < 1024:
            raise ValueError("l'icona sorgente deve essere quadrata e almeno 1024 px")
        for size in SIZES:
            resized = image.resize((size, size), Image.Resampling.LANCZOS)
            resized.save(output / f"InboxLume-{size}.png", format="PNG")
        for size in (16, 32, 128, 256, 512):
            image.resize((size, size), Image.Resampling.LANCZOS).save(
                iconset / f"icon_{size}x{size}.png",
                format="PNG",
            )
            double = size * 2
            image.resize((double, double), Image.Resampling.LANCZOS).save(
                iconset / f"icon_{size}x{size}@2x.png",
                format="PNG",
            )
        ico = output / "InboxLume.ico"
        image.save(ico, format="ICO", sizes=[(size, size) for size in SIZES])

    icns = output / "InboxLume.icns"
    build_icns(iconset, icns)
    return icns, ico, output / "InboxLume-512.png"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Genera icone sanificate per i pacchetti locali.",
    )
    parser.add_argument("--source", type=Path, default=SOURCE)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args(argv)
    try:
        paths = prepare(args.source.resolve(), args.output.resolve())
    except (FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
        parser.exit(2, f"Asset di release non creati: {exc}\n")
    for path in paths:
        print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
