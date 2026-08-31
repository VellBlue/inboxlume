#!/usr/bin/env python3
from __future__ import annotations

import argparse
import struct
from pathlib import Path


RETINA_SUFFIX = chr(64) + "2x.png"
ICON_MEMBERS = (
    (b"icp4", "icon_16x16.png"),
    (b"icp5", "icon_32x32.png"),
    (b"icp6", "icon_32x32" + RETINA_SUFFIX),
    (b"ic07", "icon_128x128.png"),
    (b"ic08", "icon_128x128" + RETINA_SUFFIX),
    (b"ic09", "icon_256x256" + RETINA_SUFFIX),
    (b"ic10", "icon_512x512" + RETINA_SUFFIX),
)
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


def build_icns(iconset: Path, output: Path) -> None:
    chunks: list[bytes] = []
    for member_type, filename in ICON_MEMBERS:
        payload = (iconset / filename).read_bytes()
        if not payload.startswith(PNG_SIGNATURE):
            raise ValueError(f"asset icona non PNG: {filename}")
        chunks.append(member_type + struct.pack(">I", len(payload) + 8) + payload)
    body = b"".join(chunks)
    output.write_bytes(b"icns" + struct.pack(">I", len(body) + 8) + body)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("iconset", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    build_icns(args.iconset, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
