#!/usr/bin/env python3
"""Render the 1200×630 social card without network or account data.

The script uses Pillow from InboxLume's ``packaging`` extra. Keeping the
renderer independent from Qt avoids loading a graphical platform plugin in a
headless build environment.
"""

from __future__ import annotations

from pathlib import Path

try:
    from PIL import Image, ImageDraw, ImageFont
except ImportError as exc:  # pragma: no cover - depends on the selected extra
    raise SystemExit(
        "Pillow non disponibile: installa prima il progetto con l'extra "
        "di packaging (`pip install -e '.[packaging]'`)."
    ) from exc


WIDTH, HEIGHT = 1200, 630
INK = "#EEFBF6"
LUME = "#63E6B3"
MUTED = "#A9C4BA"


def _font(size: int, *, bold: bool = False):
    names = (
        (
            "/System/Library/Fonts/Supplemental/Arial Bold.ttf",
            "C:/Windows/Fonts/arialbd.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        )
        if bold
        else (
            "/System/Library/Fonts/Supplemental/Arial.ttf",
            "C:/Windows/Fonts/arial.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        )
    )
    for name in names:
        if Path(name).is_file():
            return ImageFont.truetype(name, size)
    raise SystemExit("Nessun font di sistema compatibile trovato")


def _background() -> Image.Image:
    start = (17, 37, 31)
    end = (7, 21, 16)
    image = Image.new("RGB", (WIDTH, HEIGHT))
    pixels = image.load()
    for y in range(HEIGHT):
        for x in range(WIDTH):
            ratio = ((x / (WIDTH - 1)) + (y / (HEIGHT - 1))) / 2
            pixels[x, y] = tuple(
                round(left + (right - left) * ratio)
                for left, right in zip(start, end)
            )
    return image


def _brand_mark(draw: ImageDraw.ImageDraw) -> None:
    draw.rounded_rectangle((84, 76, 216, 208), radius=28, fill="#081D17")
    draw.ellipse((104, 96, 197, 189), fill="#143A30")
    draw.ellipse((171, 102, 188, 119), fill="#65D9A9")
    draw.rounded_rectangle(
        (109, 113, 190, 170),
        radius=11,
        fill="#F4FBF8",
        outline="#63E6B3",
        width=4,
    )
    draw.line(
        (113, 119, 149, 145, 186, 119),
        fill="#15966A",
        width=5,
        joint="curve",
    )
    draw.line((113, 165, 139, 141), fill="#9BDDC4", width=4)
    draw.line((186, 165, 160, 141), fill="#9BDDC4", width=4)
    draw.polygon(
        (
            (149, 97),
            (153, 105),
            (161, 109),
            (153, 113),
            (149, 121),
            (145, 113),
            (137, 109),
            (145, 105),
        ),
        fill="#CBFFE9",
    )


def _draw_tracking_text(
    draw: ImageDraw.ImageDraw,
    position: tuple[int, int],
    value: str,
    *,
    font,
    fill: str,
    spacing: int,
) -> None:
    x, y = position
    for character in value:
        draw.text((x, y), character, font=font, fill=fill, anchor="la")
        x += round(draw.textlength(character, font=font)) + spacing


def build(output: Path) -> None:
    image = _background()
    draw = ImageDraw.Draw(image)
    _brand_mark(draw)

    _draw_tracking_text(
        draw,
        (240, 110),
        "PRIVATE AI FOR A CLEANER INBOX",
        font=_font(28, bold=True),
        fill=LUME,
        spacing=3,
    )
    draw.text((84, 241), "InboxLume", font=_font(118, bold=True), fill=INK)
    draw.text(
        (84, 378),
        "Understands your mail on your own device.",
        font=_font(45),
        fill=MUTED,
    )
    draw.line((84, 448, WIDTH - 84, 448), fill="#245043", width=1)
    draw.text(
        (84, 480),
        "Local model  ·  Reversible actions  ·  No cloud AI",
        font=_font(38, bold=True),
        fill=LUME,
    )

    output.parent.mkdir(parents=True, exist_ok=True)
    image.save(output, "PNG", optimize=True)
    print(f"{output} ({output.stat().st_size} byte, {WIDTH}x{HEIGHT})")


if __name__ == "__main__":
    root = Path(__file__).resolve().parents[1]
    build(root / "docs/assets/og-card.png")
