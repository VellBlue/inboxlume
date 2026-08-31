from __future__ import annotations

import re
import unicodedata
from html.parser import HTMLParser


_BLOCK_TAGS = {
    "address",
    "article",
    "blockquote",
    "br",
    "div",
    "footer",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "header",
    "li",
    "main",
    "p",
    "section",
    "table",
    "td",
    "th",
    "tr",
}
_SKIP_TAGS = {"script", "style", "noscript", "svg", "canvas"}


class _VisibleTextParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._skip_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        normalized = tag.casefold()
        if normalized in _SKIP_TAGS:
            self._skip_depth += 1
        elif not self._skip_depth and normalized in _BLOCK_TAGS:
            self.parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        normalized = tag.casefold()
        if normalized in _SKIP_TAGS and self._skip_depth:
            self._skip_depth -= 1
        elif not self._skip_depth and normalized in _BLOCK_TAGS:
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        if not self._skip_depth:
            self.parts.append(data)


def _remove_control_characters(value: str) -> str:
    return "".join(
        char
        for char in value
        if char in "\n\t" or not unicodedata.category(char).startswith("C")
    )


def normalize_plain_text(value: str, max_chars: int = 8_000) -> str:
    cleaned = _remove_control_characters(value.replace("\r\n", "\n").replace("\r", "\n"))
    cleaned = re.sub(r"[ \t]+", " ", cleaned)
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned).strip()
    return cleaned[:max_chars]


def html_to_visible_text(value: str, max_chars: int = 8_000) -> str:
    parser = _VisibleTextParser()
    parser.feed(value)
    parser.close()
    return normalize_plain_text("".join(parser.parts), max_chars=max_chars)


def sanitize_body(value: str, content_type: str = "text/plain", max_chars: int = 8_000) -> str:
    """Converte il corpo in testo senza effettuare alcuna richiesta di rete."""

    if content_type.casefold().startswith("text/html"):
        return html_to_visible_text(value, max_chars=max_chars)
    return normalize_plain_text(value, max_chars=max_chars)

