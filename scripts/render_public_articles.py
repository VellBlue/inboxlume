from __future__ import annotations

import html
import re
import unicodedata
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True, slots=True)
class Article:
    source: Path
    output: Path
    language: str
    description: str
    canonical: str
    og_locale: str
    alternate_og_locale: str
    image_alt: str
    alternate_language: str
    alternate_href: str
    alternate_canonical: str
    home_href: str
    log_href: str
    asset_prefix: str
    preview_notice: str
    overview_label: str
    log_label: str
    source_label: str
    language_label: str
    eyebrow: str
    privacy_notice: str
    navigation_label: str


ARTICLES = (
    Article(
        source=ROOT / "docs/ARTICLE.md",
        output=ROOT / "docs/article.html",
        language="en",
        description=(
            "How InboxLume combines local AI, private learning, reversible actions, "
            "and measurable safety limits for large inboxes."
        ),
        canonical="https://vellblue.github.io/inboxlume/article.html",
        og_locale="en_US",
        alternate_og_locale="it_IT",
        image_alt="InboxLume — private AI for a cleaner inbox",
        alternate_language="it",
        alternate_href="it/article.html",
        alternate_canonical="https://vellblue.github.io/inboxlume/it/article.html",
        home_href="index.html",
        log_href="engineering-log.html",
        asset_prefix="assets",
        preview_notice=(
            "Public development preview — a supported packaged release is not yet available."
        ),
        overview_label="Overview",
        log_label="Engineering log",
        source_label="Markdown source",
        language_label="Italiano",
        eyebrow="Technical article · development snapshot",
        privacy_notice=(
            "No analytics, cookies, remote fonts, or third-party scripts. This is a "
            "sanitised public development preview, not a supported release."
        ),
        navigation_label="Main navigation",
    ),
    Article(
        source=ROOT / "docs/it/ARTICLE.md",
        output=ROOT / "docs/it/article.html",
        language="it",
        description=(
            "Come InboxLume combina IA locale, apprendimento privato, azioni reversibili "
            "e limiti di sicurezza misurabili per caselle di posta molto grandi."
        ),
        canonical="https://vellblue.github.io/inboxlume/it/article.html",
        og_locale="it_IT",
        alternate_og_locale="en_US",
        image_alt="InboxLume — IA privata per una posta più pulita",
        alternate_language="en",
        alternate_href="../article.html",
        alternate_canonical="https://vellblue.github.io/inboxlume/article.html",
        home_href="index.html",
        log_href="engineering-log.html",
        asset_prefix="../assets",
        preview_notice=(
            "Anteprima pubblica di sviluppo — non è ancora disponibile una versione "
            "installabile ufficialmente supportata."
        ),
        overview_label="Panoramica",
        log_label="Diario di ingegneria",
        source_label="Sorgente Markdown",
        language_label="English",
        eyebrow="Articolo tecnico · stato del progetto",
        privacy_notice=(
            "Nessun servizio di analisi, cookie, font remoto o script di terze parti. "
            "Questa è un'anteprima pubblica di sviluppo sanificata, non una versione "
            "installabile supportata."
        ),
        navigation_label="Navigazione principale",
    ),
)


def _slug(value: str) -> str:
    normalized = unicodedata.normalize("NFKD", value)
    ascii_value = normalized.encode("ascii", "ignore").decode("ascii")
    return re.sub(r"[^a-z0-9]+", "-", ascii_value.casefold()).strip("-")


def _inline(value: str) -> str:
    placeholders: list[str] = []

    def hold(rendered: str) -> str:
        placeholders.append(rendered)
        return f"\x00{len(placeholders) - 1}\x00"

    value = re.sub(
        r"`([^`]+)`",
        lambda match: hold(f"<code>{html.escape(match.group(1))}</code>"),
        value,
    )
    value = re.sub(
        r"<((?:https?://)[^>]+)>",
        lambda match: hold(
            f'<a href="{html.escape(match.group(1), quote=True)}">'
            f"{html.escape(match.group(1))}</a>"
        ),
        value,
    )
    value = html.escape(value, quote=False)
    value = re.sub(
        r"\[([^]]+)]\(([^)]+)\)",
        lambda match: (
            f'<a href="{html.escape(match.group(2), quote=True)}">{match.group(1)}</a>'
        ),
        value,
    )
    value = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", value)
    value = re.sub(r"(?<!\*)\*([^*]+)\*(?!\*)", r"<em>\1</em>", value)
    value = re.sub(
        r"(?<![\"=>])(https?://[^\s<]+)",
        lambda match: (
            f'<a href="{html.escape(match.group(1), quote=True)}">{match.group(1)}</a>'
        ),
        value,
    )
    for index, rendered in enumerate(placeholders):
        value = value.replace(f"\x00{index}\x00", rendered)
    return value


def _is_special(lines: list[str], index: int) -> bool:
    line = lines[index]
    if not line.strip():
        return True
    if line.startswith(("## ", "```", "> ", "- ")):
        return True
    if re.match(r"\d+\. ", line):
        return True
    return (
        line.startswith("|")
        and index + 1 < len(lines)
        and re.match(r"^\|?\s*:?-+", lines[index + 1]) is not None
    )


def _render_markdown(markdown: str) -> tuple[str, str]:
    lines = markdown.splitlines()
    if not lines or not lines[0].startswith("# "):
        raise ValueError("l'articolo deve iniziare con un titolo H1")
    title = lines[0][2:].strip()
    rendered: list[str] = []
    index = 1
    while index < len(lines):
        line = lines[index]
        if not line.strip():
            index += 1
            continue
        if line.startswith("## "):
            heading = line[3:].strip()
            rendered.append(f'<h2 id="{_slug(heading)}">{_inline(heading)}</h2>')
            index += 1
            continue
        if line.startswith("```"):
            language = line[3:].strip()
            index += 1
            code: list[str] = []
            while index < len(lines) and not lines[index].startswith("```"):
                code.append(lines[index])
                index += 1
            index += 1
            class_name = f' class="language-{html.escape(language, quote=True)}"' if language else ""
            rendered.append(
                f"<pre><code{class_name}>{html.escape(chr(10).join(code))}</code></pre>"
            )
            continue
        if line.startswith("> "):
            quote: list[str] = []
            while index < len(lines) and (lines[index].startswith("> ") or not lines[index].strip()):
                if lines[index].startswith("> "):
                    quote.append(lines[index][2:].strip())
                elif quote and quote[-1]:
                    quote.append("")
                index += 1
            paragraphs = " ".join(quote).split("  ")
            content = "".join(f"<p>{_inline(item.strip())}</p>" for item in paragraphs if item.strip())
            rendered.append(f'<aside class="article-note">{content}</aside>')
            continue
        if line.startswith("- ") or re.match(r"\d+\. ", line):
            ordered = re.match(r"\d+\. ", line) is not None
            tag = "ol" if ordered else "ul"
            marker = re.compile(r"\d+\. ") if ordered else re.compile(r"- ")
            items: list[str] = []
            while index < len(lines) and marker.match(lines[index]):
                item = marker.sub("", lines[index], count=1).strip()
                index += 1
                while index < len(lines) and lines[index].startswith("  "):
                    item += " " + lines[index].strip()
                    index += 1
                items.append(item)
            rendered.append(f"<{tag}>" + "".join(f"<li>{_inline(item)}</li>" for item in items) + f"</{tag}>")
            continue
        if (
            line.startswith("|")
            and index + 1 < len(lines)
            and re.match(r"^\|?\s*:?-+", lines[index + 1]) is not None
        ):
            headers = [cell.strip() for cell in line.strip("|").split("|")]
            index += 2
            rows: list[list[str]] = []
            while index < len(lines) and lines[index].startswith("|"):
                rows.append([cell.strip() for cell in lines[index].strip("|").split("|")])
                index += 1
            head = "".join(f"<th>{_inline(cell)}</th>" for cell in headers)
            body = "".join(
                "<tr>" + "".join(f"<td>{_inline(cell)}</td>" for cell in row) + "</tr>"
                for row in rows
            )
            rendered.append(
                f'<div class="article-table"><table class="comparison"><thead><tr>{head}</tr></thead>'
                f"<tbody>{body}</tbody></table></div>"
            )
            continue
        paragraph = [line.strip()]
        index += 1
        while index < len(lines) and not _is_special(lines, index):
            paragraph.append(lines[index].strip())
            index += 1
        rendered.append(f"<p>{_inline(' '.join(paragraph))}</p>")
    return title, "\n        ".join(rendered)


def _document(article: Article) -> str:
    title, body = _render_markdown(article.source.read_text(encoding="utf-8"))
    relative_source = article.source.name
    return f"""<!doctype html>
<html lang="{article.language}">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="description" content="{html.escape(article.description, quote=True)}">
  <meta name="color-scheme" content="dark">
  <meta property="og:type" content="article">
  <meta property="og:title" content="{html.escape(title, quote=True)}">
  <meta property="og:description" content="{html.escape(article.description, quote=True)}">
  <meta property="og:url" content="{article.canonical}">
  <meta property="og:image" content="https://vellblue.github.io/inboxlume/assets/og-card.png">
  <meta property="og:image:type" content="image/png">
  <meta property="og:image:width" content="1200">
  <meta property="og:image:height" content="630">
  <meta property="og:image:alt" content="{html.escape(article.image_alt, quote=True)}">
  <meta property="og:site_name" content="InboxLume">
  <meta property="og:locale" content="{article.og_locale}">
  <meta property="og:locale:alternate" content="{article.alternate_og_locale}">
  <meta name="twitter:card" content="summary_large_image">
  <meta name="twitter:title" content="{html.escape(title, quote=True)}">
  <meta name="twitter:description" content="{html.escape(article.description, quote=True)}">
  <meta name="twitter:image" content="https://vellblue.github.io/inboxlume/assets/og-card.png">
  <meta name="twitter:image:alt" content="{html.escape(article.image_alt, quote=True)}">
  <title>{html.escape(title)} — InboxLume</title>
  <link rel="icon" href="{article.asset_prefix}/favicon.svg" type="image/svg+xml">
  <link rel="canonical" href="{article.canonical}">
  <link rel="alternate" hreflang="{article.language}" href="{article.canonical}">
  <link rel="alternate" hreflang="{article.alternate_language}" href="{article.alternate_canonical}">
  <link rel="stylesheet" href="{article.asset_prefix}/site.css?v=20260901a">
</head>
<body>
  <div class="preflight">{html.escape(article.preview_notice)}</div>
  <header class="wrap">
    <nav aria-label="{article.navigation_label}">
      <a class="brand" href="{article.home_href}"><span class="brand-mark">IL</span><strong>InboxLume</strong></a>
      <div class="nav-links">
        <a href="{article.alternate_href}" lang="{article.alternate_language}">{article.language_label}</a>
        <a href="{article.home_href}">{article.overview_label}</a>
        <a href="{article.log_href}">{article.log_label}</a>
        <a href="{relative_source}">{article.source_label}</a>
      </div>
    </nav>
  </header>

  <main id="top">
    <article class="article-shell">
      <div class="wrap article-hero">
        <div class="eyebrow">{html.escape(article.eyebrow)}</div>
        <h1>{html.escape(title)}</h1>
      </div>
      <div class="wrap article-prose">
        {body}
      </div>
    </article>
  </main>

  <footer>
    <div class="wrap footer-grid">
      <div><a class="brand" href="{article.home_href}"><span class="brand-mark">IL</span><strong>InboxLume</strong></a></div>
      <div class="privacy-note">{html.escape(article.privacy_notice)}</div>
    </div>
  </footer>
</body>
</html>
"""


def main() -> None:
    for article in ARTICLES:
        article.output.write_text(_document(article), encoding="utf-8")


if __name__ == "__main__":
    main()
