#!/usr/bin/env python3
from __future__ import annotations

import re
import struct
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MAX_TEXT_FILE_BYTES = 4_000_000
FORBIDDEN_SUFFIXES = {
    ".db",
    ".eml",
    ".emlx",
    ".har",
    ".keyring",
    ".mbox",
    ".mobileprovision",
    ".msg",
    ".ost",
    ".p12",
    ".pcap",
    ".pem",
    ".pst",
    ".sqlite",
    ".sqlite3",
}
FORBIDDEN_NAMES = {".env", "settings.json"}
FORBIDDEN_PREFIXES = (
    "client_secret",
    "credentials-personal",
    "credentials_personal",
    "oauth-personal",
    "oauth_personal",
    "token-personal",
    "token_personal",
)
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
ALLOWED_LITERAL_EMAILS = {"nome@yahoo.com"}
ALLOWED_EMAIL_DOMAINS = {"example.com", "example.invalid", "example.test"}
ALLOWED_HISTORY_EMAILS = {"noreply" + "@" + "anthropic.com"}
ALLOWED_HISTORY_EMAIL_DOMAINS = {"users.noreply.github.com"}
PRIVATE_PATHS = (
    re.compile(re.escape("/" + "Users/") + r"(?!example(?:/|$))"),
    re.compile(re.escape("C:" + "/" + "Users/") + r"(?!example(?:/|$))", re.I),
    re.compile(re.escape("/" + "home/") + r"(?!example(?:/|$))"),
)
SECRET_SIGNATURES = (
    ("google_access_token", re.compile("ya" + r"29\.[A-Za-z0-9_-]{20,}")),
    ("google_refresh_token", re.compile(r"1/" + r"/[A-Za-z0-9_-]{20,}")),
    ("aws_access_key", re.compile("AK" + r"IA[0-9A-Z]{16}")),
    (
        "private_key",
        re.compile("-----BEGIN " + r"(?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    ),
    ("github_token", re.compile("gh" + r"[pousr]_[A-Za-z0-9]{36,255}")),
    (
        "github_fine_grained_token",
        re.compile("github_" + r"pat_[A-Za-z0-9_]{20,255}"),
    ),
    ("openai_api_key", re.compile("sk" + r"-(?:proj-)?[A-Za-z0-9_-]{20,}")),
    ("google_client_secret", re.compile("GOC" + r"SPX-[A-Za-z0-9_-]{20,}")),
    ("stripe_live_key", re.compile("sk_" + r"live_[A-Za-z0-9]{16,}")),
    ("slack_token", re.compile("xo" + r"x[baprs]-[A-Za-z0-9-]{20,}")),
)


def binary_metadata_findings(raw: bytes) -> list[str]:
    findings: list[str] = []
    if raw.startswith(b"\xff\xd8") and b"Exif\x00\x00" in raw:
        findings.append("metadati_exif_immagine")
    if not raw.startswith(b"\x89PNG\r\n\x1a\n"):
        return findings
    offset = 8
    while offset + 12 <= len(raw):
        length = struct.unpack(">I", raw[offset : offset + 4])[0]
        chunk_type = raw[offset + 4 : offset + 8]
        chunk_end = offset + 12 + length
        if chunk_end > len(raw):
            findings.append("png_malformato")
            break
        if chunk_type == b"eXIf":
            findings.append("metadati_exif_immagine")
        offset = chunk_end
        if chunk_type == b"IEND":
            break
    return findings


def candidate_files() -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    return [
        ROOT / item.decode("utf-8", errors="strict")
        for item in result.stdout.split(b"\0")
        if item
    ]


def audit_file(path: Path) -> list[str]:
    relative = path.relative_to(ROOT)
    name = relative.name.casefold()
    suffix = relative.suffix.casefold()
    findings: list[str] = []
    if name in FORBIDDEN_NAMES or suffix in FORBIDDEN_SUFFIXES:
        findings.append("tipo_file_privato")
    if name.startswith(FORBIDDEN_PREFIXES):
        findings.append("nome_file_credenziale")
    if path.is_symlink():
        findings.append("collegamento_simbolico")
        return findings
    try:
        raw = path.read_bytes()
    except OSError:
        return [*findings, "file_non_leggibile"]
    findings.extend(binary_metadata_findings(raw))
    if raw.startswith(b"SQLite format 3\x00"):
        findings.append("database_sqlite")
    if len(raw) > MAX_TEXT_FILE_BYTES or b"\x00" in raw:
        return findings
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return findings
    for address in EMAIL.findall(text):
        domain = address.rsplit("@", 1)[1].casefold()
        if address.casefold() not in ALLOWED_LITERAL_EMAILS and (
            domain not in ALLOWED_EMAIL_DOMAINS
        ):
            findings.append("indirizzo_email_non_fittizio")
            break
    if any(pattern.search(text) for pattern in PRIVATE_PATHS):
        findings.append("percorso_home_personale")
    for rule, pattern in SECRET_SIGNATURES:
        if pattern.search(text):
            findings.append(rule)
    return findings


def history_email_is_public(address: str) -> bool:
    normalized = address.casefold()
    domain = normalized.rsplit("@", 1)[-1]
    return normalized in ALLOWED_HISTORY_EMAILS or domain in ALLOWED_HISTORY_EMAIL_DOMAINS


def audit_git_history() -> list[str]:
    result = subprocess.run(
        ["git", "log", "--branches", "--tags", "--format=%ae%n%ce%n%B"],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return ["cronologia_git_non_leggibile"]
    if any(not history_email_is_public(address) for address in EMAIL.findall(result.stdout)):
        return ["indirizzo_email_personale_nella_cronologia_git"]
    return []


def main() -> int:
    findings: list[tuple[Path, str]] = []
    for path in candidate_files():
        for rule in audit_file(path):
            findings.append((path.relative_to(ROOT), rule))
    findings.extend((Path(".git"), rule) for rule in audit_git_history())
    if findings:
        print("Audit privacy repository FALLITO. Nessun contenuto viene mostrato.")
        for path, rule in findings:
            print(f"- {path}: {rule}")
        return 1
    print("Audit privacy repository superato: nessun artefatto personale rilevato.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
