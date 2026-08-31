from __future__ import annotations

import ipaddress
import math
import re
import unicodedata
from dataclasses import dataclass
from email.utils import parseaddr
from enum import StrEnum
from urllib.parse import urlsplit
from typing import Mapping

from .models import EmailRecord


THREAT_SIGNAL_ENGINE_VERSION = "threat-signals-v1"
THREAT_CONSENSUS_ENGINE_VERSION = "threat-consensus-v3"


class ThreatLevel(StrEnum):
    MINIMAL = "minimal"
    ELEVATED = "elevated"
    HIGH = "high"
    CRITICAL = "critical"


class ThreatSemanticMode(StrEnum):
    """Choose how much local-model work follows the technical screening."""

    TECHNICAL_ONLY = "technical_only"
    TARGETED_SEMANTIC = "targeted_semantic"


class ThreatSignal(StrEnum):
    MALFORMED_SENDER = "malformed_sender"
    REPLY_TO_DOMAIN_MISMATCH = "reply_to_domain_mismatch"
    BRAND_DOMAIN_MISMATCH = "brand_domain_mismatch"
    PUNYCODE_SENDER_DOMAIN = "punycode_sender_domain"
    MIXED_SCRIPT_SENDER = "mixed_script_sender"
    BIDI_CONTROL_IN_IDENTITY = "bidi_control_in_identity"
    IP_LITERAL_LINK = "ip_literal_link"
    PUNYCODE_LINK = "punycode_link"
    TRUSTED_DMARC_FAILURE = "trusted_dmarc_failure"
    TRUSTED_DKIM_FAILURE = "trusted_dkim_failure"
    TRUSTED_SPF_FAILURE = "trusted_spf_failure"
    URGENT_CREDENTIAL_REQUEST = "urgent_credential_request"
    UNUSUAL_MONEY_REQUEST = "unusual_money_request"
    COURIER_FEE_REQUEST = "courier_fee_request"
    INDEPENDENT_SIGNAL_CONSENSUS = "independent_signal_consensus"


class SemanticThreatVerdict(StrEnum):
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    LIKELY_PHISHING = "likely_phishing"
    LIKELY_SCAM = "likely_scam"
    UNCERTAIN = "uncertain"


class ThreatIntent(StrEnum):
    NONE = "none"
    CREDENTIAL_THEFT = "credential_theft"
    FINANCIAL_FRAUD = "financial_fraud"
    IMPERSONATION = "impersonation"
    DELIVERY_SCAM = "delivery_scam"
    MALWARE_LURE = "malware_lure"
    UNCERTAIN = "uncertain"


SEMANTIC_THREAT_REASON_CODES = frozenset(
    {
        "account_takeover_pressure",
        "benign_context",
        "credential_harvest_language",
        "delivery_fee_lure",
        "gift_card_or_crypto_request",
        "impersonation_language",
        "insufficient_evidence",
        "malware_or_attachment_lure",
        "payment_diversion_language",
        "suspicious_link_instruction",
        "unexpected_financial_request",
    }
)


_WEIGHTS = {
    ThreatSignal.MALFORMED_SENDER: 15,
    ThreatSignal.REPLY_TO_DOMAIN_MISMATCH: 8,
    ThreatSignal.BRAND_DOMAIN_MISMATCH: 30,
    ThreatSignal.PUNYCODE_SENDER_DOMAIN: 14,
    ThreatSignal.MIXED_SCRIPT_SENDER: 22,
    ThreatSignal.BIDI_CONTROL_IN_IDENTITY: 25,
    ThreatSignal.IP_LITERAL_LINK: 25,
    ThreatSignal.PUNYCODE_LINK: 16,
    ThreatSignal.TRUSTED_DMARC_FAILURE: 35,
    ThreatSignal.TRUSTED_DKIM_FAILURE: 12,
    ThreatSignal.TRUSTED_SPF_FAILURE: 10,
    ThreatSignal.URGENT_CREDENTIAL_REQUEST: 24,
    ThreatSignal.UNUSUAL_MONEY_REQUEST: 32,
    ThreatSignal.COURIER_FEE_REQUEST: 24,
    ThreatSignal.INDEPENDENT_SIGNAL_CONSENSUS: 12,
}

_SIGNAL_FAMILY = {
    ThreatSignal.MALFORMED_SENDER: "identity",
    ThreatSignal.REPLY_TO_DOMAIN_MISMATCH: "identity",
    ThreatSignal.BRAND_DOMAIN_MISMATCH: "identity",
    ThreatSignal.PUNYCODE_SENDER_DOMAIN: "unicode_domain",
    ThreatSignal.MIXED_SCRIPT_SENDER: "unicode_domain",
    ThreatSignal.BIDI_CONTROL_IN_IDENTITY: "unicode_domain",
    ThreatSignal.IP_LITERAL_LINK: "link",
    ThreatSignal.PUNYCODE_LINK: "link",
    ThreatSignal.TRUSTED_DMARC_FAILURE: "authentication",
    ThreatSignal.TRUSTED_DKIM_FAILURE: "authentication",
    ThreatSignal.TRUSTED_SPF_FAILURE: "authentication",
    ThreatSignal.URGENT_CREDENTIAL_REQUEST: "content",
    ThreatSignal.UNUSUAL_MONEY_REQUEST: "content",
    ThreatSignal.COURIER_FEE_REQUEST: "content",
    ThreatSignal.INDEPENDENT_SIGNAL_CONSENSUS: "consensus",
}

_BRAND_DOMAINS = {
    "amazon": ("amazon.com", "amazon.it", "amazon.co.uk", "amazon.de", "amazon.fr", "amazon.es"),
    "apple": ("apple.com",),
    "dhl": ("dhl.com",),
    "facebook": ("facebook.com", "facebookmail.com", "meta.com"),
    "fedex": ("fedex.com",),
    "gmail": ("google.com", "gmail.com"),
    "google": ("google.com", "gmail.com"),
    "instagram": ("instagram.com", "facebookmail.com"),
    "linkedin": ("linkedin.com",),
    "microsoft": ("microsoft.com", "microsoftonline.com", "outlook.com"),
    "netflix": ("netflix.com",),
    "outlook": ("microsoft.com", "microsoftonline.com", "outlook.com"),
    "paypal": ("paypal.com",),
    "poste italiane": ("poste.it", "posteitaliane.it"),
    "ups": ("ups.com",),
}

_BIDI_CONTROLS = frozenset(
    "\u061c\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"
)
_URL_PATTERN = re.compile(r"https?://[^\s<>\]\[\"']+", re.IGNORECASE)
_AUTH_RESULT = re.compile(
    r"\b(dmarc|dkim|spf)\s*=\s*"
    r"(pass|fail|softfail|neutral|none|temperror|permerror|policy)\b",
    re.IGNORECASE,
)

_URGENCY_TERMS = (
    "urgent",
    "immediately",
    "within 24 hours",
    "action required",
    "account suspended",
    "urgente",
    "immediatamente",
    "entro 24 ore",
    "azione richiesta",
    "account sospeso",
    "conto bloccato",
)
_CREDENTIAL_TERMS = (
    "password",
    "credentials",
    "login",
    "sign in",
    "verify your account",
    "security code",
    "credenziali",
    "accedi",
    "verifica il tuo account",
    "codice di sicurezza",
)
_MONEY_TERMS = (
    "gift card",
    "wire transfer",
    "send money",
    "bitcoin",
    "cryptocurrency",
    "buono regalo",
    "bonifico urgente",
    "invia denaro",
    "criptovaluta",
)
_COURIER_TERMS = (
    "courier",
    "delivery",
    "package",
    "shipment",
    "corriere",
    "consegna",
    "pacco",
    "spedizione",
)
_FEE_TERMS = (
    "fee",
    "customs charge",
    "redelivery fee",
    "small payment",
    "tariffa",
    "dazio",
    "costo di riconsegna",
    "piccolo pagamento",
)


@dataclass(frozen=True, slots=True)
class ThreatAssessment:
    score: int
    level: ThreatLevel
    signals: tuple[ThreatSignal, ...]
    signal_families: tuple[str, ...]
    engine_version: str = THREAT_SIGNAL_ENGINE_VERSION

    def __post_init__(self) -> None:
        if (
            isinstance(self.score, bool)
            or not isinstance(self.score, int)
            or not 0 <= self.score <= 100
        ):
            raise ValueError("threat score must be between zero and one hundred")
        if tuple(sorted(set(self.signals), key=lambda item: item.value)) != self.signals:
            raise ValueError("threat signals must be unique and sorted")

    @property
    def protective_review_recommended(self) -> bool:
        return self.level in {ThreatLevel.HIGH, ThreatLevel.CRITICAL}

    def as_dict(self) -> dict[str, object]:
        """Return controlled evidence only: never sender, link, subject, or body."""

        return {
            "engine_version": self.engine_version,
            "score": self.score,
            "level": self.level.value,
            "signals": [signal.value for signal in self.signals],
            "signal_families": list(self.signal_families),
            "protective_review_recommended": self.protective_review_recommended,
            "authorizes_cleanup": False,
            "stored_plaintext": False,
        }


@dataclass(frozen=True, slots=True)
class SemanticThreatAssessment:
    verdict: SemanticThreatVerdict
    intent: ThreatIntent
    impersonation: bool
    credential_request: bool
    money_request: bool
    urgency_pressure: bool
    link_action: bool
    plausible_legitimate_context: bool
    confidence: float
    reason_codes: tuple[str, ...]
    analyzer: str

    def __post_init__(self) -> None:
        if (
            isinstance(self.confidence, bool)
            or not isinstance(self.confidence, (int, float))
            or not math.isfinite(float(self.confidence))
            or not 0.0 <= float(self.confidence) <= 1.0
        ):
            raise ValueError("semantic threat confidence must be between zero and one")
        if not isinstance(self.analyzer, str) or not self.analyzer.strip() or len(
            self.analyzer
        ) > 100:
            raise ValueError("invalid semantic threat analyzer")
        if any(
            type(value) is not bool
            for value in (
                self.impersonation,
                self.credential_request,
                self.money_request,
                self.urgency_pressure,
                self.link_action,
                self.plausible_legitimate_context,
            )
        ):
            raise ValueError("invalid semantic threat booleans")
        if (
            not 1 <= len(self.reason_codes) <= 5
            or len(set(self.reason_codes)) != len(self.reason_codes)
            or any(code not in SEMANTIC_THREAT_REASON_CODES for code in self.reason_codes)
        ):
            raise ValueError("invalid semantic threat reason codes")
        if self.verdict is SemanticThreatVerdict.BENIGN and self.intent not in {
            ThreatIntent.NONE,
            ThreatIntent.UNCERTAIN,
        }:
            raise ValueError("benign verdict cannot assert a malicious intent")

    @property
    def likely_malicious(self) -> bool:
        return self.verdict in {
            SemanticThreatVerdict.LIKELY_PHISHING,
            SemanticThreatVerdict.LIKELY_SCAM,
        }

    def as_dict(self) -> dict[str, object]:
        return {
            "verdict": self.verdict.value,
            "intent": self.intent.value,
            "impersonation": self.impersonation,
            "credential_request": self.credential_request,
            "money_request": self.money_request,
            "urgency_pressure": self.urgency_pressure,
            "link_action": self.link_action,
            "plausible_legitimate_context": self.plausible_legitimate_context,
            "confidence": round(self.confidence, 4),
            "reason_codes": list(self.reason_codes),
            "analyzer": self.analyzer,
            "authorizes_cleanup": False,
            "stored_plaintext": False,
        }


@dataclass(frozen=True, slots=True)
class ThreatConsensusAssessment:
    score: int
    level: ThreatLevel
    deterministic: ThreatAssessment
    semantic: SemanticThreatAssessment
    independent_consensus: bool

    @property
    def protective_review_recommended(self) -> bool:
        return self.level in {ThreatLevel.HIGH, ThreatLevel.CRITICAL}

    def as_dict(self) -> dict[str, object]:
        return {
            "score": self.score,
            "level": self.level.value,
            "independent_consensus": self.independent_consensus,
            "deterministic": self.deterministic.as_dict(),
            "semantic": self.semantic.as_dict(),
            "protective_review_recommended": self.protective_review_recommended,
            "authorizes_cleanup": False,
            "stored_plaintext": False,
        }


def semantic_followup_recommended(deterministic: ThreatAssessment) -> bool:
    """Require an independent local-model pass only after a technical signal.

    The deterministic layer has already inspected identity, link, authentication
    and high-risk language signals.  A message without any such signal does not
    consume a second model inference in the targeted mode.  Any signal, including
    a single low-score anomaly, remains eligible so that the optimisation never
    turns the technical threshold into an implicit allow-list.
    """

    return bool(deterministic.signals)


def parse_semantic_threat_mapping(
    raw: Mapping[str, object],
    *,
    analyzer: str,
) -> SemanticThreatAssessment:
    expected = {
        "verdict",
        "intent",
        "impersonation",
        "credential_request",
        "money_request",
        "urgency_pressure",
        "link_action",
        "plausible_legitimate_context",
        "confidence",
        "reason_codes",
    }
    if set(raw) != expected:
        raise ValueError("invalid semantic threat fields")
    boolean_fields = (
        "impersonation",
        "credential_request",
        "money_request",
        "urgency_pressure",
        "link_action",
        "plausible_legitimate_context",
    )
    if any(type(raw[name]) is not bool for name in boolean_fields):
        raise ValueError("invalid semantic threat booleans")
    confidence = raw["confidence"]
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
        raise ValueError("invalid semantic threat confidence")
    reasons = raw["reason_codes"]
    if not isinstance(reasons, list) or any(not isinstance(item, str) for item in reasons):
        raise ValueError("invalid semantic threat reasons")
    return SemanticThreatAssessment(
        SemanticThreatVerdict(str(raw["verdict"])),
        ThreatIntent(str(raw["intent"])),
        *(bool(raw[name]) for name in boolean_fields),
        float(confidence),
        tuple(reasons),
        analyzer,
    )


def combine_threat_assessments(
    deterministic: ThreatAssessment,
    semantic: SemanticThreatAssessment,
) -> ThreatConsensusAssessment:
    """Combine independent evidence without letting an LLM alone declare high risk."""

    semantic_score = (
        round(30 * semantic.confidence)
        if semantic.likely_malicious
        else round(15 * semantic.confidence)
        if semantic.verdict is SemanticThreatVerdict.SUSPICIOUS
        else 0
    )
    independent_consensus = (
        semantic.likely_malicious
        and semantic.confidence >= 0.80
        and bool(deterministic.signal_families)
    )
    combined = deterministic.score + semantic_score + (15 if independent_consensus else 0)
    if not deterministic.signal_families:
        # Semantic interpretation alone remains visible but cannot create a High alert.
        combined = min(combined, 35)
    score = min(100, combined)
    level = (
        ThreatLevel.CRITICAL
        if score >= 70
        else ThreatLevel.HIGH
        if score >= 40
        else ThreatLevel.ELEVATED
        if score >= 20
        else ThreatLevel.MINIMAL
    )
    return ThreatConsensusAssessment(
        score,
        level,
        deterministic,
        semantic,
        independent_consensus,
    )


def _header(message: EmailRecord, name: str) -> str:
    wanted = name.casefold()
    return next(
        (str(value) for key, value in message.headers.items() if str(key).casefold() == wanted),
        "",
    )


def _domain(address: str) -> str:
    parsed = parseaddr(address)[1].strip().casefold()
    return parsed.rsplit("@", 1)[-1].rstrip(".") if "@" in parsed else ""


def _same_domain_family(left: str, right: str) -> bool:
    return bool(left and right) and (
        left == right or left.endswith(f".{right}") or right.endswith(f".{left}")
    )


def _domain_matches(domain: str, allowed: tuple[str, ...]) -> bool:
    return any(domain == item or domain.endswith(f".{item}") for item in allowed)


def _scripts(text: str) -> frozenset[str]:
    scripts: set[str] = set()
    for character in text:
        if not character.isalpha():
            continue
        name = unicodedata.name(character, "")
        for script in ("LATIN", "CYRILLIC", "GREEK"):
            if script in name:
                scripts.add(script)
                break
    return frozenset(scripts)


def _decoded_idna(domain: str) -> str:
    try:
        return domain.encode("ascii").decode("idna")
    except (UnicodeError, ValueError):
        return domain


def _message_urls(message: EmailRecord) -> tuple[str, ...]:
    text = "\n".join((message.subject, message.body_text))[:10_000]
    return tuple(match.group(0).rstrip(".,);:") for match in _URL_PATTERN.finditer(text))[:20]


def assess_threat_signals(
    message: EmailRecord,
    *,
    trusted_authentication_results: bool = False,
) -> ThreatAssessment:
    """Extract final-form local signals without network access or mailbox actions.

    Authentication-Results is ignored unless the provider adapter explicitly marks
    it as trusted; RFC 8601 warns that mere header presence is not proof of validity.
    """

    signals: set[ThreatSignal] = set()
    display_name, address = parseaddr(message.sender)
    sender_domain = _domain(message.sender)
    if not address or not sender_domain:
        signals.add(ThreatSignal.MALFORMED_SENDER)

    identity = f"{display_name}\n{address}\n{sender_domain}"
    if any(character in _BIDI_CONTROLS for character in identity):
        signals.add(ThreatSignal.BIDI_CONTROL_IN_IDENTITY)
    decoded_sender_domain = _decoded_idna(sender_domain)
    if "xn--" in sender_domain:
        signals.add(ThreatSignal.PUNYCODE_SENDER_DOMAIN)
    if len(_scripts(f"{display_name} {decoded_sender_domain}")) > 1:
        signals.add(ThreatSignal.MIXED_SCRIPT_SENDER)

    claimed_identity = unicodedata.normalize("NFKC", display_name).casefold()
    for brand, allowed_domains in _BRAND_DOMAINS.items():
        if brand in claimed_identity and not _domain_matches(sender_domain, allowed_domains):
            signals.add(ThreatSignal.BRAND_DOMAIN_MISMATCH)
            break

    reply_domain = _domain(_header(message, "Reply-To"))
    if reply_domain and sender_domain and not _same_domain_family(reply_domain, sender_domain):
        signals.add(ThreatSignal.REPLY_TO_DOMAIN_MISMATCH)

    urls = _message_urls(message)
    for url in urls:
        host = (urlsplit(url).hostname or "").casefold().rstrip(".")
        if not host:
            continue
        try:
            ipaddress.ip_address(host.strip("[]"))
        except ValueError:
            pass
        else:
            signals.add(ThreatSignal.IP_LITERAL_LINK)
        if "xn--" in host:
            signals.add(ThreatSignal.PUNYCODE_LINK)

    if trusted_authentication_results:
        authentication = _header(message, "Authentication-Results")
        results = {(method.casefold(), result.casefold()) for method, result in _AUTH_RESULT.findall(authentication)}
        if ("dmarc", "fail") in results:
            signals.add(ThreatSignal.TRUSTED_DMARC_FAILURE)
        if ("dkim", "fail") in results:
            signals.add(ThreatSignal.TRUSTED_DKIM_FAILURE)
        if ("spf", "fail") in results or ("spf", "softfail") in results:
            signals.add(ThreatSignal.TRUSTED_SPF_FAILURE)

    content = "\n".join((message.subject, message.body_text)).casefold()[:10_000]
    has_url = bool(urls)
    urgent = any(term in content for term in _URGENCY_TERMS)
    if urgent and has_url and any(term in content for term in _CREDENTIAL_TERMS):
        signals.add(ThreatSignal.URGENT_CREDENTIAL_REQUEST)
    if urgent and any(term in content for term in _MONEY_TERMS):
        signals.add(ThreatSignal.UNUSUAL_MONEY_REQUEST)
    if has_url and any(term in content for term in _COURIER_TERMS) and any(
        term in content for term in _FEE_TERMS
    ):
        signals.add(ThreatSignal.COURIER_FEE_REQUEST)

    independent_families = {
        _SIGNAL_FAMILY[signal]
        for signal in signals
        if signal is not ThreatSignal.INDEPENDENT_SIGNAL_CONSENSUS
    }
    if len(independent_families) >= 2:
        signals.add(ThreatSignal.INDEPENDENT_SIGNAL_CONSENSUS)

    ordered = tuple(sorted(signals, key=lambda item: item.value))
    score = min(100, sum(_WEIGHTS[signal] for signal in ordered))
    level = (
        ThreatLevel.CRITICAL
        if score >= 70
        else ThreatLevel.HIGH
        if score >= 40
        else ThreatLevel.ELEVATED
        if score >= 20
        else ThreatLevel.MINIMAL
    )
    families = tuple(sorted({_SIGNAL_FAMILY[signal] for signal in ordered}))
    return ThreatAssessment(score, level, ordered, families)
