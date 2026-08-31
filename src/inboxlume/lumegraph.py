from __future__ import annotations

import math
import re
from dataclasses import dataclass
from datetime import date, datetime
from enum import StrEnum
from typing import Protocol

from .models import Classification, EmailCategory, EmailRecord


LUMEGRAPH_ENGINE_VERSION = "lumegraph-v2"


class UtilityKind(StrEnum):
    NONE = "none"
    ONE_TIME_CODE = "one_time_code"
    ORDER = "order"
    SHIPMENT = "shipment"
    RESERVATION = "reservation"
    INVOICE = "invoice"
    PAYMENT = "payment"
    SECURITY_FLOW = "security_flow"
    PROMOTION = "promotion"


class LifecycleState(StrEnum):
    ACTIVE = "active"
    PENDING = "pending"
    COMPLETED = "completed"
    REPLACED = "replaced"
    EXPIRED = "expired"
    UNCERTAIN = "uncertain"


class DateRelation(StrEnum):
    NONE = "none"
    PAST = "past"
    TODAY = "today"
    FUTURE = "future"
    UNCERTAIN = "uncertain"


class LifecycleCondition(StrEnum):
    NONE = "none"
    USER_ACTION_REQUIRED = "user_action_required"
    EXTERNAL_ACTION_PENDING = "external_action_pending"
    TIME_BOUND = "time_bound"
    COMPLETED_CONDITION = "completed_condition"
    UNCERTAIN = "uncertain"


class TransitionKind(StrEnum):
    UPDATES = "updates"
    COMPLETES = "completes"
    REPLACES = "replaces"
    EXPIRES = "expires"


LIFECYCLE_REASON_CODES = frozenset(
    {
        "otp_language",
        "order_language",
        "shipment_language",
        "reservation_language",
        "invoice_language",
        "payment_language",
        "security_flow_language",
        "promotion_language",
        "active_language",
        "pending_language",
        "completion_language",
        "replacement_language",
        "expiry_language",
        "explicit_date",
        "evidentiary_record",
        "ambiguous_lifecycle",
        "heuristic_fallback",
        "model_failure",
    }
)


@dataclass(frozen=True, slots=True)
class UtilityVector:
    operational: bool
    evidentiary: bool
    personal: bool
    security: bool

    def __post_init__(self) -> None:
        if not all(
            isinstance(value, bool)
            for value in (
                self.operational,
                self.evidentiary,
                self.personal,
                self.security,
            )
        ):
            raise ValueError("utility vector must contain booleans")

    def as_dict(self) -> dict[str, bool]:
        return {
            "operational": self.operational,
            "evidentiary": self.evidentiary,
            "personal": self.personal,
            "security": self.security,
        }


@dataclass(frozen=True, slots=True)
class LifecycleObservation:
    kind: UtilityKind
    state: LifecycleState
    utility: UtilityVector
    date_relation: DateRelation
    condition: LifecycleCondition
    confidence: float
    reason_codes: tuple[str, ...]
    extractor: str

    def __post_init__(self) -> None:
        if self.kind is UtilityKind.NONE:
            raise ValueError("a stored lifecycle observation needs a utility kind")
        if (
            isinstance(self.confidence, bool)
            or not isinstance(self.confidence, (int, float))
            or not math.isfinite(float(self.confidence))
            or not 0.0 <= float(self.confidence) <= 1.0
        ):
            raise ValueError("lifecycle confidence must be between zero and one")
        if not self.extractor.strip() or len(self.extractor) > 100:
            raise ValueError("invalid lifecycle extractor")
        if (
            len(self.reason_codes) > 6
            or any(code not in LIFECYCLE_REASON_CODES for code in self.reason_codes)
        ):
            raise ValueError("invalid lifecycle reason codes")

    def as_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind.value,
            "state": self.state.value,
            "utility": self.utility.as_dict(),
            "date_relation": self.date_relation.value,
            "condition": self.condition.value,
            "confidence": round(self.confidence, 4),
            "reason_codes": list(self.reason_codes),
            "extractor": self.extractor,
        }


class LifecycleExtractor(Protocol):
    def extract_lifecycle(
        self,
        message: EmailRecord,
        expected_kind: UtilityKind,
        now: datetime,
    ) -> LifecycleObservation: ...


_OTP_TERMS = (
    "one-time code",
    "one time code",
    "verification code",
    "security code",
    "codice monouso",
    "codice di verifica",
    "codice temporaneo",
    " otp ",
)
_SHIPMENT_TERMS = (
    "shipment",
    "shipped",
    "tracking",
    "delivery",
    "delivered",
    "package",
    "spedizione",
    "spedito",
    "tracciamento",
    "consegna",
    "consegnato",
    "pacco",
    "corriere",
)
_ORDER_TERMS = (
    "order confirmed",
    "order confirmation",
    "purchase confirmed",
    "ordine confermato",
    "conferma ordine",
    "acquisto confermato",
)
_RESERVATION_TERMS = (
    "booking",
    "reservation",
    "check-in",
    "check in",
    "boarding pass",
    "flight",
    "hotel",
    "prenotazione",
    "check-in",
    "carta d'imbarco",
    "volo",
    "treno",
)
_INVOICE_TERMS = (
    "invoice",
    "fattura",
    "payment due",
    "pagamento dovuto",
)
_PAYMENT_TERMS = (
    "payment confirmation",
    "payment receipt",
    "transaction receipt",
    "transfer receipt",
    "pagamento confermato",
    "ricevuta di pagamento",
    "ricevuta bonifico",
    "ricarica effettuata",
    "top-up completed",
)
_SECURITY_FLOW_TERMS = (
    "password reset",
    "reset your password",
    "password changed",
    "account recovered",
    "reimposta la password",
    "reimpostazione password",
    "password modificata",
    "account recuperato",
)
_PROMOTION_TERMS = (
    "offer expires",
    "offer ends",
    "valid until",
    "promotion ends",
    "offerta scade",
    "scade il",
    "valida fino",
    "promozione termina",
)
_COMPLETED_TERMS = (
    "delivered",
    "consegnato",
    "delivery completed",
    "consegna completata",
    "completed",
    "completato",
    "cancelled",
    "canceled",
    "cancellata",
    "annullata",
    "payment confirmation",
    "payment completed",
    "payment receipt",
    "pagamento confermato",
    "pagamento completato",
    "ricevuta di pagamento",
    "password changed",
    "password modificata",
    "account recovered",
    "account recuperato",
)
_ACTIVE_TERMS = (
    "out for delivery",
    "in transit",
    "in consegna",
    "in transito",
    "check-in open",
    "check-in aperto",
    "reset your password",
    "reimposta la password",
)
_PENDING_TERMS = (
    "shipped",
    "spedito",
    "preparing",
    "in preparazione",
    "confirmed",
    "confermata",
    "confermato",
)
_REPLACED_TERMS = (
    "updated booking",
    "booking changed",
    "schedule changed",
    "prenotazione modificata",
    "orario modificato",
    "nuovo itinerario",
)


def _message_text(message: EmailRecord) -> str:
    return "\n".join((message.subject, message.body_text)).casefold()


def lifecycle_candidate_kind(
    message: EmailRecord,
    classification: Classification,
) -> UtilityKind:
    """Conservative bilingual prefilter; it never produces an action."""

    text = f" {_message_text(message)} "
    if classification.category is EmailCategory.ONE_TIME_CODE or any(
        term in text for term in _OTP_TERMS
    ):
        return UtilityKind.ONE_TIME_CODE
    if any(term in text for term in _SECURITY_FLOW_TERMS):
        return UtilityKind.SECURITY_FLOW
    if any(term in text for term in _PAYMENT_TERMS):
        return UtilityKind.PAYMENT
    if any(term in text for term in _INVOICE_TERMS):
        return UtilityKind.INVOICE
    if any(term in text for term in _SHIPMENT_TERMS):
        return UtilityKind.SHIPMENT
    if any(term in text for term in _RESERVATION_TERMS):
        return UtilityKind.RESERVATION
    if any(term in text for term in _ORDER_TERMS):
        return UtilityKind.ORDER
    if classification.category is EmailCategory.ADVERTISING and any(
        term in text for term in _PROMOTION_TERMS
    ):
        return UtilityKind.PROMOTION
    return UtilityKind.NONE


_EXPIRY_DATE_PATTERNS = (
    re.compile(
        r"(?:offer expires|offer ends|valid until|promotion ends|offerta scade|"
        r"scade il|valida fino|promozione termina)\D{0,24}"
        r"(20\d{2})[-/.](0?[1-9]|1[0-2])[-/.](0?[1-9]|[12]\d|3[01])",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:offer expires|offer ends|valid until|promotion ends|offerta scade|"
        r"scade il|valida fino|promozione termina)\D{0,24}"
        r"(0?[1-9]|[12]\d|3[01])[-/.](0?[1-9]|1[0-2])[-/.](20\d{2})",
        re.IGNORECASE,
    ),
)

_MONTH_NUMBER = {
    "january": 1,
    "jan": 1,
    "gennaio": 1,
    "february": 2,
    "feb": 2,
    "febbraio": 2,
    "march": 3,
    "mar": 3,
    "marzo": 3,
    "april": 4,
    "apr": 4,
    "aprile": 4,
    "may": 5,
    "maggio": 5,
    "june": 6,
    "jun": 6,
    "giugno": 6,
    "july": 7,
    "jul": 7,
    "luglio": 7,
    "august": 8,
    "aug": 8,
    "agosto": 8,
    "september": 9,
    "sep": 9,
    "settembre": 9,
    "october": 10,
    "oct": 10,
    "ottobre": 10,
    "november": 11,
    "nov": 11,
    "novembre": 11,
    "december": 12,
    "dec": 12,
    "dicembre": 12,
}
_MONTH_ALTERNATION = "|".join(sorted(_MONTH_NUMBER, key=len, reverse=True))
_EXPIRY_NAMED_DATE_PATTERNS = (
    re.compile(
        rf"(?:offer expires|offer ends|valid until|promotion ends|offerta scade|"
        rf"scade il|valida fino|promozione termina)\D{{0,24}}"
        rf"(0?[1-9]|[12]\d|3[01])\s+({_MONTH_ALTERNATION})\s+(20\d{{2}})",
        re.IGNORECASE,
    ),
    re.compile(
        rf"(?:offer expires|offer ends|valid until|promotion ends)\D{{0,24}}"
        rf"({_MONTH_ALTERNATION})\s+(0?[1-9]|[12]\d|3[01]),?\s+(20\d{{2}})",
        re.IGNORECASE,
    ),
)


def verified_expiry_date(message: EmailRecord, now: datetime) -> date | None:
    """Parse only explicit dates directly attached to bilingual expiry language."""

    if now.tzinfo is None:
        raise ValueError("now must include a timezone")
    text = "\n".join((message.subject, message.body_text))[:8_500]
    dates: list[date] = []
    for index, pattern in enumerate(_EXPIRY_DATE_PATTERNS):
        for match in pattern.finditer(text):
            raw = tuple(int(value) for value in match.groups())
            year, month, day = raw if index == 0 else (raw[2], raw[1], raw[0])
            try:
                dates.append(date(year, month, day))
            except ValueError:
                continue
    for index, pattern in enumerate(_EXPIRY_NAMED_DATE_PATTERNS):
        for match in pattern.finditer(text):
            if index == 0:
                day = int(match.group(1))
                month = _MONTH_NUMBER[match.group(2).casefold()]
            else:
                month = _MONTH_NUMBER[match.group(1).casefold()]
                day = int(match.group(2))
            try:
                dates.append(date(int(match.group(3)), month, day))
            except ValueError:
                continue
    return max(dates) if dates else None


_REFERENCE_PATTERNS = (
    re.compile(
        r"(?:tracking|shipment|spedizione|ordine|order|invoice|fattura|"
        r"transaction|transazione|payment|pagamento)\s*"
        r"(?:number|numero|n\.?|#|id|code|codice|reference|riferimento)\s*"
        r"[:#-]?\s*"
        r"([a-z0-9][a-z0-9-]{4,31})",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:booking|reservation|prenotazione|pnr)\s*"
        r"(?:number|numero|n\.?|#|id|code|codice|reference|riferimento)?\s*"
        r"[:#-]\s*"
        r"([a-z0-9][a-z0-9-]{4,31})",
        re.IGNORECASE,
    ),
)

_REFERENCE_STOPWORDS = frozenset(
    {
        "conferma",
        "confirmed",
        "confirmation",
        "completato",
        "completed",
        "numero",
        "number",
    }
)


def lifecycle_relation_materials(
    message: EmailRecord,
    kind: UtilityKind,
) -> tuple[str, ...]:
    """Return ephemeral reference keys; callers must HMAC before persistence."""

    if kind is UtilityKind.ONE_TIME_CODE:
        return ()
    text = "\n".join((message.subject, message.body_text))[:8_500]
    tokens = {
        match.group(1).casefold()
        for pattern in _REFERENCE_PATTERNS
        for match in pattern.finditer(text)
        if match.group(1).casefold() not in _REFERENCE_STOPWORDS
    }
    # Account-scoped HMAC makes cross-sender chains possible without persisting the
    # order, tracking, booking, invoice or transaction reference itself.
    return tuple(f"reference:{token}" for token in sorted(tokens)[:4])


def lifecycle_relation_material(
    message: EmailRecord,
    kind: UtilityKind,
) -> str | None:
    """Return an ephemeral relation key that must be HMACed before persistence."""

    materials = lifecycle_relation_materials(message, kind)
    return materials[0] if materials else None


class HeuristicLifecycleExtractor:
    """Deterministic fallback; conservative and shadow-only."""

    def extract_lifecycle(
        self,
        message: EmailRecord,
        expected_kind: UtilityKind,
        now: datetime,
    ) -> LifecycleObservation:
        if now.tzinfo is None:
            raise ValueError("now must include a timezone")
        if expected_kind is UtilityKind.NONE:
            raise ValueError("lifecycle kind is required")
        text = _message_text(message)
        kind_reason = {
            UtilityKind.ONE_TIME_CODE: "otp_language",
            UtilityKind.ORDER: "order_language",
            UtilityKind.SHIPMENT: "shipment_language",
            UtilityKind.RESERVATION: "reservation_language",
            UtilityKind.INVOICE: "invoice_language",
            UtilityKind.PAYMENT: "payment_language",
            UtilityKind.SECURITY_FLOW: "security_flow_language",
            UtilityKind.PROMOTION: "promotion_language",
        }[expected_kind]
        reasons = [kind_reason, "heuristic_fallback"]
        explicit_expiry: date | None = None
        if expected_kind is UtilityKind.ONE_TIME_CODE:
            if not message.unread and message.age_days(now) >= 7:
                state = LifecycleState.EXPIRED
                reasons.append("expiry_language")
            elif message.age_days(now) == 0:
                state = LifecycleState.ACTIVE
                reasons.append("active_language")
            else:
                state = LifecycleState.UNCERTAIN
                reasons.append("ambiguous_lifecycle")
            utility = UtilityVector(
                operational=state is LifecycleState.ACTIVE,
                evidentiary=False,
                personal=False,
                # A read code past the configured expiry window no longer carries
                # authentication utility; active/uncertain codes remain protected.
                security=state is not LifecycleState.EXPIRED,
            )
            condition = (
                LifecycleCondition.COMPLETED_CONDITION
                if state is LifecycleState.EXPIRED
                else LifecycleCondition.TIME_BOUND
                if state is LifecycleState.ACTIVE
                else LifecycleCondition.UNCERTAIN
            )
        else:
            explicit_expiry = (
                verified_expiry_date(message, now)
                if expected_kind is UtilityKind.PROMOTION
                else None
            )
            if explicit_expiry is not None:
                reasons.append("explicit_date")
            if any(term in text for term in _REPLACED_TERMS):
                state = LifecycleState.REPLACED
                reasons.append("replacement_language")
            elif any(term in text for term in _COMPLETED_TERMS):
                state = LifecycleState.COMPLETED
                reasons.append("completion_language")
            elif any(term in text for term in _ACTIVE_TERMS):
                state = LifecycleState.ACTIVE
                reasons.append("active_language")
            elif any(term in text for term in _PENDING_TERMS):
                state = LifecycleState.PENDING
                reasons.append("pending_language")
            else:
                state = LifecycleState.UNCERTAIN
                reasons.append("ambiguous_lifecycle")
            if (
                expected_kind is UtilityKind.PROMOTION
                and explicit_expiry is not None
                and explicit_expiry < now.date()
            ):
                state = LifecycleState.EXPIRED
                reasons = [
                    reason
                    for reason in reasons
                    if reason != "ambiguous_lifecycle"
                ]
                reasons.append("expiry_language")
            protected_record = expected_kind in {
                UtilityKind.INVOICE,
                UtilityKind.PAYMENT,
            }
            security_flow = expected_kind is UtilityKind.SECURITY_FLOW
            utility = UtilityVector(
                operational=state in {LifecycleState.ACTIVE, LifecycleState.PENDING},
                evidentiary=(
                    protected_record
                    or expected_kind is UtilityKind.RESERVATION
                    or state in {LifecycleState.COMPLETED, LifecycleState.REPLACED}
                ),
                personal=expected_kind is UtilityKind.RESERVATION,
                security=security_flow,
            )
            if utility.evidentiary:
                reasons.append("evidentiary_record")
            if state in {
                LifecycleState.COMPLETED,
                LifecycleState.REPLACED,
                LifecycleState.EXPIRED,
            }:
                condition = LifecycleCondition.COMPLETED_CONDITION
            elif state in {LifecycleState.ACTIVE, LifecycleState.PENDING}:
                condition = (
                    LifecycleCondition.USER_ACTION_REQUIRED
                    if expected_kind in {
                        UtilityKind.INVOICE,
                        UtilityKind.SECURITY_FLOW,
                    }
                    else LifecycleCondition.EXTERNAL_ACTION_PENDING
                )
            else:
                condition = LifecycleCondition.UNCERTAIN
        return LifecycleObservation(
            kind=expected_kind,
            state=state,
            utility=utility,
            date_relation=(
                DateRelation.PAST
                if expected_kind is UtilityKind.PROMOTION
                and explicit_expiry is not None
                and explicit_expiry < now.date()
                else DateRelation.FUTURE
                if expected_kind is UtilityKind.PROMOTION
                and explicit_expiry is not None
                and explicit_expiry > now.date()
                else DateRelation.TODAY
                if expected_kind is UtilityKind.PROMOTION
                and explicit_expiry == now.date()
                else DateRelation.UNCERTAIN
            ),
            condition=condition,
            confidence=0.76 if state is not LifecycleState.UNCERTAIN else 0.45,
            reason_codes=tuple(dict.fromkeys(reasons)),
            extractor="heuristic-lifecycle-v1",
        )


def transition_for_state(state: LifecycleState) -> TransitionKind:
    return {
        LifecycleState.COMPLETED: TransitionKind.COMPLETES,
        LifecycleState.REPLACED: TransitionKind.REPLACES,
        LifecycleState.EXPIRED: TransitionKind.EXPIRES,
    }.get(state, TransitionKind.UPDATES)
