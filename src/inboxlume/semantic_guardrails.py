from __future__ import annotations

import re
from enum import StrEnum

from .models import EmailRecord


class AccessAlertKind(StrEnum):
    ROUTINE = "routine"
    HIGH_RISK = "high_risk"


_HIGH_RISK_ACCESS_TERMS = (
    "accesso sospetto",
    "suspicious sign-in",
    "suspicious login",
    "accesso non riconosciuto",
    "unrecognized sign-in",
    "unrecognised sign-in",
    "unrecognized login",
    "unrecognised login",
    "non sei stato tu",
    "wasn't you",
    "was not you",
    "dispositivo sconosciuto",
    "unknown device",
    "password modificata",
    "password changed",
    "password was changed",
    "password has been changed",
    "password reimpostata",
    "password reset",
    "password was reset",
    "password has been reset",
    "password è stata modificata",
    "password e stata modificata",
    "password è stata reimpostata",
    "password e stata reimpostata",
    "account compromesso",
    "account compromised",
)

_ROUTINE_ACCESS_TERMS = (
    "nuovo accesso",
    "new sign-in",
    "new login",
    "accesso rilevato",
    "sign-in detected",
    "login detected",
    "accesso effettuato",
    "signed in",
    "logged in",
    "accesso da un nuovo dispositivo",
    "new device sign-in",
    "new device login",
    "attività di accesso",
    "sign-in activity",
    "login activity",
    "avviso di accesso",
    "access alert",
    "hai effettuato l'accesso",
    "you logged in",
    "usato per accedere",
    "used to sign in",
)

_BANKING_CONTEXT_TERMS = (
    "banca",
    "bank account",
    "banking",
    "bank transfer",
    "bonifico",
    "estratto conto",
    "account statement",
    "bank statement",
    "documento bancario",
    "documento del conto",
    "conto corrente",
    "carta di credito",
    "carta di debito",
    "iban",
    "addebito",
    "accredito",
    "wire transfer",
    "sepa transfer",
)

_BANKING_RECORD_TERMS = (
    "bank statement",
    "monthly bank statement",
    "documento bancario",
    "documento del conto",
    "ricevuta bonifico",
    "ricevuta del bonifico",
    "bonifico effettuato",
    "bonifico eseguito",
    "bonifico completato",
    "bonifico confermato",
    "transfer receipt",
    "bank transfer completed",
    "bank transfer successful",
    "bank transfer confirmation",
    "wire transfer receipt",
    "sepa transfer confirmation",
    "disposizione di bonifico",
    "bonifico in entrata",
    "operazione bancaria eseguita",
    "operazione completata",
    "transaction completed",
    "transaction confirmed",
    "transaction receipt",
    "addebito effettuato",
    "addebito confermato",
    "accredito ricevuto",
    "pagamento con carta effettuato",
    "card payment completed",
    "card transaction completed",
    "estratto conto",
    "account statement",
)

_GENERAL_RECORD_TERMS = (
    "la tua ricevuta",
    "your receipt",
    "ricevuta n.",
    "receipt no.",
    "receipt #",
    "ricevuta fiscale",
    "fiscal receipt",
    "ricevuta allegata",
    "receipt attached",
    "ricevuta di pagamento",
    "ricevuta del pagamento",
    "ricevuta pagamento",
    "payment receipt",
    "payment completed",
    "payment successful",
    "payment confirmation",
    "pagamento effettuato",
    "pagamento completato",
    "pagamento confermato",
    "pagamento ricevuto",
    "quietanza di pagamento",
    "ricevuta universitaria",
    "ricevuta tassa universitaria",
    "ricevuta versamento",
    "ricevuta iscrizione",
    "ricevuta domanda",
    "tuition receipt",
    "tassa universitaria pagata",
    "tuition payment receipt",
    "tuition payment received",
    "enrolment receipt",
    "enrollment receipt",
    "application receipt",
    "submission receipt",
    "ricarica effettuata",
    "ricarica completata",
    "ricarica confermata",
    "conferma ricarica",
    "ricevuta ricarica",
    "top-up receipt",
    "top-up completed",
    "top-up successful",
    "top-up confirmation",
    "recharge receipt",
    "recharge completed",
    "recharge successful",
)

_INVOICE_RECORD_TERMS = (
    "fattura",
    "invoice",
    "documento fiscale",
    "tax document",
    "nota di credito",
    "credit note",
)

_SERVICE_CONFIRMATION_PAIRS = (
    (("order", "purchase"), ("confirmation", "confirmed")),
    (("ordine", "acquisto"), ("conferma", "confermato", "confermato")),
    (("booking", "reservation"), ("confirmation", "confirmed")),
    (("prenotazione",), ("conferma", "confermata", "confermato")),
)

# These pairs deliberately require both a transactional object and evidence that
# the operation already happened.  A lone word such as "payment", "order", or
# "successful" is not enough: marketing and abandoned-cart messages commonly use
# those words without being durable records.
_TRANSACTION_CONTEXT_TERMS = (
    "payment",
    "payments",
    "pagamento",
    "pagamenti",
    "bank transfer",
    "bank transfers",
    "wire transfer",
    "wire transfers",
    "sepa transfer",
    "sepa transfers",
    "bonifico",
    "bonifici",
    "top up",
    "top ups",
    "recharge",
    "recharges",
    "ricarica",
    "ricariche",
    "order",
    "orders",
    "ordine",
    "ordini",
    "purchase",
    "purchases",
    "acquisto",
    "acquisti",
    "booking",
    "bookings",
    "reservation",
    "reservations",
    "prenotazione",
    "prenotazioni",
    "university fee",
    "university fees",
    "tuition",
    "tassa universitaria",
    "tasse universitarie",
)

_TRANSACTION_COMPLETION_TERMS = (
    "receipt",
    "receipts",
    "received",
    "processed",
    "paid",
    "completed",
    "confirmed",
    "confirmation",
    "ricevuta",
    "ricevute",
    "ricevuto",
    "ricevuti",
    "processato",
    "processata",
    "processati",
    "processate",
    "elaborato",
    "elaborata",
    "elaborati",
    "elaborate",
    "pagato",
    "pagata",
    "pagati",
    "pagate",
    "completato",
    "completata",
    "completati",
    "completate",
    "confermato",
    "confermata",
    "confermati",
    "confermate",
    "eseguito",
    "eseguita",
    "eseguiti",
    "eseguite",
    "effettuato",
    "effettuata",
    "effettuati",
    "effettuate",
)

_TRANSACTION_SUCCESS_TERMS = (
    "successful",
    "successfully",
    "succeeded",
    "riuscito",
    "riuscita",
    "riusciti",
    "riuscite",
)

_CREDENTIAL_CONTEXT_TERMS = (
    "password",
    "passwords",
    "passcode",
    "passcodes",
    "credential",
    "credentials",
    "credenziale",
    "credenziali",
    "recovery email",
    "recovery phone",
    "email di recupero",
    "telefono di recupero",
    "numero di recupero",
    "two factor authentication",
    "2fa",
    "mfa",
    "autenticazione a due fattori",
    "verifica in due passaggi",
)

_SECURITY_STATE_CHANGE_TERMS = (
    "changed",
    "updated",
    "reset",
    "disabled",
    "removed",
    "revoked",
    "change complete",
    "reset complete",
    "cambiata",
    "cambiato",
    "modificata",
    "modificato",
    "aggiornata",
    "aggiornato",
    "reimpostata",
    "reimpostato",
    "disabilitata",
    "disabilitato",
    "rimossa",
    "rimosso",
    "revocata",
    "revocato",
    "modifica completata",
    "reimpostazione completata",
)

_SECURITY_PAIR_CONNECTORS = frozenset(
    {
        "a",
        "an",
        "the",
        "your",
        "account",
        "for",
        "has",
        "have",
        "had",
        "is",
        "was",
        "were",
        "been",
        "my",
        "our",
        "il",
        "lo",
        "la",
        "i",
        "gli",
        "le",
        "tua",
        "tuo",
        "sua",
        "suo",
        "del",
        "della",
        "account",
        "e",
        "è",
        "stata",
        "stato",
        "sono",
        "state",
        "stati",
    }
)

_ACCESS_EVENT_CONTEXT_TERMS = (
    "login",
    "log in",
    "sign in",
    "signin",
    "accesso",
    "account access",
    "access to your account",
    "your account",
    "tuo account",
)

_ACCESS_EVENT_SIGNAL_TERMS = (
    "noticed",
    "detected",
    "accessed",
    "new device",
    "new location",
    "unusual location",
    "rilevato",
    "rilevata",
    "notato",
    "notata",
    "nuovo dispositivo",
    "nuova posizione",
    "posizione insolita",
)

_WORD = re.compile(r"[^\W_]+", re.UNICODE)


def _tokenize(value: str) -> tuple[str, ...]:
    # Treat punctuation and hyphens as separators, so top-up and top up share the
    # same representation without broad substring matches.
    return tuple(_WORD.findall(value.casefold()))


def _phrase_spans(
    tokens: tuple[str, ...],
    phrases: tuple[str, ...],
) -> tuple[tuple[int, int], ...]:
    spans: list[tuple[int, int]] = []
    for phrase in phrases:
        phrase_tokens = _tokenize(phrase)
        width = len(phrase_tokens)
        for start in range(0, len(tokens) - width + 1):
            if tokens[start : start + width] == phrase_tokens:
                spans.append((start, start + width))
    return tuple(spans)


def _nearby(
    left: tuple[int, int],
    right: tuple[int, int],
    *,
    maximum_gap: int = 6,
) -> bool:
    if left[1] <= right[0]:
        return right[0] - left[1] <= maximum_gap
    if right[1] <= left[0]:
        return left[0] - right[1] <= maximum_gap
    return True


def _has_transaction_completion_pair(text: str) -> bool:
    tokens = _tokenize(text)
    contexts = _phrase_spans(tokens, _TRANSACTION_CONTEXT_TERMS)
    if not contexts:
        return False
    completions = _phrase_spans(tokens, _TRANSACTION_COMPLETION_TERMS)
    if any(_nearby(context, completion) for context in contexts for completion in completions):
        return True

    # Success adjectives are intentionally directional.  This accepts "payment
    # successful" but not generic copy such as "successful summer offers ...
    # payment plans".
    successes = _phrase_spans(tokens, _TRANSACTION_SUCCESS_TERMS)
    if any(
        context[1] <= success[0] and success[0] - context[1] <= 4
        for context in contexts
        for success in successes
    ):
        return True

    # "Purchase complete" is a common completed-state label.  Requiring the
    # context first avoids treating the call to action "complete your purchase"
    # as a durable record.
    complete_states = _phrase_spans(tokens, ("complete", "completo", "completa"))
    return any(
        context[1] <= complete[0] and complete[0] - context[1] <= 3
        for context in contexts
        for complete in complete_states
    )


def _has_credential_state_change(text: str) -> bool:
    tokens = _tokenize(text)
    contexts = _phrase_spans(tokens, _CREDENTIAL_CONTEXT_TERMS)
    changes = _phrase_spans(tokens, _SECURITY_STATE_CHANGE_TERMS)
    for context in contexts:
        for change in changes:
            if context[1] <= change[0]:
                between = tokens[context[1] : change[0]]
            elif change[1] <= context[0]:
                between = tokens[change[1] : context[0]]
            else:
                between = ()
            if len(between) <= 4 and all(
                token in _SECURITY_PAIR_CONNECTORS for token in between
            ):
                return True
    return False


def _has_routine_access_event(text: str) -> bool:
    tokens = _tokenize(text)
    contexts = _phrase_spans(tokens, _ACCESS_EVENT_CONTEXT_TERMS)
    signals = _phrase_spans(tokens, _ACCESS_EVENT_SIGNAL_TERMS)
    return any(_nearby(context, signal, maximum_gap=6) for context in contexts for signal in signals)


def _message_text(message: EmailRecord) -> str:
    return "\n".join((message.sender, message.subject, message.body_text)).casefold()


def access_alert_kind(message: EmailRecord) -> AccessAlertKind | None:
    text = _message_text(message)
    if any(term in text for term in _HIGH_RISK_ACCESS_TERMS) or _has_credential_state_change(text):
        return AccessAlertKind.HIGH_RISK
    if any(term in text for term in _ROUTINE_ACCESS_TERMS) or _has_routine_access_event(text):
        return AccessAlertKind.ROUTINE
    return None


def has_banking_context(message: EmailRecord) -> bool:
    text = _message_text(message)
    return any(term in text for term in _BANKING_CONTEXT_TERMS)


def has_banking_record(message: EmailRecord) -> bool:
    text = _message_text(message)
    return any(term in text for term in _BANKING_RECORD_TERMS)


def has_permanent_transaction_record(message: EmailRecord) -> bool:
    text = _message_text(message)
    service_confirmation = any(
        any(subject in text for subject in subjects)
        and any(status in text for status in statuses)
        for subjects, statuses in _SERVICE_CONFIRMATION_PAIRS
    )
    return (
        has_banking_record(message)
        or any(term in text for term in (*_GENERAL_RECORD_TERMS, *_INVOICE_RECORD_TERMS))
        or service_confirmation
        or _has_transaction_completion_pair(text)
    )
