from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from inboxlume.models import EmailRecord, ProviderKind


def make_message(**overrides: Any) -> EmailRecord:
    values: dict[str, Any] = {
        "account_id": "gmail_personale",
        "provider": ProviderKind.GMAIL,
        "message_id": "message-1",
        "received_at": datetime(2026, 1, 1, tzinfo=timezone.utc),
        "unread": True,
        "sender": "Sender <sender@example.invalid>",
        "subject": "Oggetto",
        "body_text": "Corpo",
        "headers": {},
        "flags": frozenset(),
    }
    values.update(overrides)
    return EmailRecord(**values)

