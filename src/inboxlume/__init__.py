"""InboxLume: classificazione locale con attuazione separata."""

from .models import (
    Classification,
    EmailCategory,
    EmailRecord,
    PolicyAction,
    PolicyDecision,
    RetentionSignal,
)

__all__ = [
    "Classification",
    "EmailCategory",
    "EmailRecord",
    "PolicyAction",
    "PolicyDecision",
    "RetentionSignal",
]
