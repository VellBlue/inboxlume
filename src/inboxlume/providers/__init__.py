from .contracts import (
    GMAIL_READONLY_SCOPE,
    INBOX_FOLDER,
    YAHOO_IMAP_HOST,
    YAHOO_IMAP_PORT,
    ReadOnlyCapability,
    ReadOnlyMailbox,
)
from .gmail import GmailReadOnlyMailbox
from .gmail_finalizer import GmailDirectTrashExecutor
from .google_oauth import (
    GoogleAccessTokenProvider,
    GoogleDesktopOAuthFlow,
    MacOSKeychainStore,
    OAuthClientCredentials,
    save_authorization,
)
from .yahoo import YahooImapCredentials, YahooReadOnlyMailbox
from .yahoo_quarantine import YahooDirectTrashExecutor, YahooQuarantineExecutor

__all__ = [
    "GMAIL_READONLY_SCOPE",
    "INBOX_FOLDER",
    "YAHOO_IMAP_HOST",
    "YAHOO_IMAP_PORT",
    "ReadOnlyCapability",
    "ReadOnlyMailbox",
    "GmailReadOnlyMailbox",
    "GmailDirectTrashExecutor",
    "GoogleAccessTokenProvider",
    "GoogleDesktopOAuthFlow",
    "MacOSKeychainStore",
    "OAuthClientCredentials",
    "save_authorization",
    "YahooImapCredentials",
    "YahooReadOnlyMailbox",
    "YahooDirectTrashExecutor",
    "YahooQuarantineExecutor",
]
