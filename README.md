# InboxLume

> **Private AI for a cleaner inbox.** English is the primary project language;
> the [Italian README](README.it.md) is written as a native Italian document,
> not generated as a word-for-word translation.

> [!IMPORTANT]
> InboxLume is a public development project. There is no supported packaged
> release yet; the fail-closed release gate continues to prevent accidental
> binary or package publication.

InboxLume is a free, local-first email maintenance agent for Gmail and Yahoo.
It uses a local language model to understand the content of each Inbox message,
private account-specific feedback, and deterministic guardrails to suggest or
apply reversible cleanup. Email content is never sent to an external AI service.

English and Italian messages are evaluated together in the same batch. The UI
language is only a presentation preference: it never restricts the languages
that the classifier accepts. Mixed-language messages are supported as well.

## Safety boundaries

- Inbox only; Sent, Drafts, account settings, and SMTP are outside the domain.
- No permanent-delete, empty-trash, untrash, or IMAP `EXPUNGE` capability.
- Quarantine is the default and recommended destination.
- A message whose sender address exactly matches one of its recipient addresses
  is deterministically kept; the model cannot override this self-sent safeguard.
- Receipts and confirmations of financial/service operations are always kept,
  regardless of age, read state, sender, model category, or Governor state.
- Unread login alerts and suspicious/unrecognised access alerts are kept. Only a
  routine login notice that was read at least 90 days ago may become a reversible
  cleanup candidate.
- The model receives sanitised text in memory, not credentials or mailbox tools.
- Every account has isolated credentials, preferences, HMAC history, quiz data,
  destination, model profile, and schedule.
- Models run only during an active one-shot session and are unloaded afterwards;
  no AI process needs to remain resident. A session can use a bounded batch or
  continue in safe internal batches until no eligible, unprocessed email remains.

These are capability boundaries in the implementation, not claims of perfect
security. See the [threat model](SECURITY.md) and
[permission inventory](docs/PERMISSIONS.md).

## Current development state

The working foundation includes multiple Gmail and Yahoo accounts, a calibration
quiz, one-shot scans, reversible quarantine, optional protected Trash routing,
native per-account scheduling, and three controlled local-model profiles. If the
user restores a message previously moved by InboxLume, the next scan records that
correction locally as an HMAC-only signal: Gmail uses label history, while Yahoo
reconciles only new Inbox UIDs and the `Message-ID` header. No body is read for
this check.

The [Personal Safety Governor](docs/SAFETY_GOVERNOR.md) reports conservative
false-cleanup evidence per account, model, and message family. Its optional
operational layer is adaptive: missing evidence leaves the ordinary filter
unchanged, while concrete repeated-error evidence can restrict only the affected
family. The ordinary Direct Trash preference remains independent and keeps its
existing model, calibration, policy and confirmation safeguards. The Governor
itself gains Direct Trash authority only for a supported model when both the
overall and family envelopes have at least 299 conclusive reviews and zero `Keep`
corrections. It never authorises permanent deletion or emptying Trash.

Its first [versioned local backtest](docs/SAFETY_BACKTEST.md) records only changed
aggregate evidence snapshots and flags new protective corrections without
reopening messages or authorising mailbox actions.

The [local scan-duration estimate](docs/SCAN_DURATION_ESTIMATE.md) counts only
eligible, unprocessed IDs and reports a conservative interval before loading the
model. Matching completed runs improve the estimate using aggregate local timing;
no subject, body, provider ID, or plaintext hardware description is stored.

The first [temporal preference-drift](docs/TEMPORAL_DRIFT.md) component compares
recent and historical timestamped evidence per family. Repeated protective change
can only narrow an operational Governor; declining interest never unlocks more
cleanup. It uses the local ledger without reopening the mailbox or loading a model.

The first final-form component of [local phishing, scam, and fraud detection](docs/THREAT_DETECTION.md)
extracts controlled sender, authentication, Unicode, link, and social-engineering
signals without network lookups. It is protective-only and cannot authorise cleanup.
High-risk messages receive a visible, additive marker: Gmail adds the
`InboxLume/Sospetto phishing` label while preserving `INBOX` and all other labels;
Yahoo adds only the IMAP `\Flagged` flag while preserving Inbox and every existing
flag. Yahoo displays this as a star, which is not exclusive to InboxLume. Neither
provider uses a phishing move, the ordinary Quarantine, or Trash, and the marker
cannot authorise cleanup.

[LumeGraph](docs/LUMEGRAPH.md) builds a private temporal utility graph for OTP,
offers, orders, shipments, reservations, invoices, payments, and security flows.
The operational [Proof of Obsolescence](docs/PROOF_OF_OBSOLESCENCE.md) layer can
use a verified closure witness to promote Review to reversible Quarantine. It can
never promote directly to Trash, override deterministic Keep, permanently delete,
or empty Trash.

The controlled profiles are:

| Profile | Recommended RAM | Maximum destination |
|---|---:|---|
| Qwen 8B Lightweight | 12 GB | Quarantine only |
| Gemma 12B Balanced | 16 GB | Quarantine only |
| Gemma 26B-A4B Recommended | 24 GB | Trash only after calibration |

The older working macOS prototype remains available and is not overwritten by
the cross-platform Qt/PySide6 application.

## Run the cross-platform preview

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[desktop]'
inboxlume-desktop
```

On Windows, activate the environment with `.venv\Scripts\activate`. PySide6
wheels include Qt; a separate system Qt installation is not required.

Clean installations start in English. Existing Italian-only settings migrate to
Italian automatically. Choose **Language** in the sidebar and restart InboxLume
to change the interface language. No account rule or email data is changed by
this preference.

## Account setup

Credentials never enter the preferences file. InboxLume uses the operating
system's protected credential manager: Keychain on macOS, Credential Manager on
Windows, and an available Secret Service/KWallet backend on Linux. It refuses to
store credentials if no secure backend is available.

- Gmail uses a user-created Google OAuth **Desktop application**. Read-only Inbox
  access is authorised first; protected actions require separate authorisation.
- Yahoo uses an app password, never the account's primary password.
- Connection probes read no message body. Disconnect removes only local
  credentials for the selected account and never changes email.

See [Gmail setup](docs/GMAIL_SETUP.md), [Yahoo setup](docs/YAHOO_SETUP.md), and
[installation](docs/INSTALLATION.md).

## Calibration and classification

The onboarding quiz is strongly recommended for every account. The current
initial target is 40 diverse answers, including at least 3 **Keep** and 20
**Don't keep** examples. This is onboarding evidence, not a safety certificate.
Deterministic protected categories and abstention remain active without it, and
Direct Trash stays locked until its ordinary model and calibration requirements
are met; enabling the Governor does not change those requirements.

The model judges each message's specific content. Sender and broad category alone
never decide cleanup. A bank can send both a necessary statement and an irrelevant
promotion; two messages from the same sender may therefore receive different
outcomes. Strong similarity to a confirmed example can influence a suggestion,
while conflicts force review.

## Documentation

- [Project site](https://VellBlue.github.io/inboxlume/) · [Italian site](https://VellBlue.github.io/inboxlume/it/)
- [Technical article](https://vellblue.github.io/inboxlume/article.html) · [Italian article](https://vellblue.github.io/inboxlume/it/article.html) · [Markdown sources](docs/ARTICLE.md)
- [Engineering log](docs/engineering-log.html) · [Italian engineering log](docs/it/engineering-log.html)
- [Installation and compatibility](docs/INSTALLATION.md)
- [Local model profiles](docs/LOCAL_MODELS.md)
- [Native scheduling](docs/SCHEDULING.md)
- [Repository privacy rules](docs/REPOSITORY_PRIVACY.md)
- [Roadmap](docs/ROADMAP.md) and [sanitised product memory](docs/PRODUCT_MEMORY.md)
- [Publication checklist](docs/RELEASE_CHECKLIST.md)

## Development checks

```bash
PYTHONPATH=src python3 -m unittest discover -s tests
python3 scripts/audit_repository_privacy.py
python3 scripts/check_release_gate.py
```

The repository privacy audit rejects likely personal credentials, email
addresses, mailbox exports, state databases, and local settings. CI is prepared
for macOS, Windows, and Linux. Packaging is local and unsigned until the release
gate is deliberately opened.

## Open-source status

InboxLume source code and project documentation are licensed under the
[Apache License 2.0](LICENSE). Model weights, third-party dependencies, and user
data retain their own terms. The public repository is a development snapshot,
not a supported binary release; packaging, signing, and release gates remain
separate.

Contributions are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md).
