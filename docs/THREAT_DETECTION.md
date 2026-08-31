# Local phishing, scam, and fraud detection

Status: deterministic screening, targeted independent local-model analysis, the
protective policy gate, additive visible markers, and private persistence are
implemented in final form.

`threat-signals-v1` extracts controlled evidence locally and performs no network
lookup. It covers sender/reply-domain inconsistencies, claimed-brand/domain
mismatches, Punycode, mixed Latin/Cyrillic/Greek identities, bidirectional control
characters, IP-literal or Punycode links, trusted SPF/DKIM/DMARC failures, urgent
credential requests, unusual money requests, and courier-fee lures.

The engine does not treat spelling or poor grammar alone as fraud: that would
unfairly penalise legitimate multilingual and non-native writing. It rewards
agreement between independent identity, authentication, link, Unicode, and content
families. Its report contains only controlled reason codes, score, level, and
families—never sender, domain, URL, subject, or body.

`Authentication-Results` is ignored unless a provider adapter explicitly marks it
trusted. This follows [RFC 8601](https://www.rfc-editor.org/rfc/rfc8601.html), which
warns that mere header presence does not establish validity. Domain alignment is
modelled according to [DMARC RFC 7489](https://www.rfc-editor.org/rfc/rfc7489.html).
Unicode anomaly handling follows the concepts in
[Unicode UTS #39](https://www.unicode.org/reports/tr39/).

The detection policy itself has no generic mailbox authority: it cannot delete,
quarantine, mark spam, or choose a cleanup action. Its role is strictly protective:
`high` or `critical` evidence changes an ordinary cleanup candidate to Review.
When protected actions have been separately authorised, a constrained executor may
then add only the provider-specific visible marker described below. It does not
move the message or remove existing mailbox state. An existing Keep is never
weakened.

## Independent semantic analysis

Gemma 12B/26B through the offline MLX worker and Qwen through loopback-only Ollama
expose the same strict semantic-threat contract. The user may choose **technical
screening only** for the fastest scan, or **targeted local AI**. In targeted mode a
second tool-free inference runs only after the technical layer has found at least
one warning signal—not for every message. It returns an allow-listed verdict,
intent, six boolean observations, confidence, and one to five controlled reason
codes. The model is explicitly told not to perform sender, DNS, link, reputation,
or authentication verification and does not receive the deterministic score,
preserving independence between evidence families.

The consensus combiner has asymmetric safety behavior:

- model evidence alone is capped below `high`;
- a high-confidence malicious semantic judgment plus at least one independent
  deterministic family can reach `high` or `critical`;
- a benign model judgment never subtracts deterministic evidence;
- every output remains protective-only and has `authorizes_cleanup = false`.

## Operational gate and private ledger

The threat gate runs before LumeGraph and Proof of Obsolescence. A protected Review
cannot be promoted by Proof, recovered from an earlier batch, moved to direct
Trash, or finalised from Quarantine. Semantic-model failure falls back to the
deterministic evidence and never interrupts ordinary filtering.

The per-account, per-model-profile ledger contains only an HMAC message key,
controlled enum values, a coarse score bucket, reason-code sets, and aggregate
counts. It stores no sender, provider ID, domain, URL, subject, body, or exact
score. It has no cleanup authority.

The bilingual GUI exposes aggregate assessments, protected high-risk messages,
targeted semantic follow-ups, technical-clear messages skipped, fallbacks, and the
private ledger total. The duration estimator accounts for the selected mode and
versions timing samples so measurements from a different pipeline cannot silently
underestimate the current one.

## Visible protective marker

When protected actions are authorised, a `high` or `critical` assessment receives
a provider-native, additive visible marker—never the ordinary Quarantine or Trash.
Gmail adds the user label `InboxLume/Sospetto phishing` without removing `INBOX` or
any other label. Yahoo adds only the IMAP `\Flagged` flag without using `MOVE` and
without removing Inbox or any existing flag. Yahoo displays `\Flagged` as a star,
which is not an InboxLume-exclusive marker. Neither operation can delete, empty
Trash, mark spam, act on Sent mail, or grant cleanup authority. Marker failures
are isolated from ordinary filtering and reported only as aggregate counts.

Personal sender baselines remain a subsequent increment.
