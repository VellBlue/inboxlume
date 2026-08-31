# Proof of Obsolescence

Status: operational, local-only, and account/model isolated.

Proof of Obsolescence is the policy layer between LumeGraph observations and an
additional reversible cleanup proposal. A lifecycle label such as `completed` is
never sufficient. InboxLume requires a controlled **closure witness** and verifies
that no operational, evidentiary, personal, or security utility remains.

## Verified witnesses

The current engine supports five complementary forms of evidence:

1. a read one-time code is older than the account's configured OTP threshold and
   the deterministic lifecycle state is expired;
2. an advertising offer contains an unambiguous expiry date directly attached to
   bilingual expiry language, and that date has elapsed;
3. a later message with the same account-scoped HMAC tracking relation completes
   or replaces an earlier shipment state; this graph witness requires two
   high-confidence Gemma 26B lifecycle observations;
4. multiple highly similar messages were explicitly marked `Don't keep`, with no
   conflicting `Keep` example;
5. the local model, repeated corrections, and the current behavior regime agree
   independently that an advertising, social, or spam template has lost utility.

The similarity and behavior signals contain HMAC features and aggregate values,
not message text. The graph stores a week bucket for ordering, never the exact
received date. Equal-week successor relations are treated as ambiguous.

## Operational contract

- A verified proof may confirm an ordinary cleanup candidate.
- With **Quarantine** selected, it may promote `Review` to reversible Quarantine.
- With **Direct Trash** selected, it may support an email already selected by the
  ordinary policy, but it cannot promote `Review` directly to Trash.
- It cannot permanently delete mail, empty Trash, access Sent, or expand provider
  permissions.
- `Keep` from deterministic policy always wins.
- Absence of a proof is not evidence of absence: the proof layer abstains and the
  ordinary filter continues unchanged.

## Non-negotiable protected utility

Proof cannot authorise cleanup for self-sent mail, attachments requiring review,
known relationships, protected senders or keywords, banking records, transaction
receipts, payments, transfers, top-ups, university fees, high-risk access alerts,
or any message retaining evidentiary, personal, or security utility. Invoice,
payment, reservation, and security-flow graph nodes remain useful for protection
and context but never become proof-authorised cleanup in this engine.

## Private ledger and failure behavior

The SQLite ledger stores only account-scoped HMAC message/relation keys, controlled
enums, boolean utility flags, confidence buckets, allow-listed reason codes, and a
coarse received-week bucket. It stores no sender, subject, body, provider message
ID, extracted token, tracking number, or exact date.

Failures are isolated. If lifecycle extraction or proof persistence is unavailable,
the ordinary filter completes without graph-based promotion. The GUI reports only
aggregate witness counts.

