# LumeGraph: private temporal utility graph

Status: the complete graph core is operational. Graph observations alone have no
authority; only the separate, deterministic Proof of Obsolescence gate can promote
an eligible Review to reversible Quarantine.

## What it models

An ordinary category describes what an email resembles. LumeGraph separately
describes what the message is still useful for. The first engine recognises these
local lifecycle families in English, Italian, and mixed-language inboxes:

- one-time codes;
- orders and shipments;
- reservations and travel/event changes;
- invoices and payment/transaction receipts;
- password-reset and account-recovery flows.
- explicitly dated advertising offers.

Each node contains only controlled fields:

- lifecycle state: `active`, `pending`, `completed`, `replaced`, `expired`, or
  `uncertain`;
- independent operational, evidentiary, personal, and security utility flags;
- a relative date relation and a coarse received-week bucket, never an exact
  persisted date;
- a controlled remaining condition: user action, external action, time bound,
  completed, none, or uncertain;
- a bucketed confidence and allow-listed reason codes.

This distinction is deliberate. A payment receipt can have no remaining operational
task and still retain evidentiary value. LumeGraph records that value; it does not
turn `completed` into permission to clean up.

## Linking without retaining references

Order, tracking, booking, invoice, and transaction references exist only briefly in
memory. InboxLume derives an account-scoped HMAC and persists the HMAC, not the
reference. A message may carry several HMAC relations, allowing a chain such as
order → shipment → delivery to be connected even when the sender changes.

The SQLite ledger stores no sender, subject, body, provider message ID, extracted
code, order number, booking reference, or exact date. Accounts and model-policy
profiles remain isolated. No relation is created across accounts.

## Two independent inferences

The operational email classification is unchanged. For plausible lifecycle
messages, the already-loaded local model performs a second, schema-constrained
inference. This prevents a lifecycle experiment from changing the classification
that feeds the existing policy. A deterministic conservative fallback records an
`uncertain` or explicit state if lifecycle extraction fails.

The second inference reuses the sanitized body already present in memory. It does
not make another mailbox request. Ollama is restricted to loopback; Gemma uses the
offline MLX worker; the model is unloaded after the one-shot batch.

## Operational boundary

Every LumeGraph result reports:

```text
shadow_only = false
authorizes_policy = verified_closure_witness_exists
authorizes_actions = reversible_quarantine_only
changes_mailbox = false
```

Failure of LumeGraph cannot interrupt or broaden the ordinary filter. The GUI shows
aggregate node, transition, and closure-witness counts only. The operational
contract and protected utility classes are specified in
[PROOF_OF_OBSOLESCENCE.md](PROOF_OF_OBSOLESCENCE.md). Permanent deletion and
emptying Trash remain unavailable.

## Duration estimates

Reference estimates include the expected extra local inference for the observed
lifecycle fraction. Once matching local sessions exist, their end-to-end aggregate
timings already include LumeGraph and replace the reference adjustment. No message
content is stored as timing telemetry.
