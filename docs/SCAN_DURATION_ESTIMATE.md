# Local scan-duration estimate

InboxLume can estimate a configured one-shot scan before loading the local model.
The command is explicit: it is never run automatically when the application opens.

## Privacy boundary

The estimator asks Gmail or Yahoo only for candidate message identifiers matching
the configured age rules. It removes identifiers already present in the local
HMAC-protected scan ledger, then discards the temporary identifiers. It does not:

- fetch a subject, sender, body, attachment, or sent message;
- load or download a model;
- move, relabel, delete, or permanently erase email;
- store provider identifiers or hardware details in plaintext.

Completed scans contribute only an aggregate pair: processed-message count and
elapsed seconds. Samples are isolated by account, model-policy profile, provider,
destination, Governor state, and a one-way hardware-profile key.

## Estimate and confidence

Before matching local samples exist, InboxLume starts from the preliminary cold
benchmark for the selected controlled model and adds conservative provider and
action overhead. It also accounts for LumeGraph's shorter second inference on the
locally observed fraction of lifecycle messages. This result is labelled **low
confidence** and uses a deliberately wide range.

For a matching completed session, its observed rate is

`r_i = elapsed_seconds_i / processed_messages_i`.

The central estimate uses the median matching rate. The interval expands to cover
the observed minimum and maximum rates with additional safety margins. Three or
more reasonably stable matching sessions raise the label to **high confidence**;
fewer or dispersed samples remain **medium confidence**. This is an operational
estimate, not a promised completion time: network latency, message size, thermal
state, and concurrent computer load can still change the result.
Matching end-to-end samples already include LumeGraph and are never adjusted a
second time.

With a finite per-session limit, counting stops at that limit. The interface says
that more eligible messages may remain. With **All eligible**, the ID count is
exhaustive and naturally ends when the provider has no further matching IDs.
