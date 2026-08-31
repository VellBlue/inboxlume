# Versioned local safety backtest

InboxLume's first Safety Lab component replays the outcomes already recorded for
automatic cleanup proposals. It does not reconnect to the mailbox, reopen a
message, load a model or authorise an action.

## Versioned snapshot

Each snapshot is isolated by account, model-policy scan profile and backtest
engine version. Version `historical-v1` records only aggregate counts for each
semantic family:

- confirmed `Don't keep` outcomes;
- protective `Keep` or restore corrections;
- inconclusive answers;
- proposals that have not been reviewed.

The input receives a deterministic SHA-256 fingerprint. A repeated run with the
same evidence does not create a duplicate. If the evidence changes and later
returns to an earlier state, the return is recorded as a new chronological
snapshot. No subject, body, address, provider message ID or reversible identity
is stored by the backtest.

## Comparison

The current snapshot is compared with the immediately preceding snapshot for the
same account, profile and engine version:

- `baseline`: first usable snapshot;
- `unchanged`: the aggregate evidence is identical;
- `stable`: evidence changed without a new protective correction;
- `improved_evidence`: the conservative upper bound fell or an error was removed;
- `protective_regression`: one or more new `Keep`/restore corrections appeared,
  with the affected families reported separately.

The statistical envelope remains the exact one-sided 95% binomial bound used by
the Safety Governor. A backtest report always has `authorizes_actions = false`.
It cannot change Governor settings, move email, empty Trash or weaken a guardrail.

Recommended timing is after at least 40 conclusive reviews and before enabling
the operational Governor. Run it again after new corrections, observed restores,
or a model/policy profile change. An earlier run is allowed, but it creates only a
preliminary baseline with limited evidence.

## Current boundary

This first version is a historical replay of recorded cleanup proposals. It does
not yet reclassify stored email—InboxLume intentionally stores no email text—and
does not generate counterfactual message variants. Temporal drift windows,
fragility tests and release-to-release policy comparisons are subsequent Safety
Lab components.
