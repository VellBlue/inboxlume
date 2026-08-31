# Temporal preference drift

InboxLume's `preference-drift-v1` compares timestamped local preference evidence
across two windows for each account, model-policy profile, and semantic family:

- **recent:** the last 45 days;
- **historical:** the preceding period, up to 180 days from the present.

This first component belongs to the Safety Governor. It is deliberately narrower
than the future Preference Weather system: it detects material changes in observed
preference evidence, but does not yet create multiple personal regimes or predict
future interest.

## Evidence and weighting

The report uses only events already recorded locally for messages known to
InboxLume. It assigns different strengths to different observations:

| Signal | Positive weight | Negative weight |
|---|---:|---:|
| Opened | 1 | 0 |
| Starred / marked important | 3 | 0 |
| Restored after InboxLume cleanup | 5 | 0 |
| Quiz `Keep` | 4 | 0 |
| Quiz `Don't keep` | 0 | 3 |
| Left unread | 0 | 0.15 |

Opening is therefore weak; restore and explicit correction are durable protective
evidence. A smoothed interest score is calculated independently in both windows:

`score = (2 + positive_weight) / (4 + positive_weight + negative_weight)`.

Comparison requires at least five distinct messages and eight units of effective
weight in each window. A protective shift needs a score increase of at least 0.20
and at least two recent protective events. Conflicting recent explicit signals are
also protective. A decline is reported only and never unlocks more cleanup.

## Operational effect

When the Governor is off, drift is informative and the ordinary filter is
unchanged. When the Governor is operational:

- a qualifying protective shift restricts only the affected family in governed
  Quarantine;
- it removes the Governor's additional Direct Trash authority for that family;
- ordinary Direct Trash retains its independent model, calibration, policy, and
  confirmation safeguards, as previously specified;
- stable, weak, declining, or insufficient evidence never broadens authority.

The report cannot permanently delete email, empty Trash, restore messages, or
retroactively move anything.

## Privacy and legacy evidence

No mailbox is queried, no body is reopened, and no model is loaded to compute the
report. The database contains HMAC-linked message identities, semantic category,
event type, timestamps, and aggregate counts—not subject, body, sender, or provider
message ID.

New quiz answers receive an explicit timestamp. Older local answers created before
this schema change have no answer time; InboxLume transparently marks them as
legacy approximations and uses the known scan time. They may contribute to initial
windows, but the interface remains conservative while evidence is insufficient.

Gmail can currently contribute openings, stars, importance changes, restores, and
quiz answers already observed by InboxLume. Yahoo contributes restores and quiz
answers; ordinary Yahoo read/unread changes are not yet imported as behavioural
evidence. This limitation is shown here rather than silently treating missing
provider signals as negative interest.
