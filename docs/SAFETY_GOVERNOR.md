# Personal Safety Governor — operational capability gate

InboxLume's Safety Governor measures local evidence without making the classifier
more aggressive. The GUI reports one envelope per account and model scan profile;
an explicit per-account option can use that evidence as an adaptive capability
layer.

## Evidence boundary

The Governor joins local HMAC-keyed evidence:

- Quarantine suggestions recorded by completed scans;
- later quiz answers for the same opaque message hashes;
- restores to Inbox observed only for messages previously moved by InboxLume.

It reads aggregate category/answer counts only. It does not reconnect to the
mailbox, read a message body, recover an address or store plaintext. Accounts and
model-policy profiles remain isolated.

Gmail restore detection uses label history. Yahoo establishes a UID baseline and
then reads only the `Message-ID` header for newly present Inbox UIDs; it neither
opens Trash/Quarantine nor reads a body. An HMAC match to an earlier successful
InboxLume action is required. A first run or changed Yahoo UIDVALIDITY resets the
baseline without making an inference.

`Keep` on a Quarantine suggestion is counted as a false-cleanup observation;
restoring that suggestion has the same protective meaning. `Don't keep` is a
confirmation. `Not sure` is reported but excluded from the
binomial estimate, and unreviewed proposals remain visible as missing evidence.

## Conservative bound

The displayed number is an exact one-sided 95% Clopper–Pearson upper bound for the
false-cleanup rate, not an LLM confidence score. With zero observed errors it
reduces to:

```text
p_upper = 1 - 0.05^(1/n)
```

Forty comparable error-free reviews still produce an upper bound of about 7.2%.
Approximately 299 are required to move below the current 1% research target under
the same assumptions.

The states are deliberately narrow:

- `collecting`: fewer than 40 conclusive matched reviews;
- `not qualified`: enough reviews exist, but the upper bound exceeds the target;
- `qualified shadow`: the statistical shadow threshold is met.

The evidence report itself keeps `authorizes_actions = false`: statistics are not
a mailbox capability. The separate operational layer intersects the existing safe
policy without replacing it. Insufficient evidence leaves the ordinary filter
unchanged. A semantic family is restricted only after at least 20 conclusive
reviews, at least three `Keep` corrections, and a one-sided 95% lower bound above
the 1% error target. This is family-specific: evidence in one family never blocks
another. Additional correct confirmations can lower the bound and release the
restriction automatically.

The layer is opt-in and isolated per account and model. Its operational control
remains disabled until that account/model envelope contains at least 40
conclusive reviews; the backend enforces the same prerequisite, so a stale or
manually edited preference cannot bypass it. Adaptive Quarantine and
Governor authority over Direct Trash are separate capabilities. The ordinary
Direct Trash preference remains independent: with the Governor disabled,
or enabled but not qualified for Trash, it continues under its own model,
calibration, policy and confirmation safeguards. The Governor itself gains Direct
Trash authority only with a supported model, at least 299 conclusive reviews in
both envelopes, and exactly zero `Keep` corrections in both. A later `Keep`
correction revokes that Governor authority without disabling ordinary Direct
Trash. Unqualified families receive no Governor authority even if another family
has enough evidence.

Direct Trash means moving a message to the provider's ordinary Trash. The gate
cannot permanently delete a message or empty Trash, and it does not retroactively
move or restore messages. The first [temporal drift](TEMPORAL_DRIFT.md) component
can only narrow governed authority for a changed family. Counterfactual policy
perturbations remain a later milestone.

## Limitations

Quiz examples are not necessarily independent or representative. User interests,
mail campaigns and model behaviour drift over time. The bound therefore describes
the observed local sample under explicit assumptions; it is not a guarantee of
future correctness or “100% safety”. Rare and costly message families still need
abstention and deterministic guardrails.
