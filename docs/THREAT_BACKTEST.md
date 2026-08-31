# Synthetic local threat backtest

Status: the versioned corpus, aggregate evaluation engine, isolated desktop worker,
and bilingual GUI integration are implemented.

`synthetic-threat-corpus-v1` is packaged with InboxLume and contains 25 wholly
synthetic English, Italian, and mixed-language cases. It covers credential lures,
brand impersonation, delivery-fee scams, financial fraud, Unicode deception,
malware lures, and hard benign negatives such as requested password resets,
security notices, receipts, deliveries, school messages, newsletters, and
non-native writing.

The backtest never connects to Gmail or Yahoo. It processes the packaged cases in
memory with the same deterministic engine, local semantic analyzer, and consensus
combiner used by a scan. Output contains only aggregate confusion counts, metrics
by controlled language/scenario vocabulary, model-failure count, and a SHA-256
corpus fingerprint. It contains no case text or message identity.

The preliminary diagnostic target requires at least 20 balanced cases, local
semantic analysis, precision of at least 0.90, recall of at least 0.80, observed
false-positive rate no greater than 0.05, and zero model failures. The report also
shows the 95% Wilson upper bound for benign false positives. Passing this small
synthetic diagnostic is not statistical proof of production safety and never
authorises mailbox actions.

The Threat Protection card runs the diagnostic with the currently selected local
model in a separate process. It displays aggregate precision, recall, benign false
positives, their 95% upper bound, and model failures. The interface remains
responsive, offers Stop, never requests email authentication, and unloads the
model when the run ends.
