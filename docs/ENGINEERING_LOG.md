# What we found when we ran it

> Engineering log, 31 August 2026. Development status: this records observations
> from a development repository, not from a release.
> [Leggi la versione italiana](it/ENGINEERING_LOG.md) ·
> [Back to the main article](ARTICLE.md).

Design documents describe what a system is supposed to do. This one records what
happened the first time InboxLume met a real local model, a real IMAP server and a
real Mac, on the same day. Every number below comes from a run recorded in this
repository, and the safety diagnostic that produced the first of them can be
re-run by any reader without connecting an email account.

The entries are not curiosities. Each one is a class of failure that a design
document cannot catch, because in every case the code was doing exactly what it
had been written to do.

## 1. The model was right, and the answer was thrown away

The synthetic threat backtest was run for the first time against a real local
model rather than a test double: Gemma 12B through MLX on Apple Silicon, over the
25 packaged cases, with no account and no network.

The report came back with **14 model failures out of 25 cases** — and the 14
contained **all 12 malicious cases**.

The model was not confused. Reading its raw output, it identified the phishing
correctly, with the right intent and the right reason codes. It answered:

```json
{ "verdict": "likely_phishing", "intent": "credential_theft", "confidence": 5 }
```

The parser requires a confidence between 0 and 1. The model had answered on a
one-to-five scale. Some cases also returned `"impersonation": "none"` where a JSON
boolean was required. The prompt asked for a field called `confidence` and never
said what a confidence was. The classification prompt, written earlier, did say
`number 0..1` — and it was the only one of the three that did not fail.

Every rejected answer was replaced by an "uncertain" verdict. The consequence is
worth stating plainly: **threat protection was running on deterministic lexical
signals alone, on precisely the messages it exists for.** The subsystem was not
switched off. It was being asked a question and then ignored.

The fix is one paragraph of prompt stating the contract the parser already
enforced. Model failures went from **14 to 0**.

The interesting part is what did not change. Precision and recall stayed at
**0.9167**, exactly where they had been. The deterministic layer had been carrying
the entire result on its own.

> A metric that does not move when a subsystem dies was never measuring that
> subsystem. An aggregate score can hide a component that has been silently
> disabled for its whole life.

The failure count is now a first-class field in the report, on equal footing with
precision and recall, because it is the field that reveals this condition.

## 2. A receipt that could not answer the only question that matters

When a scan is interrupted, the local record it leaves behind used to contain
`processed = 0` and `applied = 0`.

Those are also the values a run leaves when it fails before starting. The record
was therefore unable to distinguish a scan that never touched the mailbox from one
that stopped halfway through moving messages.

After a failure, the user's question is not "what was the error". It is **"did it
touch my mailbox?"** A default value answers that question wrongly while looking
like an answer.

The record now carries the phase actually reached, the count actually processed,
and an explicit mailbox outcome of `changed`, `unchanged`, or `unknown`, where
`unknown` means a mutation had already begun and the mailbox must be checked. A
real interrupted run now reads:

```json
{ "status": "failed", "phase": "classification", "processed": 0,
  "mailbox_outcome": "unchanged" }
```

That is provable. The mailbox was not touched, and the record says so.

The honest half of this entry is what we did not do. Records written before the
change cannot be upgraded. A completed one keeps a provable outcome, because its
counts were always real; a failed one reports that its outcome is not provable,
because it never was. Reconstructing a history that was not recorded would have
produced a more satisfying document and a less trustworthy one.

## 3. A test suite that was green and proved nothing

The review action, which lets a user re-examine what the system proposed, returned
**0 candidates** for a scan that had just moved 64 messages into the reversible
quarantine folder.

An IMAP move assigns the message a new UID in the destination folder, so the
identity recorded during the scan no longer matches anything the review can see.
The intended fallback was the UIDPLUS `COPYUID` pointer returned by `MOVE`.

That pointer never arrives. `imaplib.uid()` returns the untagged `FETCH`
responses; RFC 6851 places `COPYUID` in the tagged `OK` line; a `MOVE` produces no
`FETCH` at all. The table meant to hold those pointers was empty across **121 real
quarantine operations**.

The unit test passed throughout. Its fake client answered a move with:

```python
return "OK", [b"moved"]
```

A real server does not put `COPYUID` there, and the fake did not put anything
there either. The test asserted that the code handled a response shape the
protocol never produces in that position, so it could only ever pass.

> A fake that is simpler than the protocol tests your code against a server that
> does not exist. The greener the suite, the longer the gap survives.

The relocation now uses the RFC `Message-ID`, which survives the move and is
already stored only as an HMAC, never as header text. Measured against a real
mailbox holding 65 quarantined messages: **0** were findable by UID, **0** by
pointer, **65** by `Message-ID`, none unresolved. The dead pointer path has been
removed rather than left in place looking alive.

Removing it exposed a second defect that the first fix had introduced: the old
path also excluded proposals the user had already answered, and the new one did
not, because the check upstream used the post-move identity. Without that, a
proposal already judged would have been asked again. Replacing a mechanism means
inheriting every guarantee it quietly provided.

## 4. A capability the system refuses to have

Threat protection combines two independent layers: deterministic signals over
identity, links and authentication, and a semantic judgement from the local model.

The combination is **additive**. The semantic score is added to the deterministic
one and can never subtract from it. A benign verdict contributes zero.

This has a cost, and the cost is the point. A third protection level was added so
the local model is consulted only on messages the technical layer already reports
as an alert, instead of on every message carrying any anomaly. It spends far fewer
inferences and can strengthen a finding. **It cannot clear a false positive**, by
construction, and no configuration makes it able to.

The alternative — letting a language model withdraw a deterministic security
finding — would mean accepting a model's confidence as grounds to dismiss evidence
it cannot audit, on exactly the messages an attacker is trying to get through. A
test now blocks that change, so weakening it has to be a decision rather than a
refactor.

> Stating what a system is not allowed to do, and what that refusal costs, carries
> more weight than any claim about what it can do.

## 5. The Mac that was told it was not a Mac

The application reported *"MLX currently requires macOS on Apple Silicon"* on an
Apple Silicon Mac, and disabled its primary action. The status line read
`Detected system: Darwin x86_64`.

LaunchServices was starting the bundle translated under Rosetta. Every child
process inherits the translated architecture, MLX ships no x86_64 build, and so
all three local model profiles were reported unavailable on a machine that fully
supports them.

The bundle now declares `LSRequiresNativeExecution` and an architecture priority
with `arm64` first, so translation is refused at the origin rather than repaired
afterwards; a guard in the launcher remains as a backstop for an already
translated shell.

The message mattered as much as the bug. Blaming the hardware sends a user to
consider buying a different computer for what is a launch configuration problem.
The diagnosis now distinguishes a translated process from a genuinely unsupported
platform, and says which one it is.

> An error message is part of the safety surface. A confident, wrong explanation
> costs the user more than an honest "not determined".

## What a reader can check

The safety diagnostic is reproducible without an account, without network access
and without touching a mailbox:

```bash
python -m inboxlume.desktop_worker threat-backtest --backend gemma12
```

It evaluates the packaged `synthetic-threat-corpus-v1` in memory and emits
aggregate output only: confusion counts, metrics by controlled language and
scenario vocabulary, the model-failure count, and a SHA-256 fingerprint of the
corpus. It contains no case text and no message identity, and it never authorises
a mailbox action.

## What we still cannot claim

The current corpus is 25 cases. After the prompt fix the run reports precision
0.9167, recall 0.9167, zero model failures — and **still does not pass its own
diagnostic**, because one benign Italian message is flagged, giving an observed
false-positive rate of 0.0769 against a 0.05 target. One malicious Italian case is
still missed.

With this corpus the 95% upper bound on the benign false-positive rate is
**0.33**. A sample this small cannot certify anything, and the report prints that
bound next to the metrics so the number cannot be read as reassurance.

Beyond that: no packages have been built and exercised on the three declared
platforms, no licence has been selected, provider behaviour has been verified on a
single real account rather than a test matrix, and the release gate remains
closed. This log is evidence that the system is being measured, not evidence that
it is ready.

> The claim this project is willing to defend is narrow: every automatic action
> should be able to state what ended the message's usefulness, which
> account-specific evidence supports it, and which limited reversible capability
> authorised it. Everything above is the work of finding out where that claim is
> not yet true.
