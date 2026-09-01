# InboxLume: maintaining a large inbox without handing it to another AI

> Public development article. It describes the current source snapshot, not a
> supported packaged release, and must continue to be updated against measured
> features and benchmarks. [Leggi la versione italiana](it/article.html).

> For measured results from real development runs, see the
> [engineering log](engineering-log.html).

An email account is more than a list of messages. It is a partial record of
purchases, relationships, access credentials, school, health, work, and changing
periods of a person's life. Once tens of thousands of messages make traditional
filters inadequate, the convenient answer is to send the archive to an AI
service. That also creates the harder question: how much private memory should be
transferred elsewhere merely to organise it?

InboxLume starts from a constraint rather than a product claim: **the model must
understand email without sending its content to an external AI service**. Gmail or
Yahoo still necessarily hosts and delivers the selected account's messages, but
inference, preference learning, and private state remain on the user's computer.
The program is not a general email client and not an assistant with access to the
whole machine. Its operational vocabulary is deliberately small and inspectable.

## Why sender rules are not enough

The sender does not determine a message's value. A bank may send both a necessary
statement and an irrelevant offer. A shop may send a generic promotion and a
receipt needed for a warranty. Read state is ambiguous too: an old unread message
may be noise, or important mail that was simply missed.

InboxLume therefore separates three layers:

1. a local model assesses the category and retention value of this particular
   message;
2. private memory compares the case with corrections and local behavioural
   signals for the same account;
3. a deterministic policy chooses protection, review, or a reversible cleanup
   destination.

The model does not control the mailbox. This distinction matters: a language model
can interpret context, but its confidence is not a guarantee, and the text of an
email can itself contain hostile instructions.

English and Italian email are processed together. A batch may contain either
language or mix both inside one message. Interface language never becomes a
classifier filter; the model produces the same language-independent schema for
every message.

## Capability separation

```text
Gmail / Yahoo
      |
      v
Inbox-only reader ----> sanitised text in memory
                                |
                                v
                         local AI model
                                |
                                v
                    deterministic decision engine
                                |
                     approved opaque message IDs
                                |
                                v
                         restricted executor
                       Quarantine or Trash
```

The reader holds only the credentials needed for the Inbox. The model process sees
message text, but no credentials and no email methods. The decision engine applies
protected categories, calibrated thresholds, and feedback. The executor receives
opaque IDs and an enumerated destination.

The most dangerous operations are not merely hidden behind a confirmation dialog:
they are absent from the operational interface. InboxLume implements no sending,
SMTP, drafts, Sent access, permanent delete, `EXPUNGE`, or empty-trash command.
Yahoo never falls back to `STORE \\Deleted`; Gmail transports are separated and
allowlisted.

This cannot make every bug or compromised operating system impossible. It makes
the authority smaller, testable, and easier to reason about than that of a general
email agent.

## Threat protection cannot authorise cleanup

Phishing and scam protection is a separate protective path, not another cleanup
classifier. A deterministic layer checks controlled evidence about identity,
authentication, links, Unicode anomalies, and suspicious requests. A second local
model pass is optional and targeted: in the recommended mode it runs only after
the technical layer has already raised an alert.

The combination is deliberately additive. A malicious semantic judgement may
strengthen independent technical evidence, but a benign model answer cannot erase
it. A high-risk result can force Review and add a visible provider-native marker —
the `InboxLume/Sospetto phishing` Gmail label or Yahoo's additive `\Flagged` flag —
while preserving Inbox and existing labels or flags. It can never authorise
Quarantine, Trash, or permanent deletion.

This boundary has been exercised against the packaged bilingual synthetic corpus.
The first real-model run also exposed a prompt/parser contract mismatch that an
aggregate precision score did not reveal; the measured failure and correction are
documented in the [engineering log](engineering-log.html#model).

## What “local” means here

The term *local AI* is often used without defining its boundary. In InboxLume it
means:

- content moves directly from the chosen email provider to the user's computer;
- it is not sent to model APIs, analytics, telemetry, or an InboxLume service;
- model weights are already in a local cache and are not downloaded during a scan;
- the model is loaded only for a quiz or batch and unloaded afterwards;
- learned preferences remain isolated per account;
- the database stores HMAC-derived identifiers and minimised features, not sender,
  subject, or body in plaintext.

It does not mean that Gmail or Yahoo ceases to host the email. Nor does local
execution automatically guarantee safety: runtime behaviour, loopback endpoints,
cache paths, and network capabilities must still be tested. A planned Verifiable
Locality layer will make those effective capabilities visible for each run.

## Operational evidence without reopening messages

The desktop interface now includes an account-scoped operational dashboard. It
reads the same private aggregate ledgers used by the safety components and shows,
for the selected account and model, completed analyses, actual reversible
Quarantine moves, suspicious messages protected, verified Proof of Obsolescence
witnesses, LumeGraph activity, and progress towards the Safety Governor evidence
threshold.

During a scan the dashboard identifies the live run and states explicitly whether
Threat Protection, the operational Governor, LumeGraph, and Proof of Obsolescence
are active. Locked selections retain a visible check mark, so disabled controls do
not become ambiguous grey squares. Refreshing these counts does not reopen a
message or expose provider identifiers or plaintext.

The panel intentionally does not invent statistical charts from cumulative
totals. A trend chart becomes meaningful only when comparable per-run or temporal
series are recorded; until then, precise counters and a real Governor threshold
communicate more than decorative curves.

## Learning without building another personal archive

The calibration quiz displays real messages only on the device and asks **Keep**,
**Don't keep**, or **Not sure**. The current onboarding target is forty diverse
examples, including at least three protected cases and twenty messages not worth
keeping. The required evidence does not grow linearly with mailbox size: sixty
thousand repetitive messages do not require sixty thousand labels, while a small
but heterogeneous mailbox may need broader coverage.

For similarity, InboxLume normalises content, extracts bounded features, and stores
account-keyed HMAC fingerprints. Strong similarity to a confirmed **Don't keep**
example may strengthen a suggestion. A similar **Keep** example or conflicting
evidence forces review. No sender becomes a global blacklist.

Recent opens are weak signals. They may protect a message or increase abstention,
but cannot authorise cleanup. A future research direction, Preference Weather,
would model separate time scales so a stable interest, a three-month project, and
a short-lived curiosity do not decay in the same way.

## The mathematics of abstention

Average accuracy is not the main safety metric for inbox maintenance. Error costs
are asymmetric: leaving an advertisement in the Inbox is cheap; moving an
important communication may be costly. More useful measurements include:

- false cleanup on messages labelled **Keep**;
- coverage, or how much mail the system automates;
- abstention, or how much it leaves for review;
- results separated by semantic family and time period.

Even zero observed errors does not imply zero risk. With `n` independent cases and
zero errors, a simple one-sided 95% upper bound is:

```text
p_upper = 1 - 0.05^(1/n)
```

At forty cases the bound is still about 7.2%. Reaching below 1% under the same
assumptions and still observing no error takes roughly 299 comparable cases. Real
email violates the neat assumptions: topics, seasons, and interests change.
Consequently the quiz is onboarding evidence, not certification.

The personal Safety Governor estimates that envelope per account, model, and
message family from HMAC-linked aggregate corrections. Its optional operational
layer is an intersection, not an override: ordinary safe proposals continue when
evidence is sparse, while only concrete repeated errors restrict the affected
family from reversible Quarantine. The ordinary Direct Trash
preference remains independent under its existing safeguards. Governor authority
over Direct Trash is a distinct, stricter capability: it requires a supported
model plus at least 299 conclusive, error-free reviews in both the overall and
family envelopes. Permanent deletion and emptying Trash remain outside its
authority. Temporal preference drift is already implemented as a protective-only
input: qualified recent Keep, restore, star, or importance evidence may restrict
the affected family, while declining interest can never unlock more cleanup. A
Counterfactual Safety Lab remains a research milestone; borderline decisions that
flip under small changes stay in review.

Methodological starting points include work on conformal risk control and
conformalised abstention policies:

- <https://proceedings.mlr.press/v162/fisch22a.html>
- <https://proceedings.mlr.press/v304/tayebati26a.html>

## Different models, different limits

InboxLume does not present an 8-billion-parameter model as equivalent to a more
capable one. The first controlled matrix is deliberately asymmetric:

| Profile | Recommended RAM | Cleanup threshold | Maximum destination |
|---|---:|---:|---|
| Qwen 8B Lightweight | 12 GB | 0.97 | Quarantine only |
| Gemma 12B Balanced | 16 GB | 0.95 | Quarantine only |
| Gemma 26B-A4B Recommended | 24 GB | 0.93 | Trash only after calibration |

On one development Mac, five synthetic messages including model load and unload
took approximately 5.4 seconds with Qwen 8B, 8.7 with Gemma 12B, and 9.7 with
Gemma 26B-A4B. Recorded peaks for the Gemma profiles were 11.2 and 14.7 GB. These
are development observations, not universal benchmarks.

In the largest local labelled sample available at the time of writing, Gemma
26B-A4B produced no false cleanup among four evaluable **Keep** examples and
identified 66.22% of **Don't keep** examples as cleanup candidates. Four protected
cases are far too few to estimate a rare failure. The defensible conclusion is not
“safe”; it is “the strongest candidate observed so far, still requiring
Quarantine, abstention, and a larger reproducible evaluation”.

## Quarantine before irreversible automation

The default destination is visible Quarantine. Gmail uses a label and can leave the
message in the Inbox; Yahoo uses a dedicated folder. Any later move to Trash can
require a delay and a new state check.

Trash is not a vault: providers apply their own retention. The interface therefore
warns that the provider may empty it, while InboxLume has no capability to do so.
Direct Trash is isolated per account, requires calibration, and is unavailable to
the less validated model profiles.

## Research directions, not release claims

Using Gemma locally is not by itself a durable contribution. Models can be changed,
and open code can be studied and reused. The more interesting work lies in the
combination of personal evidence, explicit risk, and narrow verifiable authority.

The working research sequence is:

```text
LumeGraph
  -> Proof of Obsolescence
  -> Safety Governor
  -> Counterfactual Safety Lab
  -> bounded capability
  -> restricted executor
  -> reversible quarantine
  -> causal correction
```

LumeGraph now represents utility cycles such as order → shipment → delivery or
booking → change → completed event. Its operational Proof of Obsolescence gate
requires a verified local closure witness instead of acting because a message
merely looks old. It may promote Review only to reversible Quarantine;
Proof-Carrying Cleanup would later bind that decision to one opaque ID, one
destination, and an expiry.

Other recorded directions include detecting expected-but-missing communication, a
personal sender baseline beyond the current technical and semantic threat
protection, and LumeReply: an on-demand reply adviser that covers questions and
commitments without reading Sent mail or sending anything. None of these should be
presented as an available feature until implemented and tested.

For privacy constraints in structured extraction over email, a relevant reference
is this Google Research system description:
<https://research.google/pubs/anatomy-of-a-privacy-safe-large-scale-information-extraction-system-over-email/>

## Project and release status

A companion [engineering log](ENGINEERING_LOG.md) records what happened the
first time the system met a real local model, a real IMAP server and a real Mac,
with the numbers from each run and what they still do not prove.

InboxLume is a free open-source GitHub project, not a commercial service. Source
code and project documentation are licensed under Apache-2.0; model weights,
third-party dependencies, and user data retain their own terms. The public
repository remains a development snapshot, not a supported packaged release.

The Gmail/Yahoo foundation, multiple accounts, quiz, one-shot scans, controlled
model profiles, native scheduling, local threat protection, LumeGraph, Proof of
Obsolescence, temporal drift, Safety Governor evidence, and the account-scoped
operational dashboard are working development components. CI, packaging, and the
static site are public, but the separate release gate remains closed. The
remaining gate includes the agreed feature scope, clean-machine packaging tests,
signing decisions, permission review, reproducible benchmarks, and approval of
release assets.

InboxLume will not promise 100% safety, call uncalibrated model confidence a
probability, or claim a world-first without a defensible prior-art review. The
technical objective is narrower and measurable:

> Every automatic cleanup should be able to state what utility has ended, which
> account-specific evidence supports the decision, and which limited reversible
> capability authorised that one action.

That is the project being explored: not another service that possesses the inbox,
but a local system that must earn the authority to act on each part of it.
