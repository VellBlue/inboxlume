# Changelog

Notable InboxLume changes will be recorded here. The project will use versions
compatible with Semantic Versioning after its first stable release.

## [Unreleased]

### Added

- cross-platform GUI with isolated Gmail and Yahoo accounts;
- guided authentication with credentials in the native system keyring;
- one-shot scans, incremental quiz, and HMAC-derived learning without plaintext;
- automatic Quarantine and calibration-gated Direct Trash;
- native scheduling for macOS, Windows, and Linux;
- controlled local Qwen 8B, Gemma 12B, and Gemma 26B-A4B profiles;
- English-first UI with a separately edited Italian localisation;
- simultaneous classification of English, Italian, and mixed-language email;
- reversible phishing warnings that leave messages in Inbox: a dedicated Gmail
  label and a Yahoo-compatible star, with HMAC-only local audit records;
- CI, local packaging preparation, and a fail-closed release gate.

### Security

- Inbox-only boundary with no sending, permanent deletion, or empty-trash;
- separated provider, model, decision, and execution responsibilities;
- automated repository audit for credentials, email data, and personal artefacts.

There is no supported public release yet.
