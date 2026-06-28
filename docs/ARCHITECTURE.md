# Architecture

PooleShield treats files, logs, DAT chunks, tool calls, and agent actions as local events.

Core modules:

- adapters: normalize inputs into events
- scanner: assigns labels and risk
- policy engine: maps risk to decisions
- review queue: creates human-review rows
- triage: groups repeated archived-text findings
- evidence viewer: local-only matched context review
- result bundler: exports privacy-safe bundles

Risk concepts:

- local defect density
- neighbor pressure
- fanout anomaly
- persistence pressure
- cross-context replication
- untrusted-to-dangerous action
- destructive-action proximity

The implementation here is intentionally public-safe and avoids publishing private math derivations or proprietary research data.
