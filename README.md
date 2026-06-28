# PooleShield Anti-AI-Worm

PooleShield is a privacy-first defensive scanner for AI-agent workflows, prompt-injection propagation, exported chat/log archives, and suspicious local text artifacts.

This public repository contains a **safe defensive implementation** of the PooleShield scanning and review workflow. It does **not** publish private chat logs, extracted DAT text, unpublished Poole Math derivations, Poole Manifold research notes, benchmark IP, or proprietary datasets.

## Current status

- Version line: v2.x research prototype
- Platform: Python 3.10+ / Windows-first CLI
- Scope: defensive scanning, archive triage, evidence review, policy decisions, privacy-safe reporting
- Not included: kernel drivers, real-time file-system hooks, malware samples, exploit code, private logs, or raw extracted content

## Defensive workflow

PooleShield converts local artifacts into events, scores them with a local-geometry risk model, applies policy decisions, and produces privacy bundles that exclude raw sensitive content by default.

Decision levels:

```text
ALLOW
ALLOW_LOG
REQUIRE_APPROVAL
BLOCK
QUARANTINE
```

## Quick start

```powershell
python .\pooleshield_operator.py demo --output-dir .\out\demo --clean-output --bundle-output --privacy-bundle
```

Inspect a DAT archive/folder:

```powershell
python .\pooleshield_operator.py dat-inspect --path "C:\path\to\logs_or_export" --output-dir .\out\dat_inspect --clean-output --bundle-output
```

Run a deterministic privacy-safe DAT batch:

```powershell
python .\pooleshield_operator.py dat-batch --path "C:\path\to\logs_or_export" --output-dir .\out\dat_batch_0000 --clean-output --start-index 0 --batch-size 150 --policy-profile balanced --bundle-output --privacy-bundle
```

## Privacy guarantees by default

Privacy bundles exclude decoded/private content such as:

```text
normalized_events.jsonl
extracted_dat_text/
review_evidence_local.md
review_evidence_report.json
```

## IP boundary

The source code in this repository is licensed under the repository license. The unpublished Poole Math / Poole Manifold / Poole Defect Calculus research program, private data, benchmark notes, research papers, and proprietary derivations are **not** licensed here except where explicitly embodied in this public source release.

See `NOTICE.md` and `docs/IP_BOUNDARIES.md`.

## Roadmap

See `docs/ROADMAP.md` for the antivirus / EDR expansion plan.
