# PooleShield CI Safety Guide

Version: 4.3.0

PooleShield v3.6 adds repository safety checks so GitHub can catch private or generated artifacts before they become part of the public repo.

## What CI checks

The CI workflow runs:

```bash
python -m pytest -q
python tools/repo_safety_check.py --root .
```

The safety check fails if committed files include high-risk private/generated artifacts such as:

```text
out/
local_trust/
*.dat
pooleshield_results_bundle.zip
*_results_bundle.zip
BUNDLE_MANIFEST.json
PRIVACY_BUNDLE_NOTE.md
normalized_events.jsonl
extracted_dat_text/
extracted_dat_content/
extracted_text_like/
review_evidence_local.md
review_evidence_report.json
trusted_file_baseline.json
trusted_file_baseline.csv
trusted_file_baseline.md
__pycache__/
.pytest_cache/
```

Small synthetic test fixtures are explicitly allowed, including:

```text
examples/file_av_fixture/fixture_archive.zip
examples/dat_fixture/nested_dat_bundle.zip
```

## Why this matters

PooleShield is a privacy-first scanner. The public repo must not contain raw ChatGPT logs, decoded DAT text, local review evidence, trusted baselines, result bundles, raw scanned file contents, or private Poole Math / Poole Manifold / Poole Defect Calculus IP.

## Local pre-push command

Run this before pushing:

```powershell
python -m pytest -q
python .\tools\repo_safety_check.py --root .
```

Expected:

```text
PooleShield repo safety check passed. Version 4.3.0.
```

## If CI fails

Remove generated/private artifacts from Git tracking:

```powershell
git rm -r --cached --ignore-unmatch out local_trust extracted_dat_text extracted_dat_content extracted_text_like __pycache__ .pytest_cache
```

Then check status and recommit.


## v3.9.0 CI bootstrap fix

v3.9.0 adds an explicit GitHub Actions dependency-install step before pytest:

```yaml
- name: Install test dependencies
  run: |
    python -m pip install --upgrade pip
    python -m pip install pytest
```

This fixes fresh Ubuntu runners that do not already have pytest installed.


## v3.9.0 CI action runtime update

PooleShield v3.9.0 updates the workflow actions from:

```yaml
actions/checkout@v4
actions/setup-python@v5
```

to:

```yaml
actions/checkout@v7
actions/setup-python@v6
```

This removes the GitHub Actions Node 20 deprecation warning while keeping the same test and repo-safety behavior.


## v3.8 config privacy guard

Local `pooleshield_config.json` and `.pooleshield_config.json` files are treated as private/generated operator files and should not be committed. The public-safe reference is `examples/pooleshield_config.example.json`.
