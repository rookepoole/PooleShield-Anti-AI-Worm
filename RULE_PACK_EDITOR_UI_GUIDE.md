# PooleShield v5.3.0 Rule Pack Editor UI Guide

PooleShield v5.3.0 adds the first local Rule Pack Editor UI on top of the v4.0 Engine API and the v4.1-v4.3 desktop UI stack.

The Rule Pack Editor is local and defensive:

- reads local file-AV rule pack JSON
- validates rule-pack structure and regexes
- lists rules by id, type, enabled state, label, risk delta, pattern, and reason
- filters by enabled/disabled state, rule type, and text
- exports the public default rule pack to a local editable copy
- writes edited rule-pack JSON copies only after explicit operator action
- does not execute scanned files
- does not delete files
- does not quarantine files
- does not modify scanned files
- does not silently trust files

## CLI smoke tests

```powershell
python .\pooleshield_operator.py rule-pack-load `
  --rule-pack .\examples\rule_packs\file_av_rules.default.json `
  --enabled enabled `
  --limit 25 `
  --output .\rule_pack_response.json
```

Export an editable copy:

```powershell
python .\pooleshield_operator.py rule-pack-export-default `
  --output .\local_rule_packs\file_av_rules.editable.json `
  --force
```

Edit one selected rule into a copy:

```powershell
python .\pooleshield_operator.py rule-pack-update-rule `
  --rule-pack .\local_rule_packs\file_av_rules.editable.json `
  --output .\local_rule_packs\file_av_rules.edited.json `
  --index 0 `
  --disabled `
  --risk-delta 0.10
```

## Engine operations

```text
rule_pack.load
rule_pack.export_default
rule_pack.update_rule
```

These operations are UI-ready JSON request/response calls. They only inspect or write rule-pack JSON files. They do not inspect or mutate scanned files.

## Desktop tab

The desktop app now includes:

```text
Dashboard
Scan Folder
Results
Baseline
Rule Packs
History
About
```

The Rule Packs tab lets you load a local rule pack, filter rules, inspect details, export an editable default copy, and save selected-rule edits to a rule-pack JSON copy.

## Privacy boundary

Do not commit local edited rule packs unless you intentionally want them in the public repo. Local edited rule packs should normally stay under `local_rule_packs/`, which is ignored and blocked by the repo safety check.
