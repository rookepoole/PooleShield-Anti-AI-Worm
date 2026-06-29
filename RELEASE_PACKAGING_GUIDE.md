# PooleShield v5.2 Release Packaging Guide

Version: 5.2.0

PooleShield v5.2 adds local release packaging and integrity-manifest tooling. This release does **not** add real-time protection, a Windows service, kernel hooks, automatic quarantine, or cloud upload behavior.

The release helper is metadata-only:

- hashes a locally built portable folder
- hashes a locally built installer executable
- writes a release manifest JSON
- optionally writes a release-notes draft
- does not copy release artifacts into the manifest
- does not execute the portable app or installer
- does not install, uninstall, delete, quarantine, upload, or modify scanned files

## CLI

```powershell
python .\pooleshield_operator.py release-manifest `
  --status `
  --portable-dir C:\Users\rookp\Desktop\PooleShieldPortable_v5_0_RELEASE `
  --installer-path C:\path\to\PooleShieldSetup.exe `
  --output .\release_status_response.json
```

Create the manifest and release-notes draft:

```powershell
python .\pooleshield_operator.py release-manifest `
  --release-version 5.2.0 `
  --portable-dir C:\Users\rookp\Desktop\PooleShieldPortable_v5_0_RELEASE `
  --installer-path C:\path\to\PooleShieldSetup.exe `
  --output .\release_manifest_response.json `
  --notes-output .\release_notes_draft.md
```

## Engine API

```json
{"operation":"release.status","params":{"portable_dir":"C:\\path\\to\\portable","installer_path":"C:\\path\\to\\PooleShieldSetup.exe"}}
```

```json
{"operation":"release.manifest","params":{"release_version":"5.2.0","portable_dir":"C:\\path\\to\\portable","installer_path":"C:\\path\\to\\PooleShieldSetup.exe"}}
```

## Do not commit

Generated release files are local artifacts and should not be committed unless intentionally curated later:

```text
release_manifest.json
release_manifest_response.json
release_status_response.json
release_notes_draft.md
release_output/
release_artifacts/
release_verify/
*_release_manifest_verification.zip
```

## Unsigned Windows build note

Local Windows installer builds are unsigned unless a separate code-signing step has been performed. Windows SmartScreen may warn on first launch/install. Publish SHA256 checksums with releases so users can verify artifacts before running them.
