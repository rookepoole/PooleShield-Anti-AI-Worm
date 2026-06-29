# Next Best Move

Test PooleShield v5.2 locally and verify release-manifest packaging.

v5.2 adds metadata-only release integrity manifests and release-note drafts for the already verified portable folder and installer executable.

```powershell
python -m pytest -q
python .\tools\repo_safety_check.py --root .
python .\tools\privacy_leak_check.py --root .
python .\pooleshield_operator.py release-manifest --help
```

Create a release status response:

```powershell
python .\pooleshield_operator.py release-manifest `
  --status `
  --portable-dir C:\Users\rookp\Desktop\PooleShieldPortable_v5_0_RELEASE `
  --installer-path C:\path\to\PooleShieldSetup.exe `
  --output .\release_status_response.json
```

Create the release manifest and release notes draft:

```powershell
python .\pooleshield_operator.py release-manifest `
  --release-version 5.2.1 `
  --portable-dir C:\Users\rookp\Desktop\PooleShieldPortable_v5_0_RELEASE `
  --installer-path C:\path\to\PooleShieldSetup.exe `
  --output .\release_manifest_response.json `
  --notes-output .\release_notes_draft.md
```

Upload the metadata-only release-manifest verification ZIP, not the installer executable or portable folder.
