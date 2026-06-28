# PooleShield v1.8 Output Hygiene Guide

Cycle 10 keeps generated reports out of the package root. By default everything goes to:

```text
out/cycle10/
```

Use `--clean-output` to delete that output folder before writing new reports:

```powershell
python .\pooleshield_cycle10.py --path .\examples\corpus_scan_fixture --policy-profile balanced --demo-review-decisions --clean-output
```

The v1.8 ZIP is flat-packed. When extracted to `C:\Users\rookp\pooleshield_v0_9_package`, files such as `pooleshield_cycle10.py` should be directly inside that folder.

Correct:

```text
C:\Users\rookp\pooleshield_v0_9_package\pooleshield_cycle10.py
```

Wrong nested extraction:

```text
C:\Users\rookp\pooleshield_v0_9_package\pooleshield_v0_9_package\pooleshield_cycle10.py
```

If nested extraction happens, delete the outer folder and rerun the install commands from `INSTALL_WINDOWS.md`.
