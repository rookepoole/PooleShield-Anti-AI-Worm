# Next Best Move

1. Run `python -m pytest -q` in the v3.2 package.
2. Build a trusted baseline from the already-reviewed file AV scan.
3. Rescan the same small real folder.
4. Apply the baseline and verify trusted helper scripts move to `ALLOW_LOG` without manual ledger editing.
5. Upload the privacy bundle.
6. If clean, push v3.2 to GitHub.

Do not use baseline trust for unknown downloads or unreviewed files.
