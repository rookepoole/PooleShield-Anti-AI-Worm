# Next Best Move

1. Run the v3.3 test suite.
2. Run `file-av-scan-baseline` against the already-reviewed real-small folder using the local trusted baseline.
3. Upload the resulting privacy bundle.
4. If the bundle verifies clean, push v3.3 to GitHub.

The goal is to make baseline-aware file AV scanning one command instead of scan -> apply baseline -> interpret two reports.
