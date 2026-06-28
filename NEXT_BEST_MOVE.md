# Next Best Move

Run the v3.0.1 read-only file AV fixture.

```powershell
cd "C:\Users\rookp\pooleshield_v3_0_package"
python .\pooleshield_operator.py scan-folder --path .\examples\file_av_fixture --output-dir .\out\file_av_demo --clean-output --bundle-output --privacy-bundle
```

Upload:

```text
out\file_av_demo\pooleshield_results_bundle.zip
```

Do not run v3.0.1 on the whole drive yet. After the fixture passes, scan a small real folder such as Downloads or Desktop with the read-only scanner.
