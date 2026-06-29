# Next Best Move

Test PooleShield v5.3 locally and verify the Safe Corpus + Benchmark Harness.

v5.3 is intentionally safe: it uses feature/metadata JSONL records and synthetic fixtures only. Do not download, commit, unpack, or execute live malware samples.

```powershell
python -m pytest -q
python .\tools\repo_safety_check.py --root .
python .\tools\privacy_leak_check.py --root .
python .\pooleshield_operator.py safe-corpus-status --dataset .\examples\safe_corpus\tiny_feature_dataset.jsonl --output .\safe_corpus_status_response.json
python .\pooleshield_operator.py safe-corpus-benchmark --dataset .\examples\safe_corpus\tiny_feature_dataset.jsonl --output-dir .\out\safe_corpus_v5_3 --clean-output --bundle-output --privacy-bundle
```

Upload only:

```text
out\safe_corpus_v5_3\pooleshield_results_bundle.zip
```

If the bundle verifies clean, push v5.3. After v5.3, improve code-tester onboarding around how to bring EMBER/SOREL-style feature rows without adding raw samples.
