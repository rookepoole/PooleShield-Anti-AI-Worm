# Safe Corpus Fixtures

These fixtures are metadata/features only. They do not contain executable malware, raw binaries, live samples, decoded payloads, or the canonical EICAR test string.

Use them to test the v5.3 safe-corpus benchmark path:

```powershell
python .\pooleshield_operator.py safe-corpus-benchmark `
  --dataset .\examples\safe_corpus\tiny_feature_dataset.jsonl `
  --output-dir .\out\safe_corpus_v5_3 `
  --clean-output `
  --bundle-output `
  --privacy-bundle
```
