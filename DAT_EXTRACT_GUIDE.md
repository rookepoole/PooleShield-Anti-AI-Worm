# PooleShield DAT Extract Guide

PooleShield v1.8 adds a local-only DAT extraction step for ChatGPT/export folders that contain opaque `.dat` blobs.

## What this does

`dat-extract` reads `.dat` files and `.dat` entries inside ZIP archives, classifies them, and extracts only text-like or JSON-like DAT blobs to a local folder:

```text
out/dat_extract/extracted_dat_text/
```

It does not execute files, unpack archive binaries, extract images, extract PDFs, or upload decoded content.

## Recommended workflow

First inspect the DAT export:

```powershell
python .\pooleshield_operator.py dat-inspect --path "C:\Users\rookp\Desktop\ChatGPT logs" --output-dir .\out\dat_inspect --clean-output --bundle-output
```

If the report shows `plain_text` or `json_text` entries, extract a bounded local fixture:

```powershell
python .\pooleshield_operator.py dat-extract --path "C:\Users\rookp\Desktop\ChatGPT logs" --output-dir .\out\dat_extract --clean-output --bundle-output --privacy-bundle --max-files 50
```

Then scan the local extracted text folder:

```powershell
python .\pooleshield_operator.py chat-scan --path ".\out\dat_extract\extracted_dat_text" --output-dir .\out\dat_chat_scan --clean-output --policy-profile balanced --bundle-output --privacy-bundle
```

Upload only the privacy bundle from the chat-scan output:

```text
out\dat_chat_scan\pooleshield_results_bundle.zip
```

## Privacy behavior

When `--privacy-bundle` is used, the ZIP bundle excludes:

```text
normalized_events.jsonl
extracted_dat_text/
```

The local extracted files remain on your machine, but are not included in upload bundles.

## Useful limits

Use these when scanning huge exports:

```powershell
--max-files 50
--max-bytes-per-file 5242880
--json-only
```

`--json-only` extracts only JSON-like DAT blobs and skips plain text blobs.
