# PooleShield DAT Export Guide

PooleShield v1.8 adds a safe `dat-inspect` workflow for export bundles that contain opaque `.dat` blobs instead of friendly `conversations.json` files.

## Why this exists

Some ChatGPT-related export or artifact bundles may contain `.dat` files. In practice those `.dat` files can be many different things:

- text-like records
- JSON-like records
- PNG/JPEG/GIF/WebP images
- PDFs
- ZIP/GZIP/archive data
- SQLite/database-like blobs
- unknown binary attachments

PooleShield should not assume a `.dat` file is a chat transcript. The safe first step is to inventory it.

## Safety boundary

`dat-inspect`:

- does not execute anything
- does not follow links
- does not call APIs
- does not extract runnable content
- does not decrypt or bypass access controls
- writes metadata, hashes, magic/type guesses, and summary reports only

## Run DAT inspection on a folder

```powershell
python .\pooleshield_operator.py dat-inspect --path "C:\path\to\export_folder" --output-dir .\out\dat_inspect --clean-output --bundle-output
```

## Run DAT inspection on a ZIP

```powershell
python .\pooleshield_operator.py dat-inspect --path "C:\path\to\chat_export_bundle.zip" --output-dir .\out\dat_inspect --clean-output --bundle-output
```

Upload only:

```text
out\dat_inspect\pooleshield_results_bundle.zip
```

## Outputs

```text
dat_inventory.json
dat_inventory.csv
dat_inventory.md
RUN_SUMMARY.json
pooleshield_results_bundle.zip
```

## How to interpret likely types

- `json_text`: likely safe to copy locally into `.json` and run `chat-scan`
- `plain_text`: likely safe to copy locally into `.txt` / `.md` and run `chat-scan` or `scan`
- `image_binary`: likely an image attachment, not a chat log
- `pdf_binary`: likely a PDF attachment
- `archive_binary`: likely a ZIP/GZIP or nested archive
- `database_binary`: likely SQLite/database-style binary
- `unknown_binary`: inventory only; do not treat as text

## Next step after DAT inventory

If DAT inventory finds `json_text` or `plain_text`, the next PooleShield feature should be a local-only extraction helper that writes decoded text into a private folder. That helper should not include decoded content in upload bundles by default.
