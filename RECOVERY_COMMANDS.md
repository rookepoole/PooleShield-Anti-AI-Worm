# Recovery Commands

Resume the DAT rollup checkpoint:

```powershell
cd "C:\Users\rookp\pooleshield_v2_1_package"
python .\pooleshield_operator.py batch-rollup --path "dat_batch_0000=C:\Users\rookp\pooleshield_v1_8_package\out\dat_chat_scan" --path "dat_batch_0050=C:\Users\rookp\pooleshield_v2_0_package\out\dat_batch_0050\dat_chat_scan" --path "dat_batch_0200=C:\Users\rookp\pooleshield_v2_0_package\out\dat_batch_0200\dat_chat_scan" --path "dat_batch_0350=C:\Users\rookp\pooleshield_v2_0_package\out\dat_batch_0350\dat_chat_scan" --path "dat_batch_0500=C:\Users\rookp\pooleshield_v2_0_package\out\dat_batch_0500\dat_chat_scan" --output-dir .\out\dat_archive_rollup --clean-output --bundle-output --privacy-bundle
```
