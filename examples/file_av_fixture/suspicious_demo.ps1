# Inert test fixture only. Do not run. This exists so the scanner can detect risky static script wording.
$payload = "AAAA"
IEX ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload)))
