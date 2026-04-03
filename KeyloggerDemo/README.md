# Secure Input Logger Demo

**For security awareness only — does not capture system-wide input.**  
This desktop app (Python + Tkinter) logs *only* what you type into its own input fields. It does **not** capture global keystrokes or clipboard content.

## What it logs
Typing into these fields:
- `username` (non-sensitive)
- `password` (masked)
- `email` (salted SHA-256 hash)
- `OTP` (masked for 6-digit OTPs)
- `generic text` (pattern detection for email / credit-card-like sequences / token-like strings; sensitive matches are protected)

Each in-app audit record includes:
- timestamp
- field name
- sensitivity classification
- protection method used (`masked`, `hashed`, or `encrypted` (file-at-rest))

## Protecting sensitive data
- Password + OTP + credit-card-like sequences: stored as `•` masked strings (no plaintext).
- Email addresses + API/token-like strings: stored as `salted_sha256` (no plaintext).
- Exported log file: encrypted using **Fernet** (`.elog`) with a local passphrase.

## Dependencies
Install the only required dependency:
```bash
python -m pip install cryptography
```

## Run locally
```bash
cd SecureInputLoggerDemo
python main.py
```

## Export and decrypt
1. Click **Export Logs** and set a passphrase.
2. Distribute/store the resulting `.elog` file.
3. Click **Decrypt for Authorized Viewer**, select the `.elog` file, and enter the same passphrase.

## Admin notifications (unauthorized decrypt attempts)
When an encrypted file decrypt fails due to an invalid passphrase, the app will:
1. Show an entry in the in-app **Admin Notifications** box.
2. POST a sanitized JSON report to your admin webhook (if configured).

To enable reporting, set:
- `ADMIN_WEBHOOK_URL`: HTTPS webhook endpoint that accepts `POST` with JSON body.
- `ADMIN_AUTH_TOKEN` (optional): sent as `Authorization: Bearer <token>` header.

The report never includes the passphrase or decrypted plaintext.

## Sample encrypted log file
The repo includes an encrypted sample at:
- `sample_logs/sample.encrypted.elog`

Viewer passphrase used for the included sample:
- `demo-viewer-passphrase`

If you want to regenerate it:
```bash
python main.py --generate-sample --sample-out sample_logs/sample.encrypted.elog --passphrase demo-viewer-passphrase
```

