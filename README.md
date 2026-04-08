# Tyst

### Silent, zero-friction encrypted messaging

Encrypted messaging through your clipboard.

<br>

<img width="269" height="168" src="https://github.com/user-attachments/assets/6cb794a7-8153-4016-b9a2-7c54ef397bde" />
<img width="269" height="163" src="https://github.com/user-attachments/assets/f7830ecb-fc27-4ea5-8dfc-b25250fb549c" />
<br>
<img width="460" height="161" alt="image" src="https://github.com/user-attachments/assets/a33dd0f4-d4af-4263-956f-8d795534cb84" />

<br>

<img width="667" height="280" src="https://github.com/user-attachments/assets/eb12cf2c-d564-4ba0-9914-b7b36b4c8e0a" />

---

### Copy → Encrypt

### Copy encrypted → Decrypt

No buttons. No UI flow. Just copy.

---

## What it does

Tyst encrypts text **before it leaves your system** using your clipboard.

* Copy plaintext → gets encrypted
* Copy encrypted text → gets decrypted
* First contact → automatic key exchange
* Everything happens locally

---

## Why

Most platforms store and process your messages.

Tyst makes sure what you send is **not readable plaintext**, even if the platform logs or analyzes it.

---

## Features

* Clipboard-based encryption/decryption
* Zero interaction workflow
* Automatic peer discovery
* Persistent identity (DPAPI)
* Fingerprint-based peer recognition
* Real-time overlay for decrypted text
* Scrollable peer sidebar with quick switching

---

## How it works

1. Copy text → encrypted
2. Paste/send anywhere
3. Copy it again → decrypted

---

## Dependencies

* libsodium

---

## Setup

1. Install libsodium
2. Link `libsodium.lib`
3. Ensure `sodium.dll` is present
4. Build & run

---

## 🔐 Integrity

| File              | SHA256                                                             |
| ----------------- | ------------------------------------------------------------------ |
| Tyst.exe (v0.1.2) | `0EE8011E4AF2BF89EF144358128BC18CDBDD2AB3128143148F011BCAA98ECA8B` |

```powershell
Get-FileHash .\Tyst.exe -Algorithm SHA256
```

---

## Files

* `identity.bin` → encrypted keypair
* `peers.bin` → known peers

Do not share your `identity.bin`.

---

## ⚠️ Security

* Encryption: libsodium (`crypto_box`)
* Key exchange: automatic (unauthenticated)

This means:

* Messages are encrypted
* ❌ You cannot verify who you're talking to
* ❌ Vulnerable to MITM attacks

---

## ⚠️ Important

This project is experimental.

Do **not** use Tyst for real or sensitive communication.
It is intended for testing, experimentation, and learning only.

---

## ⚠️ Antivirus Notice

May be flagged due to:

* Clipboard monitoring
* Clipboard modification
* Encryption usage

No networking, persistence, or data exfiltration.

---

## Disclaimer

Prototype software.
Use at your own risk.
