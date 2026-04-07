# Tyst
### Silent, zero-friction encrypted messaging

Encrypted messaging through your clipboard.

<br>

<img width="269" height="168" alt="image" src="https://github.com/user-attachments/assets/6cb794a7-8153-4016-b9a2-7c54ef397bde" />
<img width="269" height="163" alt="image" src="https://github.com/user-attachments/assets/f7830ecb-fc27-4ea5-8dfc-b25250fb549c" />


<br>

<img width="667" height="280" alt="image" src="https://github.com/user-attachments/assets/eb12cf2c-d564-4ba0-9914-b7b36b4c8e0a" />

---

### Copy → Encrypt  
### Copy encrypted → Decrypt  

No extra buttons. No extra input. No added friction.

---

## Use Cases

- Sending encrypted messages over Discord, Slack, or similar platforms  
- Sharing sensitive text without relying on dedicated secure messaging apps  
- Lightweight, ephemeral communication  
- Adding privacy to everyday conversations over standard channels  

---

## Why this approach

Tyst is built around a simple idea: you don’t always control the platform you’re communicating through.

Most modern platforms:
- Store messages  
- Analyze content  
- Process data for features, moderation, or analytics  

Tyst encrypts your message **before it ever leaves your system**, so what gets sent through these platforms is not readable plaintext.

This allows you to:
- Keep message content private, even when using standard apps  
- Avoid exposing raw text to logging, indexing, or automated processing systems  
- Maintain control over what is actually readable versus what is merely transmitted  

---

## Data exposure

Because messages are encrypted locally:

- Platforms only receive ciphertext, not usable text  
- Content cannot be directly parsed, indexed, or profiled  
- Reduces the likelihood of messages being incorporated into analytics or large-scale data processing  

This is not about hiding activity, it’s about limiting unnecessary data exposure.

---

## ⚠️ Important context

- This does not hide that communication is happening  
- Platforms can still see message timing and metadata  
- Encrypted data may still be stored or logged  

Tyst focuses on **content privacy**, not anonymity or obfuscation  

---

## Summary

Tyst separates **where data travels** from **what data actually is**.

Even if the channel is open, logged, or processed, the message itself remains private.

---
### Automatic key exchange

With a simple `Ctrl+C`, Tyst handles identity exchange and decrypts messages automatically.  
Automatic key exchange on first contact.

No manual pairing required, identities are exchanged seamlessly through the clipboard.

<br>

<img width="655" height="161" alt="image" src="https://github.com/user-attachments/assets/6d608ac4-cbde-41f8-b5a1-01f628331af0" />

---

### Smart text handling

- Leaves normal text untouched  
- Only processes encrypted segments  
- Works with multiline selections  

<br>

<img width="646" height="170" alt="image" src="https://github.com/user-attachments/assets/455f9af7-7adb-4391-a029-165451d2d61c" />

---

### Prefix

By default, encrypted messages use:
## SHHH#:


---

## Features

- Transparent encryption/decryption via clipboard
- Zero-interaction workflow
- Automatic peer discovery via key exchange
- Persistent identity using secure local storage
- Fingerprint-based peer recognition
- Real-time overlay for decrypted content
  
---

## How it works

1. Copy plaintext → encrypted automatically  
2. Copy encrypted text → decrypted automatically  
3. First interaction → public keys exchanged  
4. Subsequent messages → encrypted with shared keys  

---

## Dependencies

- libsodium  

---

## Setup

1. Install libsodium  
2. Link `libsodium.lib` in Visual Studio  
3. Ensure `sodium.dll` is available at runtime  
4. Build `Tyst.sln`  
5. Run

---

## 🔐 Integrity

| File      | SHA256 |
|----------|--------|
| Tyst.exe (v0.1.1) | `1A5845957508D5AB576A7F37B10A3CE7E019198E092D85122AC02303CA2C2523` |
| Tyst.exe (v0.1.0) | `CDB5DE03A92A0048688ED03D7C48360E57C7361D43A8512559603C7BA98DF6FA` |

Verify with:

```powershell
Get-FileHash .\Tyst.exe -Algorithm SHA256
```


---

## Files

- `identity.bin` → your encrypted keypair (protected via DPAPI)
- `peers.bin` → known peer public keys

---

## Limitations

- Clipboard-only (no native messaging UI)
- No message history
- No authentication or trust verification
- Dependent on external transport (Discord, etc.)

## Notes

- Works entirely through clipboard interception  
- No networking layer (transport is external)  
- Designed for simplicity and UX  

---

## Security Model

- Encryption: libsodium (crypto_box)
- Transport: clipboard (out-of-band)
- Key exchange: automatic (unauthenticated)

⚠️ No identity verification, vulnerable to MITM attacks  
⚠️ Do not use for sensitive communication


## Disclaimer

This is a prototype.

- No authentication guarantees  
- Not hardened against active attacks (MITM, spoofing, etc.)  
- Use at your own risk

## ⚠️ Antivirus Notice

Some antivirus engines may flag Tyst as suspicious.

This is due to its behavior:
- Monitoring clipboard activity
- Modifying clipboard contents
- Using strong encryption (libsodium)

These patterns are commonly associated with certain types of malware, which can lead to heuristic or machine learning-based false positives.

Tyst does **not** perform any network communication, data exfiltration, or background persistence.  
All processing happens locally on your machine.

If in doubt, you are encouraged to:
- Review the source code
- Build the project yourself
<br>
Also make sure you never download Tyst from any other place than the source here and preferably as stated above compile it yourself to make sure it has not been tampered with. Also make sure to verify the SHA256 hash against the release you downloaded/built.
