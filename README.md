# Tyst

Clipboard-based encrypted messaging using libsodium.

<br>

<img width="278" height="133" alt="image" src="https://github.com/user-attachments/assets/cd77c15f-1bcd-447b-b2f2-830def21ab9d" />
<img width="283" height="135" alt="image" src="https://github.com/user-attachments/assets/82bce429-3b93-449b-a903-9c40b326232d" />

<br>

<img width="667" height="280" alt="image" src="https://github.com/user-attachments/assets/eb12cf2c-d564-4ba0-9914-b7b36b4c8e0a" />

---

### Copy → Encrypt  
### Copy encrypted → Decrypt  

No buttons. No input. No friction.

---

### Automatic key exchange

With a simple `Ctrl+C`, Tyst handles identity exchange and decrypts messages automatically.  
No setup, no manual pairing.

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
SHHH#:


---

## Features

- Automatic encryption/decryption via clipboard  
- Zero interaction workflow  
- Persistent identity (stored locally)  
- Peer recognition via fingerprint  
- Overlay display for decrypted messages  

---

## How it works

1. Copy text → it gets encrypted  
2. Copy encrypted text → it gets decrypted  
3. First contact exchanges keys automatically  
4. Future messages are end-to-end encrypted  

---

## Dependencies

- libsodium  

---

## Setup

1. Install libsodium  
2. Link it in Visual Studio  
3. Build `Tyst.sln`  
4. Run  

---

## Files

- `identity.bin` → your keypair (private + public)  
- `peers.bin` → known peers  

⚠️ Do not share `identity.bin`

---

## Notes

- Works entirely through clipboard interception  
- No networking layer (transport is external)  
- Designed for simplicity and UX  

---

## Disclaimer

This is a prototype.

- No authentication guarantees  
- Not hardened against active attacks (MITM, spoofing, etc.)  
- Use at your own risk  
