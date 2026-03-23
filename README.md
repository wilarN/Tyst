# Tyst

Clipboard-based encrypted messaging using libsodium.

## Features
- Automatic encryption/decryption via clipboard
- No UI interaction required
- Persistent identity (stored locally)
- Peer recognition via fingerprint
- Overlay display for decrypted messages

## How it works
- Copy text → gets encrypted
- Paste encrypted text → gets decrypted automatically
- Target peer is set automatically from last message

## Dependencies
- libsodium

## Setup
1. Install libsodium
2. Link it in Visual Studio
3. Build the solution

## Notes
- identity.bin stores your private key (DO NOT SHARE)
- peers.bin stores known peers

## Disclaimer
This is a prototype. No guarantees.