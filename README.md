# Advanced Encryption Tool

This project is a desktop application for encrypting and decrypting files with AES-256-GCM. It uses a password-derived key with PBKDF2-HMAC-SHA256 and gives you a simple Tkinter interface for choosing files and running the operation safely.

## Features

- AES-256-GCM authenticated encryption
- PBKDF2 key derivation with a unique salt per file
- File-based workflow with browse and save dialogs
- Password confirmation and overwrite protection
- Streaming file processing so large files do not need to fit in memory

## Requirements

- Python 3.11+ recommended
- Install dependencies:

```bash
python -m pip install -r requirements.txt
```

## Run the app

```bash
python app.py
```

## How it works

1. Choose whether you want to encrypt or decrypt.
2. Select the input file.
3. Confirm the suggested output path or choose a different one.
4. Enter your password and confirm it.
5. Run the operation.

Encrypted files are saved with the `.aes` extension by default.

## Security notes

- The app uses AES-256-GCM for confidentiality and integrity.
- Each file gets a fresh random salt and nonce.
- Passwords are turned into encryption keys with PBKDF2-HMAC-SHA256.
- If the wrong password is used during decryption, the app will reject the file instead of producing corrupted output.

## Important

If you lose the password, the encrypted file cannot be recovered.
