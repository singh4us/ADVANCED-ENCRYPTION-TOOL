# Advanced Encryption Tool
*COMPANY*: CODTECH IT SOLUTIONS 

*NAME*: SAHIL SINGH 

*INTERN ID*: CTIS7485

*DOMAIN*: CYBER SECURITY & ETHICAL HACKING

*DURATION*: 6 WEEKS

*MENTOR*: NEELA SANTOSH

## An Advanced Encryption Tool is a security application designed to protect sensitive data by converting it into an unreadable format, ensuring that only authorized users can access the original information. In today’s digital world, where data breaches and cyber threats are increasingly common, encryption plays a vital role in maintaining confidentiality, integrity, and privacy. This project presents a Python-based advanced encryption tool that enables users to securely encrypt and decrypt files and text using modern cryptographic techniques.The tool is developed using Python due to its simplicity and the availability of powerful cryptographic libraries such as cryptography. This library provides secure implementations of encryption algorithms and key management techniques. The core functionality of the tool is based on symmetric encryption, specifically using the Fernet module, which ensures that data is encrypted using a single secret key and can only be decrypted with the same key.The working of the encryption tool involves three main components: key generation, encryption, and decryption. First, a secure encryption key is generated using a cryptographically strong random number generator. This key acts as the secret required to both encrypt and decrypt data. Users can save this key securely and reuse it whenever needed. Proper key management is critical, as losing the key means losing access to the encrypted data permanently.In the encryption phase, the tool takes input in the form of text or files. The data is processed and encrypted using the generated key, transforming it into ciphertext. This ciphertext appears as random, unreadable data, ensuring that even if it is intercepted, it cannot be understood without the correct key. The encrypted output can be saved to a file or transmitted securely over networks.The decryption phase reverses this process. The user provides the encrypted data along with the correct key, and the tool restores the original content. If an incorrect key is used, the decryption fails, thereby preventing unauthorized access. This ensures both confidentiality and data protection.One of the key features of this tool is its ease of use. It provides a simple command-line interface where users can choose between encrypting or decrypting data. It supports both text-based encryption and file encryption, making it versatile for different use cases such as securing documents, configuration files, or sensitive messages.Additionally, the tool emphasizes security best practices. It avoids weak or outdated encryption methods and relies on authenticated encryption, which ensures not only confidentiality but also data integrity. This means that any tampering with encrypted data can be detected during decryption.Future enhancements for this tool may include features such as password-based key derivation, integration with secure key storage systems, graphical user interfaces (GUI), and support for asymmetric encryption methods like RSA for key exchange.It is important to note that while this tool provides strong encryption capabilities, users must handle keys responsibly and follow secure practices to ensure maximum protection.In conclusion, the Advanced Encryption Tool is a practical and secure solution for protecting sensitive data. It demonstrates the importance of encryption in cybersecurity and provides a reliable way to safeguard information against unauthorized access.


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

## OUTPUT 

<img width="797" height="514" alt="Image" src="https://github.com/user-attachments/assets/105a6259-8adc-4032-b3ec-e1337e3b8381" />

