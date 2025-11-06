# Cryptografie — Cryptography toolkit v1.0

Small command-line cryptography toolkit that provides file hashing, integrity checks, AES/RSA encrypt/decrypt helpers, and a simple password manager.

## Features

- Hash files (SHA) for integrity checks.
- Compare file integrity (hash comparison).
- AES encrypt/decrypt (prints key, ciphertext, plaintext).
- RSA encrypt/decrypt (prints ciphertext and decrypted plaintext).
- Password strength checking, salting & hashing, and verification.

## Requirements

- Python 3.8 or newer
- Install Python dependencies listed in `requirements.txt`.

If `requirements.txt` is missing or you prefer to install manually, the project typically requires libraries for cryptography such as PyCryptodome and a password hashing library. Example fallback:

```powershell
python -m pip install pycryptodome bcrypt
```

## Installation (Windows PowerShell)

Open PowerShell in the project folder (`d:\freecodecamp\cryptografie`) and run:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

This creates and activates a virtual environment and installs required packages.

## Usage

Run the main application:

```powershell
python main.py
```

You'll see the interactive menu with options 0–5. Example workflows:

- Hash a file (option 1)
  - Enter the file path when prompted (e.g. `sample_files\sample.txt`).
  - The program prints the SHA hash of the file.

- Check file integrity (option 2)
  - Provide two file paths. The program compares their hashes and reports whether they match.

- AES Encrypt/Decrypt (option 3)
  - Enter a message. The program returns the AES key, ciphertext, and decrypted plaintext.
  - Note: the AES key is printed (for demo purposes) — do not expose keys in production.

- RSA Encrypt/Decrypt (option 4)
  - Enter a message. The script prints encrypted and decrypted results using generated RSA keys.

- Password Manager (option 5)
  - Enter a password to check strength. If strong enough, the program salts & hashes it and asks you to re-enter to verify.

## Examples

Using the sample files bundled with the repo:

```powershell
# Hash a sample file
python main.py
# choose 1
# Enter file path: sample_files\sample.txt
```

## Notes & Security

- This toolkit is intended for learning and small demos only. It prints keys and hashes to the console for visibility.
- Do not use the printed keys or this tool as-is in production systems.
- For production use, securely manage keys (use OS key stores or KMS), never print secrets, and use well-audited libraries and protocols.

## Troubleshooting

- If imports fail, ensure you're running inside the virtual environment and that `pip install -r requirements.txt` completed successfully.
- Use absolute paths if relative paths fail, e.g.: `C:\full\path\to\sample_files\sample.txt`.

## License

MIT

--
Generated README for the `cryptografie` project. If you'd like, I can also auto-generate a minimal `requirements.txt` based on the modules used or inspect the code to list exact dependencies.