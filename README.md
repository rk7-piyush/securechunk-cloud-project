# SecureChunk — Encrypted File Chunking and Secure Download

A Windows-friendly academic prototype. It encrypts a file locally using AES-256-GCM, splits the ciphertext into chunks, packages the chunks and manifest into a ZIP bundle, and restores the original file after reassembly and authenticated decryption. Optional S3 upload/download is included.

## Requirements
- Windows 10/11
- Python 3.10 or newer
- Internet connection for installing Python packages
- AWS account and permission to access the target S3 bucket (only for optional S3 mode)

## Run on Windows
1. Install Python from https://www.python.org/downloads/windows/ . During installation, check **Add python.exe to PATH**.
2. Open Command Prompt in this project folder.
3. Create a virtual environment:
   ```bat
   py -m venv .venv
   .venv\Scripts\activate
   ```
4. Install dependencies:
   ```bat
   python -m pip install --upgrade pip
   pip install -r requirements.txt
   ```
5. Start the app:
   ```bat
   streamlit run app.py
   ```
6. Your browser should open the local app (usually http://localhost:8501).

## Demo steps
1. In **Encrypt & chunk**, choose a small test file (e.g. `test.txt`).
2. Enter a strong passphrase with at least 12 characters. For your demo, write it down somewhere safe temporarily; the app does not store it in the bundle.
3. Choose 64 KiB or 1024 KiB chunk size and click **Encrypt and create bundle**.
4. Download the encrypted bundle.
5. Open **Restore file**, upload the bundle, enter the same passphrase, click **Restore original file**, and download the restored file.
6. Compare the restored file with the original. Wrong passphrase should fail authentication.

## Optional AWS S3 integration
The code uses the standard AWS SDK credential chain and the Mumbai region `ap-south-1`. Do not put AWS access keys in the source code or in screenshots.

If AWS CLI is installed and your account is verified, configure an AWS profile in Command Prompt:
```bat
aws configure
```
Use an IAM user's credentials only if your instructor/account owner has intentionally set up an IAM user for this purpose. Do not use root account access keys. If using AWS IAM Identity Center or another organization login, use its approved login flow instead.

Test credentials:
```bat
aws sts get-caller-identity
```
Test bucket access:
```bat
aws s3 ls s3://encrypted-file-project-2026-unique
```
Then run the app and use the **Optional S3** tab. The app uploads only the encrypted ZIP bundle, not the original plaintext file. It requests SSE-S3 on the object (`AES256`) and stores the bundle at `securechunk-demo/securechunk_bundle.zip`.

If API access is not yet enabled for your new AWS account, the local encryption/decryption demo still works. Do not change bucket public-access settings to make uploads work.

## Security notes / limitations
- This is a learning prototype, not a production file-transfer service.
- AES-GCM authenticates encrypted content. The manifest includes a SHA-256 digest to detect accidental or malicious chunk modification before decryption.
- The encryption key is derived from a passphrase using Scrypt with a fresh random salt. Use a strong, unique passphrase. Losing it means the file cannot be decrypted.
- The full file is encrypted in memory before chunking, so use small files for the demo.
- The bundle contains encrypted chunks and non-secret metadata; it does not store the passphrase or derived key.
- S3 SSE-S3 protects the uploaded bundle at rest. It is separate from the client-side encryption.
- The application does not make any S3 object public.
