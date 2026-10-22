# SecureChunk

Encrypts a file in chunks, stores every encrypted chunk in an AWS S3 bucket, and restores the original file on download.

## How it behaves
- **Upload:** the file is split into chunks of the size you pick. Each chunk is encrypted on its own with AES-256-GCM and uploaded straight to S3 as `<folder>/<file id>/chunk_00000.bin`, `chunk_00001.bin`, and so on. A `manifest.json` is written last. Nothing is saved locally and no plaintext reaches S3.
- **Confirmation:** after upload the app asks S3 for every object again and shows the bucket, folder, chunk count, chunk sizes, hashes and per-chunk S3 status.
- **Download:** open **Stored files**, enter the passphrase and click **Download and decrypt**. The chunks are fetched from S3, checked, decrypted, reassembled and offered as the original file.
- **Integrity:** every chunk is bound to its file, position and total chunk count. Edited, swapped, removed or corrupted chunks make decryption fail. The restored file's SHA-256 is compared with the original.

## Run on Windows
1. Install Python 3.10 or newer from https://www.python.org/downloads/windows/ (tick **Add python.exe to PATH**).
2. In Command Prompt, inside this folder:
   ```bat
   py -m venv .venv
   .venv\Scripts\activate
   python -m pip install --upgrade pip
   pip install -r requirements.txt
   streamlit run app.py
   ```
3. Open http://localhost:8501.

## AWS setup
The app finds credentials in this order:
1. `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` (+ optional `AWS_SESSION_TOKEN`) from `.streamlit/secrets.toml` or environment variables.
2. The AWS profile named by `AWS_PROFILE` (default `securechunk-login`), if it exists.
3. The normal boto3 credential chain.

Bucket, folder and region can be changed in the sidebar, or preset through `S3_BUCKET`, `S3_PREFIX` and `AWS_REGION` (see `.streamlit/secrets.example.toml`). Defaults: bucket `encrypted-file-project-2026-unique`, folder `securechunk-demo`, region `ap-south-1`.

Check access from Command Prompt:
```bat
aws sts get-caller-identity
aws s3 ls s3://encrypted-file-project-2026-unique
```

The IAM identity needs on that bucket: `s3:PutObject`, `s3:GetObject`, and `s3:ListBucket`. `s3:DeleteObject` is optional and lets the app remove partial uploads if one fails.

## Files
- `app.py` – Streamlit interface
- `core.py` – chunked encryption, S3 upload/download, listing
- `.streamlit/config.toml` – theme and upload limit (1 GB)
