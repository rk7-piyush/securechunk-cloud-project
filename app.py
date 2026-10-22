import io
import json
import os
import secrets
import tempfile
import zipfile
from pathlib import Path

import streamlit as st
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

APP_TITLE = "SecureChunk — Encrypted File Chunking"
CHUNK_SIZE_DEFAULT = 1024 * 1024  # 1 MiB


def derive_key(passphrase: str, salt: bytes) -> bytes:
    if len(passphrase) < 12:
        raise ValueError("Use a passphrase of at least 12 characters.")
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    return kdf.derive(passphrase.encode("utf-8"))


def build_encrypted_bundle(filename: str, data: bytes, passphrase: str, chunk_size: int):
    if not data:
        raise ValueError("Please choose a non-empty file.")
    if chunk_size < 64 * 1024:
        raise ValueError("Chunk size must be at least 64 KiB.")
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    key = derive_key(passphrase, salt)
    ciphertext = AESGCM(key).encrypt(nonce, data, filename.encode("utf-8"))
    chunks = [ciphertext[i:i + chunk_size] for i in range(0, len(ciphertext), chunk_size)]
    manifest = {
        "format": "securechunk-v1",
        "original_filename": Path(filename).name,
        "original_size_bytes": len(data),
        "chunk_size_bytes": chunk_size,
        "chunk_count": len(chunks),
        "cipher": "AES-256-GCM",
        "key_derivation": "scrypt (N=16384, r=8, p=1)",
        "salt_hex": salt.hex(),
        "nonce_hex": nonce.hex(),
        "aad_filename": Path(filename).name,
        "ciphertext_sha256": __import__("hashlib").sha256(ciphertext).hexdigest(),
        "note": "The passphrase is never stored in this bundle."
    }
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr("manifest.json", json.dumps(manifest, indent=2))
        for i, chunk in enumerate(chunks):
            zf.writestr(f"chunks/chunk_{i:05d}.bin", chunk)
    return output.getvalue(), manifest, chunks


def decrypt_bundle(bundle_bytes: bytes, passphrase: str):
    try:
        with zipfile.ZipFile(io.BytesIO(bundle_bytes), "r") as zf:
            manifest = json.loads(zf.read("manifest.json"))
            if manifest.get("format") != "securechunk-v1":
                raise ValueError("This is not a supported SecureChunk bundle.")
            parts = []
            for i in range(manifest["chunk_count"]):
                parts.append(zf.read(f"chunks/chunk_{i:05d}.bin"))
            ciphertext = b"".join(parts)
    except (KeyError, zipfile.BadZipFile, json.JSONDecodeError) as exc:
        raise ValueError("The bundle is incomplete or invalid.") from exc

    import hashlib
    if hashlib.sha256(ciphertext).hexdigest() != manifest["ciphertext_sha256"]:
        raise ValueError("Integrity check failed: encrypted chunks were changed or corrupted.")
    salt = bytes.fromhex(manifest["salt_hex"])
    nonce = bytes.fromhex(manifest["nonce_hex"])
    key = derive_key(passphrase, salt)
    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, manifest["aad_filename"].encode("utf-8"))
    except Exception as exc:
        raise ValueError("Decryption failed. Check the passphrase or bundle integrity.") from exc
    if len(plaintext) != manifest["original_size_bytes"]:
        raise ValueError("Restored file size does not match the manifest.")
    return manifest["original_filename"], plaintext, manifest


def get_s3_client():
    import boto3
    return boto3.client("s3", region_name="ap-south-1")


def upload_bundle_to_s3(bundle_bytes: bytes, bucket: str, prefix: str):
    # Upload only the encrypted bundle. S3 applies the bucket's default SSE-S3 encryption.
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError
    client = boto3.client("s3", region_name="ap-south-1")
    key = f"{prefix.strip('/')}/securechunk_bundle.zip" if prefix.strip("/") else "securechunk_bundle.zip"
    client.put_object(
        Bucket=bucket,
        Key=key,
        Body=bundle_bytes,
        ContentType="application/zip",
        ServerSideEncryption="AES256",
    )
    return key


def download_bundle_from_s3(bucket: str, key: str):
    import boto3
    client = boto3.client("s3", region_name="ap-south-1")
    response = client.get_object(Bucket=bucket, Key=key)
    return response["Body"].read()


st.set_page_config(page_title=APP_TITLE, page_icon="🔐", layout="centered")
st.title("🔐 SecureChunk")
st.caption("Local file encryption • Chunking • Integrity checks • Optional private S3 storage")
st.info("Your passphrase is not saved. Keep it safe: if you lose it, the file cannot be decrypted. This demo encrypts the whole file first, then splits the ciphertext into chunks.")

encrypt_tab, decrypt_tab, s3_tab, about_tab = st.tabs(["Encrypt & chunk", "Restore file", "Optional S3", "Project notes"])

with encrypt_tab:
    st.subheader("1. Encrypt a file and split it into chunks")
    uploaded = st.file_uploader("Choose a file to protect", key="encrypt_upload")
    passphrase = st.text_input("Create a passphrase (12+ characters)", type="password", key="encrypt_pass")
    chunk_size_kib = st.select_slider("Chunk size", options=[64, 128, 256, 512, 1024, 2048, 4096], value=1024, format_func=lambda x: f"{x} KiB")
    if st.button("Encrypt and create bundle", type="primary", disabled=not uploaded):
        try:
            bundle, manifest, chunks = build_encrypted_bundle(
                uploaded.name, uploaded.getvalue(), passphrase, chunk_size_kib * 1024
            )
            st.session_state["last_bundle"] = bundle
            st.session_state["last_manifest"] = manifest
            st.session_state["last_bundle_name"] = f"{Path(uploaded.name).name}.securechunk.zip"
            st.success(f"Encrypted successfully and split into {len(chunks)} chunk(s).")
            st.json({k: v for k, v in manifest.items() if k not in ("salt_hex", "nonce_hex")})
            st.download_button(
                "Download encrypted bundle",
                data=bundle,
                file_name=st.session_state["last_bundle_name"],
                mime="application/zip",
            )
        except Exception as e:
            st.error(str(e))
    if "last_bundle" in st.session_state:
        st.download_button(
            "Download bundle again",
            data=st.session_state["last_bundle"],
            file_name=st.session_state.get("last_bundle_name", "securechunk_bundle.zip"),
            mime="application/zip",
            key="download_bundle_again",
        )

with decrypt_tab:
    st.subheader("2. Reassemble chunks and decrypt")
    encrypted_bundle = st.file_uploader("Choose a .securechunk.zip bundle", type=["zip"], key="decrypt_upload")
    decrypt_pass = st.text_input("Enter the original passphrase", type="password", key="decrypt_pass")
    if st.button("Restore original file", type="primary", disabled=not encrypted_bundle):
        try:
            filename, plaintext, manifest = decrypt_bundle(encrypted_bundle.getvalue(), decrypt_pass)
            st.success(f"Restored and verified: {filename} ({len(plaintext):,} bytes).")
            st.download_button("Download restored file", data=plaintext, file_name=filename, key="restored_download")
        except Exception as e:
            st.error(str(e))

with s3_tab:
    st.subheader("3. Optional: store the encrypted bundle in S3")
    st.warning("Only try this after AWS account verification/API access works. Never paste access keys into this app. Configure credentials with AWS CLI or an AWS profile on your computer.")
    bucket_name = st.text_input("Your S3 bucket name", value="encrypted-file-project-2026-unique")
    object_prefix = st.text_input("S3 object prefix (folder)", value="securechunk-demo")
    if st.button("Upload latest encrypted bundle to S3", disabled="last_bundle" not in st.session_state):
        try:
            object_key = upload_bundle_to_s3(st.session_state["last_bundle"], bucket_name, object_prefix)
            st.success(f"Uploaded encrypted bundle to s3://{bucket_name}/{object_key}")
        except Exception as e:
            st.error(f"S3 upload failed: {e}")
    st.markdown("**Download an encrypted bundle from S3**")
    s3_key = st.text_input("Exact S3 object key", value="securechunk-demo/securechunk_bundle.zip")
    if st.button("Download encrypted bundle from S3"):
        try:
            data = download_bundle_from_s3(bucket_name, s3_key)
            st.download_button("Save encrypted bundle", data=data, file_name="securechunk_bundle.zip", mime="application/zip", key="s3_bundle_download")
            st.success("Bundle fetched from S3. Save it, then use the Restore file tab to decrypt it.")
        except Exception as e:
            st.error(f"S3 download failed: {e}")

with about_tab:
    st.subheader("How it works")
    st.markdown("""
- **AES-256-GCM:** encrypts and authenticates the original file.
- **Scrypt:** derives a 256-bit encryption key from your passphrase and a random salt.
- **Chunking:** splits the encrypted bytes into separate numbered chunks.
- **Manifest:** records chunk count, nonce, salt, size, and ciphertext hash; it does not contain your passphrase.
- **S3:** optional upload stores the encrypted ZIP bundle; the bucket applies SSE-S3 server-side encryption too.
- **Privacy:** the local encryption/decryption process happens in this app on your computer.
""")
    st.caption("Academic prototype: for very large files, use streaming/chunk-by-chunk authenticated encryption rather than loading the entire file into memory.")
