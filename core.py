"""Chunked encryption and S3 storage logic for SecureChunk.

Everything here is independent of the UI so it can be tested on its own.

Storage layout in S3 (one folder per uploaded file):

    <prefix>/<file_id>/chunk_00000.bin     encrypted chunk 0
    <prefix>/<file_id>/chunk_00001.bin     encrypted chunk 1
    ...
    <prefix>/<file_id>/manifest.json       metadata (written last)

Each chunk is encrypted independently with AES-256-GCM. The nonce is unique per
chunk, and the authenticated data binds every chunk to its file, its position
and the total chunk count, so chunks cannot be swapped, reordered, dropped or
replayed from another file without the decryption failing.
"""

from __future__ import annotations

import hashlib
import json
import math
import mimetypes
import re
import secrets
import struct
import uuid
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from datetime import datetime, timezone
from typing import BinaryIO, Callable, Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

FORMAT = "securechunk-v2"
MANIFEST_NAME = "manifest.json"
MIN_CHUNK_BYTES = 64 * 1024
MIN_PASSPHRASE_LEN = 12
SCRYPT_PARAMS = {"n": 2**14, "r": 8, "p": 1}
MAX_CHUNKS = 100_000

ProgressFn = Callable[[str, int, int], None]


class SecureChunkError(Exception):
    """Raised for any user-facing failure (bad passphrase, S3 error, tampering...)."""


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #
def fmt_bytes(n: int) -> str:
    size = float(n)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if size < 1024 or unit == "TiB":
            return f"{int(size)} {unit}" if unit == "B" else f"{size:,.2f} {unit}"
        size /= 1024
    return f"{n} B"


def clean_filename(name: str) -> str:
    """Keep only the final path component, whatever separator the browser used."""
    base = re.split(r"[\\/]", name or "")[-1].strip()
    return base or "file"


def chunk_name(index: int) -> str:
    return f"chunk_{index:05d}.bin"


def _join_key(*parts: str) -> str:
    return "/".join(p.strip("/") for p in parts if p and p.strip("/"))


def derive_key(passphrase: str, salt: bytes, params: Optional[dict] = None) -> bytes:
    p = params or SCRYPT_PARAMS
    kdf = Scrypt(salt=salt, length=32, n=int(p["n"]), r=int(p["r"]), p=int(p["p"]))
    return kdf.derive(passphrase.encode("utf-8"))


def _meta_digest(filename: str, size: int) -> bytes:
    payload = json.dumps({"name": filename, "size": size}, sort_keys=True).encode("utf-8")
    return hashlib.sha256(payload).digest()


def _aad(file_id: str, meta_digest: bytes, index: int, total: int) -> bytes:
    return b"|".join([FORMAT.encode(), file_id.encode(), meta_digest]) + struct.pack(">II", index, total)


def _nonce(prefix: bytes, index: int) -> bytes:
    return prefix + struct.pack(">I", index)


# --------------------------------------------------------------------------- #
# S3 client
# --------------------------------------------------------------------------- #
def build_s3_client(
    region: str,
    access_key: Optional[str] = None,
    secret_key: Optional[str] = None,
    session_token: Optional[str] = None,
    profile: Optional[str] = None,
):
    """Create an S3 client from explicit keys, a named profile, or the default chain."""
    import boto3
    from botocore.config import Config

    config = Config(retries={"max_attempts": 5, "mode": "standard"}, max_pool_connections=16)

    if access_key and secret_key:
        return boto3.client(
            "s3",
            region_name=region,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            aws_session_token=session_token or None,
            config=config,
        )

    if profile and profile in boto3.session.Session().available_profiles:
        session = boto3.Session(profile_name=profile, region_name=region)
    else:
        session = boto3.Session(region_name=region)
    return session.client("s3", config=config)


def check_connection(client, bucket: str) -> tuple[bool, str]:
    """Return (ok, message) for the configured bucket."""
    if not bucket:
        return False, "No bucket name set"
    try:
        client.head_bucket(Bucket=bucket)
        return True, "Connected"
    except Exception as exc:  # botocore errors vary; show a short reason
        return False, _short_error(exc)


def _short_error(exc: Exception) -> str:
    text = str(exc)
    return text if len(text) < 220 else text[:217] + "..."


# --------------------------------------------------------------------------- #
# Encrypt + upload
# --------------------------------------------------------------------------- #
def encrypt_and_upload(
    client,
    bucket: str,
    prefix: str,
    filename: str,
    stream: BinaryIO,
    size: int,
    passphrase: str,
    chunk_size: int,
    content_type: Optional[str] = None,
    workers: int = 4,
    progress: Optional[ProgressFn] = None,
) -> dict:
    """Encrypt ``stream`` chunk by chunk and store every encrypted chunk in S3.

    Returns a result dict containing the manifest, per-chunk rows and the S3
    verification summary. Plaintext never touches disk or S3.
    """
    filename = clean_filename(filename)
    if size <= 0:
        raise SecureChunkError("The selected file is empty.")
    if chunk_size < MIN_CHUNK_BYTES:
        raise SecureChunkError("Chunk size must be at least 64 KiB.")
    if len(passphrase) < MIN_PASSPHRASE_LEN:
        raise SecureChunkError(f"Use a passphrase of at least {MIN_PASSPHRASE_LEN} characters.")
    total = math.ceil(size / chunk_size)
    if total > MAX_CHUNKS:
        raise SecureChunkError("Too many chunks. Choose a larger chunk size.")

    report = progress or (lambda *_: None)
    file_id = uuid.uuid4().hex
    folder = _join_key(prefix, file_id)
    salt = secrets.token_bytes(16)
    nonce_prefix = secrets.token_bytes(8)
    key = derive_key(passphrase, salt)
    aead = AESGCM(key)
    digest = _meta_digest(filename, size)
    original_hash = hashlib.sha256()

    rows: list[dict] = []
    uploaded_keys: list[str] = []
    puts: dict = {}

    def put_chunk(obj_key: str, body: bytes) -> dict:
        resp = client.put_object(
            Bucket=bucket,
            Key=obj_key,
            Body=body,
            ContentType="application/octet-stream",
            ServerSideEncryption="AES256",
        )
        return {"etag": str(resp.get("ETag", "")).strip('"')}

    try:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            pending = set()
            done_count = 0
            report("Encrypting and uploading chunks", 0, total)

            for index in range(total):
                plain = stream.read(chunk_size)
                if not plain:
                    raise SecureChunkError("The file ended earlier than expected.")
                original_hash.update(plain)
                cipher = aead.encrypt(
                    _nonce(nonce_prefix, index), plain, _aad(file_id, digest, index, total)
                )
                obj_key = _join_key(folder, chunk_name(index))
                rows.append(
                    {
                        "index": index,
                        "plaintext_bytes": len(plain),
                        "encrypted_bytes": len(cipher),
                        "sha256": hashlib.sha256(cipher).hexdigest(),
                        "key": obj_key,
                    }
                )
                uploaded_keys.append(obj_key)
                fut = pool.submit(put_chunk, obj_key, cipher)
                puts[fut] = index
                pending.add(fut)

                if len(pending) >= workers * 2:
                    finished, pending = wait(pending, return_when=FIRST_COMPLETED)
                    for f in finished:
                        rows[puts[f]].update(f.result())
                        done_count += 1
                    report("Encrypting and uploading chunks", done_count, total)

            while pending:
                finished, pending = wait(pending, return_when=FIRST_COMPLETED)
                for f in finished:
                    rows[puts[f]].update(f.result())
                    done_count += 1
                report("Encrypting and uploading chunks", done_count, total)

            if stream.read(1):
                raise SecureChunkError("The file is larger than its reported size.")

            # Ask S3 for each object again so the UI only claims what S3 confirms.
            report("Confirming objects in S3", 0, total)

            def head_chunk(row: dict) -> dict:
                head = client.head_object(Bucket=bucket, Key=row["key"])
                if int(head["ContentLength"]) != row["encrypted_bytes"]:
                    raise SecureChunkError(f"S3 size mismatch for {row['key']}.")
                return {"s3_encryption": head.get("ServerSideEncryption", ""), "verified": True}

            head_futs = {pool.submit(head_chunk, row): row["index"] for row in rows}
            checked = 0
            pending = set(head_futs)
            while pending:
                finished, pending = wait(pending, return_when=FIRST_COMPLETED)
                for f in finished:
                    rows[head_futs[f]].update(f.result())
                    checked += 1
                report("Confirming objects in S3", checked, total)

        encrypted_total = sum(r["encrypted_bytes"] for r in rows)
        uploaded_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
        manifest = {
            "format": FORMAT,
            "file_id": file_id,
            "original_filename": filename,
            "content_type": content_type or mimetypes.guess_type(filename)[0] or "application/octet-stream",
            "original_size_bytes": size,
            "original_sha256": original_hash.hexdigest(),
            "uploaded_at": uploaded_at,
            "chunk_size_bytes": chunk_size,
            "chunk_count": total,
            "encrypted_size_bytes": encrypted_total,
            "cipher": "AES-256-GCM",
            "key_derivation": {"name": "scrypt", **SCRYPT_PARAMS},
            "salt_hex": salt.hex(),
            "nonce_prefix_hex": nonce_prefix.hex(),
            "chunks": [
                {
                    "index": r["index"],
                    "plaintext_bytes": r["plaintext_bytes"],
                    "encrypted_bytes": r["encrypted_bytes"],
                    "sha256": r["sha256"],
                }
                for r in rows
            ],
        }
        manifest_key = _join_key(folder, MANIFEST_NAME)
        report("Writing manifest", 0, 1)
        client.put_object(
            Bucket=bucket,
            Key=manifest_key,
            Body=json.dumps(manifest, indent=2).encode("utf-8"),
            ContentType="application/json",
            ServerSideEncryption="AES256",
        )
        client.head_object(Bucket=bucket, Key=manifest_key)
        report("Writing manifest", 1, 1)
        uploaded_keys.append(manifest_key)

    except SecureChunkError:
        _cleanup(client, bucket, uploaded_keys)
        raise
    except Exception as exc:
        _cleanup(client, bucket, uploaded_keys)
        raise SecureChunkError(f"S3 upload failed: {_short_error(exc)}") from exc

    return {
        "manifest": manifest,
        "chunks": rows,
        "bucket": bucket,
        "folder": folder,
        "manifest_key": manifest_key,
        "stored_objects": len(rows) + 1,
        "verified_objects": sum(1 for r in rows if r.get("verified")) + 1,
    }


def _cleanup(client, bucket: str, keys: list[str]) -> None:
    """Best-effort removal of partial uploads after a failure."""
    for i in range(0, len(keys), 1000):
        batch = keys[i : i + 1000]
        try:
            client.delete_objects(
                Bucket=bucket, Delete={"Objects": [{"Key": k} for k in batch], "Quiet": True}
            )
        except Exception:
            pass


# --------------------------------------------------------------------------- #
# List stored files
# --------------------------------------------------------------------------- #
def list_stored_files(client, bucket: str, prefix: str, workers: int = 8, limit: int = 200) -> list[dict]:
    """Return one entry per stored file (newest first), read from its manifest."""
    base = prefix.strip("/")
    list_prefix = f"{base}/" if base else ""
    manifest_keys: list[str] = []
    token = None
    try:
        while True:
            kwargs = {"Bucket": bucket, "Prefix": list_prefix}
            if token:
                kwargs["ContinuationToken"] = token
            resp = client.list_objects_v2(**kwargs)
            for obj in resp.get("Contents", []):
                if obj["Key"].endswith("/" + MANIFEST_NAME):
                    manifest_keys.append(obj["Key"])
            if not resp.get("IsTruncated"):
                break
            token = resp.get("NextContinuationToken")
    except Exception as exc:
        raise SecureChunkError(f"Could not list files in S3: {_short_error(exc)}") from exc

    def read(key: str) -> Optional[dict]:
        try:
            body = client.get_object(Bucket=bucket, Key=key)["Body"].read()
            manifest = json.loads(body)
            if manifest.get("format") != FORMAT:
                return None
            return {"manifest_key": key, "manifest": manifest}
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=workers) as pool:
        found = [item for item in pool.map(read, manifest_keys) if item]
    found.sort(key=lambda it: it["manifest"].get("uploaded_at", ""), reverse=True)
    return found[:limit]


# --------------------------------------------------------------------------- #
# Download + decrypt
# --------------------------------------------------------------------------- #
def download_and_decrypt(
    client,
    bucket: str,
    manifest_key: str,
    passphrase: str,
    workers: int = 4,
    progress: Optional[ProgressFn] = None,
) -> dict:
    """Fetch every chunk from S3, verify, decrypt and reassemble the original file."""
    report = progress or (lambda *_: None)

    try:
        report("Reading manifest", 0, 1)
        manifest = json.loads(client.get_object(Bucket=bucket, Key=manifest_key)["Body"].read())
    except Exception as exc:
        raise SecureChunkError(f"Could not read the file manifest from S3: {_short_error(exc)}") from exc

    if manifest.get("format") != FORMAT:
        raise SecureChunkError("This file was not stored by this version of SecureChunk.")
    try:
        file_id = manifest["file_id"]
        filename = clean_filename(manifest["original_filename"])
        size = int(manifest["original_size_bytes"])
        total = int(manifest["chunk_count"])
        chunk_rows = manifest["chunks"]
        salt = bytes.fromhex(manifest["salt_hex"])
        nonce_prefix = bytes.fromhex(manifest["nonce_prefix_hex"])
        kdf_params = manifest["key_derivation"]
    except (KeyError, ValueError, TypeError) as exc:
        raise SecureChunkError("The file manifest is incomplete or invalid.") from exc
    if total < 1 or total > MAX_CHUNKS or len(chunk_rows) != total:
        raise SecureChunkError("The file manifest is incomplete or invalid.")

    folder = manifest_key.rsplit("/", 1)[0] if "/" in manifest_key else ""
    digest = _meta_digest(filename, size)
    report("Deriving key", 0, 1)
    aead = AESGCM(derive_key(passphrase, salt, kdf_params))

    def fetch_and_decrypt(index: int) -> bytes:
        row = chunk_rows[index]
        obj_key = _join_key(folder, chunk_name(index))
        try:
            cipher = client.get_object(Bucket=bucket, Key=obj_key)["Body"].read()
        except Exception as exc:
            raise SecureChunkError(f"Chunk {index + 1} could not be read from S3: {_short_error(exc)}") from exc
        if hashlib.sha256(cipher).hexdigest() != row["sha256"]:
            raise SecureChunkError(f"Integrity check failed: chunk {index + 1} was changed or corrupted.")
        try:
            return aead.decrypt(_nonce(nonce_prefix, index), cipher, _aad(file_id, digest, index, total))
        except InvalidTag as exc:
            raise SecureChunkError("Decryption failed. Check the passphrase.") from exc

    # Decrypt chunk 0 first so a wrong passphrase fails immediately.
    parts: list[Optional[bytes]] = [None] * total
    report("Downloading and decrypting chunks", 0, total)
    parts[0] = fetch_and_decrypt(0)
    done_count = 1
    report("Downloading and decrypting chunks", done_count, total)

    if total > 1:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futs = {pool.submit(fetch_and_decrypt, i): i for i in range(1, total)}
            pending = set(futs)
            while pending:
                finished, pending = wait(pending, return_when=FIRST_COMPLETED)
                for f in finished:
                    parts[futs[f]] = f.result()
                    done_count += 1
                report("Downloading and decrypting chunks", done_count, total)

    data = b"".join(parts)  # type: ignore[arg-type]
    if len(data) != size:
        raise SecureChunkError("Restored file size does not match the manifest.")
    if hashlib.sha256(data).hexdigest() != manifest["original_sha256"]:
        raise SecureChunkError("Restored file checksum does not match the manifest.")

    return {
        "filename": filename,
        "data": data,
        "content_type": manifest.get("content_type") or "application/octet-stream",
        "manifest": manifest,
    }
