import html
import os
from datetime import datetime

import streamlit as st

import core
from core import SecureChunkError, fmt_bytes

APP_TITLE = "SecureChunk"
DEFAULT_BUCKET = "encrypted-file-project-2026-unique"
DEFAULT_PREFIX = "securechunk-demo"
DEFAULT_REGION = "ap-south-1"
DEFAULT_PROFILE = "securechunk-login"
CHUNK_OPTIONS_KIB = [64, 128, 256, 512, 1024, 2048, 4096]

st.set_page_config(page_title=APP_TITLE, page_icon="🔐", layout="centered", initial_sidebar_state="expanded")

# --------------------------------------------------------------------------- #
# Styling
# --------------------------------------------------------------------------- #
CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Figtree:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
:root{
  --ink:#0E1A2B; --muted:#5B6B7F; --paper:#F1F4F9; --surface:#FFFFFF; --line:#D9E0EA;
  --primary:#2F45C5; --primary-soft:#E6EAFB; --ok:#16794C; --ok-soft:#E4F3EA; --ok-line:#BFE0CC;
  --bad:#B42318; --bad-soft:#FDECEA;
}
.stApp, .stApp p, .stApp label, .stApp input, .stApp textarea, .stApp button, .stApp h1, .stApp h2, .stApp h3{
  font-family:'Figtree', system-ui, -apple-system, 'Segoe UI', sans-serif;
}
.block-container{ max-width:980px; padding-top:2.2rem; padding-bottom:4rem; }
#MainMenu, footer{ visibility:hidden; }

/* header */
.sc-header{ display:flex; align-items:center; justify-content:space-between; gap:16px; margin-bottom:1.1rem; flex-wrap:wrap; }
.sc-brand{ display:flex; align-items:center; gap:12px; }
.sc-title{ font-size:1.75rem; font-weight:700; letter-spacing:-0.02em; color:var(--ink); line-height:1; }
.sc-pill{ display:inline-flex; align-items:center; gap:8px; padding:6px 12px; border-radius:999px; font-size:.82rem; font-weight:600; border:1px solid; }
.sc-pill i{ width:8px; height:8px; border-radius:50%; background:currentColor; }
.sc-pill.ok{ color:var(--ok); background:var(--ok-soft); border-color:var(--ok-line); }
.sc-pill.bad{ color:var(--bad); background:var(--bad-soft); border-color:#F3C3BE; }
.sc-pill span{ font-family:'JetBrains Mono', monospace; font-weight:500; font-size:.78rem; }

/* tabs */
.stTabs [data-baseweb="tab-list"]{ gap:6px; border-bottom:1px solid var(--line); }
.stTabs button[data-baseweb="tab"]{ font-weight:600; padding:.55rem 1rem; }
.stTabs [data-baseweb="tab-highlight"]{ background:var(--primary); height:3px; }

/* surfaces */
[data-testid="stForm"]{ background:var(--surface); border:1px solid var(--line); border-radius:14px; padding:1.4rem 1.4rem 1.2rem; }
[data-testid="stVerticalBlockBorderWrapper"]{ border-radius:14px; }
[data-testid="stMetric"]{ background:var(--surface); border:1px solid var(--line); border-radius:12px; padding:14px 16px; }
[data-testid="stMetricLabel"] p{ color:var(--muted); font-weight:500; font-size:.85rem; }
[data-testid="stMetricValue"]{ font-weight:700; letter-spacing:-0.01em; }
.stButton button, .stDownloadButton button, .stFormSubmitButton button{ border-radius:9px; font-weight:600; }
[data-testid="stSidebar"]{ border-right:1px solid var(--line); }
.sc-side-title{ font-weight:700; font-size:1rem; margin-bottom:.4rem; }

/* upload result */
.sc-banner{ display:flex; gap:14px; align-items:flex-start; padding:16px 18px; border-radius:14px; border:1px solid var(--ok-line); background:var(--ok-soft); margin:1.4rem 0 1rem; }
.sc-banner-icon{ flex:0 0 34px; height:34px; border-radius:50%; background:var(--ok); display:flex; align-items:center; justify-content:center; }
.sc-banner-title{ font-weight:700; font-size:1.1rem; color:var(--ok); }
.sc-banner-sub{ color:var(--ink); font-size:.92rem; margin-top:2px; overflow-wrap:anywhere; }
.sc-banner-sub code{ font-family:'JetBrains Mono', monospace; font-size:.82rem; background:rgba(255,255,255,.7); padding:1px 6px; border-radius:5px; }
.sc-h{ font-weight:700; font-size:1.05rem; margin:1.6rem 0 .6rem; color:var(--ink); }

/* key/value metadata */
.sc-kv{ display:grid; grid-template-columns:190px 1fr; margin:0; background:var(--surface); border:1px solid var(--line); border-radius:12px; overflow:hidden; }
.sc-kv dt, .sc-kv dd{ margin:0; padding:10px 16px; border-bottom:1px solid var(--line); font-size:.92rem; }
.sc-kv dt{ color:var(--muted); font-weight:500; background:#FAFBFD; }
.sc-kv dd{ color:var(--ink); word-break:break-all; }
.sc-kv dt:nth-last-of-type(1), .sc-kv dd:nth-last-of-type(1){ border-bottom:none; }
.sc-kv dd.mono{ font-family:'JetBrains Mono', monospace; font-size:.8rem; }
@media (max-width:640px){ .sc-kv{ grid-template-columns:1fr; } .sc-kv dt{ border-bottom:none; padding-bottom:0; background:var(--surface);} }

/* chunk map */
.sc-map{ display:flex; flex-wrap:wrap; gap:4px; padding:14px; background:var(--surface); border:1px solid var(--line); border-radius:12px; }
.sc-map i{ width:16px; height:26px; border-radius:4px; background:var(--primary); }
.sc-map-note{ color:var(--muted); font-size:.82rem; margin:.4rem .2rem 0; }

/* stored files */
.sc-file-name{ font-weight:700; font-size:1.05rem; color:var(--ink); word-break:break-all; }
.sc-tags{ display:flex; gap:8px; flex-wrap:wrap; margin:.35rem 0 .7rem; }
.sc-tags span{ background:var(--primary-soft); color:var(--primary); font-weight:600; font-size:.78rem; padding:3px 10px; border-radius:999px; }
.sc-empty{ text-align:center; color:var(--muted); padding:2.2rem 1rem; border:1px dashed var(--line); border-radius:14px; background:var(--surface); }
</style>
"""
st.markdown(CSS, unsafe_allow_html=True)


# --------------------------------------------------------------------------- #
# Settings and S3 access
# --------------------------------------------------------------------------- #
def _setting(name, default=None):
    """Read a value from Streamlit secrets, then environment variables."""
    try:
        value = st.secrets.get(name)
    except Exception:
        value = None
    return value or os.getenv(name) or default


@st.cache_resource(ttl=900, show_spinner=False)
def get_client(region: str):
    return core.build_s3_client(
        region=region,
        access_key=_setting("AWS_ACCESS_KEY_ID"),
        secret_key=_setting("AWS_SECRET_ACCESS_KEY"),
        session_token=_setting("AWS_SESSION_TOKEN"),
        profile=_setting("AWS_PROFILE", DEFAULT_PROFILE),
    )


@st.cache_data(ttl=60, show_spinner=False)
def connection_status(bucket: str, region: str):
    try:
        return core.check_connection(get_client(region), bucket)
    except Exception as exc:
        return False, str(exc)


def friendly_date(iso_text: str) -> str:
    try:
        return datetime.fromisoformat(iso_text).strftime("%d %b %Y, %H:%M UTC")
    except (TypeError, ValueError):
        return iso_text or "-"


def esc(value) -> str:
    return html.escape(str(value), quote=True)


def dataframe(rows):
    try:
        st.dataframe(rows, hide_index=True, width="stretch")
    except Exception:
        st.dataframe(rows, hide_index=True)


# --------------------------------------------------------------------------- #
# Sidebar: storage target
# --------------------------------------------------------------------------- #
with st.sidebar:
    st.markdown('<div class="sc-side-title">Storage</div>', unsafe_allow_html=True)
    bucket = st.text_input("S3 bucket", value=_setting("S3_BUCKET", DEFAULT_BUCKET)).strip()
    prefix = st.text_input("Folder", value=_setting("S3_PREFIX", DEFAULT_PREFIX)).strip().strip("/")
    region = st.text_input("Region", value=_setting("AWS_REGION", DEFAULT_REGION)).strip()
    if st.button("Check connection"):
        connection_status.clear()
        get_client.clear()
        st.session_state["files_cache"] = None

connected, status_message = connection_status(bucket, region)

# --------------------------------------------------------------------------- #
# Header
# --------------------------------------------------------------------------- #
LOGO = (
    '<svg width="32" height="32" viewBox="0 0 32 32" aria-hidden="true">'
    '<rect x="5" y="14" width="22" height="14" rx="3" fill="#2F45C5"/>'
    '<path d="M10 14v-3a6 6 0 0 1 12 0v3" fill="none" stroke="#2F45C5" stroke-width="3" stroke-linecap="round"/>'
    '<path d="M12.4 17.5v7M16 17.5v7M19.6 17.5v7" stroke="#fff" stroke-width="1.6" stroke-linecap="round" opacity=".9"/>'
    "</svg>"
)
if connected:
    pill = f'<div class="sc-pill ok"><i></i>Connected <span>s3://{esc(bucket)}</span></div>'
else:
    pill = f'<div class="sc-pill bad" title="{esc(status_message)}"><i></i>S3 not reachable</div>'
st.markdown(
    f'<div class="sc-header"><div class="sc-brand">{LOGO}<div class="sc-title">{APP_TITLE}</div></div>{pill}</div>',
    unsafe_allow_html=True,
)
if not connected:
    st.warning(f"Could not reach the S3 bucket: {status_message}")


# --------------------------------------------------------------------------- #
# Rendering helpers
# --------------------------------------------------------------------------- #
def kv_html(pairs):
    parts = ['<dl class="sc-kv">']
    for label, value, *flags in pairs:
        cls = ' class="mono"' if flags and flags[0] else ""
        parts.append(f"<dt>{esc(label)}</dt><dd{cls}>{esc(value)}</dd>")
    parts.append("</dl>")
    return "".join(parts)


def chunk_map_html(count: int, sizes):
    max_blocks = 120
    group = -(-count // max_blocks)
    blocks = []
    for lo in range(0, count, group):
        hi = min(count, lo + group)
        label = f"Chunk {lo + 1}" if hi - lo == 1 else f"Chunks {lo + 1} to {hi}"
        blocks.append(f'<i title="{label} - {fmt_bytes(sum(sizes[lo:hi]))} encrypted"></i>')
    note = f"{count} encrypted chunk{'s' if count != 1 else ''}"
    if group > 1:
        note += f", {group} per block"
    return f'<div class="sc-map">{"".join(blocks)}</div><div class="sc-map-note">{note}</div>'


def metadata_pairs(manifest: dict, bucket_name: str, folder: str, region_name: str):
    kdf = manifest["key_derivation"]
    return [
        ("File name", manifest["original_filename"]),
        ("File type", manifest.get("content_type", "-")),
        ("Original size", f"{fmt_bytes(manifest['original_size_bytes'])} ({manifest['original_size_bytes']:,} bytes)"),
        ("Original SHA-256", manifest["original_sha256"], True),
        ("Chunk size", fmt_bytes(manifest["chunk_size_bytes"])),
        ("Number of chunks", f"{manifest['chunk_count']}"),
        ("Encrypted size", f"{fmt_bytes(manifest['encrypted_size_bytes'])} ({manifest['encrypted_size_bytes']:,} bytes)"),
        ("Cipher", manifest["cipher"]),
        ("Key derivation", f"{kdf['name']} (N={kdf['n']}, r={kdf['r']}, p={kdf['p']})"),
        ("File ID", manifest["file_id"], True),
        ("Uploaded", friendly_date(manifest["uploaded_at"])),
        ("S3 location", f"s3://{bucket_name}/{folder}/", True),
        ("Region", region_name),
    ]


def chunk_table(manifest: dict, folder: str, verified: dict | None = None):
    rows = []
    for c in manifest["chunks"]:
        row = {
            "Chunk": c["index"] + 1,
            "Original bytes": f"{c['plaintext_bytes']:,}",
            "Encrypted bytes": f"{c['encrypted_bytes']:,}",
            "SHA-256 (encrypted)": c["sha256"][:24] + "...",
            "S3 object": f"{folder}/{core.chunk_name(c['index'])}",
        }
        if verified is not None:
            row["In S3"] = "Confirmed" if verified.get(c["index"]) else "Not confirmed"
        rows.append(row)
    return rows


def render_details(manifest, bucket_name, folder, region_name, verified=None):
    st.markdown(kv_html(metadata_pairs(manifest, bucket_name, folder, region_name)), unsafe_allow_html=True)
    st.markdown('<div class="sc-h">Chunk map</div>', unsafe_allow_html=True)
    sizes = [c["encrypted_bytes"] for c in manifest["chunks"]]
    st.markdown(chunk_map_html(len(sizes), sizes), unsafe_allow_html=True)
    st.markdown('<div class="sc-h">Chunks</div>', unsafe_allow_html=True)
    dataframe(chunk_table(manifest, folder, verified))


def render_upload_result(res: dict):
    manifest = res["manifest"]
    n = manifest["chunk_count"]
    check = (
        '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="3" '
        'stroke-linecap="round" stroke-linejoin="round"><path d="M5 12.5l4.5 4.5L19 7.5"/></svg>'
    )
    st.markdown(
        f'<div class="sc-banner"><div class="sc-banner-icon">{check}</div><div>'
        f'<div class="sc-banner-title">Stored in AWS S3</div>'
        f'<div class="sc-banner-sub">{esc(manifest["original_filename"])} was encrypted in {n} chunk{"s" if n != 1 else ""}. '
        f'S3 confirmed all {res["verified_objects"]} objects in <code>s3://{esc(res["bucket"])}/{esc(res["folder"])}/</code></div>'
        f"</div></div>",
        unsafe_allow_html=True,
    )
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Original size", fmt_bytes(manifest["original_size_bytes"]))
    c2.metric("Chunks", n)
    c3.metric("Chunk size", fmt_bytes(manifest["chunk_size_bytes"]))
    c4.metric("Stored in S3", fmt_bytes(manifest["encrypted_size_bytes"]))
    st.markdown('<div class="sc-h">File metadata</div>', unsafe_allow_html=True)
    verified = {c["index"]: c.get("verified", False) for c in res["chunks"]}
    render_details(manifest, res["bucket"], res["folder"], res["region"], verified)


STAGE_RANGES = {
    "Encrypting and uploading chunks": (0.0, 0.70),
    "Confirming objects in S3": (0.70, 0.95),
    "Writing manifest": (0.95, 1.0),
    "Reading manifest": (0.0, 0.05),
    "Deriving key": (0.05, 0.10),
    "Downloading and decrypting chunks": (0.10, 1.0),
}


def make_progress(label: str):
    bar = st.progress(0.0, text=label)

    def update(stage: str, done: int, total: int):
        lo, hi = STAGE_RANGES.get(stage, (0.0, 1.0))
        fraction = lo + (hi - lo) * (done / total if total else 1)
        text = f"{stage} ({done}/{total})" if total > 1 else stage
        bar.progress(min(max(fraction, 0.0), 1.0), text=text)

    return bar, update


# --------------------------------------------------------------------------- #
# Tabs
# --------------------------------------------------------------------------- #
upload_tab, files_tab = st.tabs(["Upload", "Stored files"])

with upload_tab:
    with st.form("upload_form"):
        uploaded = st.file_uploader("File to encrypt and upload")
        col_a, col_b = st.columns(2)
        passphrase = col_a.text_input("Passphrase", type="password", placeholder="At least 12 characters")
        confirm = col_b.text_input("Confirm passphrase", type="password")
        chunk_kib = st.select_slider(
            "Chunk size",
            options=CHUNK_OPTIONS_KIB,
            value=1024,
            format_func=lambda k: f"{k} KiB" if k < 1024 else f"{k // 1024} MiB",
        )
        submitted = st.form_submit_button("Encrypt and upload to S3", type="primary")

    if submitted:
        problem = None
        if uploaded is None:
            problem = "Choose a file first."
        elif len(passphrase) < core.MIN_PASSPHRASE_LEN:
            problem = f"Use a passphrase of at least {core.MIN_PASSPHRASE_LEN} characters."
        elif passphrase != confirm:
            problem = "The two passphrases do not match."
        elif not bucket:
            problem = "Enter an S3 bucket name in the sidebar."

        if problem:
            st.error(problem)
        else:
            bar, on_progress = make_progress("Starting")
            try:
                uploaded.seek(0)
                result = core.encrypt_and_upload(
                    get_client(region),
                    bucket,
                    prefix,
                    uploaded.name,
                    uploaded,
                    uploaded.size,
                    passphrase,
                    chunk_kib * 1024,
                    content_type=uploaded.type,
                    progress=on_progress,
                )
                result["region"] = region
                st.session_state["last_upload"] = result
                st.session_state.setdefault("remembered", {})[result["manifest"]["file_id"]] = passphrase
                st.session_state["files_cache"] = None  # refresh the stored-files list
            except SecureChunkError as exc:
                st.error(str(exc))
            except Exception as exc:
                st.error(f"Something went wrong: {exc}")
            finally:
                bar.empty()

    if st.session_state.get("last_upload"):
        render_upload_result(st.session_state["last_upload"])


def load_files():
    cache = st.session_state.get("files_cache")
    if cache is None or cache.get("key") != (bucket, prefix, region):
        try:
            items = core.list_stored_files(get_client(region), bucket, prefix)
            cache = {"key": (bucket, prefix, region), "items": items, "error": None}
        except Exception as exc:
            cache = {"key": (bucket, prefix, region), "items": [], "error": str(exc)}
        st.session_state["files_cache"] = cache
    return cache


with files_tab:
    top_left, top_right = st.columns([4, 1], vertical_alignment="center")
    if top_right.button("Refresh", key="refresh_files"):
        st.session_state["files_cache"] = None
    cache = load_files()
    top_left.markdown(
        f'<div class="sc-h" style="margin:0">{len(cache["items"])} file{"s" if len(cache["items"]) != 1 else ""} in S3</div>',
        unsafe_allow_html=True,
    )

    if cache["error"]:
        st.error(cache["error"])
    elif not cache["items"]:
        st.markdown('<div class="sc-empty">No files stored yet. Upload one and it will appear here.</div>', unsafe_allow_html=True)

    for item in cache["items"]:
        manifest = item["manifest"]
        manifest_key = item["manifest_key"]
        file_id = manifest["file_id"]
        folder = manifest_key.rsplit("/", 1)[0]
        n = manifest["chunk_count"]

        with st.container(border=True):
            st.markdown(
                f'<div class="sc-file-name">{esc(manifest["original_filename"])}</div>'
                f'<div class="sc-tags"><span>{fmt_bytes(manifest["original_size_bytes"])}</span>'
                f'<span>{n} chunk{"s" if n != 1 else ""}</span>'
                f'<span>{friendly_date(manifest["uploaded_at"])}</span></div>',
                unsafe_allow_html=True,
            )
            pass_key = f"pass_{file_id}"
            remembered = st.session_state.get("remembered", {})
            if pass_key not in st.session_state and file_id in remembered:
                st.session_state[pass_key] = remembered[file_id]

            col_pass, col_btn = st.columns([5, 2], vertical_alignment="bottom")
            col_pass.text_input("Passphrase", type="password", key=pass_key, placeholder="Passphrase used for this file")
            fetch = col_btn.button("Download and decrypt", key=f"fetch_{file_id}", type="primary")

            if fetch:
                secret = st.session_state.get(pass_key, "")
                if not secret:
                    st.error("Enter the passphrase for this file.")
                else:
                    bar, on_progress = make_progress("Starting")
                    try:
                        restored = core.download_and_decrypt(
                            get_client(region), bucket, manifest_key, secret, progress=on_progress
                        )
                        st.session_state["restored"] = {"file_id": file_id, **restored}
                    except SecureChunkError as exc:
                        st.session_state.pop("restored", None)
                        st.error(str(exc))
                    except Exception as exc:
                        st.session_state.pop("restored", None)
                        st.error(f"Something went wrong: {exc}")
                    finally:
                        bar.empty()

            restored = st.session_state.get("restored")
            if restored and restored["file_id"] == file_id:
                st.success(
                    f"Decrypted and verified. {restored['filename']} is back in its original form "
                    f"({fmt_bytes(len(restored['data']))})."
                )
                st.download_button(
                    f"Save {restored['filename']}",
                    data=restored["data"],
                    file_name=restored["filename"],
                    mime=restored["content_type"],
                    key=f"save_{file_id}",
                )

            with st.expander("Metadata and chunks"):
                render_details(manifest, bucket, folder, region)
