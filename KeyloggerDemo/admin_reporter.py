import getpass
import hashlib
import json
import os
import platform
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple
from urllib import request, error


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _try_file_sha256(path: str) -> Optional[str]:
    """
    Compute SHA-256 for encrypted file identification (no plaintext involved).
    Best-effort: returns None if the file can't be read.
    """
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def _build_unauthorized_decrypt_report(
    *,
    input_path: str,
    exception_type: str,
    exception_message: str,
) -> Dict[str, Any]:
    """
    Build a sanitized report payload for admin consumption.
    Never includes passphrases or decrypted plaintext.
    """
    try:
        file_size = os.path.getsize(input_path)
    except Exception:
        file_size = None

    file_name = os.path.basename(input_path) or "unknown"
    file_sha256 = _try_file_sha256(input_path)

    return {
        "event": "unauthorized_decrypt_attempt",
        "report_id": uuid.uuid4().hex,
        "timestamp_utc": _utc_now_iso(),
        "file": {
            "name": file_name,
            "size_bytes": file_size,
            "sha256": file_sha256,
        },
        "client": {
            "user": getpass.getuser(),
            "host": platform.node(),
            "platform": platform.platform(),
            "pid": os.getpid(),
        },
        "error": {
            "type": exception_type,
            # Keep message short to avoid leaking sensitive library details.
            "message": (exception_message or "")[:200],
        },
    }


def send_admin_report(
    report: Dict[str, Any],
    *,
    webhook_url: Optional[str] = None,
    auth_token: Optional[str] = None,
    timeout_seconds: float = 5.0,
) -> Tuple[bool, str]:
    """
    Send report to admin via HTTP(S) webhook.

    Returns (success, detail_message).
    """
    webhook_url = webhook_url or os.environ.get("ADMIN_WEBHOOK_URL", "").strip()
    if not webhook_url:
        return False, "ADMIN_WEBHOOK_URL not configured"

    headers = {"Content-Type": "application/json"}
    if auth_token is None:
        auth_token = os.environ.get("ADMIN_AUTH_TOKEN", "").strip()
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"

    body = json.dumps(report, ensure_ascii=False).encode("utf-8")

    req = request.Request(webhook_url, data=body, headers=headers, method="POST")
    try:
        with request.urlopen(req, timeout=timeout_seconds) as resp:
            status = getattr(resp, "status", 200)
            if 200 <= status < 300:
                return True, f"HTTP {status}"
            return False, f"HTTP {status}"
    except error.HTTPError as e:
        return False, f"HTTPError {getattr(e, 'code', '')}: {e.reason}"
    except Exception as e:
        return False, f"Request failed: {type(e).__name__}: {e}"


def report_unauthorized_decrypt_attempt(
    *,
    input_path: str,
    exc: Exception,
    webhook_url: Optional[str] = None,
    auth_token: Optional[str] = None,
) -> Tuple[Dict[str, Any], bool, str]:
    report = _build_unauthorized_decrypt_report(
        input_path=input_path,
        exception_type=type(exc).__name__,
        exception_message=str(exc),
    )
    success, detail = send_admin_report(
        report,
        webhook_url=webhook_url,
        auth_token=auth_token,
    )
    return report, success, detail

