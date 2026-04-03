import json
import os
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any, Dict, List

from crypto_utils import EncryptedPayload, encrypt_payload, decrypt_payload


EXPORT_MAGIC = "SILDLOG01"


def export_encrypted_logs(
    records: List[Dict[str, Any]],
    output_path: str,
    passphrase: str,
) -> None:
    payload = {
        "schema_version": 1,
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "record_count": len(records),
        "records": records,
    }

    enc: EncryptedPayload = encrypt_payload(payload, passphrase)

    package = {
        "magic": EXPORT_MAGIC,
        "schema_version": 1,
        "kdf_salt_b64": enc.kdf_salt_b64,
        "kdf_iterations": enc.kdf_iterations,
        "ciphertext_b64": enc.ciphertext_b64,
    }

    out_dir = os.path.dirname(output_path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(package, f, ensure_ascii=False)


def decrypt_encrypted_logs(input_path: str, passphrase: str) -> Dict[str, Any]:
    with open(input_path, "r", encoding="utf-8") as f:
        package = json.load(f)

    if package.get("magic") != EXPORT_MAGIC:
        raise ValueError("File format not recognized (bad magic header).")

    enc = EncryptedPayload(
        kdf_salt_b64=package["kdf_salt_b64"],
        kdf_iterations=int(package["kdf_iterations"]),
        ciphertext_b64=package["ciphertext_b64"],
    )
    payload = decrypt_payload(enc, passphrase)

    # Basic schema sanity.
    if not isinstance(payload, dict) or "records" not in payload:
        raise ValueError("Decryption succeeded but payload schema is invalid.")
    return payload

