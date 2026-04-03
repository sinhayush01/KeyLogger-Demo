import base64
import json
import os
import secrets
from dataclasses import dataclass
from typing import Any, Dict, Tuple

import hashlib

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


DEFAULT_KDF_ITERATIONS = 390_000


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii")


def _b64d(raw_b64: str) -> bytes:
    return base64.urlsafe_b64decode(raw_b64.encode("ascii"))


def mask_value(value: str, mask_char: str = "•") -> str:
    """
    Create a masked representation with the same length as the original.
    This avoids storing plaintext sensitive data while preserving rough typing behavior.
    """
    # Keep behavior deterministic for the same input length.
    return mask_char * len(value)


def mask_by_length(length: int, mask_char: str = "•") -> str:
    """
    Mask by length only (useful to avoid keeping plaintext sensitive content).
    """
    if length <= 0:
        return ""
    return mask_char * length


def zeroize_bytearray(buf: bytearray) -> None:
    """
    Best-effort zeroization. Python/GC cannot guarantee removal, but we can overwrite
    the mutable buffer we own.
    """
    try:
        for i in range(len(buf)):
            buf[i] = 0
    except Exception:
        # Never fail the app because of a best-effort wipe.
        pass


def salted_sha256(value: str) -> Dict[str, str]:
    """
    Salted SHA-256 (random salt per value).

    Returns only non-reversible representations suitable for audit logs.
    """
    salt = secrets.token_bytes(16)
    value_bytes = value.encode("utf-8")
    try:
        digest = hashlib.sha256(salt + value_bytes).digest()
        return {"salt_b64": _b64e(salt), "digest_b64": _b64e(digest)}
    finally:
        # Best-effort wipe of the mutable copy.
        tmp = bytearray(value_bytes)
        zeroize_bytearray(tmp)


def derive_fernet_key(passphrase: str, salt: bytes, iterations: int) -> bytes:
    """
    Derive a Fernet key from a passphrase using PBKDF2-HMAC-SHA256.
    """
    passphrase_bytes = passphrase.encode("utf-8")
    try:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
        )
        key = kdf.derive(passphrase_bytes)
        return base64.urlsafe_b64encode(key)
    finally:
        passphrase_buf = bytearray(passphrase_bytes)
        zeroize_bytearray(passphrase_buf)


@dataclass(frozen=True)
class EncryptedPayload:
    kdf_salt_b64: str
    kdf_iterations: int
    ciphertext_b64: str


def encrypt_payload(payload: Dict[str, Any], passphrase: str, *, iterations: int = DEFAULT_KDF_ITERATIONS) -> EncryptedPayload:
    """
    Encrypt a JSON-serializable payload using Fernet with a key derived from the passphrase.
    """
    kdf_salt = secrets.token_bytes(16)
    key = derive_fernet_key(passphrase, kdf_salt, iterations)
    f = Fernet(key)

    plaintext_bytes = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    try:
        ciphertext = f.encrypt(plaintext_bytes)
        return EncryptedPayload(
            kdf_salt_b64=_b64e(kdf_salt),
            kdf_iterations=iterations,
            ciphertext_b64=_b64e(ciphertext),
        )
    finally:
        tmp = bytearray(plaintext_bytes)
        zeroize_bytearray(tmp)


def decrypt_payload(enc: EncryptedPayload, passphrase: str) -> Dict[str, Any]:
    key = derive_fernet_key(passphrase, _b64d(enc.kdf_salt_b64), enc.kdf_iterations)
    f = Fernet(key)

    ciphertext = _b64d(enc.ciphertext_b64)
    plaintext = f.decrypt(ciphertext)
    try:
        return json.loads(plaintext.decode("utf-8"))
    finally:
        tmp = bytearray(plaintext)
        zeroize_bytearray(tmp)


def protect_sensitive_value(value: str, classification: str) -> Tuple[str, Dict[str, Any]]:
    """
    Convert an input value into a safe, non-plaintext representation.

    Returns:
      (protection_method, protected_value_dict)
    """
    # Sensitive classifications
    if classification in {"password", "otp", "credit_card"}:
        masked = mask_value(value, mask_char="•")
        return "masked", {"masked": masked}

    if classification in {"email", "api_token"}:
        hashed = salted_sha256(value)
        return "hashed", {"sha256_salted": hashed}

    # Non-sensitive: the overall log export is encrypted; we keep plaintext only in the
    # app's encrypted export file (never as an unencrypted disk file).
    return "encrypted", {"plaintext": value}

