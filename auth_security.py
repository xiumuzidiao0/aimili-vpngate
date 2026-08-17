from __future__ import annotations

import base64
import binascii
import hashlib
import secrets
from typing import Any


PASSWORD_SCHEME = "scrypt"
SCRYPT_N = 1 << 14
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_DKLEN = 32
SALT_BYTES = 16


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def hash_password(password: str, salt: bytes | None = None) -> str:
    if not password:
        raise ValueError("密码不能为空")
    salt = salt or secrets.token_bytes(SALT_BYTES)
    derived = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=SCRYPT_DKLEN,
    )
    return f"{PASSWORD_SCHEME}${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${_encode(salt)}${_encode(derived)}"


def verify_password(password: str, encoded: Any) -> bool:
    try:
        scheme, n_value, r_value, p_value, salt_value, digest_value = str(encoded or "").split("$", 5)
        if scheme != PASSWORD_SCHEME:
            return False
        n = int(n_value)
        r = int(r_value)
        p = int(p_value)
        if (n, r, p) != (SCRYPT_N, SCRYPT_R, SCRYPT_P):
            return False
        salt = _decode(salt_value)
        expected = _decode(digest_value)
        if len(salt) != SALT_BYTES or len(expected) != SCRYPT_DKLEN:
            return False
        actual = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=n,
            r=r,
            p=p,
            dklen=len(expected),
        )
        return secrets.compare_digest(actual, expected)
    except (TypeError, ValueError, binascii.Error):
        return False


def has_password(config: dict[str, Any]) -> bool:
    return bool(config.get("password_hash") or config.get("password"))


def set_password(config: dict[str, Any], password: str) -> None:
    config["password_hash"] = hash_password(password)
    config.pop("password", None)


def migrate_password(config: dict[str, Any]) -> bool:
    encoded = str(config.get("password_hash") or "")
    if encoded.startswith(f"{PASSWORD_SCHEME}$"):
        if "password" in config:
            config.pop("password", None)
            return True
        return False
    plaintext = str(config.get("password") or "")
    if plaintext:
        set_password(config, plaintext)
        return True
    return False
