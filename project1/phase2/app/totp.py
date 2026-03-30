"""
TOTP implementation per RFC 6238 / RFC 4226.
NO external TOTP libraries used (PyOTP is forbidden).
Only Python stdlib: hmac, hashlib, struct, time, base64.
"""

import base64
import hashlib
import hmac
import struct
import time


def get_totp_code(secret_b32: str, t: int | None = None) -> str:
    """
    Generate a 6-digit TOTP code.

    Algorithm:
      1. key  = base32_decode(secret)
      2. T    = floor(unix_timestamp / 30)   — current 30-second window index
      3. msg  = T packed as 8-byte big-endian unsigned int
      4. hmac = HMAC-SHA1(key, msg)          — 20-byte digest
      5. offset = hmac[-1] & 0x0F            — dynamic truncation offset
      6. P    = 4 bytes from hmac[offset:]   — extract 4 bytes
      7. code = (P & 0x7FFFFFFF) % 10^6      — mask sign bit, take 6 digits
      8. zero-pad to 6 digits

    Args:
        secret_b32: base32-encoded secret (what Google Authenticator stores).
        t: time step override. Defaults to floor(now / 30).

    Returns:
        6-digit string, e.g. "048271".
    """
    if t is None:
        t = int(time.time()) // 30

    # Step 1 — decode the base32 secret into raw bytes
    key = base64.b32decode(secret_b32.upper())

    # Step 2-3 — pack time step as 8-byte big-endian (the HOTP counter)
    msg = struct.pack(">Q", t)

    # Step 4 — HMAC-SHA1 produces a 20-byte digest
    digest = hmac.new(key, msg, hashlib.sha1).digest()

    # Step 5 — dynamic truncation: offset = low nibble of last byte
    offset = digest[-1] & 0x0F

    # Step 6-7 — extract 4 bytes, clear sign bit → 31-bit integer
    raw = struct.unpack(">I", digest[offset : offset + 4])[0]
    code_int = raw & 0x7FFFFFFF

    # Step 8 — mod 10^6, then zero-pad to exactly 6 digits
    return str(code_int % 1_000_000).zfill(6)


def verify_totp(secret_b32: str, user_code: str, window: int = 1) -> bool:
    """
    Verify a user-supplied TOTP code, allowing for clock skew.

    Checks T-window ... T ... T+window.
    With window=1 that is 3 steps = ±30 seconds of tolerance,
    which satisfies the spec's "30-second window" requirement.

    Args:
        secret_b32: the base32 secret stored for this user.
        user_code:  the 6-digit string entered by the user.
        window:     number of steps to allow on each side (default 1).

    Returns:
        True if the code matches any step in the window.
    """
    t_now = int(time.time()) // 30
    candidate = user_code.strip()
    for delta in range(-window, window + 1):
        if get_totp_code(secret_b32, t_now + delta) == candidate:
            return True
    return False
