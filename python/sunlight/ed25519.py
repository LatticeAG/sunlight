"""Ed25519 via the pinned `cryptography` package (spec §3).

Signatures are deterministic RFC 8032.  Public keys must be canonical point
encodings that are not the identity and lie in the prime-order subgroup;
signatures must be canonical (R canonical point, S < group order L).
"""

from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# Group order L = 2^252 + 27742317777372353535851937790883648493
_L = 2**252 + 27742317777372353535851937790883648493
_P = 2**255 - 19
_IDENTITY_COMPRESSED = bytes([1]) + bytes(31)


def _decode_point(enc: bytes):
    """Decompress an Edwards point; returns (x, y) or raises."""
    if len(enc) != 32:
        raise ValueError("length")
    y = int.from_bytes(enc, "little") & ((1 << 255) - 1)
    sign = enc[31] >> 7
    if y >= _P:
        raise ValueError("non-canonical y")
    # x^2 = (y^2 - 1) / (d y^2 + 1)
    d = -121665 * pow(121666, _P - 2, _P) % _P
    u = (y * y - 1) % _P
    v = (d * y * y + 1) % _P
    x = u * pow(v, 3, _P) * pow(u * pow(v, 7, _P), (_P - 5) // 8, _P) % _P
    if (x * x * v - u) % _P != 0:
        x = x * pow(2, (_P - 1) // 4, _P) % _P
        if (x * x * v - u) % _P != 0:
            raise ValueError("not on curve")
    if x & 1 != sign:
        x = _P - x
    return x, y


def _is_small_order(x: int, y: int) -> bool:
    # Multiply by cofactor 8: small-order points map to the identity.
    # Edwards addition on twisted Edwards curve a=-1, d as above.
    d = -121665 * pow(121666, _P - 2, _P) % _P

    def add(p, q):
        x1, y1 = p
        x2, y2 = q
        dxxyy = d * x1 * x2 * y1 * y2 % _P
        x3 = (x1 * y2 + x2 * y1) * pow(1 + dxxyy, _P - 2, _P) % _P
        y3 = (y1 * y2 + x1 * x2) * pow(1 - dxxyy, _P - 2, _P) % _P
        return x3, y3

    p = (x, y)
    for _ in range(3):
        p = add(p, p)
    return p[1] == 1 and p[0] == 0  # identity is (0, 1)


def is_canonical_point_encoding(enc: bytes) -> bool:
    try:
        x, y = _decode_point(bytes(enc))
    except ValueError:
        return False
    return not _is_small_order(x, y)


def is_valid_public_key(pub: bytes) -> bool:
    return is_canonical_point_encoding(pub)


def is_canonical_signature(sig: bytes) -> bool:
    if len(sig) != 64:
        return False
    try:
        _decode_point(sig[:32])  # R must be a canonical point (small order ok)
    except ValueError:
        return False
    return int.from_bytes(sig[32:], "little") < _L


def private_key_from_seed(seed: bytes) -> Ed25519PrivateKey:
    if len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    return Ed25519PrivateKey.from_private_bytes(bytes(seed))


def public_from_seed(seed: bytes) -> bytes:
    return (
        private_key_from_seed(seed)
        .public_key()
        .public_bytes(Encoding.Raw, PublicFormat.Raw)
    )


def ed25519_sign(seed: bytes, message: bytes) -> bytes:
    return private_key_from_seed(seed).sign(bytes(message))


def ed25519_verify(public_hex_or_bytes, message: bytes, signature: bytes) -> bool:
    pub = (
        bytes.fromhex(public_hex_or_bytes)
        if isinstance(public_hex_or_bytes, str)
        else bytes(public_hex_or_bytes)
    )
    if len(pub) != 32 or len(signature) != 64:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(bytes(signature), bytes(message))
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False
