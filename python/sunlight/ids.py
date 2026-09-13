"""Locked ID prefixes and nanoid generation (spec §2)."""

from __future__ import annotations

import secrets

ID_SUFFIX_LENGTH = 21
ID_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
ID_PREFIXES = ("sll", "slk", "sls", "slq", "sle", "slr", "sla")


def is_valid_id(value, prefix: str | None = None) -> bool:
    if not isinstance(value, str):
        return False
    sep = value.find("_")
    if sep <= 0:
        return False
    p, suffix = value[:sep], value[sep + 1 :]
    if p not in ID_PREFIXES or (prefix is not None and p != prefix):
        return False
    return len(suffix) == ID_SUFFIX_LENGTH and all(c in ID_ALPHABET for c in suffix)


def new_id(prefix: str, rand=secrets.token_bytes) -> str:
    """Cryptographic nanoid over the 64-symbol alphabet (divides 256 evenly)."""
    if prefix not in ID_PREFIXES:
        raise ValueError(f"unknown id prefix {prefix!r}")
    out = []
    while len(out) < ID_SUFFIX_LENGTH:
        for b in rand(ID_SUFFIX_LENGTH):
            if len(out) < ID_SUFFIX_LENGTH:
                out.append(ID_ALPHABET[b & 63])
    return f"{prefix}_{''.join(out)}"


def random_hex(n: int) -> str:
    return secrets.token_bytes(n).hex()
