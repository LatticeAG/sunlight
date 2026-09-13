"""Hash and signature domains (spec §3).

``B`` is the raw sha256 digest tag; ``D(tag, x)`` is the domain-separated
object hash ``B(tag + b"\\n" + J(x))``.  Signature domains are
``"sunlight.<kind>.signature/1\\n" || RAW(object_hash)``.
"""

from __future__ import annotations

import hashlib
import re

from .jcs import jcs

DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
HEX32_RE = re.compile(r"^[0-9a-f]{64}$")
HEX64_RE = re.compile(r"^[0-9a-f]{128}$")


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def B(b: bytes) -> str:
    return "sha256:" + hashlib.sha256(b).hexdigest()


def D(tag: str, x) -> str:
    return B(tag.encode("utf-8") + b"\n" + jcs(x))


def RAW(h: str) -> bytes:
    if not DIGEST_RE.match(h):
        raise ValueError("not a sha256 digest")
    return bytes.fromhex(h[7:])


OBJECT_KINDS = ("genesis", "statement", "command", "receipt", "head")


def hash_domain(kind: str) -> str:
    return f"sunlight.{kind}/1"


def signature_domain(kind: str) -> str:
    return f"sunlight.{kind}.signature/1"


def signature_message(kind: str, object_hash: str) -> bytes:
    return signature_domain(kind).encode("utf-8") + b"\n" + RAW(object_hash)
