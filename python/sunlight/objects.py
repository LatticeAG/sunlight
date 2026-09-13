"""Object construction and signing (spec §7 CoreApi primitives)."""

from __future__ import annotations

from .domains import D, hash_domain, signature_message
from .ed25519 import ed25519_sign, ed25519_verify
from .errors import SunlightError
from .schema import (
    parse_command_body, parse_head_body, parse_receipt_body, parse_statement_body,
)


class Signer:
    """In-process signer over a raw 32-byte seed (test + keyfile path)."""

    def __init__(self, key: dict, seed: bytes):
        self.key = key
        self._seed = bytes(seed)

    def sign(self, message: bytes) -> bytes:
        return ed25519_sign(self._seed, message)


def seed_signer(key: dict, seed: bytes) -> Signer:
    return Signer(key, seed)


def _sign_body(kind: str, body: dict, signer: Signer):
    h = D(hash_domain(kind), body)
    sig = signer.sign(signature_message(kind, h))
    if len(sig) != 64:
        raise SunlightError("SIGNATURE_INVALID")
    return {"body": body, "hash": h, "signature_hex": sig.hex()}


def sign_statement(body: dict, signer: Signer) -> dict:
    b = parse_statement_body(body)
    if b["signer"] != signer.key["id"]:
        raise SunlightError("ROLE_MISMATCH")
    return _sign_body("statement", b, signer)


def sign_command(body: dict, signer: Signer) -> dict:
    b = parse_command_body(body)
    if b["signer"] != signer.key["id"]:
        raise SunlightError("ROLE_MISMATCH")
    return _sign_body("command", b, signer)


def sign_receipt(body: dict, signer: Signer) -> dict:
    b = parse_receipt_body(body)
    return _sign_body("receipt", b, signer)


def sign_head(body: dict, signer: Signer) -> dict:
    b = parse_head_body(body)
    return _sign_body("head", b, signer)


def verify_signed_object(kind: str, obj: dict, public_hex: str) -> bool:
    if D(hash_domain(kind), obj["body"]) != obj["hash"]:
        return False
    return ed25519_verify(
        public_hex, signature_message(kind, obj["hash"]), bytes.fromhex(obj["signature_hex"]),
    )
