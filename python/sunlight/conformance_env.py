"""Conformance-only deterministic hooks (spec §7).  Honored exclusively when
launched with SUNLIGHT_CONFORMANCE=1; production operation MUST ignore them.
Every honored variable is reported on stderr."""

from __future__ import annotations

import os
import sys
import time

_reported: set[str] = set()


def _report(name: str) -> None:
    if name not in _reported:
        sys.stderr.write(f"sunlight: conformance override {name} in use\n")
        _reported.add(name)


def conformance_enabled() -> bool:
    return os.environ.get("SUNLIGHT_CONFORMANCE") == "1"


def fixed_now_ms() -> int | None:
    if not conformance_enabled():
        return None
    v = os.environ.get("SUNLIGHT_FIXED_NOW_MS")
    if not v:
        return None
    try:
        n = int(v)
    except ValueError:
        return None
    if n < 0:
        return None
    _report("SUNLIGHT_FIXED_NOW_MS")
    return n


def fixed_request_id() -> str | None:
    if not conformance_enabled():
        return None
    v = os.environ.get("SUNLIGHT_FIXED_REQUEST_ID")
    if not v:
        return None
    _report("SUNLIGHT_FIXED_REQUEST_ID")
    return v


def fixed_nonce_hex() -> str | None:
    if not conformance_enabled():
        return None
    v = os.environ.get("SUNLIGHT_FIXED_NONCE_HEX")
    if not v:
        return None
    _report("SUNLIGHT_FIXED_NONCE_HEX")
    return v


def key_entropy_hex() -> str | None:
    if not conformance_enabled():
        return None
    v = os.environ.get("SUNLIGHT_KEY_ENTROPY_HEX")
    if not v:
        return None
    _report("SUNLIGHT_KEY_ENTROPY_HEX")
    return v


def now_ms() -> int:
    n = fixed_now_ms()
    return n if n is not None else int(time.time() * 1000)


def fresh_nonce_hex(rand) -> str:
    return fixed_nonce_hex() or rand(32).hex()
