"""Canonical JSON serializer — the restricted RFC 8785 domain of spec §2.

Only null, booleans, strings, protocol integers, arrays, and objects are
serializable; floats, negative integers, and values above the safe-integer
bound raise ``SunlightError("SCHEMA_INVALID")``.  Object keys sort by
UTF-16BE code units; strings are emitted verbatim (no normalization) with the
JSON escape set.
"""

from __future__ import annotations

import json as _json

from .errors import SunlightError

MAX_SAFE_UINT = 9007199254740991


def _fail(msg: str) -> None:
    raise SunlightError("SCHEMA_INVALID", cause=ValueError(msg))


def _key_sort(k: str):
    # Sort by UTF-16BE code units.
    return k.encode("utf-16-be", errors="surrogatepass")


def jcs(value) -> bytes:
    if value is None or isinstance(value, bool) or isinstance(value, str):
        return _json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if isinstance(value, int):
        if value < 0 or value > MAX_SAFE_UINT:
            _fail("integer outside protocol domain")
        return str(value).encode("ascii")
    if isinstance(value, (list, tuple)):
        return b"[" + b",".join(jcs(v) for v in value) + b"]"
    if isinstance(value, dict):
        for k in value:
            if not isinstance(k, str):
                _fail("non-string object key")
        keys = sorted(value.keys(), key=_key_sort)
        return b"{" + b",".join(jcs(k) + b":" + jcs(value[k]) for k in keys) + b"}"
    _fail(f"unserializable type {type(value).__name__}")


def jcs_str(value) -> str:
    return jcs(value).decode("utf-8")
