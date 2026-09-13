"""Foreign evidence import (spec §10 / INTERFACES.md).  Imports hash the
supplied bytes as bytes/1 and attach exactly one OPAQUE EvidenceRef; no
foreign validation, fetching, or execution is performed or implied.
"""

from __future__ import annotations

from .domains import B, DIGEST_RE
from .errors import SunlightError
from .strictjson import parse_strict_json


def compute_evidence_ref(raw: bytes, format: str) -> dict:
    artifact = {"profile": "bytes/1", "digest": B(raw), "bytes": len(raw)}
    source_commitment = None
    if format == "vislineage-bundle/1":
        try:
            parsed = parse_strict_json(raw)
        except Exception as e:
            raise SunlightError("SCHEMA_INVALID", cause=e) from e
        bh = parsed.get("hash") if isinstance(parsed, dict) else None
        if not isinstance(bh, str) or not DIGEST_RE.match(bh):
            raise SunlightError("SCHEMA_INVALID")
        source_commitment = bh
    return {
        "artifact": artifact,
        "format": format,
        "source_commitment": source_commitment,
        "assessment": "OPAQUE",
    }
