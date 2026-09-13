"""Local cache layout (spec §9):

    objects/sha256/<64hex>.json    canonical signed objects/manifests
    evidence/sha256/<64hex>.bin    explicitly imported raw evidence
    bundles/<64hex>.json           exported bundles
    pending/<slq_id>.json          durable commands awaiting a receipt
    pins/<sll_id>.json             largest verified SignedHead per ledger
    journal.ndjson                 local.* lifecycle records

Directories are 0700, files 0600; content-hash filenames are derived
internally.
"""

from __future__ import annotations

import os
import re

from .errors import SunlightError
from .fsutil import read_file_bytes, write_file_atomic
from .jcs import jcs
from .schema import parse_signed_head
from .strictjson import parse_strict_json

_PENDING_RE = re.compile(r"^slq_[A-Za-z0-9_-]{21}$")
_LEDGER_RE = re.compile(r"^sll_[A-Za-z0-9_-]{21}$")


class Cache:
    def __init__(self, dir: str):
        self.dir = dir

    def _ensure(self) -> None:
        for sub in ("objects/sha256", "evidence/sha256", "bundles", "pending", "pins"):
            os.makedirs(os.path.join(self.dir, sub), mode=0o700, exist_ok=True)
        try:
            os.chmod(self.dir, 0o700)
        except OSError:
            pass

    @staticmethod
    def _hex(digest: str) -> str:
        if not isinstance(digest, str) or not re.match(r"^sha256:[0-9a-f]{64}$", digest):
            raise SunlightError("SCHEMA_INVALID")
        return digest[7:]

    def store_object(self, digest: str, obj) -> str:
        self._ensure()
        p = os.path.join(self.dir, "objects/sha256", f"{self._hex(digest)}.json")
        if not os.path.exists(p):
            write_file_atomic(p, jcs(obj))
        return p

    def load_object(self, digest: str):
        p = os.path.join(self.dir, "objects/sha256", f"{self._hex(digest)}.json")
        if not os.path.exists(p):
            return None
        return parse_strict_json(read_file_bytes(p))

    def store_evidence(self, digest: str, raw: bytes) -> str:
        self._ensure()
        p = os.path.join(self.dir, "evidence/sha256", f"{self._hex(digest)}.bin")
        if not os.path.exists(p):
            write_file_atomic(p, raw)
        return p

    def store_bundle(self, digest: str, bundle) -> str:
        self._ensure()
        p = os.path.join(self.dir, "bundles", f"{self._hex(digest)}.json")
        if not os.path.exists(p):
            write_file_atomic(p, jcs(bundle))
        return p

    def store_pending(self, command_id: str, command) -> str:
        self._ensure()
        if not _PENDING_RE.match(command_id):
            raise SunlightError("SCHEMA_INVALID")
        p = os.path.join(self.dir, "pending", f"{command_id}.json")
        if not os.path.exists(p):
            write_file_atomic(p, jcs(command))
        return p

    def drop_pending(self, command_id: str) -> None:
        p = os.path.join(self.dir, "pending", f"{command_id}.json")
        if os.path.exists(p):
            os.unlink(p)

    def list_pending(self) -> list[str]:
        d = os.path.join(self.dir, "pending")
        if not os.path.isdir(d):
            return []
        return [f[:-5] for f in os.listdir(d) if f.endswith(".json")]

    def load_pending(self, command_id: str):
        p = os.path.join(self.dir, "pending", f"{command_id}.json")
        if not os.path.exists(p):
            return None
        return parse_strict_json(read_file_bytes(p))

    def load_pin(self, ledger: str):
        p = os.path.join(self.dir, "pins", f"{ledger}.json")
        if not os.path.exists(p):
            return None
        return parse_signed_head(parse_strict_json(read_file_bytes(p)))

    def store_pin(self, ledger: str, head) -> None:
        self._ensure()
        if not _LEDGER_RE.match(ledger):
            raise SunlightError("SCHEMA_INVALID")
        write_file_atomic(os.path.join(self.dir, "pins", f"{ledger}.json"), jcs(head))

    def journal(self, event: str, command: str | None, statement: str | None, at_ms: int) -> None:
        self._ensure()
        rec = {
            "v": "sunlight.local/1",
            "command": command,
            "statement": statement,
            "event": event,
            "at_ms": at_ms,
        }
        fd = os.open(os.path.join(self.dir, "journal.ndjson"), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(fd, jcs(rec) + b"\n")
        finally:
            os.close(fd)
