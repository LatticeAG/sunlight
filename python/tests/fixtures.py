"""Test-side fixture builder — byte-identical port of spec §6.2 / tools/gen_fixtures.py.

Seeds are PUBLIC TEST VECTORS ONLY and must never be used by a production
signer.  All objects match tests/fixtures.json byte-for-byte.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sunlight.domains import B, D, signature_message  # noqa: E402
from sunlight.ed25519 import ed25519_sign, public_from_seed  # noqa: E402
from sunlight.jcs import jcs  # noqa: E402


def fid(prefix: str, n: int) -> str:
    return prefix + str(n).zfill(21)


def make_key(n: int):
    seed = bytes([n]) * 32
    return {
        "seed": seed,
        "key": {"id": fid("slk_", n), "public_hex": public_from_seed(seed).hex()},
    }


KA = make_key(1)   # admin
KL = make_key(2)   # audit (ledger)
KP = make_key(3)   # producer
KN = make_key(4)   # new producer (added by C5)
L = fid("sll_", 1)
T = 1800000000000
NONCE = "11" * 32

G = {
    "v": "sunlight.genesis/1",
    "ledger": L,
    "created_at_ms": T,
    "admin": KA["key"],
    "audit": KL["key"],
    "producers": [KP["key"]],
}
H0 = {"seq": 0, "hash": D("sunlight.genesis/1", G)}


def signed(kind: str, body, seed: bytes):
    h = D(f"sunlight.{kind}/1", body)
    return {
        "body": body,
        "hash": h,
        "signature_hex": ed25519_sign(seed, signature_message(kind, h)).hex(),
    }


def artifact(data: bytes, profile="bytes/1"):
    return {"profile": profile, "digest": B(data), "bytes": len(data)}


A = artifact(b"abc")
Z = artifact(b"")
M = artifact(b"model-v1\n")


def parent(statement, relation):
    return {
        "statement": statement["hash"],
        "artifact": statement["body"]["subject"]["artifact"]["digest"],
        "relation": relation,
    }


def claim(n, kind, art, parents, details, capture="creation_hook", evidence=None):
    sp = sorted(parents, key=lambda p: (p["relation"], p["statement"]))
    subject = art
    if kind in ("run", "action"):
        descriptor = {"v": "sunlight.descriptor/1", "kind": kind, "parents": sp, "details": details}
        subject = artifact(jcs(descriptor), "jcs/1")
    body = {
        "v": "sunlight.statement/1",
        "id": fid("sls_", n),
        "ledger": L,
        "signer": KP["key"]["id"],
        "claimed_at_ms": T,
        "capture": capture,
        "subject": {"kind": kind, "artifact": subject},
        "parents": sp,
        "details": details,
        "evidence": evidence or [],
    }
    return signed("statement", body, KP["seed"])


S1 = claim(1, "dataset", A, [], {"type": "creation"})
S2 = claim(2, "run", None, [parent(S1, "dataset")], {
    "type": "training",
    "run_id": fid("slr_", 1),
    "code": B(b"code"),
    "environment": B(b"env"),
    "parameters": B(b"params"),
    "seed": "17",
})
S3 = claim(3, "model", M, [parent(S2, "run")], {"type": "model"})
S4 = claim(4, "action", None, [parent(S3, "model")], {
    "type": "action",
    "action_id": fid("sla_", 1),
    "input": B(b"input"),
    "output": B(b"output"),
    "outcome": "completed",
    "context": None,
})


def command(n, head, operation, admin=False):
    key = KA if admin else KP
    body = {
        "v": "sunlight.command/1",
        "id": fid("slq_", n),
        "ledger": L,
        "signer": key["key"]["id"],
        "expected_head": head,
        "issued_at_ms": T,
        "expires_at_ms": T + 300000,
        "operation": operation,
    }
    return signed("command", body, key["seed"])


_EVENTS = {
    "claim": "StatementRecorded",
    "key_add": "KeyAdded",
    "key_retire": "KeyRetired",
    "key_revoke": "KeyRevoked",
    "retract": "StatementRetracted",
}


def entry(n, cmd):
    op = cmd["body"]["operation"]
    sh = op["statement"]["hash"] if op["type"] == "claim" else None
    body = {
        "v": "sunlight.receipt/1",
        "id": fid("sle_", n),
        "ledger": L,
        "seq": n,
        "previous_hash": cmd["body"]["expected_head"]["hash"],
        "command_hash": cmd["hash"],
        "statement_hash": sh,
        "event": _EVENTS[op["type"]],
        "committed_at_ms": T,
    }
    return {"command": cmd, "receipt": signed("receipt", body, KL["seed"])}


def ref(e):
    return {"seq": e["receipt"]["body"]["seq"], "hash": e["receipt"]["hash"]}


C1 = command(1, H0, {"type": "claim", "statement": S1})
E1 = entry(1, C1)
H1 = ref(E1)
C2 = command(2, H1, {"type": "claim", "statement": S2})
E2 = entry(2, C2)
H2 = ref(E2)
C3 = command(3, H2, {"type": "claim", "statement": S3})
E3 = entry(3, C3)
H3 = ref(E3)
C4 = command(4, H3, {"type": "claim", "statement": S4})
E4 = entry(4, C4)
H4 = ref(E4)
C5 = command(5, H4, {"type": "key_add", "key": KN["key"]}, True)
E5 = entry(5, C5)
H5 = ref(E5)
C6 = command(6, H5, {"type": "key_retire", "key": KN["key"]["id"]}, True)
E6 = entry(6, C6)
H6 = ref(E6)
C7 = command(7, H6, {"type": "key_revoke", "key": KP["key"]["id"], "reason": "compromise"}, True)
E7 = entry(7, C7)
H7 = ref(E7)
C8 = command(8, H7, {"type": "retract", "statement": S1["hash"], "reason": "incorrect"}, True)
E8 = entry(8, C8)
H8 = ref(E8)
ENTRIES = [E1, E2, E3, E4, E5, E6, E7, E8]


def head(h, nonce=None):
    body = {
        "v": "sunlight.head/1",
        "ledger": L,
        "genesis_hash": H0["hash"],
        "head": h,
        "observed_at_ms": T,
        "nonce_hex": nonce,
    }
    return signed("head", body, KL["seed"])


def bundle(entries, target):
    h = ref(entries[-1]) if entries else H0
    return {"v": "sunlight.bundle/1", "genesis": G, "entries": entries,
            "head": head(h), "target": target["hash"]}


F4 = bundle(ENTRIES[:4], S4)
F7 = bundle(ENTRIES[:7], S4)
F8 = bundle(ENTRIES, S4)

TRUST = {
    "v": "sunlight.trust/1",
    "ledger": L,
    "genesis_hash": H0["hash"],
    "minimum_head": H0,
    "denied_keys": [],
    "require_training": True,
    "max_head_age_ms": 30000,
}

OBS4 = {"artifact": S4["body"]["subject"]["artifact"]}
FRESH4 = {
    "head": head(H4, NONCE),
    "expected_nonce_hex": NONCE,
    "sent_at_ms": T,
    "received_at_ms": T + 1,
}

V4 = {
    "integrity": "VALID",
    "lineage": "COMPLETE_DECLARED",
    "authority": "TRUSTED_AT_HEAD",
    "freshness": "OFFLINE",
    "artifact": "NOT_SUPPLIED",
    "claim_truth": "NOT_PROVEN",
    "overall": "VERIFIED",
    "reasons": [],
    "head": H4,
}
