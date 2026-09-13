#!/usr/bin/env python3
"""Generate tests/fixtures.json per SUNLIGHT spec section 6.2.

The block below reproduces the normative executable fixture notation exactly
(same J/B/D/ID/make_key/signed/artifact/parent/claim/command/entry/ref/head/
bundle definitions, same seeds).  The export dict at the bottom additionally
expands every named fixture value the TV-S vectors reference so that the
TypeScript and Python conformance suites test golden bytes, not self-generated
oracles.  Seeds are PUBLIC TEST VECTORS ONLY.
"""

import copy
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def J(x):
    if x is None or isinstance(x, bool) or isinstance(x, str):
        return json.dumps(x, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if isinstance(x, int) and 0 <= x <= 9007199254740991:
        return str(x).encode("ascii")
    if isinstance(x, list):
        return b"[" + b",".join(J(v) for v in x) + b"]"
    if isinstance(x, dict):
        keys = sorted(x, key=lambda k: k.encode("utf-16be"))
        return b"{" + b",".join(J(k) + b":" + J(x[k]) for k in keys) + b"}"
    raise ValueError("SCHEMA_INVALID")


def B(b):
    return "sha256:" + hashlib.sha256(b).hexdigest()


def D(tag, x):
    return B(tag.encode() + b"\n" + J(x))


def ID(prefix, n):
    return prefix + str(n).zfill(21)


def make_key(n):
    private = Ed25519PrivateKey.from_private_bytes(bytes([n]) * 32)
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    return private, {"id": ID("slk_", n), "public_hex": public}


SKA, KA = make_key(1)
SKL, KL = make_key(2)
SKP, KP = make_key(3)
SKN, KN = make_key(4)
L = ID("sll_", 1)
T = 1800000000000
NONCE = "11" * 32
G = {"v": "sunlight.genesis/1", "ledger": L, "created_at_ms": T,
     "admin": KA, "audit": KL, "producers": [KP]}
H0 = {"seq": 0, "hash": D("sunlight.genesis/1", G)}


def signed(kind, body, private):
    digest = D("sunlight." + kind + "/1", body)
    message = ("sunlight." + kind + ".signature/1\n").encode() + bytes.fromhex(digest[7:])
    return {"body": body, "hash": digest, "signature_hex": private.sign(message).hex()}


def artifact(data, profile="bytes/1"):
    return {"profile": profile, "digest": B(data), "bytes": len(data)}


A = artifact(b"abc")
Z = artifact(b"")
M = artifact(b"model-v1\n")


def parent(statement, relation):
    return {"statement": statement["hash"],
            "artifact": statement["body"]["subject"]["artifact"]["digest"], "relation": relation}


def claim(n, kind, art, parents, details, capture="creation_hook", evidence=None):
    parents = sorted(parents, key=lambda p: (p["relation"], p["statement"]))
    if kind in ("run", "action"):
        descriptor = {"v": "sunlight.descriptor/1", "kind": kind, "parents": parents, "details": details}
        art = artifact(J(descriptor), "jcs/1")
    body = {"v": "sunlight.statement/1", "id": ID("sls_", n), "ledger": L,
            "signer": KP["id"], "claimed_at_ms": T, "capture": capture,
            "subject": {"kind": kind, "artifact": art}, "parents": parents,
            "details": details, "evidence": [] if evidence is None else evidence}
    return signed("statement", body, SKP)


S1 = claim(1, "dataset", A, [], {"type": "creation"})
S2 = claim(2, "run", None, [parent(S1, "dataset")],
           {"type": "training", "run_id": ID("slr_", 1), "code": B(b"code"),
            "environment": B(b"env"), "parameters": B(b"params"), "seed": "17"})
S3 = claim(3, "model", M, [parent(S2, "run")], {"type": "model"})
S4 = claim(4, "action", None, [parent(S3, "model")],
           {"type": "action", "action_id": ID("sla_", 1), "input": B(b"input"),
            "output": B(b"output"), "outcome": "completed", "context": None})


def command(n, head, operation, admin=False):
    key, private = (KA, SKA) if admin else (KP, SKP)
    body = {"v": "sunlight.command/1", "id": ID("slq_", n), "ledger": L,
            "signer": key["id"], "expected_head": head, "issued_at_ms": T,
            "expires_at_ms": T + 300000, "operation": operation}
    return signed("command", body, private)


EVENTS = {"claim": "StatementRecorded", "key_add": "KeyAdded", "key_retire": "KeyRetired",
          "key_revoke": "KeyRevoked", "retract": "StatementRetracted"}


def entry(n, cmd):
    op = cmd["body"]["operation"]
    sh = op["statement"]["hash"] if op["type"] == "claim" else None
    body = {"v": "sunlight.receipt/1", "id": ID("sle_", n), "ledger": L, "seq": n,
            "previous_hash": cmd["body"]["expected_head"]["hash"], "command_hash": cmd["hash"],
            "statement_hash": sh, "event": EVENTS[op["type"]], "committed_at_ms": T}
    return {"command": cmd, "receipt": signed("receipt", body, SKL)}


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
C5 = command(5, H4, {"type": "key_add", "key": KN}, True)
E5 = entry(5, C5)
H5 = ref(E5)
C6 = command(6, H5, {"type": "key_retire", "key": KN["id"]}, True)
E6 = entry(6, C6)
H6 = ref(E6)
C7 = command(7, H6, {"type": "key_revoke", "key": KP["id"], "reason": "compromise"}, True)
E7 = entry(7, C7)
H7 = ref(E7)
C8 = command(8, H7, {"type": "retract", "statement": S1["hash"], "reason": "incorrect"}, True)
E8 = entry(8, C8)
H8 = ref(E8)
ENTRIES = [E1, E2, E3, E4, E5, E6, E7, E8]


def head(h, nonce=None):
    body = {"v": "sunlight.head/1", "ledger": L, "genesis_hash": H0["hash"],
            "head": h, "observed_at_ms": T, "nonce_hex": nonce}
    return signed("head", body, SKL)


def bundle(entries, target):
    h = ref(entries[-1]) if entries else H0
    return {"v": "sunlight.bundle/1", "genesis": G, "entries": entries,
            "head": head(h), "target": target["hash"]}


F4 = bundle(ENTRIES[:4], S4)
F7 = bundle(ENTRIES[:7], S4)
F8 = bundle(ENTRIES, S4)
TRUST = {"v": "sunlight.trust/1", "ledger": L, "genesis_hash": H0["hash"],
         "minimum_head": H0, "denied_keys": [], "require_training": True, "max_head_age_ms": 30000}
OBS4 = {"artifact": S4["body"]["subject"]["artifact"]}
FRESH4 = {"head": head(H4, NONCE), "expected_nonce_hex": NONCE,
          "sent_at_ms": T, "received_at_ms": T + 1}
V4 = {"integrity": "VALID", "lineage": "COMPLETE_DECLARED", "authority": "TRUSTED_AT_HEAD",
      "freshness": "OFFLINE", "artifact": "NOT_SUPPLIED", "claim_truth": "NOT_PROVEN",
      "overall": "VERIFIED", "reasons": [], "head": H4}


def pair(method, params, result, n=90):
    request = {"v": "sunlight.rpc/1", "id": ID("slq_", n), "method": method, "params": params}
    response = {"v": "sunlight.rpc/1", "id": ID("slq_", n), "ok": True, "result": result}
    return {"request": request, "http_status": 200, "response": response}


EXAMPLES = [pair("head.get", {"ledger": L, "nonce_hex": NONCE}, head(H4, NONCE), 90)]
for n, e in enumerate(ENTRIES, 1):
    EXAMPLES.append(pair("append", {"ledger": L, "command": e["command"]}, {"entry": e, "head": ref(e)}, n))
EXAMPLES.append(pair("entry.get", {"ledger": L, "seq": 1}, E1, 91))
EXAMPLES.append(pair("entries.list", {"ledger": L, "after": 0, "cut": H4, "limit": 2},
                     {"entries": [E1, E2], "next_after": 2, "cut": H4}, 92))
EXAMPLES.append(pair("statement.get", {"ledger": L, "statement": S1["hash"], "cut": H4},
                     {"statement": S1, "recorded_at": 1, "retracted": False, "key_status": "ACTIVE", "head": H4}, 93))
EXAMPLES.append(pair("artifact.lookup", {"ledger": L, "profile": "bytes/1", "digest": A["digest"],
                                       "cut": H4, "after_seq": 0, "limit": 100},
                     {"matches": [{"statement": S1["hash"], "id": S1["body"]["id"], "kind": "dataset",
                                   "signer": KP["id"], "capture": "creation_hook", "retracted": False,
                                   "key_status": "ACTIVE"}], "next_after_seq": None, "cut": H4}, 94))
EXAMPLES.append(pair("bundle.export", {"ledger": L, "target": S4["hash"], "cut": H4},
                     {"bundle": F4, "digest": B(J(F4))}, 95))

# ---- Extended exports for the TV-S vector suite ---------------------------
# Everything below is derived exclusively through the normative helpers above.

# S1 variant used by the `sign` CLI vector: identical body with capture posthoc,
# re-signed by the producer.
S1_POSTHOC_BODY = dict(S1["body"], capture="posthoc")
S1_POSTHOC = signed("statement", S1_POSTHOC_BODY, SKP)

# TV-S--11: artifact changed at the byte level, observation over hex 61626300.
OBS_CHANGED = {"artifact": artifact(bytes.fromhex("61626300"))}
F1 = bundle(ENTRIES[:1], S1)

# TV-S--31: new claim under revoked producer at P7.
S31 = claim(31, "dataset", Z, [], {"type": "creation"})
C31 = command(31, H7, {"type": "claim", "statement": S31})
# TV-S--32: producer-signed key_add at P4.
C32 = command(32, H4, {"type": "key_add", "key": KN})
# TV-S--34: future-issued command at P0.
C34_BODY = {"v": "sunlight.command/1", "id": ID("slq_", 34), "ledger": L,
            "signer": KP["id"], "expected_head": H0, "issued_at_ms": T + 60001,
            "expires_at_ms": T + 360001, "operation": {"type": "claim", "statement": S1}}
C34 = signed("command", C34_BODY, SKP)
# TV-S--35: S2 with wrong parent artifact, re-signed.
S35_BODY = copy.deepcopy(S2["body"])
S35_BODY["parents"][0]["artifact"] = Z["digest"]
S35 = signed("statement", S35_BODY, SKP)
C35 = command(35, H1, {"type": "claim", "statement": S35})
# TV-S--36: forward reference — S2 submitted at P0.
C36 = command(36, H0, {"type": "claim", "statement": S2})
# TV-S--37/38: model creation root, no training ancestry.
R37 = claim(37, "model", M, [], {"type": "creation"})
C37 = command(37, H0, {"type": "claim", "statement": R37})
E37 = entry(1, C37)
F37 = bundle([E37], R37)
# TV-S--41: statement id sls_...001 rebound to a different hash.
S41 = claim(1, "dataset", Z, [], {"type": "creation"})
C41 = command(41, H1, {"type": "claim", "statement": S41})
# TV-S--42: S2 whose subject artifact no longer commits the descriptor.
S42_BODY = copy.deepcopy(S2["body"])
S42_BODY["subject"]["artifact"] = {"profile": "jcs/1", "digest": Z["digest"], "bytes": 0}
S42 = signed("statement", S42_BODY, SKP)
C42 = command(42, H1, {"type": "claim", "statement": S42})
# TV-S--55: competing claim at the same head as C7.
S55 = claim(55, "dataset", Z, [], {"type": "creation"})
C55 = command(55, H6, {"type": "claim", "statement": S55})
# TV-S--56: no-op transform statement.
S56 = claim(56, "dataset", A, [parent(S1, "source")],
            {"type": "transform", "procedure": B(b"validate-only")})
C56 = command(56, H1, {"type": "claim", "statement": S56})
E56 = entry(2, C56)
# TV-S--57: creation statement illegally carrying a parent.
S57 = claim(57, "dataset", A, [parent(S1, "source")], {"type": "creation"})
C57 = command(57, H1, {"type": "claim", "statement": S57})
# TV-S--58: retract of an absent statement.
C58 = command(58, H4, {"type": "retract", "statement": B(b"absent"), "reason": "incorrect"}, True)
# TV-S--17: same successful command ID binding different canonical bytes.
C17_BODY = copy.deepcopy(C1["body"])
C17_BODY["operation"] = {"type": "claim", "statement": S2}
C17 = signed("command", C17_BODY, SKP)
# TV-S--50: opaque C2PA evidence reference.
C2PA_BYTES = bytes.fromhex("6e6f742d63327061")
EVIDENCE_C2PA = {"artifact": artifact(C2PA_BYTES), "format": "c2pa/opaque",
                 "source_commitment": None, "assessment": "OPAQUE"}

# Tree manifest fixture (section 14 preamble).
TM = {"v": "sunlight.tree/1", "files": [{"path": "a.txt", "digest": A["digest"], "bytes": 3},
                                        {"path": "b.txt", "digest": Z["digest"], "bytes": 0}]}
TM_ARTIFACT = {"profile": "tree/1", "digest": B(J(TM)), "bytes": len(J(TM))}

CLIENT_CONFIG = {"v": "sunlight.config/1", "default_ledger": L,
    "registries": [{"ledger": L, "origin": "http://127.0.0.1:8787", "bearer_env": "SUNLIGHT_REGISTRY_TOKEN",
                    "trust_file": "./trust.json"}], "cache_dir": "./.sunlight-cache",
    "connect_timeout_ms": 3000, "read_timeout_ms": 10000, "allow_loopback_http": True}
DEPLOY_CONFIG = {"v": "sunlight.deployment/1", "ledgers": [{"genesis": G, "audit_secret_binding": "AUDIT_L1"}],
    "auth_secret_binding": "REGISTRY_TOKENS", "rate_per_token_per_minute": 120,
    "max_inflight_per_ledger": 8, "protocol": "sunlight/1"}

OUT = {
    "seeds_hex": {"admin": (bytes([1]) * 32).hex(), "audit": (bytes([2]) * 32).hex(),
                  "producer": (bytes([3]) * 32).hex(), "newkey": (bytes([4]) * 32).hex()},
    "keys": {"KA": KA, "KL": KL, "KP": KP, "KN": KN},
    "ledger": L, "now_ms": T, "nonce_hex": NONCE,
    "genesis": G, "genesis_hash": H0["hash"], "H0": H0,
    "artifacts": {"A": A, "Z": Z, "M": M, "changed_61626300": OBS_CHANGED["artifact"]},
    "tree_manifest": TM, "tree_artifact": TM_ARTIFACT,
    "statements": {"S1": S1, "S2": S2, "S3": S3, "S4": S4, "S1_posthoc": S1_POSTHOC,
                   "S31": S31, "S35": S35, "S41": S41, "S42": S42, "S55": S55,
                   "S56": S56, "S57": S57, "R37": R37},
    "commands": {"C1": C1, "C2": C2, "C3": C3, "C4": C4, "C5": C5, "C6": C6,
                 "C7": C7, "C8": C8, "C17": C17, "C31": C31, "C32": C32,
                 "C34": C34, "C35": C35, "C36": C36, "C37": C37, "C41": C41,
                 "C42": C42, "C55": C55, "C56": C56, "C57": C57, "C58": C58},
    "entries": {"E1": E1, "E2": E2, "E3": E3, "E4": E4, "E5": E5, "E6": E6,
                "E7": E7, "E8": E8, "E37": E37, "E56": E56},
    "heads": {"H0": H0, "H1": H1, "H2": H2, "H3": H3, "H4": H4, "H5": H5,
              "H6": H6, "H7": H7, "H8": H8},
    "bundles": {"F4": F4, "F7": F7, "F8": F8, "F1": F1, "F37": F37},
    "trust": TRUST, "obs4": OBS4, "obs_changed": OBS_CHANGED, "fresh4": FRESH4,
    "verification_v4": V4,
    "evidence_c2pa": EVIDENCE_C2PA,
    "examples": EXAMPLES,
    "client_config": CLIENT_CONFIG, "deploy_config": DEPLOY_CONFIG,
    "heads_signed": {"H4_nonce": head(H4, NONCE), "H4_plain": head(H4)},
}


def main():
    out = Path(__file__).resolve().parent.parent / "tests" / "fixtures.json"
    out.write_text(json.dumps(OUT, indent=2, ensure_ascii=False) + "\n")
    print(f"wrote {out} ({out.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
