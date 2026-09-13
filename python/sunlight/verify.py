"""Offline verification (spec §4.3).

verify() performs no network, clock, filesystem, or key-discovery work.
Structural failures raise SunlightError; a well-formed cryptographically
failing bundle returns an integrity-INVALID Verification.
"""

from __future__ import annotations

from .domains import B, D, signature_message
from .ed25519 import ed25519_verify
from .errors import SunlightError
from .jcs import jcs
from .schema import (
    MAX_BUNDLE_BYTES, MAX_BUNDLE_ENTRIES, MAX_COMMAND_TTL_MS,
    parse_artifact_observation, parse_bundle, parse_freshness_evidence,
    parse_trust,
)

MAX_GRAPH_DEPTH = 256
MAX_GRAPH_NODES = 4096


class IntegrityFailure(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _fail(code: str, reasons=None):
    return {
        "integrity": "INVALID",
        "lineage": "INVALID",
        "authority": "UNKNOWN",
        "freshness": "OFFLINE",
        "artifact": "NOT_SUPPLIED",
        "claim_truth": "NOT_PROVEN",
        "overall": "INVALID",
        "reasons": reasons or [code],
        "head": None,
    }


def _sorted_unique(xs):
    return sorted(set(xs))


def _expected_head(genesis_hash: str, entries: list, i: int) -> dict:
    if i == 0:
        return {"seq": 0, "hash": genesis_hash}
    r = entries[i - 1]["receipt"]
    return {"seq": r["body"]["seq"], "hash": r["hash"]}


_EVENT_FOR_OP = {
    "claim": "StatementRecorded",
    "key_add": "KeyAdded",
    "key_retire": "KeyRetired",
    "key_revoke": "KeyRevoked",
    "retract": "StatementRetracted",
}


def verify(request: dict) -> dict:
    bundle = parse_bundle(request["bundle"])
    trust = parse_trust(request["trust"])
    observation = request.get("observation")
    if observation is not None:
        observation = parse_artifact_observation(observation)
    freshness = request.get("freshness")
    if freshness is not None:
        freshness = parse_freshness_evidence(freshness)
    if len(jcs(bundle)) > MAX_BUNDLE_BYTES:
        raise SunlightError("BUNDLE_LIMIT")
    if len(bundle["entries"]) > MAX_BUNDLE_ENTRIES:
        raise SunlightError("BUNDLE_LIMIT")

    genesis = bundle["genesis"]
    genesis_hash = D("sunlight.genesis/1", genesis)
    pinned = trust["ledger"] == genesis["ledger"] and trust["genesis_hash"] == genesis_hash

    genesis_keys = {genesis["admin"]["id"]: {"public_hex": genesis["admin"]["public_hex"], "role": "admin"},
                    genesis["audit"]["id"]: {"public_hex": genesis["audit"]["public_hex"], "role": "audit"}}
    for p in genesis["producers"]:
        genesis_keys[p["id"]] = {"public_hex": p["public_hex"], "role": "producer"}

    try:
        # Phase 3a — recompute every object hash before any signature check.
        for e in bundle["entries"]:
            if D("sunlight.command/1", e["command"]["body"]) != e["command"]["hash"]:
                raise IntegrityFailure("HASH_MISMATCH")
            if e["command"]["body"]["operation"]["type"] == "claim":
                s = e["command"]["body"]["operation"]["statement"]
                if D("sunlight.statement/1", s["body"]) != s["hash"]:
                    raise IntegrityFailure("HASH_MISMATCH")
            if D("sunlight.receipt/1", e["receipt"]["body"]) != e["receipt"]["hash"]:
                raise IntegrityFailure("HASH_MISMATCH")
        if D("sunlight.head/1", bundle["head"]["body"]) != bundle["head"]["hash"]:
            raise IntegrityFailure("HASH_MISMATCH")

        # Phase 3b — signatures with role-correct keys.  Unresolved signers
        # defer to replay, which produces the admission code.
        resolved = {k: v["public_hex"] for k, v in genesis_keys.items()}

        def verify_sig(kind, obj, key_id=None, forced_pub=None):
            pub = forced_pub if forced_pub is not None else resolved.get(key_id)
            if pub is None:
                return
            ok = ed25519_verify(
                bytes.fromhex(pub), signature_message(kind, obj["hash"]),
                bytes.fromhex(obj["signature_hex"]),
            )
            if not ok:
                raise IntegrityFailure("SIGNATURE_INVALID")

        for e in bundle["entries"]:
            cmd = e["command"]
            verify_sig("command", cmd, key_id=cmd["body"]["signer"])
            if cmd["body"]["operation"]["type"] == "claim":
                s = cmd["body"]["operation"]["statement"]
                verify_sig("statement", s, key_id=s["body"]["signer"])
            verify_sig("receipt", e["receipt"], forced_pub=genesis["audit"]["public_hex"])
            if cmd["body"]["operation"]["type"] == "key_add":
                k = cmd["body"]["operation"]["key"]
                if k["id"] not in resolved:
                    resolved[k["id"]] = k["public_hex"]
        verify_sig("head", bundle["head"], forced_pub=genesis["audit"]["public_hex"])

        # Phase 4 — chain linkage.
        prev_commit = 0
        for i, e in enumerate(bundle["entries"]):
            r = e["receipt"]["body"]
            c = e["command"]["body"]
            if r["seq"] != i + 1:
                raise IntegrityFailure("CHAIN_MISMATCH")
            eh = _expected_head(genesis_hash, bundle["entries"], i)
            if r["previous_hash"] != eh["hash"]:
                raise IntegrityFailure("CHAIN_MISMATCH")
            if c["expected_head"]["seq"] != eh["seq"] or c["expected_head"]["hash"] != eh["hash"]:
                raise IntegrityFailure("CHAIN_MISMATCH")
            if r["command_hash"] != e["command"]["hash"]:
                raise IntegrityFailure("CHAIN_MISMATCH")
            expected_stmt = (
                c["operation"]["statement"]["hash"] if c["operation"]["type"] == "claim" else None
            )
            if r["statement_hash"] != expected_stmt:
                raise IntegrityFailure("CHAIN_MISMATCH")
            if r["committed_at_ms"] < prev_commit:
                raise IntegrityFailure("CHAIN_MISMATCH")
            prev_commit = r["committed_at_ms"]

        # Phase 5 — replay admission semantics.
        state = _replay(bundle, genesis_keys)

        # Phase 6 — head binding and target presence.
        bundle_head = _expected_head(genesis_hash, bundle["entries"], len(bundle["entries"]))
        hb = bundle["head"]["body"]
        if hb["head"]["seq"] != bundle_head["seq"] or hb["head"]["hash"] != bundle_head["hash"]:
            raise IntegrityFailure("CHAIN_MISMATCH")
        if hb["ledger"] != genesis["ledger"] or hb["genesis_hash"] != genesis_hash:
            raise IntegrityFailure("CHAIN_MISMATCH")
        target_record = state["statements"].get(bundle["target"])
        if target_record is None:
            raise IntegrityFailure("TARGET_MISSING")

        # Phase 7 — minimum head pin at its exact sequence.
        m = trust["minimum_head"]
        min_ok = (
            m["hash"] == genesis_hash
            if m["seq"] == 0
            else m["seq"] <= len(bundle["entries"])
            and bundle["entries"][m["seq"] - 1]["receipt"]["hash"] == m["hash"]
        )
        if not min_ok:
            raise IntegrityFailure("MINIMUM_HEAD_MISMATCH")

        # Phases 8–12.
        reasons = []
        if not pinned:
            reasons.append("UNTRUSTED_GENESIS")

        cut_seq = len(bundle["entries"])
        reached = _ancestry(bundle["target"], state)
        saw_retracted = saw_revoked = saw_denied = False
        denied = set(trust["denied_keys"])
        for rec in reached:
            if rec["retract_seq"] is not None and rec["retract_seq"] <= cut_seq:
                saw_retracted = True
            signer = rec["statement"]["body"]["signer"]
            tl = state["keys"].get(signer)
            if tl is not None and tl["revoked_seq"] is not None and tl["revoked_seq"] <= cut_seq:
                saw_revoked = True
            if signer in denied:
                saw_denied = True
        if saw_retracted:
            reasons.append("RETRACTED_ANCESTOR")
        if saw_revoked:
            reasons.append("REVOKED_ANCESTOR")
        if saw_denied:
            reasons.append("DENIED_KEY")

        # Phase 9 — required training ancestry for reached models.
        missing_training = False
        if trust["require_training"]:
            for rec in reached:
                if rec["statement"]["body"]["subject"]["kind"] != "model":
                    continue
                if not _model_trained(rec["statement"], state, set()):
                    missing_training = True
            if missing_training:
                reasons.append("MISSING_TRAINING")

        # Phase 10 — artifact observation.
        if observation is None:
            artifact_dim = "NOT_SUPPLIED"
        else:
            t = target_record["statement"]["body"]["subject"]["artifact"]
            o = observation["artifact"]
            artifact_dim = (
                "MATCH"
                if o["profile"] == t["profile"]
                and o["digest"] == t["digest"]
                and o["bytes"] == t["bytes"]
                else "MISMATCH"
            )
        if artifact_dim == "MISMATCH":
            reasons.append("ARTIFACT_MISMATCH")

        # Phase 11 — freshness evidence.
        freshness_dim = "OFFLINE"
        if freshness is not None:
            freshness_dim = "CURRENT" if _check_freshness(freshness, bundle, genesis, trust) else "STALE"
            if freshness_dim == "STALE":
                reasons.append("STALE_HEAD")

        # Phase 12 — deterministic result dimensions.
        lineage = "INCOMPLETE" if (saw_retracted or missing_training) else "COMPLETE_DECLARED"
        authority = (
            "REVOKED" if (saw_revoked or saw_denied)
            else ("UNTRUSTED" if not pinned else "TRUSTED_AT_HEAD")
        )
        overall = (
            "INVALID"
            if artifact_dim == "MISMATCH"
            else "VERIFIED"
            if lineage == "COMPLETE_DECLARED"
            and authority == "TRUSTED_AT_HEAD"
            and artifact_dim in ("MATCH", "NOT_SUPPLIED")
            and freshness_dim in ("CURRENT", "OFFLINE")
            else "UNVERIFIED"
        )

        return {
            "integrity": "VALID",
            "lineage": lineage,
            "authority": authority,
            "freshness": freshness_dim,
            "artifact": artifact_dim,
            "claim_truth": "NOT_PROVEN",
            "overall": overall,
            "reasons": _sorted_unique(reasons),
            "head": bundle_head,
        }
    except IntegrityFailure as e:
        v = _fail(e.code)
        v["freshness"] = "OFFLINE" if freshness is None else "STALE"
        v["artifact"] = "NOT_SUPPLIED" if observation is None else "UNCHECKED"
        return v


def _replay(bundle, genesis_keys):
    state = {
        "keys": {
            k: {
                "public_hex": v["public_hex"], "role": v["role"],
                "added_seq": 0, "retired_seq": None, "revoked_seq": None,
            }
            for k, v in genesis_keys.items()
        },
        "statements": {},
        "statement_ids": {},
        "descriptor_ids": {},
        "command_ids": set(),
    }
    for e in bundle["entries"]:
        _replay_entry(state, e, bundle["genesis"])
    return state


def _key_status_at(tl):
    if tl is None:
        return "unregistered"
    if tl["revoked_seq"] is not None:
        return "revoked"
    if tl["retired_seq"] is not None:
        return "retired"
    return "active"


def _replay_entry(state, e, genesis):
    cmd = e["command"]
    c = cmd["body"]
    op = c["operation"]
    r = e["receipt"]["body"]
    seq = r["seq"]

    if c["ledger"] != genesis["ledger"] or r["ledger"] != genesis["ledger"]:
        raise IntegrityFailure("CHAIN_MISMATCH")
    if op["type"] == "claim" and op["statement"]["body"]["ledger"] != genesis["ledger"]:
        raise IntegrityFailure("CHAIN_MISMATCH")
    if c["id"] in state["command_ids"]:
        raise IntegrityFailure("AUDIT_BINDING_MISMATCH")

    window = c["expires_at_ms"] - c["issued_at_ms"]
    if not (0 < window <= MAX_COMMAND_TTL_MS):
        raise IntegrityFailure("AUDIT_BINDING_MISMATCH")
    if not (c["issued_at_ms"] <= r["committed_at_ms"] + 60000):
        raise IntegrityFailure("AUDIT_BINDING_MISMATCH")
    if not (r["committed_at_ms"] < c["expires_at_ms"]):
        raise IntegrityFailure("AUDIT_BINDING_MISMATCH")

    signer_tl = state["keys"].get(c["signer"])
    signer_status = _key_status_at(signer_tl)
    admin_id = genesis["admin"]["id"]

    if op["type"] == "claim":
        s = op["statement"]
        if c["signer"] != s["body"]["signer"]:
            raise IntegrityFailure("ROLE_MISMATCH")
        if signer_tl is None or signer_tl["role"] != "producer":
            raise IntegrityFailure("ROLE_MISMATCH")
        if signer_status != "active":
            raise IntegrityFailure("KEY_INACTIVE")
    elif op["type"] in ("key_add", "key_retire", "key_revoke"):
        if c["signer"] != admin_id:
            raise IntegrityFailure("ROLE_MISMATCH")
    elif op["type"] == "retract":
        target = state["statements"].get(op["statement"])
        if target is None:
            raise IntegrityFailure("NOT_FOUND")
        if target["retract_seq"] is not None:
            raise IntegrityFailure("STATE_CONFLICT")
        is_admin = c["signer"] == admin_id
        is_own_active = (
            c["signer"] == target["statement"]["body"]["signer"]
            and signer_tl is not None
            and signer_tl["role"] == "producer"
            and signer_status == "active"
        )
        if not is_admin and not is_own_active:
            raise IntegrityFailure("ROLE_MISMATCH")
    if signer_tl is not None and signer_tl["role"] == "audit":
        raise IntegrityFailure("ROLE_MISMATCH")

    if op["type"] == "claim":
        s = op["statement"]
        if s["hash"] in state["statements"]:
            raise IntegrityFailure("STATEMENT_EXISTS")
        bound = state["statement_ids"].get(s["body"]["id"])
        if bound is not None and bound != s["hash"]:
            raise IntegrityFailure("ID_CONFLICT")
        d = s["body"]["details"]
        if d["type"] in ("training", "action"):
            object_id = d["run_id"] if d["type"] == "training" else d["action_id"]
            k = f"{s['body']['subject']['kind']}:{object_id}"
            prev = state["descriptor_ids"].get(k)
            if prev is not None and prev != s["hash"]:
                raise IntegrityFailure("ID_CONFLICT")
            if prev is not None and prev == s["hash"]:
                raise IntegrityFailure("STATEMENT_EXISTS")
        _check_intrinsic(s)
        _check_parents(state, s)
        _check_descriptor(s)
    elif op["type"] == "key_add":
        k = op["key"]
        if (
            k["id"] in (genesis["admin"]["id"], genesis["audit"]["id"])
            or k["public_hex"] in (genesis["admin"]["public_hex"], genesis["audit"]["public_hex"])
        ):
            raise IntegrityFailure("STATE_CONFLICT")
        if k["id"] in state["keys"]:
            raise IntegrityFailure("ID_CONFLICT")
        for tid, tl in state["keys"].items():
            if tl["public_hex"] == k["public_hex"] and tid != k["id"]:
                raise IntegrityFailure("ID_CONFLICT")
    elif op["type"] in ("key_retire", "key_revoke"):
        kid = op["key"]
        if kid in (genesis["admin"]["id"], genesis["audit"]["id"]):
            raise IntegrityFailure("STATE_CONFLICT")
        tl = state["keys"].get(kid)
        if tl is None:
            raise IntegrityFailure("NOT_FOUND")
        if op["type"] == "key_retire" and _key_status_at(tl) != "active":
            raise IntegrityFailure("STATE_CONFLICT")
        if op["type"] == "key_revoke" and _key_status_at(tl) == "revoked":
            raise IntegrityFailure("STATE_CONFLICT")

    if r["event"] != _EVENT_FOR_OP[op["type"]]:
        raise IntegrityFailure("AUDIT_BINDING_MISMATCH")

    state["command_ids"].add(c["id"])
    if op["type"] == "claim":
        s = op["statement"]
        state["statements"][s["hash"]] = {"statement": s, "seq": seq, "retract_seq": None}
        state["statement_ids"][s["body"]["id"]] = s["hash"]
        d = s["body"]["details"]
        if d["type"] in ("training", "action"):
            object_id = d["run_id"] if d["type"] == "training" else d["action_id"]
            state["descriptor_ids"][f"{s['body']['subject']['kind']}:{object_id}"] = s["hash"]
    elif op["type"] == "key_add":
        state["keys"][op["key"]["id"]] = {
            "public_hex": op["key"]["public_hex"], "role": "producer",
            "added_seq": seq, "retired_seq": None, "revoked_seq": None,
        }
    elif op["type"] == "key_retire":
        state["keys"][op["key"]]["retired_seq"] = seq
    elif op["type"] == "key_revoke":
        state["keys"][op["key"]]["revoked_seq"] = seq
    elif op["type"] == "retract":
        state["statements"][op["statement"]]["retract_seq"] = seq


def _check_intrinsic(s):
    kind = s["body"]["subject"]["kind"]
    d = s["body"]["details"]
    parents = s["body"]["parents"]
    relations = [p["relation"] for p in parents]
    count = relations.count
    only = lambda allowed: all(r in allowed for r in relations)

    t = d["type"]
    if t == "creation":
        if kind not in ("dataset", "model", "evidence"):
            raise IntegrityFailure("STATEMENT_INVALID")
        if len(parents) != 0:
            raise IntegrityFailure("STATEMENT_INVALID")
        return
    if t == "transform":
        if kind not in ("dataset", "model"):
            raise IntegrityFailure("STATEMENT_INVALID")
        if len(parents) < 1 or not only(["source"]):
            raise IntegrityFailure("STATEMENT_INVALID")
        return
    if t == "training":
        if kind != "run":
            raise IntegrityFailure("STATEMENT_INVALID")
        if s["body"]["subject"]["artifact"]["profile"] != "jcs/1":
            raise IntegrityFailure("STATEMENT_INVALID")
        if not (1 <= count("dataset") <= 63) or count("base_model") > 1 or not only(["dataset", "base_model"]):
            raise IntegrityFailure("STATEMENT_INVALID")
        return
    if t == "model":
        if kind != "model":
            raise IntegrityFailure("STATEMENT_INVALID")
        if len(parents) != 1 or count("run") != 1:
            raise IntegrityFailure("STATEMENT_INVALID")
        return
    if t == "action":
        if kind != "action":
            raise IntegrityFailure("STATEMENT_INVALID")
        if s["body"]["subject"]["artifact"]["profile"] != "jcs/1":
            raise IntegrityFailure("STATEMENT_INVALID")
        if len(parents) != 1 or count("model") != 1:
            raise IntegrityFailure("STATEMENT_INVALID")
        if d["outcome"] == "attempted" and d["output"] is not None:
            raise IntegrityFailure("STATEMENT_INVALID")
        if d["outcome"] == "completed" and d["output"] is None:
            raise IntegrityFailure("STATEMENT_INVALID")
        return


def _check_parents(state, s):
    parents = s["body"]["parents"]
    records = []
    for p in parents:
        rec = state["statements"].get(p["statement"])
        if rec is None:
            raise IntegrityFailure("PARENT_MISSING")
        if rec["retract_seq"] is not None:
            raise IntegrityFailure("PARENT_INACTIVE")
        if rec["statement"]["body"]["subject"]["artifact"]["digest"] != p["artifact"]:
            raise IntegrityFailure("PARENT_MISMATCH")
        records.append(rec)
    for anc in _ancestry_from(records, state):
        if anc["retract_seq"] is not None:
            raise IntegrityFailure("PARENT_INACTIVE")
        tl = state["keys"].get(anc["statement"]["body"]["signer"])
        if tl is not None and tl["revoked_seq"] is not None:
            raise IntegrityFailure("PARENT_INACTIVE")
    d = s["body"]["details"]

    def by_rel(rel):
        return [
            state["statements"][p["statement"]]
            for p in s["body"]["parents"]
            if p["relation"] == rel
        ]

    t = d["type"]
    if t == "transform":
        for rec in records:
            if rec["statement"]["body"]["subject"]["kind"] != s["body"]["subject"]["kind"]:
                raise IntegrityFailure("STATEMENT_INVALID")
    elif t == "training":
        for rec in by_rel("dataset"):
            if rec["statement"]["body"]["subject"]["kind"] != "dataset":
                raise IntegrityFailure("STATEMENT_INVALID")
        for rec in by_rel("base_model"):
            if rec["statement"]["body"]["subject"]["kind"] != "model":
                raise IntegrityFailure("STATEMENT_INVALID")
    elif t == "model":
        run = by_rel("run")[0]
        if (
            run["statement"]["body"]["subject"]["kind"] != "run"
            or run["statement"]["body"]["details"]["type"] != "training"
        ):
            raise IntegrityFailure("STATEMENT_INVALID")
    elif t == "action":
        model = by_rel("model")[0]
        if model["statement"]["body"]["subject"]["kind"] != "model":
            raise IntegrityFailure("STATEMENT_INVALID")


def _check_descriptor(s):
    kind = s["body"]["subject"]["kind"]
    if kind not in ("run", "action"):
        return
    descriptor = {
        "v": "sunlight.descriptor/1",
        "kind": kind,
        "parents": s["body"]["parents"],
        "details": s["body"]["details"],
    }
    canon = jcs(descriptor)
    expected = {"profile": "jcs/1", "digest": B(canon), "bytes": len(canon)}
    a = s["body"]["subject"]["artifact"]
    if a["profile"] != expected["profile"] or a["digest"] != expected["digest"] or a["bytes"] != expected["bytes"]:
        raise IntegrityFailure("DESCRIPTOR_MISMATCH")


def _ancestry(root_hash, state):
    root = state["statements"].get(root_hash)
    if root is None:
        return []
    return _ancestry_from([root], state)


def _ancestry_from(roots, state):
    seen = {}
    stack = [(rec, 0) for rec in roots]
    while stack:
        rec, depth = stack.pop()
        h = rec["statement"]["hash"]
        if h in seen:
            continue
        if depth > MAX_GRAPH_DEPTH:
            raise IntegrityFailure("GRAPH_LIMIT")
        if len(seen) >= MAX_GRAPH_NODES:
            raise IntegrityFailure("GRAPH_LIMIT")
        seen[h] = rec
        for p in rec["statement"]["body"]["parents"]:
            pr = state["statements"].get(p["statement"])
            if pr is not None:
                stack.append((pr, depth + 1))
    return list(seen.values())


def _model_trained(s, state, visiting):
    if s["hash"] in visiting:
        return True
    visiting.add(s["hash"])
    d = s["body"]["details"]
    if d["type"] == "model":
        return True
    if d["type"] == "transform":
        for p in s["body"]["parents"]:
            rec = state["statements"].get(p["statement"])
            if rec is None:
                return False
            if rec["statement"]["body"]["subject"]["kind"] != "model":
                return False
            if not _model_trained(rec["statement"], state, visiting):
                return False
        return True
    return False


def _check_freshness(f, bundle, genesis, trust):
    hb = f["head"]["body"]
    if hb["ledger"] != genesis["ledger"]:
        return False
    if hb["genesis_hash"] != D("sunlight.genesis/1", genesis):
        return False
    bh = bundle["head"]["body"]["head"]
    if hb["head"]["seq"] != bh["seq"] or hb["head"]["hash"] != bh["hash"]:
        return False
    if hb["nonce_hex"] != f["expected_nonce_hex"]:
        return False
    if f["received_at_ms"] < f["sent_at_ms"]:
        return False
    if f["received_at_ms"] - f["sent_at_ms"] > trust["max_head_age_ms"]:
        return False
    if hb["observed_at_ms"] < f["sent_at_ms"] - 60000:
        return False
    if hb["observed_at_ms"] > f["received_at_ms"] + 60000:
        return False
    if D("sunlight.head/1", f["head"]["body"]) != f["head"]["hash"]:
        return False
    return ed25519_verify(
        bytes.fromhex(genesis["audit"]["public_hex"]),
        signature_message("head", f["head"]["hash"]),
        bytes.fromhex(f["head"]["signature_hex"]),
    )
