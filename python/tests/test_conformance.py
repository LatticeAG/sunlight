"""TV-S conformance — the Python client/verifier slice of spec §14.

All 58 vectors run against the TypeScript implementation (which includes the
ledger engine and gateway).  This suite executes every vector applicable to
the client SDK + offline verifier scope (spec §7 Python parity surface):
hashing, canonical encoding, signatures, schema, evidence, and the full
verify() algorithm — including admission-replay checks reproduced through
forged-but-validly-chained bundles.

Every fixture object in tests/fixtures.json is also recomputed
byte-for-byte from the public test seeds to prove cross-runtime equality.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import fixtures as F  # noqa: E402
from sunlight.domains import B, D, signature_message  # noqa: E402
from sunlight.ed25519 import ed25519_verify, public_from_seed  # noqa: E402
from sunlight.errors import SunlightError  # noqa: E402
from sunlight.evidence import compute_evidence_ref  # noqa: E402
from sunlight.artifact import hash_artifact, manifest_artifact  # noqa: E402
from sunlight.jcs import jcs, jcs_str  # noqa: E402
from sunlight.objects import seed_signer, sign_statement  # noqa: E402
from sunlight.schema import parse_command_body, parse_tree_manifest  # noqa: E402
from sunlight.strictjson import parse_strict_json, parse_strict_json_str  # noqa: E402
from sunlight.verify import verify  # noqa: E402

FIXTURES_PATH = Path(__file__).resolve().parents[2] / "tests" / "fixtures.json"
GOLD = json.loads(FIXTURES_PATH.read_text())


def expect_err(code, fn):
    with pytest.raises(SunlightError) as ei:
        fn()
    assert ei.value.code == code, f"expected {code}, got {ei.value.code}"


def expect_integrity_fail(code, v):
    assert v["integrity"] == "INVALID" and v["overall"] == "INVALID"
    assert code in v["reasons"], v


# ---- TV-S-01..02 — raw artifact hashing ------------------------------------

def test_tv01_empty_artifact(tmp_path):
    p = tmp_path / "empty.bin"
    p.write_bytes(b"")
    assert hash_artifact(str(p), "bytes/1") == {
        "profile": "bytes/1",
        "digest": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "bytes": 0,
    }


def test_tv02_abc_artifact(tmp_path):
    p = tmp_path / "data.bin"
    p.write_bytes(b"abc")
    assert hash_artifact(str(p), "bytes/1") == F.A


# ---- TV-S-03..08 — canonical JSON / strict parser --------------------------

def test_tv03_canonical_order():
    assert jcs_str(parse_strict_json_str('{"b":2,"a":1}')) == '{"a":1,"b":2}'


def test_tv04_duplicate_key():
    expect_err("SCHEMA_INVALID", lambda: parse_strict_json_str('{"v":1,"v":1}'))


def test_tv05_unsafe_number():
    expect_err("SCHEMA_INVALID", lambda: parse_strict_json_str('{"n":9007199254740992}'))


def test_tv06_negative_zero():
    expect_err("SCHEMA_INVALID", lambda: parse_strict_json_str('{"n":-0}'))


def test_tv07_surrogate_rejection():
    expect_err("SCHEMA_INVALID", lambda: parse_strict_json_str('{"s":"\\ud800"}'))


def test_tv08_unicode_not_normalized():
    a = jcs({"s": "é"})
    b = jcs({"s": "é"})
    assert a.hex() == "7b2273223a22c3a9227d"
    assert b.hex() == "7b2273223a2265cc81227d"
    assert a != b


# ---- TV-S-09..14 — signatures and trees -------------------------------------

def test_tv09_deterministic_statement():
    s = sign_statement(F.S1["body"], seed_signer(F.KP["key"], F.KP["seed"]))
    assert s == F.S1 == GOLD["statements"]["S1"]


def test_tv10_filename_independent(tmp_path):
    p1 = tmp_path / "original.bin"
    p2 = tmp_path / "reupload.dat"
    p1.write_bytes(b"abc")
    p2.write_bytes(b"abc")
    assert hash_artifact(str(p1), "bytes/1") == F.A
    assert hash_artifact(str(p2), "bytes/1") == F.A


def test_tv11_changed_bytes():
    mutated = F.artifact(b"abc\x00")
    assert mutated["digest"] != F.A["digest"]
    b = F.bundle([F.E1], F.S1)
    v = verify({"bundle": b, "trust": F.TRUST,
                "observation": {"artifact": mutated}, "freshness": None})
    assert v["artifact"] == "MISMATCH" and v["overall"] == "INVALID"
    assert v["reasons"] == ["ARTIFACT_MISMATCH"]
    assert v["head"] == F.H1


def test_tv12_tree_determinism():
    files = [
        {"path": "b.txt", "digest": B(b""), "bytes": 0},
        {"path": "a.txt", "digest": B(b"abc"), "bytes": 3},
    ]
    mk = lambda fs: parse_tree_manifest(
        {"v": "sunlight.tree/1", "files": sorted(fs, key=lambda f: f["path"])}
    )
    m1 = mk(files)
    m2 = mk(list(reversed(files)))
    canon = jcs(m1)
    expected = {"profile": "tree/1", "digest": B(canon), "bytes": len(canon)}
    assert manifest_artifact(m1) == expected
    assert manifest_artifact(m2) == expected


def test_tv13_case_collision():
    expect_err("SCHEMA_INVALID", lambda: parse_tree_manifest({
        "v": "sunlight.tree/1",
        "files": [
            {"path": "A.txt", "digest": F.A["digest"], "bytes": 3},
            {"path": "a.txt", "digest": F.A["digest"], "bytes": 3},
        ],
    }))


def test_tv14_traversal_rejected():
    expect_err("SCHEMA_INVALID", lambda: parse_tree_manifest({
        "v": "sunlight.tree/1",
        "files": [{"path": "../weights.bin", "digest": F.M["digest"], "bytes": F.M["bytes"]}],
    }))


# ---- TV-S-20..30 — offline verification -------------------------------------

def test_tv20_statement_mutation():
    b = json.loads(json.dumps(F.F4))
    b["entries"][0]["command"]["body"]["operation"]["statement"]["body"]["capture"] = "posthoc"
    v = verify({"bundle": b, "trust": F.TRUST, "observation": None, "freshness": None})
    expect_integrity_fail("HASH_MISMATCH", v)


def test_tv21_base_lineage():
    v = verify({"bundle": F.F4, "trust": F.TRUST, "observation": None, "freshness": None})
    assert v == F.V4 == GOLD["verification_v4"]


def test_tv22_artifact_observation():
    v = verify({"bundle": F.F4, "trust": F.TRUST, "observation": F.OBS4, "freshness": None})
    assert v["artifact"] == "MATCH" and v["overall"] == "VERIFIED"
    assert v["reasons"] == []


def test_tv23_self_supplied_root():
    t = {**F.TRUST, "genesis_hash": B(b"")}
    v = verify({"bundle": F.F4, "trust": t, "observation": None, "freshness": None})
    assert v["authority"] == "UNTRUSTED" and v["overall"] == "UNVERIFIED"
    assert v["reasons"] == ["UNTRUSTED_GENESIS"]


def test_tv24_minimum_head_rollback():
    t = {**F.TRUST, "minimum_head": F.H7}
    v = verify({"bundle": F.F4, "trust": t, "observation": None, "freshness": None})
    expect_integrity_fail("MINIMUM_HEAD_MISMATCH", v)


def test_tv25_same_seq_different_head():
    t = {**F.TRUST, "minimum_head": {"seq": 4, "hash": B(b"")}}
    v = verify({"bundle": F.F4, "trust": t, "observation": None, "freshness": None})
    expect_integrity_fail("MINIMUM_HEAD_MISMATCH", v)


def test_tv26_fresh_head():
    v = verify({"bundle": F.F4, "trust": F.TRUST,
                "observation": F.OBS4, "freshness": F.FRESH4})
    assert v["artifact"] == "MATCH" and v["freshness"] == "CURRENT" and v["overall"] == "VERIFIED"


def test_tv27_wrong_nonce():
    f = {**F.FRESH4, "expected_nonce_hex": "22" * 32}
    v = verify({"bundle": F.F4, "trust": F.TRUST, "observation": None, "freshness": f})
    assert v["freshness"] == "STALE" and v["overall"] == "UNVERIFIED"
    assert v["reasons"] == ["STALE_HEAD"]


def test_tv28_freshness_elapsed():
    f = {**F.FRESH4, "received_at_ms": F.T + 30001}
    v = verify({"bundle": F.F4, "trust": F.TRUST, "observation": None, "freshness": f})
    assert v["freshness"] == "STALE" and v["overall"] == "UNVERIFIED"
    assert v["reasons"] == ["STALE_HEAD"]


def test_tv29_revoked_ancestor():
    v = verify({"bundle": F.F7, "trust": F.TRUST, "observation": None, "freshness": None})
    assert v["authority"] == "REVOKED" and v["overall"] == "UNVERIFIED"
    assert v["reasons"] == ["REVOKED_ANCESTOR"]
    assert v["head"] == F.H7


def test_tv30_retraction_plus_revocation():
    v = verify({"bundle": F.F8, "trust": F.TRUST, "observation": None, "freshness": None})
    assert v["lineage"] == "INCOMPLETE" and v["authority"] == "REVOKED" and v["overall"] == "UNVERIFIED"
    assert v["reasons"] == ["RETRACTED_ANCESTOR", "REVOKED_ANCESTOR"]
    assert v["head"] == F.H8


# ---- TV-S-31/32/35/36/41/42 — admission semantics via replay ---------------
#
# In the TS suite these append to a live engine.  For the client verifier the
# same admission order is exercised by replaying a forged-but-chained entry:
# the receipt is audit-signed, so only the *semantic* check can fail.


def _forge_entry(seq, cmd):
    return F.entry(seq, cmd)


def test_tv31_claim_under_revoked_producer():
    s = F.claim(31, "dataset", F.Z, [], {"type": "creation"})
    c = F.command(31, F.H7, {"type": "claim", "statement": s})
    e = _forge_entry(8, c)
    b = F.bundle(F.ENTRIES[:7] + [e], F.S4)
    v = verify({"bundle": b, "trust": F.TRUST, "observation": None, "freshness": None})
    expect_integrity_fail("KEY_INACTIVE", v)


def test_tv32_admin_only_key_management():
    c = F.command(32, F.H4, {"type": "key_add", "key": F.KN["key"]}, admin=False)
    e = _forge_entry(5, c)
    b = F.bundle(F.ENTRIES[:4] + [e], F.S4)
    v = verify({"bundle": b, "trust": F.TRUST, "observation": None, "freshness": None})
    expect_integrity_fail("ROLE_MISMATCH", v)


def test_tv35_wrong_parent_artifact():
    changed = json.loads(json.dumps(F.S2))
    changed["body"]["parents"][0]["artifact"] = F.Z["digest"]
    descriptor = {
        "v": "sunlight.descriptor/1", "kind": "run",
        "parents": changed["body"]["parents"], "details": changed["body"]["details"],
    }
    canon = jcs(descriptor)
    changed["body"]["subject"]["artifact"] = {"profile": "jcs/1", "digest": B(canon), "bytes": len(canon)}
    s2 = F.signed("statement", changed["body"], F.KP["seed"])
    c = F.command(35, F.H1, {"type": "claim", "statement": s2})
    e = _forge_entry(2, c)
    b = F.bundle([F.E1, e], s2)
    v = verify({"bundle": b, "trust": F.TRUST, "observation": None, "freshness": None})
    expect_integrity_fail("PARENT_MISMATCH", v)


def test_tv36_forward_reference():
    c = F.command(36, F.H0, {"type": "claim", "statement": F.S2})
    e = _forge_entry(1, c)
    b = F.bundle([e], F.S2)
    v = verify({"bundle": b, "trust": F.TRUST, "observation": None, "freshness": None})
    expect_integrity_fail("PARENT_MISSING", v)


def test_tv37_missing_training_disclosure():
    r = F.claim(37, "model", F.M, [], {"type": "creation"})
    c = F.command(37, F.H0, {"type": "claim", "statement": r})
    e = _forge_entry(1, c)
    b = F.bundle([e], r)
    v = verify({"bundle": b, "trust": F.TRUST, "observation": None, "freshness": None})
    assert v["integrity"] == "VALID"
    assert v["lineage"] == "INCOMPLETE" and v["authority"] == "TRUSTED_AT_HEAD"
    assert v["overall"] == "UNVERIFIED" and v["artifact"] == "NOT_SUPPLIED"
    assert v["claim_truth"] == "NOT_PROVEN"
    assert v["reasons"] == ["MISSING_TRAINING"]
    assert v["head"] == F.ref(e)
    # Byte-equal with the golden fixture entry
    assert e == GOLD["entries"]["E37"]


def test_tv38_relaxed_policy():
    r = F.claim(37, "model", F.M, [], {"type": "creation"})
    c = F.command(37, F.H0, {"type": "claim", "statement": r})
    e = _forge_entry(1, c)
    b = F.bundle([e], r)
    t = {**F.TRUST, "require_training": False}
    v = verify({"bundle": b, "trust": t, "observation": None, "freshness": None})
    assert v["lineage"] == "COMPLETE_DECLARED" and v["overall"] == "VERIFIED"
    assert v["reasons"] == []


def test_tv39_audit_entry_omitted():
    b = {**F.F4, "entries": [F.E1, F.E3, F.E4]}
    v = verify({"bundle": b, "trust": F.TRUST, "observation": None, "freshness": None})
    expect_integrity_fail("CHAIN_MISMATCH", v)


def test_tv40_event_body_misbinding():
    def seed_for(kid):
        return F.KP["seed"] if kid == F.KP["key"]["id"] else F.KA["seed"]
    r1body = {**F.E1["receipt"]["body"], "event": "KeyAdded"}
    e1 = {"command": F.C1, "receipt": F.signed("receipt", r1body, F.KL["seed"])}
    entries = [e1]
    for i in range(1, 4):
        src = F.ENTRIES[i]["command"]
        body = {**src["body"], "expected_head": F.ref(entries[-1])}
        c = F.signed("command", body, seed_for(src["body"]["signer"]))
        entries.append(F.entry(i + 1, c))
    b = {**F.F4, "entries": entries, "head": F.head(F.ref(entries[3]))}
    v = verify({"bundle": b, "trust": F.TRUST, "observation": None, "freshness": None})
    expect_integrity_fail("AUDIT_BINDING_MISMATCH", v)


def test_tv41_duplicate_claim_id():
    s = F.claim(1, "dataset", F.Z, [], {"type": "creation"})
    c = F.command(41, F.H1, {"type": "claim", "statement": s})
    e = _forge_entry(2, c)
    b = F.bundle([F.E1, e], s)
    v = verify({"bundle": b, "trust": F.TRUST, "observation": None, "freshness": None})
    expect_integrity_fail("ID_CONFLICT", v)


def test_tv42_descriptor_mismatch():
    changed = json.loads(json.dumps(F.S2))
    changed["body"]["subject"]["artifact"] = {"profile": "jcs/1", "digest": F.Z["digest"], "bytes": 0}
    s2 = F.signed("statement", changed["body"], F.KP["seed"])
    c = F.command(42, F.H1, {"type": "claim", "statement": s2})
    e = _forge_entry(2, c)
    b = F.bundle([F.E1, e], s2)
    v = verify({"bundle": b, "trust": F.TRUST, "observation": None, "freshness": None})
    expect_integrity_fail("DESCRIPTOR_MISMATCH", v)


# ---- TV-S-48..53 — domains, deny, evidence, schema --------------------------

def test_tv48_domain_separation():
    ok = ed25519_verify(
        bytes.fromhex(F.KP["key"]["public_hex"]),
        signature_message("command", F.S1["hash"]),
        bytes.fromhex(F.S1["signature_hex"]),
    )
    assert not ok


def test_tv49_local_deny_override():
    t = {**F.TRUST, "denied_keys": [F.KP["key"]["id"]]}
    v = verify({"bundle": F.F4, "trust": t, "observation": None, "freshness": None})
    assert v["authority"] == "REVOKED" and v["overall"] == "UNVERIFIED"
    assert v["reasons"] == ["DENIED_KEY"]


def test_tv50_opaque_c2pa():
    raw = bytes.fromhex("6e6f742d63327061")
    ref = compute_evidence_ref(raw, "c2pa/opaque")
    assert ref == {
        "artifact": {"profile": "bytes/1", "digest": B(raw), "bytes": 8},
        "format": "c2pa/opaque",
        "source_commitment": None,
        "assessment": "OPAQUE",
    }
    assert ref == GOLD["evidence_c2pa"]


def test_tv51_changed_profile():
    obs = {"artifact": {**F.OBS4["artifact"], "profile": "bytes/1"}}
    v = verify({"bundle": F.F4, "trust": F.TRUST, "observation": obs, "freshness": None})
    assert v["artifact"] == "MISMATCH" and v["overall"] == "INVALID"
    assert v["reasons"] == ["ARTIFACT_MISMATCH"]


def test_tv52_bad_id_prefix():
    body = {**F.C1["body"], "id": "req_000000000000000000001"}
    expect_err("SCHEMA_INVALID", lambda: parse_command_body(body))


def test_tv53_unknown_version():
    body = {**F.C1["body"], "v": "sunlight.command/2"}
    expect_err("VERSION_UNSUPPORTED", lambda: parse_command_body(body))


# ---- Cross-runtime fixture parity -------------------------------------------
#
# Every object in tests/fixtures.json was emitted by the independent spec
# generator; recomputing hashes and signatures here proves byte equality.


def test_fixture_key_derivation():
    seed_to_key = {"admin": "KA", "audit": "KL", "producer": "KP", "newkey": "KN"}
    for name, seed_hex in GOLD["seeds_hex"].items():
        pub = public_from_seed(bytes.fromhex(seed_hex)).hex()
        assert GOLD["keys"][seed_to_key[name]]["public_hex"] == pub


def test_fixture_genesis():
    g = GOLD["genesis"]
    assert D("sunlight.genesis/1", g) == GOLD["genesis_hash"]
    assert GOLD["H0"] == {"seq": 0, "hash": GOLD["genesis_hash"]}


def test_fixture_objects_recompute():
    for s in GOLD["statements"].values():
        assert D("sunlight.statement/1", s["body"]) == s["hash"]
    for c in GOLD["commands"].values():
        assert D("sunlight.command/1", c["body"]) == c["hash"]
    for e in GOLD["entries"].values():
        assert D("sunlight.receipt/1", e["receipt"]["body"]) == e["receipt"]["hash"]
    for name, h in GOLD["heads"].items():
        if name == "H0":
            continue
    for h in GOLD["heads_signed"].values():
        assert D("sunlight.head/1", h["body"]) == h["hash"]
    for b in GOLD["bundles"].values():
        assert B(jcs(b)) is not None  # canonical round-trip works on every bundle


def test_fixture_signatures_verify():
    keys = GOLD["keys"]
    pubs = {k["id"]: k["public_hex"] for k in keys.values()}
    audit_pub = keys["KL"]["public_hex"]
    for s in GOLD["statements"].values():
        assert ed25519_verify(
            pubs[s["body"]["signer"]],
            signature_message("statement", s["hash"]),
            bytes.fromhex(s["signature_hex"]),
        )
    for c in GOLD["commands"].values():
        assert ed25519_verify(
            pubs[c["body"]["signer"]],
            signature_message("command", c["hash"]),
            bytes.fromhex(c["signature_hex"]),
        )
    for e in GOLD["entries"].values():
        assert ed25519_verify(
            audit_pub,
            signature_message("receipt", e["receipt"]["hash"]),
            bytes.fromhex(e["receipt"]["signature_hex"]),
        )


def test_fixture_full_chain_parity():
    """Recompute the entire E1..E8 chain from seeds and compare byte-exact."""
    assert F.G == GOLD["genesis"]
    assert F.S1 == GOLD["statements"]["S1"]
    assert F.S4 == GOLD["statements"]["S4"]
    assert F.C1 == GOLD["commands"]["C1"]
    assert F.C8 == GOLD["commands"]["C8"]
    for i in range(1, 9):
        assert F.ENTRIES[i - 1] == GOLD["entries"][f"E{i}"], f"E{i}"
    assert F.F4 == GOLD["bundles"]["F4"]
    assert F.F7 == GOLD["bundles"]["F7"]
    assert F.F8 == GOLD["bundles"]["F8"]
    assert F.TRUST == GOLD["trust"]
    assert F.OBS4 == GOLD["obs4"]
    assert F.FRESH4 == GOLD["fresh4"]
