"""Closed-shape protocol object validators (spec §3).

Every validator enforces exact key sets, protocol integer domain, digest and
hex forms, locked ID prefixes, and version tags.  Unknown ``v`` versions
raise VERSION_UNSUPPORTED; every other violation raises SCHEMA_INVALID.
"""

from __future__ import annotations

import re

from .domains import DIGEST_RE, HEX32_RE, HEX64_RE
from .ed25519 import is_valid_public_key
from .errors import SunlightError
from .ids import is_valid_id
from .jcs import jcs

MAX_TEXT_UTF8 = 1024
MAX_PARENTS = 64
MAX_EVIDENCE = 16
MAX_STATEMENT_BYTES = 16 * 1024
MAX_COMMAND_BYTES = 24 * 1024
MAX_ENTRY_BYTES = 32 * 1024
MAX_BUNDLE_ENTRIES = 4096
MAX_BUNDLE_BYTES = 16 * 1024 * 1024
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_MANIFEST_FILES = 10000
MAX_HEAD_AGE_MS = 30000
MAX_COMMAND_TTL_MS = 300000

ARTIFACT_PROFILES = ("bytes/1", "jcs/1", "tree/1")
FOREIGN_FORMATS = (
    "c2pa/opaque", "fv.sunlight-export/1", "vislineage-bundle/1",
    "world/opaque", "mint/opaque", "treaty/opaque", "generic/opaque",
)
SUBJECT_KINDS = ("dataset", "run", "model", "action", "evidence")
CAPTURE_MODES = ("creation_hook", "posthoc")
PARENT_RELATIONS = ("source", "dataset", "base_model", "run", "model")
EVENTS = (
    "StatementRecorded", "KeyAdded", "KeyRetired", "KeyRevoked", "StatementRetracted",
)


def bad(msg: str):
    raise SunlightError("SCHEMA_INVALID", cause=ValueError(msg))


def unsupported():
    raise SunlightError("VERSION_UNSUPPORTED")


def is_obj(v) -> bool:
    return isinstance(v, dict)


def keys(v: dict, want: list[str]) -> None:
    if set(v.keys()) != set(want):
        bad(f"keys {sorted(v.keys())} != {want}")


def need_int(v, name: str) -> int:
    if isinstance(v, bool) or not isinstance(v, int) or v < 0 or v > 9007199254740991:
        bad(f"{name} not a protocol integer")
    return v


def need_str(v, name: str) -> str:
    if not isinstance(v, str) or len(v.encode("utf-8")) > MAX_TEXT_UTF8:
        bad(f"{name} not text")
    return v


def need_digest(v, name: str) -> str:
    if not isinstance(v, str) or not DIGEST_RE.match(v):
        bad(f"{name} not digest")
    return v


def need_hex32(v, name: str) -> str:
    if not isinstance(v, str) or not HEX32_RE.match(v):
        bad(f"{name} not hex32")
    return v


def need_hex64(v, name: str) -> str:
    if not isinstance(v, str) or not HEX64_RE.match(v):
        bad(f"{name} not hex64")
    return v


def need_id(v, prefix: str, name: str) -> str:
    if not is_valid_id(v, prefix):
        bad(f"{name} not a {prefix}_ id")
    return v


def need_arr(v, name: str) -> list:
    if not isinstance(v, list):
        bad(f"{name} not array")
    return v


def need_enum(v, name: str, allowed) -> str:
    if v not in allowed:
        bad(f"{name} not in {allowed}")
    return v


def _sorted_unique_strs(xs: list[str], name: str) -> None:
    if len(set(xs)) != len(xs) or xs != sorted(xs):
        bad(f"{name} not strictly sorted/unique")


def parse_public_key(v):
    if not is_obj(v):
        bad("public key not object")
    keys(v, ["id", "public_hex"])
    k = {"id": need_id(v["id"], "slk", "key.id"), "public_hex": need_hex32(v["public_hex"], "key.public_hex")}
    if not is_valid_public_key(bytes.fromhex(k["public_hex"])):
        bad("key.public_hex not a canonical Ed25519 key")
    return k


def parse_head_ref(v):
    if not is_obj(v):
        bad("head ref not object")
    keys(v, ["seq", "hash"])
    return {"seq": need_int(v["seq"], "head.seq"), "hash": need_digest(v["hash"], "head.hash")}


_TREE_PATH_RE = re.compile(r"^[A-Za-z0-9._\-/]+$")


def is_valid_tree_path(p: str) -> bool:
    b = p.encode("utf-8")
    if len(b) < 1 or len(b) > 240 or not p.isascii():
        return False
    if not _TREE_PATH_RE.match(p):
        return False
    if p.startswith("/") or p.endswith("/") or "\\" in p:
        return False
    return all(c not in ("", ".", "..") for c in p.split("/"))


def parse_tree_manifest(v):
    if not is_obj(v):
        bad("manifest not object")
    keys(v, ["v", "files"])
    if v["v"] != "sunlight.tree/1":
        if isinstance(v["v"], str):
            unsupported()
        bad("manifest v")
    files = need_arr(v["files"], "manifest.files")
    if len(files) > MAX_MANIFEST_FILES:
        bad("manifest file count")
    out = []
    for i, f in enumerate(files):
        if not is_obj(f):
            bad(f"manifest.files[{i}] not object")
        keys(f, ["path", "digest", "bytes"])
        path = need_str(f["path"], f"manifest.files[{i}].path")
        if not is_valid_tree_path(path):
            bad(f"manifest.files[{i}].path invalid")
        out.append({
            "path": path,
            "digest": need_digest(f["digest"], f"manifest.files[{i}].digest"),
            "bytes": need_int(f["bytes"], f"manifest.files[{i}].bytes"),
        })
    paths = [f["path"] for f in out]
    _sorted_unique_strs(paths, "manifest.files")
    seen = set()
    for f in out:
        fold = f["path"].lower()
        if fold in seen:
            bad("manifest case-insensitive path collision")
        seen.add(fold)
    m = {"v": "sunlight.tree/1", "files": out}
    if len(jcs(m)) > MAX_MANIFEST_BYTES:
        bad("manifest over 1 MiB")
    return m


def parse_genesis(v):
    if not is_obj(v):
        bad("genesis not object")
    keys(v, ["v", "ledger", "created_at_ms", "admin", "audit", "producers"])
    if v["v"] != "sunlight.genesis/1":
        if isinstance(v["v"], str):
            unsupported()
        bad("genesis v")
    producers = [parse_public_key(p) for p in need_arr(v["producers"], "genesis.producers")]
    if len(producers) < 1 or len(producers) > 64:
        bad("genesis.producers count")
    pids = [p["id"] for p in producers]
    pubs = [p["public_hex"] for p in producers]
    admin = parse_public_key(v["admin"])
    audit = parse_public_key(v["audit"])
    all_ids = [admin["id"], audit["id"], *pids]
    all_pubs = [admin["public_hex"], audit["public_hex"], *pubs]
    if len(set(all_ids)) != len(all_ids) or len(set(all_pubs)) != len(all_pubs):
        bad("genesis keys not unique")
    return {
        "v": "sunlight.genesis/1",
        "ledger": need_id(v["ledger"], "sll", "genesis.ledger"),
        "created_at_ms": need_int(v["created_at_ms"], "genesis.created_at_ms"),
        "admin": admin,
        "audit": audit,
        "producers": producers,
    }


def parse_parent(v):
    if not is_obj(v):
        bad("parent not object")
    keys(v, ["statement", "artifact", "relation"])
    return {
        "statement": need_digest(v["statement"], "parent.statement"),
        "artifact": need_digest(v["artifact"], "parent.artifact"),
        "relation": need_enum(v["relation"], "parent.relation", PARENT_RELATIONS),
    }


def parse_evidence_ref(v):
    if not is_obj(v):
        bad("evidence ref not object")
    keys(v, ["artifact", "format", "source_commitment", "assessment"])
    fmt = need_enum(v["format"], "evidence.format", FOREIGN_FORMATS)
    sc = v["source_commitment"]
    if sc is not None:
        sc = need_digest(sc, "evidence.source_commitment")
    if fmt != "vislineage-bundle/1" and sc is not None:
        bad("evidence.source_commitment only for vislineage-bundle/1")
    if fmt == "vislineage-bundle/1" and sc is None:
        bad("vislineage evidence requires source_commitment")
    if v["assessment"] != "OPAQUE":
        bad("evidence.assessment not OPAQUE")
    return {
        "artifact": parse_artifact(v["artifact"]),
        "format": fmt,
        "source_commitment": sc,
        "assessment": "OPAQUE",
    }


def parse_artifact(v):
    if not is_obj(v):
        bad("artifact not object")
    keys(v, ["profile", "digest", "bytes"])
    return {
        "profile": need_enum(v["profile"], "artifact.profile", ARTIFACT_PROFILES),
        "digest": need_digest(v["digest"], "artifact.digest"),
        "bytes": need_int(v["bytes"], "artifact.bytes"),
    }


def parse_details(v):
    if not is_obj(v):
        bad("details not object")
    t = v.get("type")
    if t == "creation":
        keys(v, ["type"])
        return {"type": "creation"}
    if t == "transform":
        keys(v, ["type", "procedure"])
        return {"type": "transform", "procedure": need_digest(v["procedure"], "details.procedure")}
    if t == "training":
        keys(v, ["type", "run_id", "code", "environment", "parameters", "seed"])
        seed = v["seed"]
        if seed is not None:
            seed = need_str(seed, "details.seed")
            if not re.match(r"^(?:0|[1-9][0-9]{0,127})$", seed):
                bad("details.seed not a decimal seed")
        return {
            "type": "training",
            "run_id": need_id(v["run_id"], "slr", "details.run_id"),
            "code": need_digest(v["code"], "details.code"),
            "environment": need_digest(v["environment"], "details.environment"),
            "parameters": need_digest(v["parameters"], "details.parameters"),
            "seed": seed,
        }
    if t == "model":
        keys(v, ["type"])
        return {"type": "model"}
    if t == "action":
        keys(v, ["type", "action_id", "input", "output", "outcome", "context"])
        out = {
            "type": "action",
            "action_id": need_id(v["action_id"], "sla", "details.action_id"),
            "input": need_digest(v["input"], "details.input"),
            "output": need_digest(v["output"], "details.output") if v["output"] is not None else None,
            "outcome": need_enum(v["outcome"], "details.outcome", ("attempted", "completed", "failed")),
            "context": need_digest(v["context"], "details.context") if v["context"] is not None else None,
        }
        return out
    if isinstance(t, str):
        bad("details.type unknown")
    bad("details.type")


def parse_statement_body(v):
    if not is_obj(v):
        bad("statement body not object")
    keys(v, ["v", "id", "ledger", "signer", "claimed_at_ms", "capture", "subject", "parents", "details", "evidence"])
    if v["v"] != "sunlight.statement/1":
        if isinstance(v["v"], str):
            unsupported()
        bad("statement v")
    subject = v["subject"]
    if not is_obj(subject):
        bad("subject not object")
    keys(subject, ["kind", "artifact"])
    parents = [parse_parent(p) for p in need_arr(v["parents"], "statement.parents")]
    if len(parents) > MAX_PARENTS:
        bad("parents count")
    _sorted_unique_strs(
        [p["relation"] + p["statement"] for p in parents], "statement.parents",
    )
    evidence = [parse_evidence_ref(e) for e in need_arr(v["evidence"], "statement.evidence")]
    if len(evidence) > MAX_EVIDENCE:
        bad("evidence count")
    _sorted_unique_strs(
        [e["format"] + e["artifact"]["digest"] for e in evidence], "statement.evidence",
    )
    return {
        "v": "sunlight.statement/1",
        "id": need_id(v["id"], "sls", "statement.id"),
        "ledger": need_id(v["ledger"], "sll", "statement.ledger"),
        "signer": need_id(v["signer"], "slk", "statement.signer"),
        "claimed_at_ms": need_int(v["claimed_at_ms"], "statement.claimed_at_ms"),
        "capture": need_enum(v["capture"], "statement.capture", CAPTURE_MODES),
        "subject": {
            "kind": need_enum(subject["kind"], "subject.kind", SUBJECT_KINDS),
            "artifact": parse_artifact(subject["artifact"]),
        },
        "parents": parents,
        "details": parse_details(v["details"]),
        "evidence": evidence,
    }


def parse_statement(v):
    if not is_obj(v):
        bad("statement not object")
    keys(v, ["body", "hash", "signature_hex"])
    return {
        "body": parse_statement_body(v["body"]),
        "hash": need_digest(v["hash"], "statement.hash"),
        "signature_hex": need_hex64(v["signature_hex"], "statement.signature_hex"),
    }


def parse_operation(v):
    if not is_obj(v):
        bad("operation not object")
    t = v.get("type")
    if t == "claim":
        keys(v, ["type", "statement"])
        return {"type": "claim", "statement": parse_statement(v["statement"])}
    if t == "key_add":
        keys(v, ["type", "key"])
        return {"type": "key_add", "key": parse_public_key(v["key"])}
    if t == "key_retire":
        keys(v, ["type", "key"])
        return {"type": "key_retire", "key": need_id(v["key"], "slk", "operation.key")}
    if t == "key_revoke":
        keys(v, ["type", "key", "reason"])
        return {
            "type": "key_revoke",
            "key": need_id(v["key"], "slk", "operation.key"),
            "reason": need_enum(v["reason"], "operation.reason", ("compromise", "withdrawn")),
        }
    if t == "retract":
        keys(v, ["type", "statement", "reason"])
        return {
            "type": "retract",
            "statement": need_digest(v["statement"], "operation.statement"),
            "reason": need_enum(v["reason"], "operation.reason", ("incorrect", "withdrawn")),
        }
    bad("operation.type unknown")


def parse_command_body(v):
    if not is_obj(v):
        bad("command body not object")
    keys(v, ["v", "id", "ledger", "signer", "expected_head", "issued_at_ms", "expires_at_ms", "operation"])
    if v["v"] != "sunlight.command/1":
        if isinstance(v["v"], str):
            unsupported()
        bad("command v")
    issued = need_int(v["issued_at_ms"], "command.issued_at_ms")
    expires = need_int(v["expires_at_ms"], "command.expires_at_ms")
    if not (0 < expires - issued <= MAX_COMMAND_TTL_MS):
        bad("command TTL window")
    return {
        "v": "sunlight.command/1",
        "id": need_id(v["id"], "slq", "command.id"),
        "ledger": need_id(v["ledger"], "sll", "command.ledger"),
        "signer": need_id(v["signer"], "slk", "command.signer"),
        "expected_head": parse_head_ref(v["expected_head"]),
        "issued_at_ms": issued,
        "expires_at_ms": expires,
        "operation": parse_operation(v["operation"]),
    }


def parse_command(v):
    if not is_obj(v):
        bad("command not object")
    keys(v, ["body", "hash", "signature_hex"])
    return {
        "body": parse_command_body(v["body"]),
        "hash": need_digest(v["hash"], "command.hash"),
        "signature_hex": need_hex64(v["signature_hex"], "command.signature_hex"),
    }


def parse_receipt_body(v):
    if not is_obj(v):
        bad("receipt body not object")
    keys(v, ["v", "id", "ledger", "seq", "previous_hash", "command_hash", "statement_hash", "event", "committed_at_ms"])
    if v["v"] != "sunlight.receipt/1":
        if isinstance(v["v"], str):
            unsupported()
        bad("receipt v")
    sh = v["statement_hash"]
    if sh is not None:
        sh = need_digest(sh, "receipt.statement_hash")
    return {
        "v": "sunlight.receipt/1",
        "id": need_id(v["id"], "sle", "receipt.id"),
        "ledger": need_id(v["ledger"], "sll", "receipt.ledger"),
        "seq": need_int(v["seq"], "receipt.seq"),
        "previous_hash": need_digest(v["previous_hash"], "receipt.previous_hash"),
        "command_hash": need_digest(v["command_hash"], "receipt.command_hash"),
        "statement_hash": sh,
        "event": need_enum(v["event"], "receipt.event", EVENTS),
        "committed_at_ms": need_int(v["committed_at_ms"], "receipt.committed_at_ms"),
    }


def parse_receipt(v):
    if not is_obj(v):
        bad("receipt not object")
    keys(v, ["body", "hash", "signature_hex"])
    return {
        "body": parse_receipt_body(v["body"]),
        "hash": need_digest(v["hash"], "receipt.hash"),
        "signature_hex": need_hex64(v["signature_hex"], "receipt.signature_hex"),
    }


def parse_entry(v):
    if not is_obj(v):
        bad("entry not object")
    keys(v, ["command", "receipt"])
    return {"command": parse_command(v["command"]), "receipt": parse_receipt(v["receipt"])}


def parse_head_body(v):
    if not is_obj(v):
        bad("head body not object")
    keys(v, ["v", "ledger", "genesis_hash", "head", "observed_at_ms", "nonce_hex"])
    if v["v"] != "sunlight.head/1":
        if isinstance(v["v"], str):
            unsupported()
        bad("head v")
    nonce = v["nonce_hex"]
    if nonce is not None:
        nonce = need_hex32(nonce, "head.nonce_hex")
    return {
        "v": "sunlight.head/1",
        "ledger": need_id(v["ledger"], "sll", "head.ledger"),
        "genesis_hash": need_digest(v["genesis_hash"], "head.genesis_hash"),
        "head": parse_head_ref(v["head"]),
        "observed_at_ms": need_int(v["observed_at_ms"], "head.observed_at_ms"),
        "nonce_hex": nonce,
    }


def parse_signed_head(v):
    if not is_obj(v):
        bad("head not object")
    keys(v, ["body", "hash", "signature_hex"])
    return {
        "body": parse_head_body(v["body"]),
        "hash": need_digest(v["hash"], "head.hash"),
        "signature_hex": need_hex64(v["signature_hex"], "head.signature_hex"),
    }


def parse_bundle(v):
    if not is_obj(v):
        bad("bundle not object")
    keys(v, ["v", "genesis", "entries", "head", "target"])
    if v["v"] != "sunlight.bundle/1":
        if isinstance(v["v"], str):
            unsupported()
        bad("bundle v")
    entries = [parse_entry(e) for e in need_arr(v["entries"], "bundle.entries")]
    return {
        "v": "sunlight.bundle/1",
        "genesis": parse_genesis(v["genesis"]),
        "entries": entries,
        "head": parse_signed_head(v["head"]),
        "target": need_digest(v["target"], "bundle.target"),
    }


def parse_trust(v):
    if not is_obj(v):
        bad("trust not object")
    keys(v, ["v", "ledger", "genesis_hash", "minimum_head", "denied_keys", "require_training", "max_head_age_ms"])
    if v["v"] != "sunlight.trust/1":
        if isinstance(v["v"], str):
            unsupported()
        bad("trust v")
    denied = need_arr(v["denied_keys"], "trust.denied_keys")
    denied_ids = [need_id(x, "slk", "trust.denied_keys[]") for x in denied]
    if len(set(denied_ids)) != len(denied_ids):
        bad("trust.denied_keys duplicate")
    if not isinstance(v["require_training"], bool):
        bad("trust.require_training")
    max_age = need_int(v["max_head_age_ms"], "trust.max_head_age_ms")
    if max_age > MAX_HEAD_AGE_MS * 100:
        bad("trust.max_head_age_ms")
    return {
        "v": "sunlight.trust/1",
        "ledger": need_id(v["ledger"], "sll", "trust.ledger"),
        "genesis_hash": need_digest(v["genesis_hash"], "trust.genesis_hash"),
        "minimum_head": parse_head_ref(v["minimum_head"]),
        "denied_keys": denied_ids,
        "require_training": v["require_training"],
        "max_head_age_ms": max_age,
    }


def parse_freshness_evidence(v):
    if not is_obj(v):
        bad("freshness not object")
    keys(v, ["head", "expected_nonce_hex", "sent_at_ms", "received_at_ms"])
    return {
        "head": parse_signed_head(v["head"]),
        "expected_nonce_hex": need_hex32(v["expected_nonce_hex"], "freshness.expected_nonce_hex"),
        "sent_at_ms": need_int(v["sent_at_ms"], "freshness.sent_at_ms"),
        "received_at_ms": need_int(v["received_at_ms"], "freshness.received_at_ms"),
    }


def parse_artifact_observation(v):
    if not is_obj(v):
        bad("observation not object")
    keys(v, ["artifact"])
    return {"artifact": parse_artifact(v["artifact"])}


_ENV_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")


def parse_client_config(v):
    if not is_obj(v):
        bad("config not object")
    keys(v, ["v", "default_ledger", "registries", "cache_dir", "connect_timeout_ms",
             "read_timeout_ms", "allow_loopback_http"])
    if v["v"] != "sunlight.config/1":
        if isinstance(v["v"], str):
            unsupported()
        bad("config v")
    regs = []
    for i, r in enumerate(need_arr(v["registries"], "config.registries")):
        if not is_obj(r):
            bad(f"config.registries[{i}]")
        keys(r, ["ledger", "origin", "bearer_env", "trust_file"])
        be = need_str(r["bearer_env"], f"config.registries[{i}].bearer_env")
        if not _ENV_NAME_RE.match(be):
            bad("bearer_env name")
        regs.append({
            "ledger": need_id(r["ledger"], "sll", f"config.registries[{i}].ledger"),
            "origin": need_str(r["origin"], f"config.registries[{i}].origin"),
            "bearer_env": be,
            "trust_file": need_str(r["trust_file"], f"config.registries[{i}].trust_file"),
        })
    if len(regs) < 1 or len(regs) > 32:
        bad("config.registries count")
    ledger = need_id(v["default_ledger"], "sll", "config.default_ledger")
    if ledger not in {r["ledger"] for r in regs}:
        bad("config.default_ledger not in registries")
    if len({r["ledger"] for r in regs}) != len(regs):
        bad("config.registries duplicate ledgers")
    conn = need_int(v["connect_timeout_ms"], "config.connect_timeout_ms")
    read = need_int(v["read_timeout_ms"], "config.read_timeout_ms")
    if not (100 <= conn <= 30000 and 100 <= read <= 30000):
        bad("config timeouts out of range")
    if not isinstance(v["allow_loopback_http"], bool):
        bad("config.allow_loopback_http")
    return {
        "v": "sunlight.config/1",
        "default_ledger": ledger,
        "registries": regs,
        "cache_dir": need_str(v["cache_dir"], "config.cache_dir"),
        "connect_timeout_ms": conn,
        "read_timeout_ms": read,
        "allow_loopback_http": v["allow_loopback_http"],
    }


def parse_local_key_file(v):
    if not is_obj(v):
        bad("keyfile not object")
    keys(v, ["v", "key", "encrypted_pkcs8_pem"])
    if v["v"] != "sunlight.keyfile/1":
        if isinstance(v["v"], str):
            unsupported()
        bad("keyfile v")
    pem = need_str(v["encrypted_pkcs8_pem"], "keyfile.encrypted_pkcs8_pem")
    if len(pem.encode("ascii", errors="ignore")) != len(pem.encode("utf-8")) or len(pem) > 4096:
        bad("keyfile pem bounds")
    if "ENCRYPTED PRIVATE KEY" not in pem:
        bad("keyfile pem type")
    return {"v": "sunlight.keyfile/1", "key": parse_public_key(v["key"]), "encrypted_pkcs8_pem": pem}


def parse_token_binding(v):
    if not is_obj(v):
        bad("token binding not object")
    keys(v, ["token_sha256", "ledger", "role"])
    return {
        "token_sha256": need_digest(v["token_sha256"], "token.token_sha256"),
        "ledger": need_id(v["ledger"], "sll", "token.ledger"),
        "role": need_enum(v["role"], "token.role", ("read", "write")),
    }


def parse_deployment_config(v):
    if not is_obj(v):
        bad("deployment not object")
    keys(v, ["v", "ledgers", "auth_secret_binding", "rate_per_token_per_minute",
             "max_inflight_per_ledger", "protocol"])
    if v["v"] != "sunlight.deployment/1":
        if isinstance(v["v"], str):
            unsupported()
        bad("deployment v")
    if v["protocol"] != "sunlight/1":
        bad("deployment protocol")
    auth = need_str(v["auth_secret_binding"], "deployment.auth_secret_binding")
    if not _ENV_NAME_RE.match(auth):
        bad("auth_secret_binding name")
    ledgers = []
    for i, l in enumerate(need_arr(v["ledgers"], "deployment.ledgers")):
        if not is_obj(l):
            bad(f"deployment.ledgers[{i}]")
        keys(l, ["genesis", "audit_secret_binding"])
        asb = need_str(l["audit_secret_binding"], f"ledgers[{i}].audit_secret_binding")
        if not _ENV_NAME_RE.match(asb):
            bad("audit_secret_binding name")
        ledgers.append({"genesis": parse_genesis(l["genesis"]), "audit_secret_binding": asb})
    if len(ledgers) < 1 or len(ledgers) > 32:
        bad("deployment.ledgers count")
    if len({l["genesis"]["ledger"] for l in ledgers}) != len(ledgers):
        bad("duplicate deployment ledgers")
    rate = need_int(v["rate_per_token_per_minute"], "deployment.rate")
    inflight = need_int(v["max_inflight_per_ledger"], "deployment.max_inflight")
    if not (1 <= rate <= 10000) or not (1 <= inflight <= 32):
        bad("deployment limits")
    return {
        "v": "sunlight.deployment/1",
        "ledgers": ledgers,
        "auth_secret_binding": auth,
        "rate_per_token_per_minute": rate,
        "max_inflight_per_ledger": inflight,
        "protocol": "sunlight/1",
    }
