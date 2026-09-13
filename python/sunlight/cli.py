"""`sunlight` CLI (spec §7) — Python client parity.

Every mutating operation goes through the same signed-command admission path
as the network protocol; the CLI never mutates a ledger directly.  The
Python CLI covers the client command surface; the registry server and the
``conformance`` runner ship in the TypeScript package.

Exit codes (spec §7 table):
  0 ok · 2 usage/config/schema · 3 well-formed evidence invalid ·
  4 untrusted/insufficient evidence · 5 authn/authz/key-file ·
  6 retryable network/service · 7 state/idempotency conflict ·
  8 I/O/resource · 130 interrupt.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import sys
from urllib.parse import urlparse

from . import conformance_env
from .artifact import hash_artifact
from .cache import Cache
from .config import DEFAULT_CONFIG_PATH, config_path, load_config, resolve_registry
from .domains import B, D, DIGEST_RE
from .errors import SunlightError, cli_exit_for, error_body
from .fsutil import read_file_bytes, write_file_exclusive
from .ids import new_id
from .jcs import jcs
from .keys import generate_key, load_key_file, write_key_file, write_public_key_file
from .objects import sign_command, sign_statement
from .schema import (
    parse_bundle, parse_command, parse_genesis, parse_public_key,
    parse_signed_head, parse_statement, parse_statement_body, parse_trust,
)
from .strictjson import parse_strict_json
from .transport import RegistryTransport
from .verify import verify

ENV_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
FOREIGN_FORMATS = {
    "c2pa/opaque", "fv.sunlight-export/1", "vislineage-bundle/1",
    "world/opaque", "mint/opaque", "treaty/opaque", "generic/opaque",
}


def parse_argv(argv):
    positional, opts = [], {}
    i = 0
    while i < len(argv):
        a = argv[i]
        if a.startswith("--"):
            if "=" in a:
                k, v = a[2:].split("=", 1)
                opts[k] = v
            elif i + 1 < len(argv) and not argv[i + 1].startswith("--"):
                opts[a[2:]] = argv[i + 1]
                i += 1
            else:
                opts[a[2:]] = True
        else:
            positional.append(a)
        i += 1
    return {"positional": positional, "opts": opts}


def _need(flags, name):
    v = flags["opts"].get(name)
    if not isinstance(v, str) or v == "":
        raise SunlightError("USAGE")
    return v


def _opt(flags, name):
    v = flags["opts"].get(name)
    return v if isinstance(v, str) and v != "" else None


def _read_json(path):
    try:
        raw = read_file_bytes(path)
    except Exception as e:
        raise SunlightError("IO_ERROR", cause=e) from e
    return parse_strict_json(raw)


def _cut_from(flags):
    p = _opt(flags, "cut")
    if p is None:
        return None
    v = _read_json(p)
    if not isinstance(v, dict):
        raise SunlightError("SCHEMA_INVALID")
    if isinstance(v.get("seq"), int) and isinstance(v.get("hash"), str):
        return {"seq": v["seq"], "hash": v["hash"]}
    return parse_signed_head(v)["body"]["head"]


def _client_ctx(flags, for_write):
    if flags["opts"].get("offline") is True:
        raise SunlightError("USAGE")
    config_path_ = _opt(flags, "config") or DEFAULT_CONFIG_PATH
    cfg = load_config(config_path_)
    ledger_flag = _opt(flags, "ledger")
    registry = resolve_registry(cfg, config_path_, None if for_write else ledger_flag)
    timeout = _opt(flags, "timeout-ms")
    read_timeout = cfg["read_timeout_ms"]
    if timeout is not None:
        try:
            n = int(timeout)
        except ValueError:
            raise SunlightError("USAGE")
        if not (100 <= n <= 30000):
            raise SunlightError("USAGE")
        read_timeout = n
    transport = RegistryTransport(
        origin=registry["origin"],
        bearer=registry["bearer"],
        connect_timeout_ms=cfg["connect_timeout_ms"],
        read_timeout_ms=read_timeout,
        request_id=lambda: conformance_env.fixed_request_id() or new_id("slq"),
    )
    cache = Cache(config_path(config_path_, cfg["cache_dir"]))
    return {"flags": flags, "config_path": config_path_, "cfg": cfg,
            "registry": registry, "transport": transport, "cache": cache}


def _fetch_head(ctx):
    nonce = conformance_env.fresh_nonce_hex(secrets.token_bytes)
    res = ctx["transport"].rpc("head.get", {
        "ledger": ctx["registry"]["ledger"], "nonce_hex": nonce,
    })
    return parse_signed_head(res)


def _read_cut_or_head(ctx, flags):
    cut = _cut_from(flags)
    return cut if cut is not None else _fetch_head(ctx)["body"]["head"]


def _submit_operation(ctx, signer, operation):
    head = _fetch_head(ctx)
    now = conformance_env.now_ms()
    body = {
        "v": "sunlight.command/1",
        "id": conformance_env.fixed_request_id() or new_id("slq"),
        "ledger": ctx["registry"]["ledger"],
        "signer": signer.key["id"],
        "expected_head": head["body"]["head"],
        "issued_at_ms": now,
        "expires_at_ms": now + 300_000,
        "operation": operation,
    }
    command = sign_command(body, signer)
    ctx["cache"].store_pending(command["body"]["id"], command)
    ctx["cache"].journal("local.CommandDurable", None, None, conformance_env.now_ms())
    try:
        result = ctx["transport"].rpc(
            "append", {"ledger": ctx["registry"]["ledger"], "command": command},
            command["body"]["id"],
        )
        ctx["cache"].drop_pending(command["body"]["id"])
        return result
    except Exception:
        raise  # pending command left for `command submit` recovery


def _passphrase_for_key():
    fd = os.environ.get("SUNLIGHT_KEY_PASSPHRASE_FD")
    if fd:
        n = int(fd)
        chunks = []
        while True:
            b = os.read(n, 4096)
            if not b:
                break
            chunks.append(b)
            if b"\n" in b:
                break
        return b"".join(chunks).decode("utf-8").split("\n")[0].rstrip("\r")
    raise SunlightError(
        "KEY_ERROR", cause=ValueError("passphrase required via SUNLIGHT_KEY_PASSPHRASE_FD")
    )


def run_cli(argv):
    flags = parse_argv(argv)
    pos = flags["positional"]
    cmd = pos[0] if pos else None

    if cmd == "init":
        ledger = _need(flags, "ledger")
        genesis = parse_genesis(_read_json(_need(flags, "genesis")))
        if genesis["ledger"] != ledger:
            raise SunlightError("UNTRUSTED_GENESIS")
        trust = parse_trust(_read_json(_need(flags, "trust")))
        if trust["ledger"] != genesis["ledger"] or trust["genesis_hash"] != D("sunlight.genesis/1", genesis):
            raise SunlightError("UNTRUSTED_GENESIS")
        origin = _need(flags, "origin")
        bearer_env = _need(flags, "bearer-env")
        if not ENV_NAME_RE.match(bearer_env):
            raise SunlightError("USAGE")
        u = urlparse(origin)
        loopback = (u.hostname or "") in ("127.0.0.1", "::1")
        allow_loopback = u.scheme == "http" and loopback
        if u.scheme != "https" and not allow_loopback:
            raise SunlightError("USAGE")
        cfg = {
            "v": "sunlight.config/1",
            "default_ledger": ledger,
            "registries": [{
                "ledger": ledger, "origin": origin,
                "bearer_env": bearer_env, "trust_file": _need(flags, "trust"),
            }],
            "cache_dir": "./.sunlight-cache",
            "connect_timeout_ms": 3000,
            "read_timeout_ms": 10000,
            "allow_loopback_http": allow_loopback,
        }
        out = _need(flags, "out")
        write_file_exclusive(out, jcs(cfg), 0o600)
        return 0, {"config": out, "ledger": ledger}

    if cmd == "key":
        sub = pos[1] if len(pos) > 1 else None
        if sub == "generate":
            out = _need(flags, "out")
            public_out = _need(flags, "public-out")
            eh = conformance_env.key_entropy_hex()
            entropy = bytes.fromhex(eh) if eh is not None else None
            g = generate_key(_passphrase_for_key(), entropy)
            write_key_file(out, g["file"])
            write_public_key_file(public_out, g["key"])
            return 0, {"private_path": out, "public_path": public_out, "key": g["key"]}
        ctx = _client_ctx(flags, True)
        admin_key = load_key_file(_need(flags, "admin-key"))
        if sub == "add":
            operation = {"type": "key_add", "key": parse_public_key(_read_json(_need(flags, "public")))}
        elif sub == "retire":
            operation = {"type": "key_retire", "key": _need(flags, "id")}
        elif sub == "revoke":
            reason = _need(flags, "reason")
            if reason not in ("compromise", "withdrawn"):
                raise SunlightError("USAGE")
            operation = {"type": "key_revoke", "key": _need(flags, "id"), "reason": reason}
        else:
            raise SunlightError("USAGE")
        return 0, _submit_operation(ctx, admin_key, operation)

    if cmd == "hash":
        file = pos[1] if len(pos) > 1 else _opt(flags, "file")
        if file is None:
            raise SunlightError("USAGE")
        profile = _need(flags, "profile")
        if profile not in ("bytes/1", "tree/1", "jcs/1"):
            raise SunlightError("USAGE")
        return 0, hash_artifact(file, profile)

    if cmd == "sign":
        body = parse_statement_body(_read_json(_need(flags, "body")))
        if body["capture"] != "posthoc":
            raise SunlightError("USAGE")
        artifact = hash_artifact(_need(flags, "artifact"), body["subject"]["artifact"]["profile"])
        want = body["subject"]["artifact"]
        if artifact["digest"] != want["digest"] or artifact["bytes"] != want["bytes"] or artifact["profile"] != want["profile"]:
            raise SunlightError("HASH_MISMATCH")
        statement = sign_statement(body, load_key_file(_need(flags, "key")))
        out = _opt(flags, "out")
        if out is not None:
            write_file_exclusive(out, jcs(statement), 0o600)
        return 0, statement

    if cmd == "submit":
        ctx = _client_ctx(flags, True)
        statement = parse_statement(_read_json(_need(flags, "statement")))
        signer = load_key_file(_need(flags, "key"))
        head = _fetch_head(ctx)
        now = conformance_env.now_ms()
        body = {
            "v": "sunlight.command/1",
            "id": conformance_env.fixed_request_id() or new_id("slq"),
            "ledger": ctx["registry"]["ledger"],
            "signer": signer.key["id"],
            "expected_head": head["body"]["head"],
            "issued_at_ms": now,
            "expires_at_ms": now + 300_000,
            "operation": {"type": "claim", "statement": statement},
        }
        command = sign_command(body, signer)
        ctx["cache"].store_pending(command["body"]["id"], command)
        out = _opt(flags, "command-out")
        if out is not None:
            write_file_exclusive(out, jcs(command), 0o600)
        result = ctx["transport"].rpc(
            "append", {"ledger": ctx["registry"]["ledger"], "command": command},
            command["body"]["id"],
        )
        ctx["cache"].drop_pending(command["body"]["id"])
        return 0, result

    if cmd == "command":
        if len(pos) < 2 or pos[1] != "submit":
            raise SunlightError("USAGE")
        ctx = _client_ctx(flags, True)
        command = parse_command(_read_json(_need(flags, "command")))
        result = ctx["transport"].rpc(
            "append", {"ledger": ctx["registry"]["ledger"], "command": command},
            command["body"]["id"],
        )
        ctx["cache"].drop_pending(command["body"]["id"])
        return 0, result

    if cmd == "retract":
        ctx = _client_ctx(flags, True)
        signer = load_key_file(_need(flags, "key"))
        reason = _need(flags, "reason")
        if reason not in ("incorrect", "withdrawn"):
            raise SunlightError("USAGE")
        return 0, _submit_operation(ctx, signer, {
            "type": "retract", "statement": _need(flags, "statement"), "reason": reason,
        })

    if cmd == "head":
        ctx = _client_ctx(flags, False)
        return 0, _fetch_head(ctx)

    if cmd == "lookup":
        ctx = _client_ctx(flags, False)
        profile = _need(flags, "profile")
        if profile not in ("bytes/1", "tree/1", "jcs/1"):
            raise SunlightError("USAGE")
        artifact = hash_artifact(_need(flags, "artifact"), profile)
        cut = _read_cut_or_head(ctx, flags)
        result = ctx["transport"].rpc("artifact.lookup", {
            "ledger": ctx["registry"]["ledger"],
            "profile": profile,
            "digest": artifact["digest"],
            "cut": cut,
            "after_seq": int(_opt(flags, "after-seq") or "0"),
            "limit": int(_opt(flags, "limit") or "100"),
        })
        return 0, result

    if cmd == "statement":
        ctx = _client_ctx(flags, False)
        result = ctx["transport"].rpc("statement.get", {
            "ledger": ctx["registry"]["ledger"],
            "statement": _need(flags, "hash"),
            "cut": _read_cut_or_head(ctx, flags),
        })
        return 0, result

    if cmd == "entries":
        ctx = _client_ctx(flags, False)
        result = ctx["transport"].rpc("entries.list", {
            "ledger": ctx["registry"]["ledger"],
            "after": int(_need(flags, "after")),
            "cut": _read_cut_or_head(ctx, flags),
            "limit": int(_opt(flags, "limit") or "100"),
        })
        return 0, result

    if cmd == "export":
        ctx = _client_ctx(flags, False)
        out = _need(flags, "out")
        res = ctx["transport"].rpc("bundle.export", {
            "ledger": ctx["registry"]["ledger"],
            "target": _need(flags, "statement"),
            "cut": _read_cut_or_head(ctx, flags),
        })
        bundle = parse_bundle(res["bundle"])
        write_file_exclusive(out, jcs(bundle), 0o600)
        ctx["cache"].store_bundle(res["digest"], bundle)
        return 0, {"output": out, "digest": res["digest"], "head": bundle["head"]["body"]["head"]}

    if cmd == "verify":
        bundle = parse_bundle(_read_json(_need(flags, "bundle")))
        trust = parse_trust(_read_json(_need(flags, "trust")))
        observation = None
        artifact_path = _opt(flags, "artifact")
        if artifact_path is not None:
            profile = _need(flags, "profile")
            if profile not in ("bytes/1", "tree/1", "jcs/1"):
                raise SunlightError("USAGE")
            observation = {"artifact": hash_artifact(artifact_path, profile)}
        freshness = None
        bundle_to_verify = bundle
        if flags["opts"].get("online") is True:
            if flags["opts"].get("offline") is True:
                raise SunlightError("USAGE")
            ctx = _client_ctx(flags, False)
            done = False
            for _ in range(3):
                nonce0 = conformance_env.fresh_nonce_hex(secrets.token_bytes)
                sent0 = conformance_env.now_ms()
                h0 = parse_signed_head(ctx["transport"].rpc("head.get", {
                    "ledger": ctx["registry"]["ledger"], "nonce_hex": nonce0,
                }))
                recv0 = conformance_env.now_ms()
                remote = ctx["transport"].rpc("bundle.export", {
                    "ledger": ctx["registry"]["ledger"],
                    "target": bundle["target"],
                    "cut": h0["body"]["head"],
                })
                candidate = parse_bundle(remote["bundle"])
                nonce1 = conformance_env.fresh_nonce_hex(secrets.token_bytes)
                h1 = parse_signed_head(ctx["transport"].rpc("head.get", {
                    "ledger": ctx["registry"]["ledger"], "nonce_hex": nonce1,
                }))
                if h1["body"]["head"]["seq"] == h0["body"]["head"]["seq"] and \
                        h1["body"]["head"]["hash"] == h0["body"]["head"]["hash"]:
                    bundle_to_verify = candidate
                    freshness = {
                        "head": h0, "expected_nonce_hex": nonce0,
                        "sent_at_ms": sent0, "received_at_ms": recv0,
                    }
                    done = True
                    break
            if not done:
                raise SunlightError("HEAD_CONFLICT")
        v = verify({
            "bundle": bundle_to_verify, "trust": trust,
            "observation": observation, "freshness": freshness,
        })
        code = 3 if v["overall"] == "INVALID" else (4 if v["overall"] == "UNVERIFIED" else 0)
        return code, v, _human_verify(v)

    if cmd == "import":
        if len(pos) < 2 or pos[1] != "evidence":
            raise SunlightError("USAGE")
        fmt = _need(flags, "format")
        if fmt not in FOREIGN_FORMATS:
            raise SunlightError("USAGE")
        try:
            raw = read_file_bytes(_need(flags, "input"))
        except Exception as e:
            raise SunlightError("IO_ERROR", cause=e) from e
        artifact = {"profile": "bytes/1", "digest": B(raw), "bytes": len(raw)}
        source_commitment = None
        if fmt == "vislineage-bundle/1":
            try:
                bj = parse_strict_json(raw)
            except Exception as e:
                raise SunlightError("SCHEMA_INVALID", cause=e) from e
            bh = bj.get("hash") if isinstance(bj, dict) else None
            if not isinstance(bh, str) or not DIGEST_RE.match(bh):
                raise SunlightError("SCHEMA_INVALID")
            source_commitment = bh
        computed = {
            "artifact": artifact, "format": fmt,
            "source_commitment": source_commitment, "assessment": "OPAQUE",
        }
        body = parse_statement_body(_read_json(_need(flags, "body")))
        if body["capture"] != "posthoc":
            raise SunlightError("USAGE")
        requested = body["evidence"]
        if len(requested) > 1:
            raise SunlightError("SCHEMA_INVALID")
        if len(requested) == 1:
            r = requested[0]
            if (
                r["format"] != computed["format"]
                or r["source_commitment"] != computed["source_commitment"]
                or r["assessment"] != "OPAQUE"
                or r["artifact"]["profile"] != computed["artifact"]["profile"]
                or r["artifact"]["digest"] != computed["artifact"]["digest"]
                or r["artifact"]["bytes"] != computed["artifact"]["bytes"]
            ):
                raise SunlightError("HASH_MISMATCH")
        signer = load_key_file(_need(flags, "key"))
        statement = sign_statement({**body, "evidence": [computed]}, signer)
        out = _opt(flags, "out")
        if out is not None:
            write_file_exclusive(out, jcs(statement), 0o600)
        return 0, statement

    if cmd == "audit":
        if len(pos) < 2 or pos[1] != "verify":
            raise SunlightError("USAGE")
        bundle = parse_bundle(_read_json(_need(flags, "bundle")))
        trust = parse_trust(_read_json(_need(flags, "trust")))
        v = verify({"bundle": bundle, "trust": trust, "observation": None, "freshness": None})
        if v["integrity"] != "VALID" or v["authority"] in ("UNTRUSTED", "UNKNOWN"):
            raise SunlightError(v["reasons"][0] if v["reasons"] else "HASH_MISMATCH")
        return 0, {"integrity": "VALID", "head": v["head"]}

    raise SunlightError("USAGE")


def _human_verify(v):
    lines = [
        "DECLARED LINEAGE — ledger verification result",
        f"  integrity:    {v['integrity']}",
        f"  lineage:      {v['lineage']}",
        f"  authority:    {v['authority']}",
        f"  freshness:    {v['freshness']}",
        f"  artifact:     {v['artifact']}",
        f"  claim truth:  {v['claim_truth']}",
        f"  overall:      {v['overall']}",
    ]
    if v["head"] is not None:
        lines.append(f"  head:         seq {v['head']['seq']} {v['head']['hash']}")
    if v["reasons"]:
        lines.append(f"  reasons:      {', '.join(v['reasons'])}")
    lines += [
        "",
        "  TRAINING/OWNERSHIP NOT PROVEN — a signature attests the",
        "  declared lineage, not the factual truth of its claims.",
    ]
    return "\n".join(lines)


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    flags = parse_argv(argv)
    as_json = flags["opts"].get("json") is True
    try:
        out = run_cli(argv)
        code, result = out[0], out[1]
        human = out[2] if len(out) > 2 else None
        if as_json:
            sys.stdout.write(json.dumps(result, separators=(",", ":")) + "\n")
        elif human is not None:
            sys.stdout.write(human + "\n")
            sys.stdout.write(json.dumps(result, indent=2) + "\n")
        else:
            sys.stdout.write(json.dumps(result, indent=2) + "\n")
        return code
    except SunlightError as e:
        sys.stderr.write(json.dumps({"error": error_body(e)}) + "\n")
        return cli_exit_for(e.code)
    except KeyboardInterrupt:
        sys.stderr.write(json.dumps({"error": {"code": "INTERRUPTED", "retryable": False, "head": None}}) + "\n")
        return 130
    except Exception as e:
        sys.stderr.write(json.dumps({"error": error_body(e)}) + "\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
