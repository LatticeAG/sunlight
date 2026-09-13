"""SDK mechanics: key custody, staged capture, config, cache, CLI surface."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import fixtures as F  # noqa: E402
from sunlight.cache import Cache  # noqa: E402
from sunlight.capture import capture  # noqa: E402
from sunlight.config import load_config, resolve_registry  # noqa: E402
from sunlight.errors import SunlightError  # noqa: E402
from sunlight.jcs import jcs  # noqa: E402
from sunlight.keys import generate_key, load_key_file, write_key_file  # noqa: E402
from sunlight.objects import seed_signer  # noqa: E402
from sunlight.schema import parse_client_config  # noqa: E402
from sunlight.strictjson import parse_strict_json  # noqa: E402

GOLD = json.loads((Path(__file__).resolve().parents[2] / "tests" / "fixtures.json").read_text())


def test_key_generate_and_load(tmp_path):
    g = generate_key("test-passphrase", None)
    assert g["file"]["v"] == "sunlight.keyfile/1"
    assert g["key"]["id"].startswith("slk_")
    kf = tmp_path / "k.key.json"
    write_key_file(str(kf), g["file"])
    assert oct(os.lstat(kf).st_mode & 0o777) == "0o600"
    signer = load_key_file(str(kf), "test-passphrase")
    assert signer.key["id"] == g["key"]["id"]
    # Bad passphrase → KEY_ERROR
    with pytest.raises(SunlightError) as ei:
        load_key_file(str(kf), "wrong")
    assert ei.value.code == "KEY_ERROR"
    # Group/other-readable file → KEY_PERMISSIONS
    os.chmod(kf, 0o644)
    with pytest.raises(SunlightError) as ei:
        load_key_file(str(kf), "test-passphrase")
    assert ei.value.code == "KEY_PERMISSIONS"


def test_capture_bytes(tmp_path):
    staging = tmp_path / "staging"
    staging.mkdir()
    pub = tmp_path / "out.bin"
    events = []
    res = capture(
        {
            "staging_parent": str(staging),
            "publish_path": str(pub),
            "profile": "bytes/1",
            "template": {
                "v": "sunlight.statement/1",
                "id": "sls_999999999999999999999",
                "ledger": F.L,
                "signer": F.KP["key"]["id"],
                "claimed_at_ms": F.T,
                "kind": "dataset",
                "parents": [],
                "details": {"type": "creation"},
                "evidence": [],
            },
        },
        lambda staged: Path(staged).write_bytes(b"abc"),
        seed_signer(F.KP["key"], F.KP["seed"]),
        lambda ev, d=None: events.append(ev),
    )
    assert res["recorded"] is False
    assert pub.read_bytes() == b"abc"
    assert res["statement"]["body"]["subject"]["artifact"] == F.A
    assert "local.ArtifactPublished" in events


def test_capture_jcs_canonicalizes(tmp_path):
    staging = tmp_path / "staging"
    staging.mkdir()
    pub = tmp_path / "out.json"
    res = capture(
        {
            "staging_parent": str(staging),
            "publish_path": str(pub),
            "profile": "jcs/1",
            "template": {
                "v": "sunlight.statement/1",
                "id": "sls_888888888888888888888",
                "ledger": F.L,
                "signer": F.KP["key"]["id"],
                "claimed_at_ms": F.T,
                "kind": "dataset",
                "parents": [],
                "details": {"type": "creation"},
                "evidence": [],
            },
        },
        lambda staged: Path(staged).write_text('{"b":2,"a":1}'),
        seed_signer(F.KP["key"], F.KP["seed"]),
    )
    assert pub.read_bytes() == b'{"a":1,"b":2}'
    assert res["statement"]["body"]["subject"]["artifact"]["digest"].startswith("sha256:")


def test_capture_output_exists(tmp_path):
    staging = tmp_path / "staging"
    staging.mkdir()
    pub = tmp_path / "out.bin"
    pub.write_bytes(b"preexisting")
    with pytest.raises(SunlightError) as ei:
        capture(
            {
                "staging_parent": str(staging),
                "publish_path": str(pub),
                "profile": "bytes/1",
                "template": {"v": "sunlight.statement/1", "id": "sls_777777777777777777777",
                             "ledger": F.L, "signer": F.KP["key"]["id"], "claimed_at_ms": F.T,
                             "kind": "dataset", "parents": [], "details": {"type": "creation"},
                             "evidence": []},
            },
            lambda staged: Path(staged).write_bytes(b"abc"),
            seed_signer(F.KP["key"], F.KP["seed"]),
        )
    assert ei.value.code == "OUTPUT_EXISTS"
    assert pub.read_bytes() == b"preexisting"


def test_client_config_fixture():
    cfg = parse_client_config(GOLD["client_config"])
    assert cfg["default_ledger"] == F.L


def test_config_loopback_policy(tmp_path):
    # http non-loopback is rejected even when allow_loopback_http=true
    cfg = {
        "v": "sunlight.config/1",
        "default_ledger": F.L,
        "registries": [{
            "ledger": F.L, "origin": "http://example.com",
            "bearer_env": "SUNLIGHT_REGISTRY_TOKEN", "trust_file": "./trust.json",
        }],
        "cache_dir": "./cache",
        "connect_timeout_ms": 3000,
        "read_timeout_ms": 10000,
        "allow_loopback_http": True,
    }
    p = tmp_path / "sunlight.json"
    p.write_bytes(jcs(cfg))
    with pytest.raises(SunlightError) as ei:
        load_config(str(p))
    assert ei.value.code == "CONFIG_INVALID"


def test_cache_roundtrip(tmp_path):
    c = Cache(str(tmp_path / "cache"))
    digest = F.S1["hash"]
    c.store_object(digest, F.S1)
    assert c.load_object(digest) == F.S1
    c.store_pending(F.C1["body"]["id"], F.C1)
    assert c.load_pending(F.C1["body"]["id"]) == F.C1
    assert F.C1["body"]["id"] in c.list_pending()
    c.drop_pending(F.C1["body"]["id"])
    assert c.list_pending() == []
    c.store_pin(F.L, F.head(F.H4))
    assert c.load_pin(F.L) == F.head(F.H4)


def _run_cli(args, env_extra=None, cwd=None):
    env = dict(os.environ)
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1])
    env.update(env_extra or {})
    return subprocess.run(
        [sys.executable, "-m", "sunlight", *args],
        capture_output=True, text=True, env=env, cwd=cwd,
    )


def test_cli_hash_json(tmp_path):
    p = tmp_path / "a.bin"
    p.write_bytes(b"abc")
    r = _run_cli(["hash", str(p), "--profile", "bytes/1", "--json"])
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout)
    assert out == F.A


def test_cli_hash_tree(tmp_path):
    d = tmp_path / "tree"
    d.mkdir()
    (d / "a.txt").write_bytes(b"abc")
    (d / "b.txt").write_bytes(b"")
    r = _run_cli(["hash", str(d), "--profile", "tree/1", "--json"])
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout)
    assert out["profile"] == "tree/1"
    assert out["digest"] == GOLD["tree_artifact"]["digest"]
    assert out["bytes"] == GOLD["tree_artifact"]["bytes"]


def test_cli_error_exit_code(tmp_path):
    r = _run_cli(["hash", str(tmp_path / "missing.bin"), "--profile", "bytes/1", "--json"])
    assert r.returncode != 0
    err = json.loads(r.stderr)
    assert err["error"]["code"] in ("IO_ERROR", "USAGE")


def test_cli_init(tmp_path):
    genesis_p = tmp_path / "genesis.json"
    genesis_p.write_bytes(jcs(F.G))
    trust_p = tmp_path / "trust.json"
    trust_p.write_bytes(jcs(F.TRUST))
    out = tmp_path / "sunlight.json"
    r = _run_cli([
        "init", "--ledger", F.L, "--genesis", str(genesis_p), "--trust", str(trust_p),
        "--origin", "http://127.0.0.1:8787", "--bearer-env", "SUNLIGHT_REGISTRY_TOKEN",
        "--out", str(out), "--json",
    ])
    assert r.returncode == 0, r.stderr
    cfg = json.loads(out.read_bytes())
    assert cfg["v"] == "sunlight.config/1"
    assert cfg["allow_loopback_http"] is True


def test_cli_key_generate(tmp_path):
    r, w = os.pipe()
    os.write(w, b"pass1\n")
    os.close(w)
    key_out = tmp_path / "k.json"
    pub_out = tmp_path / "k.pub.json"
    env = dict(os.environ)
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1])
    env["SUNLIGHT_KEY_PASSPHRASE_FD"] = str(r)
    proc = subprocess.Popen(
        [sys.executable, "-m", "sunlight", "key", "generate",
         "--out", str(key_out), "--public-out", str(pub_out), "--json"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env,
        pass_fds=(r,),
    )
    stdout, stderr = proc.communicate()
    os.close(r)
    assert proc.returncode == 0, stderr
    kf = json.loads(key_out.read_bytes())
    pub = json.loads(pub_out.read_bytes())
    assert kf["v"] == "sunlight.keyfile/1"
    assert kf["key"] == pub
    assert oct(os.lstat(key_out).st_mode & 0o777) == "0o600"
