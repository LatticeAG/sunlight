"""Client configuration (spec §8).  Strict closed JSON; relative paths
resolve against the containing config file; only referenced secret
environment variables are read; loopback HTTP only for literal
127.0.0.1 / [::1]."""

from __future__ import annotations

import os
from urllib.parse import urlparse

from .errors import SunlightError
from .fsutil import read_file_bytes
from .schema import parse_client_config
from .strictjson import parse_strict_json

DEFAULT_CONFIG_PATH = "./sunlight.json"


def load_config(path: str) -> dict:
    try:
        raw = read_file_bytes(path, 1024 * 1024)
    except Exception as e:
        raise SunlightError("CONFIG_INVALID", cause=e) from e
    try:
        cfg = parse_client_config(parse_strict_json(raw))
    except SunlightError as e:
        raise SunlightError("CONFIG_INVALID", cause=e) from e
    for r in cfg["registries"]:
        u = urlparse(r["origin"])
        if u.path not in ("", "/") or u.query or u.fragment or u.username or u.password:
            raise SunlightError("CONFIG_INVALID")
        host = u.hostname or ""
        loopback = host in ("127.0.0.1", "::1")
        if u.scheme == "http":
            if not (cfg["allow_loopback_http"] and loopback):
                raise SunlightError("CONFIG_INVALID")
        elif u.scheme != "https":
            raise SunlightError("CONFIG_INVALID")
    return cfg


def config_path(config_file: str, p: str) -> str:
    if os.path.isabs(p):
        return p
    return os.path.abspath(os.path.join(os.path.dirname(config_file), p))


def resolve_registry(cfg: dict, config_file: str, ledger: str | None) -> dict:
    ledger_id = ledger or cfg["default_ledger"]
    reg = next((r for r in cfg["registries"] if r["ledger"] == ledger_id), None)
    if reg is None:
        raise SunlightError("CONFIG_INVALID")
    bearer = os.environ.get(reg["bearer_env"])
    if not bearer:
        raise SunlightError("CONFIG_INVALID", cause=ValueError(f"missing env {reg['bearer_env']}"))
    return {
        "ledger": reg["ledger"],
        "origin": reg["origin"],
        "bearer": bearer,
        "trust_file": config_path(config_file, reg["trust_file"]),
    }
