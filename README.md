# Sunlight

[![CI](https://github.com/LatticeAG/sunlight/actions/workflows/ci.yml/badge.svg)](https://github.com/LatticeAG/sunlight/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![TypeScript](https://img.shields.io/badge/typescript-5.9%2B-blue.svg)](package.json)
[![Python](https://img.shields.io/badge/python-3.12%2B-blue.svg)](pyproject.toml)
[![Protocol](https://img.shields.io/badge/protocol-sunlight%2F1-blue.svg)](#protocol)

**Sunlight** is the LatticeAG provenance and lineage protocol. It gives
datasets, training runs, models, and downstream actions a declared lineage
that any third party can verify offline: canonical artifact hashing,
Ed25519-signed statements and commands, a signed hash-chained audit ledger
with optimistic concurrency and exact idempotency, and portable bundles
that carry everything a verifier needs.

The daemon is zero-dependency Node.js (>= 22.5, `node:sqlite`). The Python
package `sunlight` is a protocol-equivalent SDK and verifier — it signs,
submits, and verifies against the same canonical encodings and fixtures.

> A signature binds a *declared* claim to a key at a ledger position. It
> does not prove the claim is factually true, that training occurred, that
> the signer owns the artifact, or that a model is good. Verification
> answers "is this chain authentic, complete, authorized at its head, and
> does the artifact match" — never "is the claim true".

## What it does

- **Artifact commitments** — `bytes/1`, `jcs/1`, and `tree/1` hashing over
  a restricted RFC 8785 canonical JSON; trees are normalized, sorted,
  unique, and reject traversal, symlinks, and case collisions.
- **Signed lineage** — `sunlight.statement/1` objects carry subject,
  parent edges (statement + artifact commitments), transform details, and
  opaque foreign evidence; Ed25519 with domain-separated signing.
- **Audit ledger** — every accepted command produces one signed,
  hash-chained receipt and a signed head; optimistic `expect_head`
  concurrency; exact byte-level idempotent replay (`IDEMPOTENCY_CONFLICT`
  on any canonical-byte change under a used command ID).
- **Key lifecycle** — administrator-gated `key.add` / `key.retire` /
  `key.revoke`, statement retraction, and revocation-aware authority
  evaluation that never rewrites historical canonical bytes.
- **Portable bundles** — `sunlight.bundle/1` exports close over a
  statement's ancestry and verify with no network, filesystem, clock, key
  discovery, plugins, subprocesses, or model parsing.
- **Self-hosted registry** — reference HTTP gateway (`/healthz`,
  `/v1/rpc`) with seven RPC methods, plus a Cloudflare Worker gateway with
  one SQLite Durable Object per ledger in `worker/`.
- **Foreign evidence** — `c2pa/opaque`, `world/opaque`, `mint/opaque`,
  `treaty/opaque`, and friends are carried opaquely. Import grants no
  foreign authenticity, authorization, licensing, or settlement semantics.

## Quickstart

```sh
npm install -g @latticeag/sunlight      # or: npm ci && npm run build

# Mint a complete development deployment: fresh ledger id, admin/audit/
# producer key files (encrypted with your passphrase), a genesis stamped at
# the current time, the matching trust pin, a deployment config, a bearer
# token, and a worked example.  The golden TV-S fixture in tests/ keeps its
# pinned clock — do NOT serve it; `genesis` is the fixture meant for real
# use on any date.
SUNLIGHT_KEY_PASSPHRASE_FD=3 sunlight genesis --out demo 3<<<"dev pass"
cd demo && source env.sh        # SUNLIGHT_LEDGER / _AUDIT_SEED / _TOKENS / _TOKEN

# Serve it.  `registry serve` takes a sunlight.deployment/1 file; the two
# secret bindings it names must exist in the environment (env.sh set them).
sunlight registry serve --deployment deployment.json --listen 127.0.0.1:8787 &

# Point the client at the registry (writes ./sunlight.json).
sunlight init --ledger "$SUNLIGHT_LEDGER" --genesis genesis.json \
  --trust trust.json --origin http://127.0.0.1:8787 \
  --bearer-env SUNLIGHT_REGISTRY_TOKEN --out sunlight.json

# Key-using commands read the passphrase from SUNLIGHT_KEY_PASSPHRASE_FD.
export SUNLIGHT_KEY_PASSPHRASE_FD=3

sunlight hash dataset.bin --profile bytes/1 --json
sunlight sign --body statement-body.json --artifact dataset.bin \
  --key producer.key.json --out statement.json 3<<<"dev pass"
sunlight submit --statement statement.json --key producer.key.json \
  --json 3<<<"dev pass"                                   # head seq 0 -> 1
sunlight head --json
sunlight lookup --artifact dataset.bin --profile bytes/1 --json
sunlight export --statement sha256:<statement hash> --out bundle.json
sunlight verify --bundle bundle.json --trust trust.json \
  --artifact dataset.bin --profile bytes/1 --json         # overall VERIFIED
sunlight audit verify --bundle bundle.json --trust trust.json   # VALID
```

`sunlight genesis` defaults `created_at_ms` to the current time; pass
`--created-at-ms <int>` to pin a different stamp (a future stamp makes every
command inadmissible until the clock catches up — `COMMAND_EXPIRED`).

`submit`/`key`/`retract` write through the client config (`--config`, default
`./sunlight.json`); `verify`/`audit verify` run fully offline and need only
`--bundle` + `--trust`.  All file outputs are exclusive-create — rerunning a
step onto an existing path fails `OUTPUT_EXISTS` (exit `8`); remove the file
or pick a fresh name.

Exit codes: `0` verified/ok, `2` usage/schema (`CLOCK_AHEAD`, ...), `3`
invalid verification, `4` untrusted/insufficient evidence (`STALE_HEAD`,
`UNTRUSTED_GENESIS`, ...), `5` authn/authz/key (`KEY_PERMISSIONS`, ...), `6`
retryable transport, `7` state/idempotency (`IDEMPOTENCY_CONFLICT`,
`COMMAND_EXPIRED`, `HEAD_CONFLICT`, ...), `8` I/O (`OUTPUT_EXISTS`, ...).

Python client:

```python
from sunlight import load_key_file, sign_statement, verify
from sunlight.artifact import hash_artifact

signer = load_key_file("producer.key.json", "dev pass")
stmt = sign_statement(body, signer)
result = verify({
    "bundle": bundle, "trust": trust,
    "observation": {"artifact": hash_artifact("dataset.bin", "bytes/1")},
    "freshness": None,
})
assert result["overall"] == "VERIFIED"
```

### Bearer tokens

A bearer token is the **base64url encoding of 32 raw random bytes** —
presented as `Authorization: Bearer <token>`.  The deployment never stores
the token: each entry in the `auth_secret_binding` array binds it by hash,
`token_sha256 = B(raw)`, i.e. `"sha256:" + lowercase_hex(SHA256(raw_bytes))`
— the same `B()`/`RAW()` digest helpers the protocol uses everywhere else.

```sh
# Generate a token + its binding digest by hand:
node -e 'const c=require("crypto"),r=c.randomBytes(32);
  console.log(JSON.stringify({
    token: r.toString("base64url"),
    token_sha256: "sha256:"+c.createHash("sha256").update(r).digest("hex")}))'
```

…then put the raw `token` in your client's `bearer_env` variable and a
`{"token_sha256": "...", "ledger": "sll_...", "role": "write"|"read"}`
object in the env array named by `auth_secret_binding`.  `sunlight genesis`
emits both already wired (`bearer.txt`, `tokens.json`, `env.sh`).

## Protocol

`sunlight/1` over HTTP. RPC methods: `head.get`, `append`, `entry.get`,
`entries.list`, `statement.get`, `artifact.lookup`, `bundle.export`.
Digests are `sha256:<64 lowercase hex>`; signatures are lowercase-hex
Ed25519 over domain-separated canonical bytes. Reads evaluate against a
fixed cut; audit anchoring never appends on read.

The registry stores commitments, receipts, and metadata — never raw
datasets, model weights, or evidence payloads. It is not a global content
oracle: `artifact.lookup` answers only whether a digest was observed.

## Layout

| Path            | Contents                                              |
|-----------------|-------------------------------------------------------|
| `src/`          | core SDK, verifier, ledger engine, HTTP server, CLI   |
| `worker/`       | Cloudflare Worker gateway + per-ledger Durable Object |
| `python/`       | `sunlight` Python SDK, verifier, and CLI              |
| `tests/`        | TV-S-01…58 conformance vectors + generated fixtures   |
| `tools/`        | normative fixture generator                           |

## Development

```sh
npm run check          # typecheck
npm test               # build + TS suite (22 tests; all 58 TV-S vectors)
npm run test:python    # Python contract + parity suite (58 tests)
sunlight conformance   # standalone vector runner
```

## Hosted boundary

The open-source core is complete and self-hostable. Hosted registry
surfaces (multi-tenant custody, managed keys, dashboards, billing) are a
documented, fail-closed boundary — declared in the API as
`NOT_IMPLEMENTED` stubs with a pointer to LatticeAG hosted offerings,
never fake working code.

## License

MIT — see [LICENSE](LICENSE).
