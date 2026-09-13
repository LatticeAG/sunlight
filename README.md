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
sunlight registry serve --data ./registry.db --listen 127.0.0.1:8787 &
sunlight init --registry http://127.0.0.1:8787 --ledger sll_...
sunlight key generate --role producer --out producer.key.json
sunlight hash --artifact dataset.bin --profile bytes/1 --json
sunlight sign --body statement-body.json --artifact dataset.bin \
  --key producer.key.json --out statement.json
sunlight submit --statement statement.json --key producer.key.json --json
sunlight head --json
sunlight lookup --artifact dataset.bin --profile bytes/1 --json
sunlight export --statement sha256:... --out bundle.json
sunlight verify --bundle bundle.json --trust trust.json \
  --artifact dataset.bin --profile bytes/1 --json
sunlight audit verify --bundle bundle.json
```

Exit codes: `0` verified/ok, `3` invalid verification, `5` transport,
`7` command rejection (`IDEMPOTENCY_CONFLICT`, `STALE_HEAD`, ...).

Python client:

```python
from sunlight import sign_statement, verify_bundle

stmt = sign_statement(body, key)
result = verify_bundle(bundle, trust, artifact=artifact_bytes)
assert result.overall == "VERIFIED"
```

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
