/**
 * Replay every §6.2 RPC example through the real RegistryGateway →
 * LedgerService → LedgerEngine stack and require the byte-identical
 * RpcResponse.  This is the exact-request/exact-response fixture gate.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import * as F from "../src/fixtures.js";
import { B } from "../src/crypto/domains.js";
import { jcsBytes } from "../src/encoding/jcs.js";
import { parseStrictJson } from "../src/encoding/strict-json.js";
import { NodeSqliteStore, applySchema } from "../src/ledger/store.js";
import { LedgerService } from "../src/ledger/service.js";
import { RegistryGateway } from "../src/server.js";

const here = dirname(fileURLToPath(import.meta.url));
const fx = JSON.parse(readFileSync(join(here, "fixtures.json"), "utf8"));

const TOKEN_RAW = Buffer.alloc(32, 7);

function mkGateway(loadPrefix: number): RegistryGateway {
  const store = new NodeSqliteStore(":memory:");
  applySchema(store);
  const service = new LedgerService(store, F.G, F.KL.seed, {
    now: () => F.T,
    entryId: (seq) => F.fid("sle_", seq),
  });
  const cmds = [F.C1, F.C2, F.C3, F.C4, F.C5, F.C6, F.C7, F.C8];
  for (let i = 0; i < loadPrefix; i++) service.append(cmds[i]!);
  return new RegistryGateway({
    services: new Map([[F.L, service]]),
    tokens: [{ token_sha256: B(TOKEN_RAW), ledger: F.L, role: "write" }],
    ratePerMinute: 120,
    maxInflightPerLedger: 8,
  });
}

async function call(gw: RegistryGateway, request: unknown): Promise<unknown> {
  const out = await gw.handle("POST", "/v1/rpc", {
    "content-type": "application/json",
    authorization: `Bearer ${TOKEN_RAW.toString("base64url")}`,
  }, jcsBytes(request));
  return parseStrictJson(out.body);
}

test("head.get example: head(H4, NONCE)", async () => {
  const gw = mkGateway(4);
  const ex = fx.examples[0];
  const res = await call(gw, ex.request);
  assert.deepEqual(res, ex.response);
});

test("append examples C1..C8 produce E1..E8 exactly", async () => {
  const gw = mkGateway(0);
  for (let i = 1; i <= 8; i++) {
    const ex = fx.examples[i];
    const res = await call(gw, ex.request);
    assert.deepEqual(res, ex.response, `append example ${i}`);
  }
});

test("read examples at P8 with cut H4", async () => {
  const gw = mkGateway(8);
  for (let i = 9; i < fx.examples.length; i++) {
    const ex = fx.examples[i];
    const res = await call(gw, ex.request);
    assert.deepEqual(res, ex.response, `${ex.request.method} example`);
  }
});

test("unauthenticated and wrong-ledger calls are uniform 401/404", async () => {
  const gw = mkGateway(4);
  const noAuth = await gw.handle("POST", "/v1/rpc", {
    "content-type": "application/json",
  }, jcsBytes({ v: "sunlight.rpc/1", id: "slq_" + "0".repeat(21), method: "head.get", params: { ledger: F.L, nonce_hex: F.NONCE } }));
  assert.equal(noAuth.status, 401);
  assert.deepEqual(parseStrictJson(noAuth.body), {
    error: { code: "UNAUTHENTICATED", retryable: false, head: null },
  });
});

test("non-POST and unknown paths return 404 NOT_FOUND", async () => {
  const gw = mkGateway(4);
  const r = await gw.handle("GET", "/v1/rpc", {}, Buffer.alloc(0));
  assert.equal(r.status, 404);
  const r2 = await gw.handle("POST", "/v1/other", {}, Buffer.alloc(0));
  assert.equal(r2.status, 404);
});

test("healthz returns protocol marker without tenant state", async () => {
  const gw = mkGateway(4);
  const r = await gw.handle("GET", "/healthz", {}, Buffer.alloc(0));
  assert.equal(r.status, 200);
  assert.deepEqual(parseStrictJson(r.body), { status: "ok", protocol: "sunlight/1" });
});
