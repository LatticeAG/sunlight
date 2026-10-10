/**
 * `sunlight genesis` emits a development deployment whose genesis is dated
 * at the real clock — the regression test for a fixture that must admit
 * freshly issued commands on any date (the golden TV-S genesis stays pinned
 * because the conformance suite drives the engine with a fixed clock).
 */

import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { emitGenesis } from "../src/genesis.js";
import { parseStrictJsonString } from "../src/encoding/strict-json.js";
import {
  parseDeploymentConfig, parseGenesis, parseStatementBody,
  parseTokenBinding, parseTrust,
} from "../src/schema.js";
import { writeFileExclusive } from "../src/fsutil.js";
import { loadKeyFile } from "../src/keys.js";
import { newId } from "../src/ids.js";
import { signCommand, signStatement } from "../src/objects.js";
import { NodeSqliteStore, applySchema } from "../src/ledger/store.js";
import { LedgerService } from "../src/ledger/service.js";

function tmp(): string {
  return mkdtempSync(join(tmpdir(), "sunlight-genesis-"));
}

test("emitted files parse as their schema types", () => {
  const dir = tmp();
  try {
    const r = emitGenesis(join(dir, "demo"), "pw", Date.now());
    const read = (n: string) => parseStrictJsonString(readFileSync(n, "utf8"));
    const genesis = parseGenesis(read(r.files.genesis!));
    const trust = parseTrust(read(r.files.trust!));
    const dep = parseDeploymentConfig(read(r.files.deployment!));
    const tokens = read(r.files.tokens!) as unknown[];
    assert.ok(Array.isArray(tokens) && tokens.length === 1);
    const binding = parseTokenBinding(tokens[0]);
    parseStatementBody(read(r.files.statement_body!));

    assert.equal(genesis.ledger, r.ledger);
    assert.equal(trust.ledger, r.ledger);
    assert.equal(trust.genesis_hash.startsWith("sha256:"), true);
    assert.equal(dep.ledgers[0]!.genesis.ledger, r.ledger);
    assert.equal(dep.auth_secret_binding, r.env.tokens);
    assert.equal(dep.ledgers[0]!.audit_secret_binding, r.env.auditSeed);
    assert.equal(binding.ledger, r.ledger);
    assert.equal(binding.role, "write");
    assert.notEqual(genesis.created_at_ms, 1800000000000);
    // Key custody: encrypted keyfile round-trips with its passphrase.
    const signer = loadKeyFile(r.files.producer_key!, "pw");
    assert.equal(signer.key.id, genesis.producers[0]!.id);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a now-dated genesis admits a real-clock submit (seq 0 -> 1)", async () => {
  const dir = tmp();
  try {
    const r = emitGenesis(join(dir, "demo"), "pw", Date.now());
    const read = (n: string) => parseStrictJsonString(readFileSync(n, "utf8"));
    const genesis = parseGenesis(read(r.files.genesis!));
    const auditSeed = Buffer.from(
      readFileSync(r.files.audit_seed!, "utf8").trim(), "hex",
    );
    const store = new NodeSqliteStore(":memory:");
    applySchema(store);
    // No clock hook: the engine runs on the real wall clock.
    const service = new LedgerService(store, genesis, auditSeed);
    const head = service.headGet("11".repeat(32));
    const signer = loadKeyFile(r.files.producer_key!, "pw");
    const body = parseStatementBody(read(r.files.statement_body!));
    const statement = await signStatement(body, signer);
    const command = await signCommand(
      {
        v: "sunlight.command/1",
        id: newId("slq"),
        ledger: genesis.ledger,
        signer: signer.key.id,
        expected_head: head.body.head,
        issued_at_ms: Date.now(),
        expires_at_ms: Date.now() + 300_000,
        operation: { type: "claim", statement },
      },
      signer,
    );
    const res = service.append(command) as { head: { seq: number } };
    assert.equal(res.head.seq, 1);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("exclusive writes report OUTPUT_EXISTS, not IO_ERROR", () => {
  const dir = tmp();
  try {
    const p = join(dir, "out.json");
    writeFileExclusive(p, Buffer.from("{}"));
    assert.throws(
      () => writeFileExclusive(p, Buffer.from("{}")),
      (e: unknown) => (e as { code?: string }).code === "OUTPUT_EXISTS",
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
