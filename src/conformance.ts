/**
 * TV-S-01 … TV-S-58 — executable conformance vectors (spec §14).
 *
 * Pure vectors run against the SDK; ledger vectors run against a real
 * LedgerEngine over an in-memory SQLite store with fixture-deterministic
 * hooks (now=T, entryId=sle_<seq>); gateway vectors exercise the real
 * RegistryGateway.  `sunlight conformance` and the node test suite both call
 * runConformance() — one source of truth for pass/fail.
 */

import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { jcsBytes, jcsString } from "./encoding/jcs.js";
import { parseStrictJson, parseStrictJsonString } from "./encoding/strict-json.js";
import { SunlightError, type ErrorCode } from "./errors.js";
import { B, D, signatureMessage } from "./crypto/domains.js";
import { ed25519Verify } from "./crypto/ed25519.js";
import {
  parseCommandBody, parseTreeManifest,
  type Artifact, type Bundle, type Command, type Entry, type HeadRef,
  type Statement, type Trust, type Verification,
} from "./schema.js";
import { hashArtifact, manifestArtifact } from "./artifact.js";
import { signStatement, seedSigner, signCommand } from "./objects.js";
import { verify } from "./verify.js";
import { computeEvidenceRef } from "./evidence.js";
import { NodeSqliteStore, applySchema } from "./ledger/store.js";
import { LedgerService } from "./ledger/service.js";
import { RegistryGateway } from "./server.js";
import * as F from "./fixtures.js";

export interface VectorResult {
  id: string;
  pass: boolean;
  detail?: string;
}
export interface ConformanceReport {
  suite: "TV-S";
  vectors: VectorResult[];
}

type V = () => void | Promise<void>;

function assert(cond: boolean, msg: string): void {
  if (!cond) throw new Error(`assert: ${msg}`);
}
function eq(a: unknown, b: unknown, msg: string): void {
  if (JSON.stringify(a) !== JSON.stringify(b)) {
    throw new Error(`assert equal failed: ${msg}\n  got:  ${JSON.stringify(a)}\n  want: ${JSON.stringify(b)}`);
  }
}
async function expectErr(code: ErrorCode, fn: () => unknown | Promise<unknown>): Promise<void> {
  try {
    await fn();
  } catch (e) {
    if (e instanceof SunlightError && e.code === code) return;
    throw new Error(`expected ${code}, got ${e instanceof SunlightError ? e.code : String(e)}`);
  }
  throw new Error(`expected ${code}, got success`);
}
function expectIntegrityFail(code: string, v: Verification): void {
  assert(v.integrity === "INVALID" && v.overall === "INVALID", `expected INVALID (${code})`);
  assert(v.reasons.includes(code), `expected reasons to include ${code}, got ${v.reasons}`);
}

/** Fresh in-memory ledger service with fixture-deterministic hooks. */
function mkService(nowRef?: { v: number }, extra?: { measureBundleBytes?: (b: Bundle) => number }): {
  service: LedgerService;
  store: NodeSqliteStore;
} {
  const store = new NodeSqliteStore(":memory:");
  applySchema(store);
  const service = new LedgerService(store, F.G, F.KL.seed, {
    now: () => nowRef?.v ?? F.T,
    entryId: (seq) => F.fid("sle_", seq),
    measureBundleBytes: extra?.measureBundleBytes,
  });
  if (service.getState() !== "READY") throw new Error("service not READY");
  return { service, store };
}

/** Append fixture commands C1..Cn to reach head Pn. */
async function loadTo(service: LedgerService, n: number): Promise<void> {
  const cmds = [F.C1, F.C2, F.C3, F.C4, F.C5, F.C6, F.C7, F.C8];
  for (let i = 0; i < n; i++) service.append(cmds[i]!);
}

function headEq(service: LedgerService, h: HeadRef): void {
  eq(service.engine.headRef(), h, "ledger head");
}

function tmpdirOnce(): string {
  return mkdtempSync(join(tmpdir(), "sunlight-tv-"));
}

// ---- the 58 vectors ------------------------------------------------------

const vectors: [string, V][] = [
  ["TV-S-01", async () => {
    const dir = tmpdirOnce();
    try {
      const p = join(dir, "empty.bin");
      writeFileSync(p, Buffer.alloc(0));
      const a = await hashArtifact({ profile: "bytes/1", path: p });
      eq(a, { profile: "bytes/1", digest: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", bytes: 0 }, "empty artifact");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }],

  ["TV-S-02", async () => {
    const dir = tmpdirOnce();
    try {
      const p = join(dir, "data.bin");
      writeFileSync(p, Buffer.from("abc"));
      const a = await hashArtifact({ profile: "bytes/1", path: p });
      eq(a, { profile: "bytes/1", digest: "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", bytes: 3 }, "abc artifact");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }],

  ["TV-S-03", () => {
    eq(jcsString(parseStrictJsonString(`{"b":2,"a":1}`)), `{"a":1,"b":2}`, "canonical order");
  }],

  ["TV-S-04", async () => {
    await expectErr("SCHEMA_INVALID", () => parseStrictJsonString(`{"v":1,"v":1}`));
  }],

  ["TV-S-05", async () => {
    await expectErr("SCHEMA_INVALID", () => parseStrictJsonString(`{"n":9007199254740992}`));
  }],

  ["TV-S-06", async () => {
    await expectErr("SCHEMA_INVALID", () => parseStrictJsonString(`{"n":-0}`));
  }],

  ["TV-S-07", async () => {
    await expectErr("SCHEMA_INVALID", () => parseStrictJsonString(`{"s":"\\ud800"}`));
  }],

  ["TV-S-08", () => {
    const a = jcsBytes({ s: "é" });
    const b = jcsBytes({ s: "é" });
    eq(a.toString("hex"), "7b2273223a22c3a9227d", "NFC bytes");
    eq(b.toString("hex"), "7b2273223a2265cc81227d", "decomposed bytes");
    assert(!a.equals(b), "unicode must not normalize");
  }],

  ["TV-S-09", async () => {
    const s = await signStatement(F.S1.body, seedSigner(F.KP.key, F.KP.seed));
    eq(s, F.S1, "deterministic Ed25519 statement");
  }],

  ["TV-S-10", async () => {
    const dir = tmpdirOnce();
    try {
      const p1 = join(dir, "original.bin");
      const p2 = join(dir, "reupload.dat");
      writeFileSync(p1, Buffer.from("abc"));
      writeFileSync(p2, Buffer.from("abc"));
      const a1 = await hashArtifact({ profile: "bytes/1", path: p1 });
      const a2 = await hashArtifact({ profile: "bytes/1", path: p2 });
      eq(a1, F.A, "original.bin hash");
      eq(a2, F.A, "reupload.dat hash");
      const { service } = mkService();
      await loadTo(service, 4);
      const res = service.artifactLookup("bytes/1", F.A.digest, F.H4, 0, 100);
      eq(res, {
        matches: [{
          statement: F.S1.hash, id: F.S1.body.id, kind: "dataset",
          signer: F.KP.key.id, capture: "creation_hook", retracted: false,
          key_status: "ACTIVE",
        }],
        next_after_seq: null,
        cut: F.H4,
      }, "lookup at P4/H4");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }],

  ["TV-S-11", () => {
    const mutated = F.artifact(Buffer.from("abc\0"));
    assert(mutated.digest !== F.A.digest, "changed bytes must differ");
    const b: Bundle = F.bundle([F.E1], F.S1);
    const v = verify({
      bundle: b, trust: F.TRUST,
      observation: { artifact: mutated }, freshness: null,
    });
    assert(v.artifact === "MISMATCH" && v.overall === "INVALID", "changed bytes → INVALID");
    eq(v.reasons, ["ARTIFACT_MISMATCH"], "reasons");
    eq(v.head, F.H1, "head");
  }],

  ["TV-S-12", () => {
    const mk = (files: { path: string; digest: string; bytes: number }[]) => {
      const sorted = [...files].sort((x, y) => (x.path < y.path ? -1 : x.path > y.path ? 1 : 0));
      return parseTreeManifest({ v: "sunlight.tree/1", files: sorted });
    };
    const m1 = mk([
      { path: "b.txt", digest: B(Buffer.alloc(0)), bytes: 0 },
      { path: "a.txt", digest: B(Buffer.from("abc")), bytes: 3 },
    ]);
    const m2 = mk([
      { path: "a.txt", digest: B(Buffer.from("abc")), bytes: 3 },
      { path: "b.txt", digest: B(Buffer.alloc(0)), bytes: 0 },
    ]);
    const canon = jcsBytes(m1);
    const expected: Artifact = { profile: "tree/1", digest: B(canon), bytes: canon.length };
    eq(manifestArtifact(m1), expected, "manifest artifact");
    eq(manifestArtifact(m2), expected, "enumeration order irrelevant");
  }],

  ["TV-S-13", async () => {
    await expectErr("SCHEMA_INVALID", () => parseTreeManifest({
      v: "sunlight.tree/1",
      files: [
        { path: "A.txt", digest: F.A.digest, bytes: 3 },
        { path: "a.txt", digest: F.A.digest, bytes: 3 },
      ],
    }));
  }],

  ["TV-S-14", async () => {
    await expectErr("SCHEMA_INVALID", () => parseTreeManifest({
      v: "sunlight.tree/1",
      files: [{ path: "../weights.bin", digest: F.M.digest, bytes: F.M.bytes }],
    }));
  }],

  ["TV-S-15", async () => {
    const { service, store } = mkService();
    const res = service.append(F.C1);
    eq(res, { entry: F.E1, head: F.H1 }, "first append result");
    eq(store.query("SELECT COUNT(*) c FROM entries")[0]!.c, 1, "entries rows");
    eq(store.query("SELECT COUNT(*) c FROM commands")[0]!.c, 1, "commands rows");
    eq(store.query("SELECT COUNT(*) c FROM statements")[0]!.c, 1, "statements rows");
  }],

  ["TV-S-16", async () => {
    const now = { v: F.T };
    const { service } = mkService(now);
    await loadTo(service, 4);
    now.v = F.T + 300001;
    const res = service.append(F.C1);
    eq(res, { entry: F.E1, head: F.H1 }, "replay after expiry");
    headEq(service, F.H4);
  }],

  ["TV-S-17", async () => {
    const { service } = mkService();
    await loadTo(service, 4);
    const body = {
      ...F.C1.body,
      operation: { type: "claim" as const, statement: F.S2 },
    };
    const c2 = F.signed("command", body, F.KP.seed) as unknown as Command;
    await expectErr("IDEMPOTENCY_CONFLICT", () => service.append(c2));
    headEq(service, F.H4);
  }],

  ["TV-S-18", async () => {
    const { service } = mkService();
    try {
      service.append(F.C2);
    } catch (e) {
      assert(e instanceof SunlightError && e.code === "HEAD_CONFLICT", "HEAD_CONFLICT");
      eq((e as SunlightError).body.head, F.H0, "conflict head");
      headEq(service, F.H0);
      return;
    }
    throw new Error("append should have failed");
  }],

  ["TV-S-19", async () => {
    const { service } = mkService();
    const bad: Command = { ...F.C1, signature_hex: "0".repeat(128) };
    await expectErr("SIGNATURE_INVALID", () => service.append(bad));
    headEq(service, F.H0);
  }],

  ["TV-S-20", () => {
    const b = structuredClone(F.F4);
    const op = b.entries[0]!.command.body.operation;
    if (op.type !== "claim") throw new Error("fixture op not claim");
    (op.statement.body as { capture: string }).capture = "posthoc";
    const v = verify({ bundle: b, trust: F.TRUST, observation: null, freshness: null });
    expectIntegrityFail("HASH_MISMATCH", v);
  }],

  ["TV-S-21", () => {
    const v = verify({ bundle: F.F4, trust: F.TRUST, observation: null, freshness: null });
    eq(v, F.V4, "V4 exact");
  }],

  ["TV-S-22", () => {
    const v = verify({ bundle: F.F4, trust: F.TRUST, observation: F.OBS4, freshness: null });
    assert(v.artifact === "MATCH" && v.overall === "VERIFIED", "OBS4 → MATCH");
    eq(v.reasons, [], "reasons empty");
  }],

  ["TV-S-23", () => {
    const t: Trust = { ...F.TRUST, genesis_hash: B(Buffer.alloc(0)) };
    const v = verify({ bundle: F.F4, trust: t, observation: null, freshness: null });
    assert(v.authority === "UNTRUSTED" && v.overall === "UNVERIFIED", "self-supplied root");
    eq(v.reasons, ["UNTRUSTED_GENESIS"], "reasons");
  }],

  ["TV-S-24", () => {
    const t: Trust = { ...F.TRUST, minimum_head: F.H7 };
    const v = verify({ bundle: F.F4, trust: t, observation: null, freshness: null });
    expectIntegrityFail("MINIMUM_HEAD_MISMATCH", v);
  }],

  ["TV-S-25", () => {
    const t: Trust = { ...F.TRUST, minimum_head: { seq: 4, hash: B(Buffer.alloc(0)) } };
    const v = verify({ bundle: F.F4, trust: t, observation: null, freshness: null });
    expectIntegrityFail("MINIMUM_HEAD_MISMATCH", v);
  }],

  ["TV-S-26", () => {
    const v = verify({ bundle: F.F4, trust: F.TRUST, observation: F.OBS4, freshness: F.FRESH4 });
    assert(v.artifact === "MATCH" && v.freshness === "CURRENT" && v.overall === "VERIFIED", "fresh");
  }],

  ["TV-S-27", () => {
    const v = verify({
      bundle: F.F4, trust: F.TRUST, observation: null,
      freshness: { ...F.FRESH4, expected_nonce_hex: "22".repeat(32) },
    });
    assert(v.freshness === "STALE" && v.overall === "UNVERIFIED", "wrong nonce");
    eq(v.reasons, ["STALE_HEAD"], "reasons");
  }],

  ["TV-S-28", () => {
    const v = verify({
      bundle: F.F4, trust: F.TRUST, observation: null,
      freshness: { ...F.FRESH4, received_at_ms: F.T + 30001 },
    });
    assert(v.freshness === "STALE" && v.overall === "UNVERIFIED", "elapsed 30001");
    eq(v.reasons, ["STALE_HEAD"], "reasons");
  }],

  ["TV-S-29", () => {
    const v = verify({ bundle: F.F7, trust: F.TRUST, observation: null, freshness: null });
    assert(v.authority === "REVOKED" && v.overall === "UNVERIFIED", "revoked ancestor");
    eq(v.reasons, ["REVOKED_ANCESTOR"], "reasons");
    eq(v.head, F.H7, "head");
  }],

  ["TV-S-30", () => {
    const v = verify({ bundle: F.F8, trust: F.TRUST, observation: null, freshness: null });
    assert(v.lineage === "INCOMPLETE" && v.authority === "REVOKED" && v.overall === "UNVERIFIED",
      "retraction+revocation");
    eq(v.reasons, ["RETRACTED_ANCESTOR", "REVOKED_ANCESTOR"], "reasons");
    eq(v.head, F.H8, "head");
  }],

  ["TV-S-31", async () => {
    const { service } = mkService();
    await loadTo(service, 7);
    const s = F.claim(31, "dataset", F.Z, [], { type: "creation" });
    const c = F.command(31, F.H7, { type: "claim", statement: s });
    await expectErr("KEY_INACTIVE", () => service.append(c));
    headEq(service, F.H7);
  }],

  ["TV-S-32", async () => {
    const { service } = mkService();
    await loadTo(service, 4);
    const c = F.command(32, F.H4, { type: "key_add", key: F.KN.key }, false);
    await expectErr("ROLE_MISMATCH", () => service.append(c));
  }],

  ["TV-S-33", async () => {
    const now = { v: F.T + 300000 };
    const { service } = mkService(now);
    await expectErr("COMMAND_EXPIRED", () => service.append(F.C1));
    headEq(service, F.H0);
  }],

  ["TV-S-34", async () => {
    const { service } = mkService();
    const body = { ...F.C1.body, issued_at_ms: F.T + 60001, expires_at_ms: F.T + 360001 };
    const c = F.signed("command", body, F.KP.seed) as unknown as Command;
    await expectErr("CLOCK_AHEAD", () => service.append(c));
    headEq(service, F.H0);
  }],

  ["TV-S-35", async () => {
    const { service } = mkService();
    await loadTo(service, 1);
    const changed = structuredClone(F.S2);
    changed.body.parents[0]!.artifact = F.Z.digest;
    // Descriptor must be recomputed over the mutated parents, then re-sign.
    const descriptor = {
      v: "sunlight.descriptor/1", kind: "run",
      parents: changed.body.parents, details: changed.body.details,
    };
    const canon = jcsBytes(descriptor);
    changed.body.subject.artifact = { profile: "jcs/1", digest: B(canon), bytes: canon.length };
    const s2 = F.signed("statement", changed.body, F.KP.seed) as unknown as Statement;
    const c = F.command(35, F.H1, { type: "claim", statement: s2 });
    await expectErr("PARENT_MISMATCH", () => service.append(c));
    headEq(service, F.H1);
  }],

  ["TV-S-36", async () => {
    const { service } = mkService();
    const c = F.command(36, F.H0, { type: "claim", statement: F.S2 });
    await expectErr("PARENT_MISSING", () => service.append(c));
    headEq(service, F.H0);
  }],

  ["TV-S-37", () => {
    const r = F.claim(37, "model", F.M, [], { type: "creation" });
    const c = F.command(37, F.H0, { type: "claim", statement: r });
    const e = F.entry(1, c);
    const b = F.bundle([e], r);
    const v = verify({ bundle: b, trust: F.TRUST, observation: null, freshness: null });
    assert(v.integrity === "VALID", "integrity");
    assert(v.lineage === "INCOMPLETE" && v.authority === "TRUSTED_AT_HEAD" &&
      v.overall === "UNVERIFIED" && v.artifact === "NOT_SUPPLIED" &&
      v.claim_truth === "NOT_PROVEN", "missing training dims");
    eq(v.reasons, ["MISSING_TRAINING"], "reasons");
    eq(v.head, F.ref(e), "head");
  }],

  ["TV-S-38", () => {
    const r = F.claim(37, "model", F.M, [], { type: "creation" });
    const c = F.command(37, F.H0, { type: "claim", statement: r });
    const e = F.entry(1, c);
    const b = F.bundle([e], r);
    const v = verify({
      bundle: b, trust: { ...F.TRUST, require_training: false },
      observation: null, freshness: null,
    });
    assert(v.lineage === "COMPLETE_DECLARED" && v.overall === "VERIFIED", "relaxed policy");
    eq(v.reasons, [], "reasons");
  }],

  ["TV-S-39", () => {
    const b: Bundle = { ...F.F4, entries: [F.E1, F.E3, F.E4] };
    const v = verify({ bundle: b, trust: F.TRUST, observation: null, freshness: null });
    expectIntegrityFail("CHAIN_MISMATCH", v);
  }],

  ["TV-S-40", async () => {
    // Replace E1's receipt event with KeyAdded, re-sign the receipt, and
    // rebuild the rest of the chain + head so linkage stays consistent.
    const signerSeed = (id: string): Buffer => {
      if (id === F.KP.key.id) return F.KP.seed;
      if (id === F.KA.key.id) return F.KA.seed;
      throw new Error("unknown signer");
    };
    // Rebuild: E1' has a forged event; C2..C4 re-signed to point at the new
    // receipt hashes so linkage stays consistent.
    const entries: Entry[] = [];
    const r1body = { ...F.E1.receipt.body, event: "KeyAdded" as const };
    const e1: Entry = {
      command: F.C1,
      receipt: F.signed("receipt", r1body, F.KL.seed) as unknown as Entry["receipt"],
    };
    entries.push(e1);
    for (let i = 1; i < 4; i++) {
      const src = F.ENTRIES[i]!.command;
      const body = { ...src.body, expected_head: F.ref(entries[entries.length - 1]!) };
      const c = F.signed("command", body, signerSeed(src.body.signer)) as unknown as Command;
      entries.push(F.entry(i + 1, c));
    }
    const b: Bundle = { ...F.F4, entries, head: F.head(F.ref(entries[3]!)) };
    const v = verify({ bundle: b, trust: F.TRUST, observation: null, freshness: null });
    expectIntegrityFail("AUDIT_BINDING_MISMATCH", v);
  }],

  ["TV-S-41", async () => {
    const { service } = mkService();
    await loadTo(service, 1);
    const s = F.claim(1, "dataset", F.Z, [], { type: "creation" });
    const c = F.command(41, F.H1, { type: "claim", statement: s });
    await expectErr("ID_CONFLICT", () => service.append(c));
    headEq(service, F.H1);
  }],

  ["TV-S-42", async () => {
    const { service } = mkService();
    await loadTo(service, 1);
    const changed = structuredClone(F.S2);
    changed.body.subject.artifact = { profile: "jcs/1", digest: F.Z.digest, bytes: 0 };
    const s2 = F.signed("statement", changed.body, F.KP.seed) as unknown as Statement;
    const c = F.command(42, F.H1, { type: "claim", statement: s2 });
    await expectErr("DESCRIPTOR_MISMATCH", () => service.append(c));
    headEq(service, F.H1);
  }],

  ["TV-S-43", async () => {
    const { service } = mkService();
    await loadTo(service, 8);
    const p1 = service.entriesList(0, F.H4, 2);
    eq(p1, { entries: [F.E1, F.E2], next_after: 2, cut: F.H4 }, "page 1");
    const p2 = service.entriesList(2, F.H4, 2);
    eq(p2, { entries: [F.E3, F.E4], next_after: null, cut: F.H4 }, "page 2");
  }],

  ["TV-S-44", async () => {
    const { service } = mkService();
    await loadTo(service, 8);
    const res = service.artifactLookup("bytes/1", F.A.digest, F.H8, 0, 100);
    eq(res, {
      matches: [{
        statement: F.S1.hash, id: F.S1.body.id, kind: "dataset",
        signer: F.KP.key.id, capture: "creation_hook", retracted: true,
        key_status: "REVOKED",
      }],
      next_after_seq: null,
      cut: F.H8,
    }, "lookup at H8");
  }],

  ["TV-S-45", async () => {
    const { service } = mkService();
    await loadTo(service, 4);
    const tokenRaw = Buffer.alloc(32, 0xab);
    const foreign = { token_sha256: B(tokenRaw), ledger: F.fid("sll_", 2), role: "read" as const };
    const gw = new RegistryGateway({
      services: new Map([[F.L, service]]),
      tokens: [foreign],
      ratePerMinute: 120,
      maxInflightPerLedger: 8,
    });
    const req = {
      v: "sunlight.rpc/1", id: F.fid("slq_", 70), method: "artifact.lookup",
      params: {
        ledger: F.L, profile: "bytes/1", digest: F.A.digest,
        cut: F.H4, after_seq: 0, limit: 100,
      },
    };
    const out = await gw.handle("POST", "/v1/rpc", {
      "content-type": "application/json",
      authorization: `Bearer ${tokenRaw.toString("base64url")}`,
    }, jcsBytes(req));
    assert(out.status === 404, `status ${out.status}`);
    const parsed = parseStrictJson(out.body) as { ok: boolean; error: { code: string; head: unknown } };
    assert(parsed.error.code === "NOT_FOUND" && parsed.error.head === null, "NOT_FOUND uniform");

    // Same lookup when the ledger is entirely unconfigured.
    const gw2 = new RegistryGateway({
      services: new Map(),
      tokens: [foreign],
      ratePerMinute: 120,
      maxInflightPerLedger: 8,
    });
    const out2 = await gw2.handle("POST", "/v1/rpc", {
      "content-type": "application/json",
      authorization: `Bearer ${tokenRaw.toString("base64url")}`,
    }, jcsBytes(req));
    assert(out2.status === 404, `status ${out2.status}`);
  }],

  ["TV-S-46", async () => {
    const { service } = mkService();
    const tokenRaw = Buffer.alloc(32, 0xcd);
    const gw = new RegistryGateway({
      services: new Map([[F.L, service]]),
      tokens: [{ token_sha256: B(tokenRaw), ledger: F.L, role: "write" }],
      ratePerMinute: 120,
      maxInflightPerLedger: 8,
    });
    const out = await gw.handle("POST", "/v1/rpc", {
      "content-type": "application/json",
      authorization: `Bearer ${tokenRaw.toString("base64url")}`,
    }, Buffer.alloc(32769, 0x20));
    assert(out.status === 413, `status ${out.status}`);
    const parsed = parseStrictJson(out.body) as { error: { code: string } };
    assert(parsed.error.code === "BODY_LIMIT", "BODY_LIMIT");
  }],

  ["TV-S-47", async () => {
    const { service } = mkService(undefined, { measureBundleBytes: () => 16777217 });
    await loadTo(service, 4);
    await expectErr("BUNDLE_LIMIT", () => service.bundleExport(F.S4.hash, F.H4));
  }],

  ["TV-S-48", () => {
    const ok = ed25519Verify(
      Buffer.from(F.KP.key.public_hex, "hex"),
      signatureMessage("command", F.S1.hash),
      Buffer.from(F.S1.signature_hex, "hex"),
    );
    assert(!ok, "domain separation must fail");
  }],

  ["TV-S-49", () => {
    const t: Trust = { ...F.TRUST, denied_keys: [F.KP.key.id] };
    const v = verify({ bundle: F.F4, trust: t, observation: null, freshness: null });
    assert(v.authority === "REVOKED" && v.overall === "UNVERIFIED", "deny override");
    eq(v.reasons, ["DENIED_KEY"], "reasons");
  }],

  ["TV-S-50", () => {
    const ref = computeEvidenceRef(Buffer.from("6e6f742d63327061", "hex"), "c2pa/opaque");
    eq(ref, {
      artifact: {
        profile: "bytes/1",
        digest: B(Buffer.from("6e6f742d63327061", "hex")),
        bytes: 8,
      },
      format: "c2pa/opaque",
      source_commitment: null,
      assessment: "OPAQUE",
    }, "opaque C2PA ref");
  }],

  ["TV-S-51", () => {
    const v = verify({
      bundle: F.F4, trust: F.TRUST,
      observation: { artifact: { ...F.OBS4.artifact, profile: "bytes/1" } },
      freshness: null,
    });
    assert(v.artifact === "MISMATCH" && v.overall === "INVALID", "profile mismatch");
    eq(v.reasons, ["ARTIFACT_MISMATCH"], "reasons");
  }],

  ["TV-S-52", async () => {
    await expectErr("SCHEMA_INVALID", () =>
      parseCommandBody({ ...F.C1.body, id: "req_000000000000000000001" }));
  }],

  ["TV-S-53", async () => {
    await expectErr("VERSION_UNSUPPORTED", () =>
      parseCommandBody({ ...F.C1.body, v: "sunlight.command/2" as never }));
  }],

  ["TV-S-54", async () => {
    const { service, store } = mkService();
    const r1 = service.append(F.C1);
    eq(r1, { entry: F.E1, head: F.H1 }, "commit");
    // Crash after commit, before response: new service over the same store.
    const service2 = new LedgerService(store, F.G, F.KL.seed, {
      now: () => F.T,
      entryId: (seq) => F.fid("sle_", seq),
    });
    assert(service2.getState() === "READY", "restart READY");
    const r2 = service2.append(F.C1);
    eq(r2, { entry: F.E1, head: F.H1 }, "replay after crash");
    eq(store.query("SELECT COUNT(*) c FROM entries")[0]!.c, 1, "one entry");
    eq(store.query("SELECT COUNT(*) c FROM commands")[0]!.c, 1, "one command");
  }],

  ["TV-S-55", async () => {
    // Order A: C7 (revoke) wins at H6.
    {
      const { service } = mkService();
      await loadTo(service, 6);
      const r = service.append(F.C7);
      eq(r.head, F.H7, "C7 wins");
      const s = F.claim(55, "dataset", F.Z, [], { type: "creation" });
      const c = F.command(55, F.H6, { type: "claim", statement: s });
      await expectErr("HEAD_CONFLICT", () => service.append(c));
      // Resigned retry at H7: producer is now revoked.
      const retry = F.command(550, F.H7, { type: "claim", statement: s });
      await expectErr("KEY_INACTIVE", () => service.append(retry));
      const b = F.bundle(F.ENTRIES.slice(0, 7), F.S4);
      const v = verify({ bundle: b, trust: F.TRUST, observation: null, freshness: null });
      assert(v.authority === "REVOKED", "revocation cut marks claim revoked");
    }
    // Order B: the claim wins at H6.
    {
      const { service } = mkService();
      await loadTo(service, 6);
      const s = F.claim(55, "dataset", F.Z, [], { type: "creation" });
      const c = F.command(55, F.H6, { type: "claim", statement: s });
      const r = service.append(c);
      assert(r.head.seq === 7, "claim wins");
      await expectErr("HEAD_CONFLICT", () => service.append(F.C7));
      // A new admin revoke command at the new head succeeds.
      const c7b = F.command(551, r.head, { type: "key_revoke", key: F.KP.key.id, reason: "compromise" }, true);
      const r2 = service.append(c7b);
      assert(r2.head.seq === 8, "revoke at new head");
    }
  }],

  ["TV-S-56", async () => {
    const { service } = mkService();
    await loadTo(service, 1);
    const s = F.claim(56, "dataset", F.A, [F.parent(F.S1, "source")], {
      type: "transform", procedure: B(Buffer.from("validate-only")),
    });
    assert(s.hash !== F.S1.hash, "distinct attestation");
    const c = F.command(56, F.H1, { type: "claim", statement: s });
    const r = service.append(c);
    assert(r.head.seq === 2, "appended");
    const res = service.artifactLookup("bytes/1", F.A.digest, r.head, 0, 100);
    eq(
      res.matches.map((m) => m.statement),
      [F.S1.hash, s.hash],
      "lookup returns S1 then S",
    );
  }],

  ["TV-S-57", async () => {
    const { service } = mkService();
    await loadTo(service, 1);
    const s = F.claim(57, "dataset", F.A, [F.parent(F.S1, "source")], { type: "creation" });
    const c = F.command(57, F.H1, { type: "claim", statement: s });
    await expectErr("STATEMENT_INVALID", () => service.append(c));
    headEq(service, F.H1);
  }],

  ["TV-S-58", async () => {
    const { service } = mkService();
    await loadTo(service, 4);
    const absent = B(Buffer.from("absent"));
    await expectErr("NOT_FOUND", () => service.statementGet(absent, F.H4));
    const c = F.command(58, F.H4, { type: "retract", statement: absent, reason: "incorrect" }, true);
    await expectErr("NOT_FOUND", () => service.append(c));
    headEq(service, F.H4);
  }],
];

/** TV-S-01 is empty-hash; numbering follows the spec table exactly. */
export async function runConformance(): Promise<ConformanceReport> {
  const results: VectorResult[] = [];
  for (const [id, fn] of vectors) {
    try {
      await fn();
      results.push({ id, pass: true });
    } catch (e) {
      results.push({
        id,
        pass: false,
        detail: e instanceof Error ? e.message.slice(0, 500) : String(e),
      });
    }
  }
  return { suite: "TV-S", vectors: results };
}
