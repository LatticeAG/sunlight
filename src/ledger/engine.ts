/**
 * LedgerEngine — the authoritative per-ledger logic owned by the Durable
 * Object (worker/) and by the self-hosted reference server (server.ts).
 *
 * Ordering, admission, replay, and fixed-cut reads follow spec §6/§9 exactly:
 *   append: structural+hash checks → successful-ID replay → signature +
 *   static role → TTL → expected head → (inside the commit boundary)
 *   key status → statement/ID uniqueness → intrinsic form → parent
 *   existence → parent artifact → ancestor status → dependent rules →
 *   descriptor recomputation → insert + signed receipt + head advance.
 *
 * Every accepted mutation is atomic with exactly one audit entry and a
 * durable idempotency result.
 */

import { jcsBytes } from "../encoding/jcs.js";
import { parseStrictJson } from "../encoding/strict-json.js";
import { B, D, signatureMessage } from "../crypto/domains.js";
import { ed25519Verify, ed25519Sign } from "../crypto/ed25519.js";
import { SunlightError } from "../errors.js";
import { newId } from "../ids.js";
import {
  parseCommand, parseEntry, parseGenesis,
  MAX_COMMAND_TTL_MS, MAX_BUNDLE_BYTES, MAX_BUNDLE_ENTRIES,
  type AppendResult, type Bundle, type Command, type Entry, type Event,
  type Genesis, type HeadRef, type LookupItem, type Receipt, type SignedHead,
  type Statement, type StatementResult,
} from "../schema.js";
import type { Store } from "./store.js";

export interface EngineHooks {
  now?: () => number;
  /** Deterministic receipt id; receives the seq being committed. */
  entryId?: (seq: number) => string;
  /** Test hook: deterministic canonical-bundle byte measurement. */
  measureBundleBytes?: (bundle: Bundle) => number;
}

const EVENT_FOR_OP: Record<string, Event> = {
  claim: "StatementRecorded",
  key_add: "KeyAdded",
  key_retire: "KeyRetired",
  key_revoke: "KeyRevoked",
  retract: "StatementRetracted",
};

interface KeyRow {
  key_id: string;
  public_hex: string;
  added_seq: number;
  retired_seq: number | null;
  revoked_seq: number | null;
}

interface StatementRow {
  statement_hash: string;
  statement_id: string;
  recorded_seq: number;
  signer_key: string;
  subject_kind: string;
  artifact_profile: string;
  artifact_digest: string;
  artifact_bytes: number;
  retract_seq: number | null;
}

function rowToKey(r: Record<string, unknown>): KeyRow {
  return {
    key_id: r.key_id as string,
    public_hex: r.public_hex as string,
    added_seq: Number(r.added_seq),
    retired_seq: r.retired_seq === null ? null : Number(r.retired_seq),
    revoked_seq: r.revoked_seq === null ? null : Number(r.revoked_seq),
  };
}

function rowToStatement(r: Record<string, unknown>): StatementRow {
  return {
    statement_hash: r.statement_hash as string,
    statement_id: r.statement_id as string,
    recorded_seq: Number(r.recorded_seq),
    signer_key: r.signer_key as string,
    subject_kind: r.subject_kind as string,
    artifact_profile: r.artifact_profile as string,
    artifact_digest: r.artifact_digest as string,
    artifact_bytes: Number(r.artifact_bytes),
    retract_seq: r.retract_seq === null ? null : Number(r.retract_seq),
  };
}

export function keyStatusAtCut(k: KeyRow | null, cutSeq: number): "ACTIVE" | "RETIRED" | "REVOKED" {
  if (k === null) return "ACTIVE"; // genesis keys are never in the table
  if (k.revoked_seq !== null && k.revoked_seq <= cutSeq) return "REVOKED";
  if (k.retired_seq !== null && k.retired_seq <= cutSeq) return "RETIRED";
  return "ACTIVE";
}

export class LedgerEngine {
  readonly genesis: Genesis;
  readonly genesisHash: string;
  private readonly auditSeed: Buffer;
  private readonly now: () => number;
  private readonly entryId: (seq: number) => string;
  private readonly measureBundle: ((bundle: Bundle) => number) | null;

  constructor(
    private readonly store: Store,
    genesis: unknown,
    auditSeed: Buffer,
    hooks: EngineHooks = {},
  ) {
    this.genesis = parseGenesis(genesis);
    this.genesisHash = D("sunlight.genesis/1", this.genesis);
    this.auditSeed = auditSeed;
    this.now = hooks.now ?? (() => Date.now());
    this.entryId = hooks.entryId ?? (() => newId("sle"));
    this.measureBundle = hooks.measureBundleBytes ?? null;
  }

  /** Idempotent bootstrap; returns false if persisted genesis drifts. */
  boot(): boolean {
    return this.store.tx(() => {
      const g = this.store.query("SELECT value FROM meta WHERE name='genesis'");
      if (g.length === 0) {
        this.store.run("INSERT INTO meta(name,value) VALUES('genesis',?)", [
          jcsBytes(this.genesis),
        ]);
        this.store.run("INSERT INTO meta(name,value) VALUES('head',?)", [
          JSON.stringify({ seq: 0, hash: this.genesisHash }),
        ]);
        this.store.run("INSERT INTO meta(name,value) VALUES('last_commit_ms',?)", [
          String(this.genesis.created_at_ms),
        ]);
        for (const p of this.genesis.producers) {
          this.store.run(
            "INSERT INTO keys(key_id,public_hex,added_seq,retired_seq,revoked_seq) VALUES(?,?,0,NULL,NULL)",
            [p.id, p.public_hex],
          );
        }
        return true;
      }
      const persisted = Buffer.from(g[0]!.value as Uint8Array);
      if (!persisted.equals(jcsBytes(this.genesis))) return false;
      return true;
    });
  }

  headRef(): HeadRef {
    const r = this.store.query("SELECT value FROM meta WHERE name='head'");
    return JSON.parse(Buffer.from(r[0]!.value as Uint8Array).toString("utf8")) as HeadRef;
  }

  private lastCommitMs(): number {
    const r = this.store.query("SELECT value FROM meta WHERE name='last_commit_ms'");
    return Number(Buffer.from(r[0]!.value as Uint8Array).toString("utf8"));
  }

  // ---- key/statement lookups ---------------------------------------------

  private keyById(id: string): KeyRow | null {
    const rows = this.store.query("SELECT * FROM keys WHERE key_id=?", [id]);
    return rows.length ? rowToKey(rows[0]!) : null;
  }

  private keyByPub(pub: string): KeyRow | null {
    const rows = this.store.query("SELECT * FROM keys WHERE public_hex=?", [pub]);
    return rows.length ? rowToKey(rows[0]!) : null;
  }

  private keyStatus(id: string): "unregistered" | "active" | "retired" | "revoked" | "admin" | "audit" {
    if (id === this.genesis.admin.id) return "admin";
    if (id === this.genesis.audit.id) return "audit";
    const k = this.keyById(id);
    if (k === null) return "unregistered";
    if (k.revoked_seq !== null) return "revoked";
    if (k.retired_seq !== null) return "retired";
    return "active";
  }

  private publicHexFor(id: string): string | null {
    if (id === this.genesis.admin.id) return this.genesis.admin.public_hex;
    if (id === this.genesis.audit.id) return this.genesis.audit.public_hex;
    return this.keyById(id)?.public_hex ?? null;
  }

  private statementByHash(hash: string): StatementRow | null {
    const rows = this.store.query("SELECT * FROM statements WHERE statement_hash=?", [hash]);
    return rows.length ? rowToStatement(rows[0]!) : null;
  }

  private entryBySeq(seq: number): Entry | null {
    const rows = this.store.query("SELECT canonical_entry FROM entries WHERE seq=?", [seq]);
    if (rows.length === 0) return null;
    return parseEntry(parseStrictJson(Buffer.from(rows[0]!.canonical_entry as Uint8Array)));
  }

  /** Ancestor reachability over stored statements (bounded). */
  private ancestorsActive(rootHash: string): void {
    const seen = new Set<string>();
    const stack = [rootHash];
    let depth = 0;
    while (stack.length > 0) {
      const h = stack.pop()!;
      if (seen.has(h)) continue;
      if (++depth > 256 || seen.size >= 4096) throw new SunlightError("GRAPH_LIMIT");
      seen.add(h);
      const rec = this.statementByHash(h);
      if (rec === null) continue;
      if (rec.retract_seq !== null) throw new SunlightError("PARENT_INACTIVE");
      const signerStatus = this.keyStatus(rec.signer_key);
      if (signerStatus === "revoked") throw new SunlightError("PARENT_INACTIVE");
      const entry = this.entryBySeq(rec.recorded_seq);
      if (entry === null) continue;
      const st = entry.command.body.operation;
      if (st.type !== "claim") continue;
      for (const p of st.statement.body.parents) stack.push(p.statement);
    }
  }

  // ---- append -------------------------------------------------------------

  append(rawCommand: unknown): AppendResult {
    const command = parseCommand(rawCommand);
    const c = command.body;

    // Ledger binding: the command must name this ledger.
    if (c.ledger !== this.genesis.ledger) throw new SunlightError("NOT_FOUND");

    // Structural hash checks before replay.
    if (D("sunlight.command/1", c) !== command.hash) {
      throw new SunlightError("HASH_MISMATCH");
    }
    if (c.operation.type === "claim") {
      const s = c.operation.statement;
      if (s.body.ledger !== this.genesis.ledger) throw new SunlightError("NOT_FOUND");
      if (D("sunlight.statement/1", s.body) !== s.hash) {
        throw new SunlightError("HASH_MISMATCH");
      }
    }

    // Successful-ID replay precedes TTL/head/state checks.  Replay equality
    // is over the full canonical command bytes (body + hash + signature):
    // any changed byte under a used ID is IDEMPOTENCY_CONFLICT.
    const prior = this.store.query(
      "SELECT command_hash,canonical_result FROM commands WHERE command_id=?",
      [c.id],
    );
    if (prior.length > 0) {
      const stored = JSON.parse(
        Buffer.from(prior[0]!.canonical_result as Uint8Array).toString("utf8"),
      ) as AppendResult;
      if (
        prior[0]!.command_hash !== command.hash ||
        !jcsBytes(stored.entry.command).equals(jcsBytes(command))
      ) {
        throw new SunlightError("IDEMPOTENCY_CONFLICT");
      }
      return stored;
    }

    // Signature + static role.  Static role covers identity only —
    // registered-producer/admin binding and signer equality.  Key *status*
    // (active/retired/revoked) is a mutable check evaluated after the
    // expected-head gate, inside the commit boundary.
    const signerPub = this.publicHexFor(c.signer);
    const status = this.keyStatus(c.signer);
    if (status === "audit") throw new SunlightError("ROLE_MISMATCH");
    if (signerPub !== null) {
      const ok = ed25519Verify(
        Buffer.from(signerPub, "hex"),
        signatureMessage("command", command.hash),
        Buffer.from(command.signature_hex, "hex"),
      );
      if (!ok) throw new SunlightError("SIGNATURE_INVALID");
    }
    const op = c.operation;
    if (op.type === "claim") {
      const s = op.statement;
      // A missing or non-producer key is ROLE_MISMATCH.
      if (signerPub === null || status === "unregistered" || status === "admin") {
        throw new SunlightError("ROLE_MISMATCH");
      }
      if (c.signer !== s.body.signer) throw new SunlightError("ROLE_MISMATCH");
      const stmtPub = this.publicHexFor(s.body.signer);
      if (stmtPub === null) throw new SunlightError("ROLE_MISMATCH");
      const ok = ed25519Verify(
        Buffer.from(stmtPub, "hex"),
        signatureMessage("statement", s.hash),
        Buffer.from(s.signature_hex, "hex"),
      );
      if (!ok) throw new SunlightError("SIGNATURE_INVALID");
    } else if (op.type === "key_add" || op.type === "key_retire" || op.type === "key_revoke") {
      if (c.signer !== this.genesis.admin.id) throw new SunlightError("ROLE_MISMATCH");
      if (signerPub === null) throw new SunlightError("ROLE_MISMATCH");
    } else {
      // retract: target must exist; signer is admin or the statement's own
      // still-ACTIVE producer.
      const target = this.statementByHash(op.statement);
      if (target === null) throw new SunlightError("NOT_FOUND");
      const isAdmin = c.signer === this.genesis.admin.id;
      const isOwnActive = c.signer === target.signer_key && status === "active";
      if (!isAdmin && !isOwnActive) throw new SunlightError("ROLE_MISMATCH");
      if (signerPub === null) throw new SunlightError("ROLE_MISMATCH");
    }

    // TTL against admission_time = max(now, last_committed_at_ms).
    const admissionTime = Math.max(this.now(), this.lastCommitMs());
    const window = c.expires_at_ms - c.issued_at_ms;
    if (window <= 0) throw new SunlightError("COMMAND_EXPIRED");
    if (window > MAX_COMMAND_TTL_MS) throw new SunlightError("SCHEMA_INVALID");
    if (c.issued_at_ms > admissionTime + 60000) throw new SunlightError("CLOCK_AHEAD");
    if (admissionTime >= c.expires_at_ms) throw new SunlightError("COMMAND_EXPIRED");

    // Expected head.
    const head = this.headRef();
    if (c.expected_head.seq !== head.seq || c.expected_head.hash !== head.hash) {
      throw new SunlightError("HEAD_CONFLICT", head);
    }

    // Commit boundary: recheck every mutable precondition in order, then
    // assign seq, construct+sign the receipt, and advance the head.
    return this.store.tx(() => {
      // Replay recheck inside the boundary, on full canonical command bytes.
      const prior2 = this.store.query(
        "SELECT command_hash,canonical_result FROM commands WHERE command_id=?",
        [c.id],
      );
      if (prior2.length > 0) {
        const stored2 = JSON.parse(
          Buffer.from(prior2[0]!.canonical_result as Uint8Array).toString("utf8"),
        ) as AppendResult;
        if (
          prior2[0]!.command_hash !== command.hash ||
          !jcsBytes(stored2.entry.command).equals(jcsBytes(command))
        ) {
          throw new SunlightError("IDEMPOTENCY_CONFLICT");
        }
        return stored2;
      }
      const head2 = this.headRef();
      if (c.expected_head.seq !== head2.seq || c.expected_head.hash !== head2.hash) {
        throw new SunlightError("HEAD_CONFLICT", head2);
      }
      // Signer key status may have changed since the pre-check.
      if (op.type === "claim" && this.keyStatus(c.signer) !== "active") {
        throw new SunlightError("KEY_INACTIVE");
      }

      let event: Event;
      let statementHash: string | null = null;

      if (op.type === "claim") {
        const s = op.statement;
        if (this.statementByHash(s.hash) !== null) throw new SunlightError("STATEMENT_EXISTS");
        const byId = this.store.query(
          "SELECT statement_hash FROM statements WHERE statement_id=?",
          [s.body.id],
        );
        if (byId.length > 0 && byId[0]!.statement_hash !== s.hash) {
          throw new SunlightError("ID_CONFLICT");
        }
        const d = s.body.details;
        if (d.type === "training" || d.type === "action") {
          const objectId = d.type === "training" ? d.run_id : d.action_id;
          const prev = this.store.query(
            "SELECT statement_hash FROM descriptor_ids WHERE kind=? AND object_id=?",
            [s.body.subject.kind, objectId],
          );
          if (prev.length > 0) {
            if (prev[0]!.statement_hash !== s.hash) throw new SunlightError("ID_CONFLICT");
            throw new SunlightError("STATEMENT_EXISTS");
          }
        }
        this.checkIntrinsic(s);
        this.checkParents(s);
        this.checkDescriptor(s);
        event = "StatementRecorded";
        statementHash = s.hash;
      } else if (op.type === "key_add") {
        const k = op.key;
        if (k.id === this.genesis.admin.id || k.id === this.genesis.audit.id ||
            k.public_hex === this.genesis.admin.public_hex ||
            k.public_hex === this.genesis.audit.public_hex) {
          throw new SunlightError("STATE_CONFLICT");
        }
        const byId = this.keyById(k.id);
        if (byId !== null) {
          if (byId.public_hex === k.public_hex) throw new SunlightError("STATE_CONFLICT");
          throw new SunlightError("ID_CONFLICT");
        }
        if (this.keyByPub(k.public_hex) !== null) throw new SunlightError("ID_CONFLICT");
        event = "KeyAdded";
      } else if (op.type === "key_retire" || op.type === "key_revoke") {
        const id = op.key;
        if (id === this.genesis.admin.id || id === this.genesis.audit.id) {
          throw new SunlightError("STATE_CONFLICT");
        }
        const k = this.keyById(id);
        if (k === null) throw new SunlightError("NOT_FOUND");
        if (op.type === "key_retire" && (k.retired_seq !== null || k.revoked_seq !== null)) {
          throw new SunlightError("STATE_CONFLICT");
        }
        if (op.type === "key_revoke" && k.revoked_seq !== null) {
          throw new SunlightError("STATE_CONFLICT");
        }
        event = op.type === "key_retire" ? "KeyRetired" : "KeyRevoked";
      } else {
        // retract — target status rechecked inside the boundary.
        const target = this.statementByHash(op.statement);
        if (target === null) throw new SunlightError("NOT_FOUND");
        if (target.retract_seq !== null) throw new SunlightError("STATE_CONFLICT");
        event = "StatementRetracted";
      }

      // Construct + sign the receipt at the new head.
      const seq = head2.seq + 1;
      const receiptBody = {
        v: "sunlight.receipt/1" as const,
        id: this.entryId(seq),
        ledger: this.genesis.ledger,
        seq,
        previous_hash: head2.hash,
        command_hash: command.hash,
        statement_hash: statementHash,
        event,
        committed_at_ms: admissionTime,
      };
      const receiptHash = D("sunlight.receipt/1", receiptBody);
      const receipt: Receipt = {
        body: receiptBody,
        hash: receiptHash,
        signature_hex: ed25519Sign(
          this.auditSeed, signatureMessage("receipt", receiptHash),
        ).toString("hex"),
      };
      const entry: Entry = { command, receipt };
      const newHead: HeadRef = { seq, hash: receiptHash };
      const result: AppendResult = { entry, head: newHead };

      // Inserts + projections + head advance — one atomic transaction.
      this.store.run(
        "INSERT INTO entries(seq,entry_id,entry_hash,command_id,canonical_entry) VALUES(?,?,?,?,?)",
        [seq, receiptBody.id, receiptHash, c.id, jcsBytes(entry)],
      );
      this.store.run(
        "INSERT INTO commands(command_id,command_hash,canonical_result) VALUES(?,?,?)",
        [c.id, command.hash, Buffer.from(JSON.stringify(result), "utf8")],
      );
      if (op.type === "claim") {
        const s = op.statement;
        this.store.run(
          `INSERT INTO statements(statement_hash,statement_id,recorded_seq,signer_key,
             subject_kind,artifact_profile,artifact_digest,artifact_bytes,retract_seq)
           VALUES(?,?,?,?,?,?,?,?,NULL)`,
          [s.hash, s.body.id, seq, s.body.signer, s.body.subject.kind,
           s.body.subject.artifact.profile, s.body.subject.artifact.digest,
           s.body.subject.artifact.bytes],
        );
        const d = s.body.details;
        if (d.type === "training" || d.type === "action") {
          const objectId = d.type === "training" ? d.run_id : d.action_id;
          this.store.run(
            "INSERT INTO descriptor_ids(kind,object_id,statement_hash) VALUES(?,?,?)",
            [s.body.subject.kind, objectId, s.hash],
          );
        }
      } else if (op.type === "key_add") {
        this.store.run(
          "INSERT INTO keys(key_id,public_hex,added_seq,retired_seq,revoked_seq) VALUES(?,?,?,NULL,NULL)",
          [op.key.id, op.key.public_hex, seq],
        );
      } else if (op.type === "key_retire") {
        this.store.run("UPDATE keys SET retired_seq=? WHERE key_id=?", [seq, op.key]);
      } else if (op.type === "key_revoke") {
        this.store.run("UPDATE keys SET revoked_seq=? WHERE key_id=?", [seq, op.key]);
      } else if (op.type === "retract") {
        this.store.run("UPDATE statements SET retract_seq=? WHERE statement_hash=?", [seq, op.statement]);
      }
      this.store.run("UPDATE meta SET value=? WHERE name='head'", [JSON.stringify(newHead)]);
      this.store.run("UPDATE meta SET value=? WHERE name='last_commit_ms'", [String(admissionTime)]);
      return result;
    });
  }

  // ---- intrinsic form / parents / descriptor (shared shape with verify) ---

  private checkIntrinsic(s: Statement): void {
    const kind = s.body.subject.kind;
    const d = s.body.details;
    const parents = s.body.parents;
    const relations = parents.map((p) => p.relation);
    const count = (rel: string) => relations.filter((r) => r === rel).length;
    const only = (allowed: string[]) => relations.every((r) => allowed.includes(r));
    const invalid = (): never => {
      throw new SunlightError("STATEMENT_INVALID");
    };
    switch (d.type) {
      case "creation":
        if (kind !== "dataset" && kind !== "model" && kind !== "evidence") invalid();
        if (parents.length !== 0) invalid();
        return;
      case "transform":
        if (kind !== "dataset" && kind !== "model") invalid();
        if (parents.length < 1 || !only(["source"])) invalid();
        return;
      case "training":
        if (kind !== "run") invalid();
        if (s.body.subject.artifact.profile !== "jcs/1") invalid();
        if (count("dataset") < 1 || count("dataset") > 63 || count("base_model") > 1 ||
            !only(["dataset", "base_model"])) invalid();
        return;
      case "model":
        if (kind !== "model") invalid();
        if (parents.length !== 1 || count("run") !== 1) invalid();
        return;
      case "action":
        if (kind !== "action") invalid();
        if (s.body.subject.artifact.profile !== "jcs/1") invalid();
        if (parents.length !== 1 || count("model") !== 1) invalid();
        if (d.outcome === "attempted" && d.output !== null) invalid();
        if (d.outcome === "completed" && d.output === null) invalid();
        return;
    }
  }

  private checkParents(s: Statement): void {
    const d = s.body.details;
    const rows: { p: { statement: string; artifact: string; relation: string }; rec: StatementRow }[] = [];
    for (const p of s.body.parents) {
      const rec = this.statementByHash(p.statement);
      if (rec === null) throw new SunlightError("PARENT_MISSING");
      if (rec.retract_seq !== null) throw new SunlightError("PARENT_INACTIVE");
      if (rec.artifact_digest !== p.artifact) throw new SunlightError("PARENT_MISMATCH");
      rows.push({ p, rec });
    }
    // Every reached ancestor must be unretracted with an unrevoked producer.
    for (const { rec } of rows) this.ancestorsActive(rec.statement_hash);
    // Dependent parent kind/details rules.
    const entryKind = (hash: string): { kind: string; detailsType: string } => {
      const rec = this.statementByHash(hash)!;
      const e = this.entryBySeq(rec.recorded_seq)!;
      const st = (e.command.body.operation as { statement: Statement }).statement;
      return { kind: st.body.subject.kind, detailsType: st.body.details.type };
    };
    switch (d.type) {
      case "transform":
        for (const { rec } of rows) {
          if (rec.subject_kind !== s.body.subject.kind) throw new SunlightError("STATEMENT_INVALID");
        }
        return;
      case "training":
        for (const { p, rec } of rows) {
          if (p.relation === "dataset" && rec.subject_kind !== "dataset") {
            throw new SunlightError("STATEMENT_INVALID");
          }
          if (p.relation === "base_model" && rec.subject_kind !== "model") {
            throw new SunlightError("STATEMENT_INVALID");
          }
        }
        return;
      case "model": {
        const run = rows.find((r) => r.p.relation === "run")!;
        const k = entryKind(run.rec.statement_hash);
        if (k.kind !== "run" || k.detailsType !== "training") {
          throw new SunlightError("STATEMENT_INVALID");
        }
        return;
      }
      case "action": {
        const model = rows.find((r) => r.p.relation === "model")!;
        if (model.rec.subject_kind !== "model") throw new SunlightError("STATEMENT_INVALID");
        return;
      }
      default:
        return;
    }
  }

  private checkDescriptor(s: Statement): void {
    const kind = s.body.subject.kind;
    if (kind !== "run" && kind !== "action") return;
    const descriptor = {
      v: "sunlight.descriptor/1",
      kind,
      parents: s.body.parents,
      details: s.body.details,
    };
    const canon = jcsBytes(descriptor);
    const expected = { profile: "jcs/1", digest: B(canon), bytes: canon.length };
    const a = s.body.subject.artifact;
    if (a.profile !== expected.profile || a.digest !== expected.digest || a.bytes !== expected.bytes) {
      throw new SunlightError("DESCRIPTOR_MISMATCH");
    }
  }

  // ---- reads ---------------------------------------------------------------

  /** Signed head over the CURRENT ledger head — freshness challenges only. */
  headGet(nonceHex: string): SignedHead {
    const head = this.headRef();
    const body = {
      v: "sunlight.head/1" as const,
      ledger: this.genesis.ledger,
      genesis_hash: this.genesisHash,
      head,
      observed_at_ms: this.now(),
      nonce_hex: nonceHex,
    };
    const hash = D("sunlight.head/1", body);
    return {
      body,
      hash,
      signature_hex: ed25519Sign(this.auditSeed, signatureMessage("head", hash)).toString("hex"),
    };
  }

  entryGet(seq: number): Entry {
    const e = this.entryBySeq(seq);
    if (e === null) throw new SunlightError("NOT_FOUND");
    return e;
  }

  private checkCut(cut: HeadRef): void {
    if (cut.seq === 0) {
      if (cut.hash !== this.genesisHash) throw new SunlightError("CUT_MISMATCH", this.headRef());
      return;
    }
    const rows = this.store.query("SELECT entry_hash FROM entries WHERE seq=?", [cut.seq]);
    if (rows.length === 0 || rows[0]!.entry_hash !== cut.hash) {
      throw new SunlightError("CUT_MISMATCH", this.headRef());
    }
  }

  entriesList(after: number, cut: HeadRef, limit: number): { entries: Entry[]; next_after: number | null; cut: HeadRef } {
    this.checkCut(cut);
    const rows = this.store.query(
      "SELECT canonical_entry,seq FROM entries WHERE seq>? AND seq<=? ORDER BY seq ASC LIMIT ?",
      [after, cut.seq, limit + 1],
    );
    const page = rows.slice(0, limit);
    const entries = page.map((r) =>
      parseEntry(parseStrictJson(Buffer.from(r.canonical_entry as Uint8Array))));
    const next = rows.length > limit ? Number(page[page.length - 1]!.seq) : null;
    return { entries, next_after: next, cut };
  }

  private statementObject(row: StatementRow): Statement {
    const e = this.entryBySeq(row.recorded_seq);
    if (e === null || e.command.body.operation.type !== "claim") {
      throw new SunlightError("STORAGE_UNAVAILABLE");
    }
    return e.command.body.operation.statement;
  }

  statementGet(statementHash: string, cut: HeadRef): StatementResult {
    this.checkCut(cut);
    const row = this.statementByHash(statementHash);
    if (row === null || row.recorded_seq > cut.seq) throw new SunlightError("NOT_FOUND");
    const key = this.keyById(row.signer_key);
    return {
      statement: this.statementObject(row),
      recorded_at: row.recorded_seq,
      retracted: row.retract_seq !== null && row.retract_seq <= cut.seq,
      key_status: keyStatusAtCut(key, cut.seq),
      head: cut,
    };
  }

  artifactLookup(
    profile: string,
    digest: string,
    cut: HeadRef,
    afterSeq: number,
    limit: number,
  ): { matches: LookupItem[]; next_after_seq: number | null; cut: HeadRef } {
    this.checkCut(cut);
    const rows = this.store.query(
      `SELECT * FROM statements
       WHERE artifact_profile=? AND artifact_digest=? AND recorded_seq>? AND recorded_seq<=?
       ORDER BY recorded_seq ASC LIMIT ?`,
      [profile, digest, afterSeq, cut.seq, limit + 1],
    );
    const page = rows.slice(0, limit);
    const matches: LookupItem[] = page.map((r) => {
      const row = rowToStatement(r);
      const st = this.statementObject(row);
      const key = this.keyById(row.signer_key);
      return {
        statement: row.statement_hash,
        id: row.statement_id,
        kind: st.body.subject.kind,
        signer: row.signer_key,
        capture: st.body.capture,
        retracted: row.retract_seq !== null && row.retract_seq <= cut.seq,
        key_status: keyStatusAtCut(key, cut.seq),
      };
    });
    const next =
      rows.length > limit ? rowToStatement(page[page.length - 1]!).recorded_seq : null;
    return { matches, next_after_seq: next, cut };
  }

  /**
   * Export a bundle covering the prefix up to an exact cut.  The head is a
   * SignedHead committing the requested cut — not the live head — signed at
   * export time with nonce null.
   */
  bundleExport(target: string, cut: HeadRef): { bundle: Bundle; digest: string } {
    this.checkCut(cut);
    const t = this.statementByHash(target);
    if (t === null || t.recorded_seq > cut.seq) throw new SunlightError("NOT_FOUND");
    const rows = this.store.query(
      "SELECT canonical_entry FROM entries WHERE seq<=? ORDER BY seq ASC",
      [cut.seq],
    );
    if (rows.length > MAX_BUNDLE_ENTRIES) throw new SunlightError("BUNDLE_LIMIT");
    const entries = rows.map((r) =>
      parseEntry(parseStrictJson(Buffer.from(r.canonical_entry as Uint8Array))));
    const headBody = {
      v: "sunlight.head/1" as const,
      ledger: this.genesis.ledger,
      genesis_hash: this.genesisHash,
      head: cut,
      observed_at_ms: this.now(),
      nonce_hex: null,
    };
    const headHash = D("sunlight.head/1", headBody);
    const signedHead: SignedHead = {
      body: headBody,
      hash: headHash,
      signature_hex: ed25519Sign(this.auditSeed, signatureMessage("head", headHash)).toString("hex"),
    };
    const bundle: Bundle = {
      v: "sunlight.bundle/1",
      genesis: this.genesis,
      entries,
      head: signedHead,
      target,
    };
    const canon = jcsBytes(bundle);
    const measured = this.measureBundle !== null ? this.measureBundle(bundle) : canon.length;
    if (measured > MAX_BUNDLE_BYTES) throw new SunlightError("BUNDLE_LIMIT");
    return { bundle, digest: B(canon) };
  }
}
