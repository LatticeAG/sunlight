/**
 * Offline verification (spec §4.3).
 *
 * verify() performs no network, clock, filesystem, or key-discovery work.
 * Structural failures throw SunlightError; a well-formed cryptographically
 * failing bundle returns an integrity-INVALID Verification.
 */

import { jcsBytes } from "./encoding/jcs.js";
import { B, D, signatureMessage } from "./crypto/domains.js";
import { ed25519Verify } from "./crypto/ed25519.js";
import { SunlightError, type ErrorCode } from "./errors.js";
import {
  parseBundle, parseTrust, parseArtifactObservation, parseFreshnessEvidence,
  MAX_COMMAND_TTL_MS, MAX_BUNDLE_BYTES, MAX_BUNDLE_ENTRIES,
  type Bundle, type Command, type Entry, type FreshnessEvidence, type Genesis,
  type HeadRef, type Statement, type Trust, type Verification,
  type ArtifactObservation,
} from "./schema.js";

const MAX_GRAPH_DEPTH = 256;
const MAX_GRAPH_NODES = 4096;

interface KeyTimeline {
  public_hex: string;
  role: "admin" | "audit" | "producer";
  added_seq: number;
  retired_seq: number | null;
  revoked_seq: number | null;
}

interface StatementRecord {
  statement: Statement;
  seq: number;
  retract_seq: number | null;
}

interface ReplayState {
  keys: Map<string, KeyTimeline>;
  statements: Map<string, StatementRecord>;
  statementIds: Map<string, string>;
  descriptorIds: Map<string, string>; // `${kind}:${object_id}` → statement hash
  commandIds: Set<string>;
}

function fail(code: ErrorCode, reasons?: string[]): Verification {
  return {
    integrity: "INVALID",
    lineage: "INVALID",
    authority: "UNKNOWN",
    freshness: "OFFLINE",
    artifact: "NOT_SUPPLIED",
    claim_truth: "NOT_PROVEN",
    overall: "INVALID",
    reasons: reasons ?? [code],
    head: null,
  };
}

class IntegrityFailure extends Error {
  constructor(readonly code: ErrorCode) {
    super(code);
  }
}

function sortedUnique(xs: string[]): string[] {
  return [...new Set(xs)].sort();
}

/** Expected HeadRef preceding entry at index i (genesis ref at seq 1). */
function expectedHead(genesisHash: string, entries: Entry[], i: number): HeadRef {
  if (i === 0) return { seq: 0, hash: genesisHash };
  const r = entries[i - 1]!.receipt;
  return { seq: r.body.seq, hash: r.hash };
}

const EVENT_FOR_OP: Record<string, string> = {
  claim: "StatementRecorded",
  key_add: "KeyAdded",
  key_retire: "KeyRetired",
  key_revoke: "KeyRevoked",
  retract: "StatementRetracted",
};

export interface VerifyRequest {
  bundle: Bundle;
  trust: Trust;
  observation: ArtifactObservation | null;
  freshness: FreshnessEvidence | null;
}

export function verify(request: VerifyRequest): Verification {
  // Phase 1 — strict structural validation.  Throws on malformed input.
  const bundle = parseBundle(request.bundle);
  const trust = parseTrust(request.trust);
  const observation =
    request.observation === null ? null : parseArtifactObservation(request.observation);
  const freshness =
    request.freshness === null ? null : parseFreshnessEvidence(request.freshness);
  if (jcsBytes(bundle).length > MAX_BUNDLE_BYTES) throw new SunlightError("BUNDLE_LIMIT");
  if (bundle.entries.length > MAX_BUNDLE_ENTRIES) throw new SunlightError("BUNDLE_LIMIT");

  const genesis: Genesis = bundle.genesis;
  const genesisHash = D("sunlight.genesis/1", genesis);
  const pinned = trust.ledger === genesis.ledger && trust.genesis_hash === genesisHash;

  const genesisKeys = new Map<string, { public_hex: string; role: "admin" | "audit" | "producer" }>();
  genesisKeys.set(genesis.admin.id, { public_hex: genesis.admin.public_hex, role: "admin" });
  genesisKeys.set(genesis.audit.id, { public_hex: genesis.audit.public_hex, role: "audit" });
  for (const p of genesis.producers) {
    genesisKeys.set(p.id, { public_hex: p.public_hex, role: "producer" });
  }

  try {
    // Phase 3a — recompute every object hash before any signature check.
    for (const e of bundle.entries) {
      if (D("sunlight.command/1", e.command.body) !== e.command.hash) {
        throw new IntegrityFailure("HASH_MISMATCH");
      }
      if (e.command.body.operation.type === "claim") {
        const s = e.command.body.operation.statement;
        if (D("sunlight.statement/1", s.body) !== s.hash) {
          throw new IntegrityFailure("HASH_MISMATCH");
        }
      }
      if (D("sunlight.receipt/1", e.receipt.body) !== e.receipt.hash) {
        throw new IntegrityFailure("HASH_MISMATCH");
      }
    }
    if (D("sunlight.head/1", bundle.head.body) !== bundle.head.hash) {
      throw new IntegrityFailure("HASH_MISMATCH");
    }

    // Phase 3b — signatures with role-correct keys.  Signer key resolution
    // uses genesis keys plus first-seen key_add payloads; unresolved signers
    // are deferred to replay, which produces the admission code.
    {
      const resolved = new Map<string, string>(); // key id → public_hex
      for (const [id, k] of genesisKeys) resolved.set(id, k.public_hex);
      const pubFor = (id: string): string | null => resolved.get(id) ?? null;

      const verifySig = (
        kind: "statement" | "command" | "receipt" | "head",
        obj: { body: unknown; hash: string; signature_hex: string },
        keyId: string | null,
        forcedPub?: string,
      ): void => {
        const pub = forcedPub ?? (keyId === null ? null : pubFor(keyId));
        if (pub === null || pub === undefined) return; // deferred to replay
        const ok = ed25519Verify(
          Buffer.from(pub, "hex"),
          signatureMessage(kind, obj.hash),
          Buffer.from(obj.signature_hex, "hex"),
        );
        if (!ok) throw new IntegrityFailure("SIGNATURE_INVALID");
      };

      for (const e of bundle.entries) {
        const cmd = e.command;
        verifySig("command", cmd, cmd.body.signer);
        if (cmd.body.operation.type === "claim") {
          const s = cmd.body.operation.statement;
          verifySig("statement", s, s.body.signer);
        }
        verifySig("receipt", e.receipt, null, genesis.audit.public_hex);
        // Optimistically register key_add payloads so later entries can
        // resolve signers; admission validity is still decided by replay.
        if (cmd.body.operation.type === "key_add") {
          const k = cmd.body.operation.key;
          if (!resolved.has(k.id)) resolved.set(k.id, k.public_hex);
        }
      }
      verifySig("head", bundle.head, null, genesis.audit.public_hex);
    }

    // Phase 4 — chain linkage: contiguous seqs from 1, genesis-anchored
    // previous hashes, expected_head binding, field binding, monotone time.
    let prevCommit = 0;
    for (let i = 0; i < bundle.entries.length; i++) {
      const e = bundle.entries[i]!;
      const r = e.receipt.body;
      const c = e.command.body;
      if (r.seq !== i + 1) throw new IntegrityFailure("CHAIN_MISMATCH");
      const eh = expectedHead(genesisHash, bundle.entries, i);
      if (r.previous_hash !== eh.hash) throw new IntegrityFailure("CHAIN_MISMATCH");
      if (c.expected_head.seq !== eh.seq || c.expected_head.hash !== eh.hash) {
        throw new IntegrityFailure("CHAIN_MISMATCH");
      }
      if (r.command_hash !== e.command.hash) throw new IntegrityFailure("CHAIN_MISMATCH");
      const expectedStmtHash =
        c.operation.type === "claim" ? c.operation.statement.hash : null;
      if (r.statement_hash !== expectedStmtHash) throw new IntegrityFailure("CHAIN_MISMATCH");
      if (r.committed_at_ms < prevCommit) throw new IntegrityFailure("CHAIN_MISMATCH");
      prevCommit = r.committed_at_ms;
    }

    // Phase 5 — replay admission semantics.
    const state = replay(bundle, genesisKeys);

    // Phase 6 — head binding and target presence.
    const bundleHead = expectedHead(genesisHash, bundle.entries, bundle.entries.length);
    const hb = bundle.head.body;
    if (hb.head.seq !== bundleHead.seq || hb.head.hash !== bundleHead.hash) {
      throw new IntegrityFailure("CHAIN_MISMATCH");
    }
    if (hb.ledger !== genesis.ledger || hb.genesis_hash !== genesisHash) {
      throw new IntegrityFailure("CHAIN_MISMATCH");
    }
    const targetRecord = state.statements.get(bundle.target);
    if (targetRecord === undefined) throw new IntegrityFailure("TARGET_MISSING");

    // Phase 7 — minimum head pin at its exact sequence.
    const min = trust.minimum_head;
    const minOk =
      min.seq === 0
        ? min.hash === genesisHash
        : min.seq <= bundle.entries.length &&
          bundle.entries[min.seq - 1]!.receipt.hash === min.hash;
    if (!minOk) throw new IntegrityFailure("MINIMUM_HEAD_MISMATCH");

    // Phases 8–12 — lineage, authority, artifact, freshness, result.
    const reasons: string[] = [];
    if (!pinned) reasons.push("UNTRUSTED_GENESIS");

    // Phase 8 — traverse declared ancestry; compute current-at-cut status.
    const cutSeq = bundle.entries.length;
    const reached = ancestry(bundle.target, state); // throws GRAPH_LIMIT
    let sawRetracted = false;
    let sawRevoked = false;
    let sawDenied = false;
    const denied = new Set(trust.denied_keys);
    for (const rec of reached) {
      if (rec.retract_seq !== null && rec.retract_seq <= cutSeq) sawRetracted = true;
      const signer = rec.statement.body.signer;
      const tl = state.keys.get(signer);
      if (tl !== undefined && tl.revoked_seq !== null && tl.revoked_seq <= cutSeq) {
        sawRevoked = true;
      }
      if (denied.has(signer)) sawDenied = true;
    }
    if (sawRetracted) reasons.push("RETRACTED_ANCESTOR");
    if (sawRevoked) reasons.push("REVOKED_ANCESTOR");
    if (sawDenied) reasons.push("DENIED_KEY");

    // Phase 9 — required training ancestry for reached models.
    let missingTraining = false;
    if (trust.require_training) {
      for (const rec of reached) {
        if (rec.statement.body.subject.kind !== "model") continue;
        if (!modelTrained(rec.statement, state, new Set())) missingTraining = true;
      }
      if (missingTraining) reasons.push("MISSING_TRAINING");
    }

    // Phase 10 — artifact observation against the complete tuple.
    let artifactDim: Verification["artifact"];
    if (observation === null) {
      artifactDim = "NOT_SUPPLIED";
    } else {
      const t = targetRecord.statement.body.subject.artifact;
      const o = observation.artifact;
      artifactDim =
        o.profile === t.profile && o.digest === t.digest && o.bytes === t.bytes
          ? "MATCH"
          : "MISMATCH";
    }
    if (artifactDim === "MISMATCH") reasons.push("ARTIFACT_MISMATCH");

    // Phase 11 — freshness evidence.
    let freshnessDim: Verification["freshness"] = "OFFLINE";
    if (freshness !== null) {
      freshnessDim = checkFreshness(freshness, bundle, genesis, trust) ? "CURRENT" : "STALE";
      if (freshnessDim === "STALE") reasons.push("STALE_HEAD");
    }

    // Phase 12 — deterministic result dimensions.
    const lineage: Verification["lineage"] =
      sawRetracted || missingTraining ? "INCOMPLETE" : "COMPLETE_DECLARED";
    const authority: Verification["authority"] =
      sawRevoked || sawDenied ? "REVOKED" : !pinned ? "UNTRUSTED" : "TRUSTED_AT_HEAD";
    const overall: Verification["overall"] =
      artifactDim === "MISMATCH"
        ? "INVALID"
        : lineage === "COMPLETE_DECLARED" &&
            authority === "TRUSTED_AT_HEAD" &&
            (artifactDim === "MATCH" || artifactDim === "NOT_SUPPLIED") &&
            (freshnessDim === "CURRENT" || freshnessDim === "OFFLINE")
          ? "VERIFIED"
          : "UNVERIFIED";

    return {
      integrity: "VALID",
      lineage,
      authority,
      freshness: freshnessDim,
      artifact: artifactDim,
      claim_truth: "NOT_PROVEN",
      overall,
      reasons: sortedUnique(reasons),
      head: bundleHead,
    };
  } catch (e) {
    if (e instanceof IntegrityFailure) {
      const v = fail(e.code);
      // On integrity failure freshness is OFFLINE unless evidence was
      // provided (then STALE); artifact is NOT_SUPPLIED unless an observation
      // was provided (then UNCHECKED).
      v.freshness = freshness === null ? "OFFLINE" : "STALE";
      v.artifact = observation === null ? "NOT_SUPPLIED" : "UNCHECKED";
      return v;
    }
    throw e;
  }
}

/**
 * Phase 5 replay: re-run admission semantics over the prefix, building the
 * key/statement timelines used by the status checks.
 */
function replay(
  bundle: Bundle,
  genesisKeys: Map<string, { public_hex: string; role: "admin" | "audit" | "producer" }>,
): ReplayState {
  const state: ReplayState = {
    keys: new Map(),
    statements: new Map(),
    statementIds: new Map(),
    descriptorIds: new Map(),
    commandIds: new Set(),
  };
  for (const [id, k] of genesisKeys) {
    state.keys.set(id, {
      public_hex: k.public_hex, role: k.role,
      added_seq: 0, retired_seq: null, revoked_seq: null,
    });
  }
  for (const e of bundle.entries) {
    replayEntry(state, e, bundle.genesis);
  }
  return state;
}

function keyStatusAt(tl: KeyTimeline | undefined): "unregistered" | "active" | "retired" | "revoked" {
  if (tl === undefined) return "unregistered";
  if (tl.revoked_seq !== null) return "revoked";
  if (tl.retired_seq !== null) return "retired";
  return "active";
}

function replayEntry(state: ReplayState, e: Entry, genesis: Genesis): void {
  const cmd = e.command;
  const c = cmd.body;
  const op = c.operation;
  const r = e.receipt.body;
  const seq = r.seq;

  // Ledger binding: every nested ledger field equals the bundle genesis ledger.
  if (c.ledger !== genesis.ledger || r.ledger !== genesis.ledger) {
    throw new IntegrityFailure("CHAIN_MISMATCH");
  }
  if (op.type === "claim" && op.statement.body.ledger !== genesis.ledger) {
    throw new IntegrityFailure("CHAIN_MISMATCH");
  }
  // A second entry for an already committed command id cannot exist.
  if (state.commandIds.has(c.id)) throw new IntegrityFailure("AUDIT_BINDING_MISMATCH");

  // TTL recheck against the recorded time (spec §4.3 step 5).
  const window = c.expires_at_ms - c.issued_at_ms;
  if (!(window > 0 && window <= MAX_COMMAND_TTL_MS)) {
    throw new IntegrityFailure("AUDIT_BINDING_MISMATCH");
  }
  if (!(c.issued_at_ms <= r.committed_at_ms + 60000)) {
    throw new IntegrityFailure("AUDIT_BINDING_MISMATCH");
  }
  if (!(r.committed_at_ms < c.expires_at_ms)) {
    throw new IntegrityFailure("AUDIT_BINDING_MISMATCH");
  }

  const signerTl = state.keys.get(c.signer);
  const signerStatus = keyStatusAt(signerTl);
  const adminId = genesis.admin.id;

  // Static role + signer key status, in admission order.
  if (op.type === "claim") {
    const s = op.statement;
    if (c.signer !== s.body.signer) throw new IntegrityFailure("ROLE_MISMATCH");
    if (signerTl === undefined || signerTl.role !== "producer") {
      throw new IntegrityFailure("ROLE_MISMATCH");
    }
    if (signerStatus !== "active") throw new IntegrityFailure("KEY_INACTIVE");
  } else if (op.type === "key_add" || op.type === "key_retire" || op.type === "key_revoke") {
    if (c.signer !== adminId) throw new IntegrityFailure("ROLE_MISMATCH");
  } else if (op.type === "retract") {
    const target = state.statements.get(op.statement);
    if (target === undefined) throw new IntegrityFailure("NOT_FOUND");
    if (target.retract_seq !== null) throw new IntegrityFailure("STATE_CONFLICT");
    const isAdmin = c.signer === adminId;
    const isOwnActiveProducer =
      c.signer === target.statement.body.signer &&
      signerTl !== undefined &&
      signerTl.role === "producer" &&
      signerStatus === "active";
    if (!isAdmin && !isOwnActiveProducer) throw new IntegrityFailure("ROLE_MISMATCH");
  }
  // Audit key can never submit any command.
  if (signerTl !== undefined && signerTl.role === "audit") {
    throw new IntegrityFailure("ROLE_MISMATCH");
  }

  // Uniqueness and state transitions.
  if (op.type === "claim") {
    const s = op.statement;
    if (state.statements.has(s.hash)) throw new IntegrityFailure("STATEMENT_EXISTS");
    const bound = state.statementIds.get(s.body.id);
    if (bound !== undefined && bound !== s.hash) throw new IntegrityFailure("ID_CONFLICT");
    const d = s.body.details;
    if (d.type === "training" || d.type === "action") {
      const objectId = d.type === "training" ? d.run_id : d.action_id;
      const k = `${s.body.subject.kind}:${objectId}`;
      const prev = state.descriptorIds.get(k);
      if (prev !== undefined && prev !== s.hash) throw new IntegrityFailure("ID_CONFLICT");
      if (prev !== undefined && prev === s.hash) throw new IntegrityFailure("STATEMENT_EXISTS");
    }
    checkIntrinsic(s);
    checkParents(state, s);
    checkDescriptor(s);
  } else if (op.type === "key_add") {
    const k = op.key;
    if (k.id === genesis.admin.id || k.id === genesis.audit.id ||
        k.public_hex === genesis.admin.public_hex || k.public_hex === genesis.audit.public_hex) {
      throw new IntegrityFailure("STATE_CONFLICT");
    }
    const existing = state.keys.get(k.id);
    if (existing !== undefined) throw new IntegrityFailure("ID_CONFLICT");
    for (const [id, tl] of state.keys) {
      if (tl.public_hex === k.public_hex && id !== k.id) {
        throw new IntegrityFailure("ID_CONFLICT");
      }
    }
  } else if (op.type === "key_retire" || op.type === "key_revoke") {
    const id = op.key;
    if (id === genesis.admin.id || id === genesis.audit.id) {
      throw new IntegrityFailure("STATE_CONFLICT");
    }
    const tl = state.keys.get(id);
    if (tl === undefined) throw new IntegrityFailure("NOT_FOUND");
    if (op.type === "key_retire" && keyStatusAt(tl) !== "active") {
      throw new IntegrityFailure("STATE_CONFLICT");
    }
    if (op.type === "key_revoke" && keyStatusAt(tl) === "revoked") {
      throw new IntegrityFailure("STATE_CONFLICT");
    }
  }

  // Event binding: the receipt must attest exactly the event replay produced.
  if (r.event !== EVENT_FOR_OP[op.type]) throw new IntegrityFailure("AUDIT_BINDING_MISMATCH");

  // Apply.
  state.commandIds.add(c.id);
  if (op.type === "claim") {
    const s = op.statement;
    state.statements.set(s.hash, { statement: s, seq, retract_seq: null });
    state.statementIds.set(s.body.id, s.hash);
    const d = s.body.details;
    if (d.type === "training" || d.type === "action") {
      const objectId = d.type === "training" ? d.run_id : d.action_id;
      state.descriptorIds.set(`${s.body.subject.kind}:${objectId}`, s.hash);
    }
  } else if (op.type === "key_add") {
    state.keys.set(op.key.id, {
      public_hex: op.key.public_hex, role: "producer",
      added_seq: seq, retired_seq: null, revoked_seq: null,
    });
  } else if (op.type === "key_retire") {
    state.keys.get(op.key)!.retired_seq = seq;
  } else if (op.type === "key_revoke") {
    state.keys.get(op.key)!.revoked_seq = seq;
  } else if (op.type === "retract") {
    state.statements.get(op.statement)!.retract_seq = seq;
  }
}

/** Intrinsic statement form (spec §4.1) — checked before any parent lookup. */
function checkIntrinsic(s: Statement): void {
  const kind = s.body.subject.kind;
  const d = s.body.details;
  const parents = s.body.parents;
  const relations = parents.map((p) => p.relation);
  const count = (rel: string) => relations.filter((r) => r === rel).length;
  const only = (allowed: string[]) => relations.every((r) => allowed.includes(r));

  switch (d.type) {
    case "creation":
      if (kind !== "dataset" && kind !== "model" && kind !== "evidence") {
        throw new IntegrityFailure("STATEMENT_INVALID");
      }
      if (parents.length !== 0) throw new IntegrityFailure("STATEMENT_INVALID");
      return;
    case "transform":
      if (kind !== "dataset" && kind !== "model") throw new IntegrityFailure("STATEMENT_INVALID");
      if (parents.length < 1 || !only(["source"])) throw new IntegrityFailure("STATEMENT_INVALID");
      return;
    case "training":
      if (kind !== "run") throw new IntegrityFailure("STATEMENT_INVALID");
      if (s.body.subject.artifact.profile !== "jcs/1") throw new IntegrityFailure("STATEMENT_INVALID");
      if (count("dataset") < 1 || count("dataset") > 63 || count("base_model") > 1 ||
          !only(["dataset", "base_model"])) {
        throw new IntegrityFailure("STATEMENT_INVALID");
      }
      return;
    case "model":
      if (kind !== "model") throw new IntegrityFailure("STATEMENT_INVALID");
      if (parents.length !== 1 || count("run") !== 1) throw new IntegrityFailure("STATEMENT_INVALID");
      return;
    case "action": {
      if (kind !== "action") throw new IntegrityFailure("STATEMENT_INVALID");
      if (s.body.subject.artifact.profile !== "jcs/1") throw new IntegrityFailure("STATEMENT_INVALID");
      if (parents.length !== 1 || count("model") !== 1) throw new IntegrityFailure("STATEMENT_INVALID");
      if (d.outcome === "attempted" && d.output !== null) throw new IntegrityFailure("STATEMENT_INVALID");
      if (d.outcome === "completed" && d.output === null) throw new IntegrityFailure("STATEMENT_INVALID");
      return;
    }
  }
}

/** Parent existence, artifact, status, and dependent rules (spec §4.1). */
function checkParents(state: ReplayState, s: Statement): void {
  const parents = s.body.parents;
  const records: StatementRecord[] = [];
  for (const p of parents) {
    const rec = state.statements.get(p.statement);
    if (rec === undefined) throw new IntegrityFailure("PARENT_MISSING");
    if (rec.retract_seq !== null) throw new IntegrityFailure("PARENT_INACTIVE");
    if (rec.statement.body.subject.artifact.digest !== p.artifact) {
      throw new IntegrityFailure("PARENT_MISMATCH");
    }
    records.push(rec);
  }
  // Every reached ancestor must be unretracted with an unrevoked producer.
  for (const anc of ancestryFrom(records, state)) {
    if (anc.retract_seq !== null) throw new IntegrityFailure("PARENT_INACTIVE");
    const tl = state.keys.get(anc.statement.body.signer);
    if (tl !== undefined && tl.revoked_seq !== null) throw new IntegrityFailure("PARENT_INACTIVE");
  }
  // Dependent parent kind/details rules.
  const d = s.body.details;
  const byRel = (rel: string) =>
    s.body.parents.filter((p) => p.relation === rel).map((p) => state.statements.get(p.statement)!);
  switch (d.type) {
    case "transform":
      for (const rec of records) {
        if (rec.statement.body.subject.kind !== s.body.subject.kind) {
          throw new IntegrityFailure("STATEMENT_INVALID");
        }
      }
      return;
    case "training":
      for (const rec of byRel("dataset")) {
        if (rec.statement.body.subject.kind !== "dataset") throw new IntegrityFailure("STATEMENT_INVALID");
      }
      for (const rec of byRel("base_model")) {
        if (rec.statement.body.subject.kind !== "model") throw new IntegrityFailure("STATEMENT_INVALID");
      }
      return;
    case "model": {
      const run = byRel("run")[0]!;
      if (run.statement.body.subject.kind !== "run" ||
          run.statement.body.details.type !== "training") {
        throw new IntegrityFailure("STATEMENT_INVALID");
      }
      return;
    }
    case "action": {
      const model = byRel("model")[0]!;
      if (model.statement.body.subject.kind !== "model") {
        throw new IntegrityFailure("STATEMENT_INVALID");
      }
      return;
    }
    default:
      return;
  }
}

/** Run/action subjects must commit the recomputed descriptor (spec §4.1). */
function checkDescriptor(s: Statement): void {
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
    throw new IntegrityFailure("DESCRIPTOR_MISMATCH");
  }
}

/** All statements reached from `root`'s declared ancestry (incl. root). */
function ancestry(rootHash: string, state: ReplayState): StatementRecord[] {
  const root = state.statements.get(rootHash);
  if (root === undefined) return [];
  return ancestryFrom([root], state);
}

function ancestryFrom(roots: StatementRecord[], state: ReplayState): StatementRecord[] {
  const seen = new Map<string, StatementRecord>();
  const stack: { rec: StatementRecord; depth: number }[] = roots.map((rec) => ({ rec, depth: 0 }));
  while (stack.length > 0) {
    const { rec, depth } = stack.pop()!;
    if (seen.has(rec.statement.hash)) continue;
    if (depth > MAX_GRAPH_DEPTH) throw new IntegrityFailure("GRAPH_LIMIT");
    if (seen.size >= MAX_GRAPH_NODES) throw new IntegrityFailure("GRAPH_LIMIT");
    seen.set(rec.statement.hash, rec);
    for (const p of rec.statement.body.parents) {
      const pr = state.statements.get(p.statement);
      if (pr !== undefined) stack.push({ rec: pr, depth: depth + 1 });
    }
  }
  return [...seen.values()];
}

/**
 * A reached model satisfies require_training when its declared ancestry
 * terminates through model→run→dataset paths; transforms recurse into source
 * models and base models are checked recursively (spec §4.3 step 9).
 */
function modelTrained(s: Statement, state: ReplayState, visiting: Set<string>): boolean {
  if (visiting.has(s.hash)) return true;
  visiting.add(s.hash);
  const d = s.body.details;
  if (d.type === "model") {
    // exactly one run parent — admission already guaranteed the chain.
    return true;
  }
  if (d.type === "transform") {
    for (const p of s.body.parents) {
      const rec = state.statements.get(p.statement);
      if (rec === undefined) return false;
      if (rec.statement.body.subject.kind !== "model") return false;
      if (!modelTrained(rec.statement, state, visiting)) return false;
    }
    return true;
  }
  return false; // creation root (or anything else): no training ancestry
}

function checkFreshness(
  f: FreshnessEvidence,
  bundle: Bundle,
  genesis: Genesis,
  trust: Trust,
): boolean {
  const hb = f.head.body;
  if (hb.ledger !== genesis.ledger) return false;
  if (hb.genesis_hash !== D("sunlight.genesis/1", genesis)) return false;
  const bundleHead = bundle.head.body.head;
  if (hb.head.seq !== bundleHead.seq || hb.head.hash !== bundleHead.hash) return false;
  if (hb.nonce_hex !== f.expected_nonce_hex) return false;
  if (f.received_at_ms < f.sent_at_ms) return false;
  if (f.received_at_ms - f.sent_at_ms > trust.max_head_age_ms) return false;
  if (hb.observed_at_ms < f.sent_at_ms - 60000) return false;
  if (hb.observed_at_ms > f.received_at_ms + 60000) return false;
  if (D("sunlight.head/1", f.head.body) !== f.head.hash) return false;
  return ed25519Verify(
    Buffer.from(genesis.audit.public_hex, "hex"),
    signatureMessage("head", f.head.hash),
    Buffer.from(f.head.signature_hex, "hex"),
  );
}
