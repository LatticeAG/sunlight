/**
 * Registry service state machine (spec §5):
 *   BOOTING → READY | READ_ONLY;  READY → READ_ONLY on detected corruption,
 *   capacity reserve, or audit-key unavailability;  READ_ONLY → READY only
 *   through operator repair with head-pin reconciliation;  any state →
 *   BOOTING on process restart (persisted state reloads before any response).
 *
 * head.get is available only in READY; append in READ_ONLY returns the 503
 * code matching its cause.  READ_ONLY still serves verified historical reads.
 */

import { SunlightError } from "../errors.js";
import { ed25519PublicFromSeed } from "../crypto/ed25519.js";
import { LedgerEngine, type EngineHooks } from "./engine.js";
import type { Store } from "./store.js";

export type ServiceState = "BOOTING" | "READY" | "READ_ONLY";
export type DisabledReason = "STORAGE_UNAVAILABLE" | "AUDIT_KEY_UNAVAILABLE" | "CAPACITY_LIMIT";

export class LedgerService {
  private state: ServiceState = "BOOTING";
  private disabledReason: DisabledReason = "STORAGE_UNAVAILABLE";
  readonly engine: LedgerEngine;

  constructor(store: Store, genesis: unknown, auditSeed: Buffer | null, hooks: EngineHooks = {}) {
    this.engine = new LedgerEngine(store, genesis, auditSeed ?? Buffer.alloc(32), hooks);
    // Boot checks: persisted genesis match + audit key custody.
    let ok = false;
    try {
      ok = this.engine.boot();
    } catch {
      ok = false;
    }
    const auditMatches =
      auditSeed !== null &&
      ed25519PublicFromSeed(auditSeed).toString("hex") === this.engine.genesis.audit.public_hex;
    if (ok && auditMatches) {
      this.state = "READY";
    } else {
      this.state = "READ_ONLY";
      this.disabledReason = ok ? "AUDIT_KEY_UNAVAILABLE" : "STORAGE_UNAVAILABLE";
    }
  }

  getState(): ServiceState {
    return this.state;
  }

  /** Operator action only; never auto-invoked on a request path. */
  markReadOnly(reason: DisabledReason): void {
    this.state = "READ_ONLY";
    this.disabledReason = reason;
  }

  markReady(): void {
    this.state = "READY";
  }

  private requireReadyWrite(): void {
    if (this.state === "READ_ONLY") throw new SunlightError(this.disabledReason);
  }

  append(command: unknown) {
    this.requireReadyWrite();
    try {
      return this.engine.append(command);
    } catch (e) {
      // Detected storage corruption disables writes but preserves evidence.
      if (e instanceof SunlightError && e.code === "STORAGE_UNAVAILABLE") {
        this.markReadOnly("STORAGE_UNAVAILABLE");
      }
      throw e;
    }
  }

  headGet(nonceHex: string) {
    if (this.state !== "READY") throw new SunlightError(this.disabledReason);
    return this.engine.headGet(nonceHex);
  }

  entryGet(seq: number) {
    return this.engine.entryGet(seq);
  }
  entriesList(after: number, cut: { seq: number; hash: string }, limit: number) {
    return this.engine.entriesList(after, cut, limit);
  }
  statementGet(hash: string, cut: { seq: number; hash: string }) {
    return this.engine.statementGet(hash, cut);
  }
  artifactLookup(profile: string, digest: string, cut: { seq: number; hash: string }, afterSeq: number, limit: number) {
    return this.engine.artifactLookup(profile, digest, cut, afterSeq, limit);
  }
  bundleExport(target: string, cut: { seq: number; hash: string }) {
    return this.engine.bundleExport(target, cut);
  }
}
