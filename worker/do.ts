/**
 * LedgerDO — one authoritative SQLite-backed Durable Object per ledger
 * (spec §8-§9).  Selected by `idFromName(ledger)`; the Worker has already
 * authenticated and bound the request to this ledger.  The DO owns
 * ordering, admission replay, reads, and the atomic append boundary.
 *
 * Boot: the static deployment genesis must match any persisted genesis and
 * the audit secret's derived public key; drift or a missing audit secret
 * leaves the ledger READ_ONLY (spec §8).
 */

import { parseStrictJson, parseStrictJsonString } from "../src/encoding/strict-json.js";
import { jcsBytes } from "../src/encoding/jcs.js";
import { SunlightError } from "../src/errors.js";
import { isValidId } from "../src/ids.js";
import { parseDeploymentConfig } from "../src/schema.js";
import { applySchema } from "../src/ledger/store.js";
import { LedgerService } from "../src/ledger/service.js";
import { dispatchRpc, rpcOk, rpcErr, httpError } from "../src/server.js";
import { SqlStorageStore } from "./store-sql.js";

export class LedgerDO {
  private ledger: string | null = null;
  private service: LedgerService | null = null;

  constructor(
    private readonly ctx: DurableObjectState,
    private readonly env: SunlightWorkerEnv,
  ) {}

  private serviceFor(ledger: string): LedgerService {
    if (this.service !== null && this.ledger === ledger) return this.service;
    if (this.service !== null) {
      // idFromName pins one ledger per DO; a mismatched ledger can only
      // arrive through a misrouted caller — refuse it.
      throw new SunlightError("NOT_FOUND");
    }
    const depJson = this.env.SUNLIGHT_DEPLOYMENT;
    if (typeof depJson !== "string" || depJson === "") {
      throw new SunlightError("STORAGE_UNAVAILABLE");
    }
    const dep = parseDeploymentConfig(parseStrictJsonString(depJson));
    const cfg = dep.ledgers.find((l) => l.genesis.ledger === ledger);
    if (cfg === undefined) throw new SunlightError("NOT_FOUND");

    const seedHex = this.env[cfg.audit_secret_binding];
    const auditSeed =
      typeof seedHex === "string" && /^[0-9a-f]{64}$/.test(seedHex)
        ? Buffer.from(seedHex, "hex")
        : null; // malformed/missing audit secret → READ_ONLY

    const store = new SqlStorageStore(this.ctx.storage);
    applySchema(store);
    this.service = new LedgerService(store, cfg.genesis, auditSeed);
    this.ledger = ledger;
    return this.service;
  }

  async fetch(request: Request): Promise<Response> {
    const respond = (r: { status: number; body: Buffer; headers: Record<string, string> }) =>
      new Response(new Uint8Array(r.body), {
        status: r.status,
        headers: r.headers,
      });
    let requestId: string | null = null;
    try {
      if (request.method !== "POST") return respond(httpError("NOT_FOUND", 404));
      const raw = new Uint8Array(await request.arrayBuffer());
      let req: Record<string, unknown>;
      try {
        const v = parseStrictJson(Buffer.from(raw));
        if (typeof v !== "object" || v === null || Array.isArray(v)) throw new Error("not object");
        req = v as Record<string, unknown>;
      } catch {
        return respond(httpError("BAD_REQUEST", 400));
      }
      const id = req.id;
      if (req.v !== "sunlight.rpc/1" || typeof req.method !== "string" || !isValidId(id, "slq")) {
        return respond(httpError("BAD_REQUEST", 400));
      }
      requestId = id;
      const params = req.params;
      if (typeof params !== "object" || params === null || Array.isArray(params)) {
        return respond(rpcErr(id, new SunlightError("SCHEMA_INVALID")));
      }
      const p = params as Record<string, unknown>;
      if (typeof p.ledger !== "string" || (this.ledger !== null && p.ledger !== this.ledger)) {
        return respond(rpcErr(id, new SunlightError("NOT_FOUND")));
      }
      const service = this.serviceFor(p.ledger);
      const result = dispatchRpc(service, req.method, p, id);
      return respond(rpcOk(id, result));
    } catch (e) {
      if (e instanceof SunlightError) {
        const id = requestId ?? "slq_000000000000000000000";
        return respond(rpcErr(id, e));
      }
      return respond(httpError("STORAGE_UNAVAILABLE", 503));
    }
  }
}
