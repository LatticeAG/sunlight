/**
 * Registry HTTP gateway (spec §6).  Exactly two routes: GET /healthz and
 * POST /v1/rpc.  The gateway validates transport auth, rate limits, and
 * ledger binding, then dispatches to the per-ledger LedgerService; the engine
 * independently verifies every signed command.
 *
 * The handle() core is transport-agnostic so the identical gateway runs on
 * node:http (self-hosted) and inside a Cloudflare Worker (worker/).
 */

import { createServer, type Server } from "node:http";
import { timingSafeEqual } from "node:crypto";
import { jcsBytes } from "./encoding/jcs.js";
import { parseStrictJson } from "./encoding/strict-json.js";
import { SunlightError, httpStatusFor, type ErrorCode } from "./errors.js";
import { isValidId } from "./ids.js";
import { B, RAW } from "./crypto/domains.js";
import {
  parseCommand, parseHeadRef, parseArtifact,
  type HeadRef, type TokenBinding,
} from "./schema.js";
import type { LedgerService } from "./ledger/service.js";

export interface GatewayDeps {
  services: Map<string, LedgerService>;
  tokens: TokenBinding[];
  ratePerMinute: number;   // default 120
  maxInflightPerLedger: number; // default 8
}

export interface HttpResult {
  status: number;
  body: Buffer;
  headers: Record<string, string>;
}

const BODY_CAP = 32 * 1024;
export const BASE_HEADERS: Record<string, string> = {
  "cache-control": "no-store",
  "x-content-type-options": "nosniff",
  "content-type": "application/json",
};

export function httpError(code: ErrorCode, status?: number, retryAfter?: number): HttpResult {
  const headers: Record<string, string> = { ...BASE_HEADERS };
  if (retryAfter !== undefined) headers["retry-after"] = String(retryAfter);
  return {
    status: status ?? httpStatusFor(code),
    headers,
    body: jcsBytes({ error: { code, retryable: code === "RATE_LIMIT" || status === 503, head: null } }),
  };
}

export function rpcOk(id: string, result: unknown): HttpResult {
  return {
    status: 200,
    headers: { ...BASE_HEADERS },
    body: jcsBytes({ v: "sunlight.rpc/1", id, ok: true, result }),
  };
}

export function rpcErr(id: string, e: SunlightError, retryAfter?: number): HttpResult {
  const code = e.code;
  // Only HEAD_CONFLICT and CUT_MISMATCH may carry a head.
  const head = code === "HEAD_CONFLICT" || code === "CUT_MISMATCH" ? e.body.head : null;
  const headers: Record<string, string> = { ...BASE_HEADERS };
  const status = httpStatusFor(code);
  if (status === 429) headers["retry-after"] = String(retryAfter ?? 1);
  if (status === 503) headers["retry-after"] = String(retryAfter ?? 5);
  return {
    status,
    headers,
    body: jcsBytes({ v: "sunlight.rpc/1", id, ok: false, error: { code, retryable: e.body.retryable, head } }),
  };
}

/** Constant-time token lookup after hashing (spec §8). */
export function authenticate(tokens: TokenBinding[], presented: string): TokenBinding | null {
  const raw = Buffer.from(presented, "base64url");
  if (raw.length !== 32) return null;
  const h = Buffer.from(RAW(B(raw)));
  let found: TokenBinding | null = null;
  for (const t of tokens) {
    const th = Buffer.from(RAW(t.token_sha256));
    if (timingSafeEqual(h, th)) found = t;
  }
  return found;
}

interface Bucket {
  allowance: number;
  lastMs: number;
}

export class RegistryGateway {
  private buckets = new Map<string, Bucket>();
  private inflight = new Map<string, number>();
  private readonly burst = 20;

  constructor(private readonly deps: GatewayDeps) {}

  /** Rate-limit a token; returns retry-after seconds or null. */
  private throttle(tokenHash: string, ledger: string): number | null {
    const now = Date.now();
    const rate = this.deps.ratePerMinute;
    let b = this.buckets.get(tokenHash);
    if (b === undefined) {
      b = { allowance: this.burst, lastMs: now };
      this.buckets.set(tokenHash, b);
    }
    const refill = ((now - b.lastMs) / 60000) * rate;
    b.allowance = Math.min(this.burst, b.allowance + refill);
    b.lastMs = now;
    const inFlight = this.inflight.get(ledger) ?? 0;
    if (b.allowance < 1 || inFlight >= this.deps.maxInflightPerLedger) {
      return Math.max(1, Math.ceil(60000 / rate));
    }
    b.allowance -= 1;
    return null;
  }

  private begin(ledger: string): void {
    this.inflight.set(ledger, (this.inflight.get(ledger) ?? 0) + 1);
  }
  private end(ledger: string): void {
    this.inflight.set(ledger, Math.max(0, (this.inflight.get(ledger) ?? 1) - 1));
  }

  /**
   * Transport-agnostic request handler.
   * `headers` keys must be lowercase.  Returns status + canonical JSON body.
   */
  async handle(
    method: string,
    path: string,
    headers: Record<string, string | string[] | undefined>,
    body: Buffer,
  ): Promise<HttpResult> {
    const h = (n: string): string | undefined => {
      const v = headers[n];
      return Array.isArray(v) ? v[0] : v;
    };
    if (method === "GET" && path === "/healthz") {
      return { status: 200, headers: { ...BASE_HEADERS }, body: jcsBytes({ status: "ok", protocol: "sunlight/1" }) };
    }
    if (path !== "/v1/rpc" || method !== "POST") {
      return httpError("NOT_FOUND", 404);
    }
    if (h("content-encoding") !== undefined) return httpError("CONTENT_ENCODING", 415);
    const ct = h("content-type");
    if (ct === undefined || !ct.toLowerCase().startsWith("application/json")) {
      return httpError("CONTENT_TYPE", 415);
    }
    if (body.length > BODY_CAP) return httpError("BODY_LIMIT", 413);

    const auth = h("authorization");
    if (auth === undefined || !auth.startsWith("Bearer ")) {
      return httpError("UNAUTHENTICATED", 401);
    }
    const binding = authenticate(this.deps.tokens, auth.slice(7));
    if (binding === null) return httpError("UNAUTHENTICATED", 401);

    // Parse the RPC envelope; failures before a valid request id use the
    // HTTP-layer error shape.
    let req: Record<string, unknown>;
    try {
      const v = parseStrictJson(body);
      if (typeof v !== "object" || v === null || Array.isArray(v)) throw new Error("not object");
      req = v as Record<string, unknown>;
    } catch {
      return httpError("BAD_REQUEST", 400);
    }
    const id = req.id;
    if (req.v !== "sunlight.rpc/1" || typeof req.method !== "string" || !isValidId(id, "slq")) {
      return httpError("BAD_REQUEST", 400);
    }
    const method3 = req.method;
    const known = ["head.get", "append", "entry.get", "entries.list", "statement.get", "artifact.lookup", "bundle.export"];
    if (!known.includes(method3)) {
      return rpcErr(id, new SunlightError("METHOD_UNKNOWN"));
    }
    const params = req.params;
    if (typeof params !== "object" || params === null || Array.isArray(params)) {
      return rpcErr(id, new SunlightError("SCHEMA_INVALID"));
    }
    const p = params as Record<string, unknown>;

    // Ledger binding is evaluated before any ledger lookup; inaccessible
    // ledgers uniformly return NOT_FOUND without disclosing existence.
    if (typeof p.ledger !== "string" || p.ledger !== binding.ledger) {
      return rpcErr(id, new SunlightError("NOT_FOUND"));
    }
    if (method3 === "append" && binding.role !== "write") {
      return rpcErr(id, new SunlightError("FORBIDDEN"));
    }

    const retry = this.throttle(binding.token_sha256, binding.ledger);
    if (retry !== null) return rpcErr(id, new SunlightError("RATE_LIMIT"), retry);

    this.begin(binding.ledger);
    try {
      const service = this.deps.services.get(binding.ledger);
      if (service === undefined) return rpcErr(id, new SunlightError("NOT_FOUND"));
      const result = await dispatchRpc(service, method3, p, id);
      return rpcOk(id, result);
    } catch (e) {
      if (e instanceof SunlightError) return rpcErr(id, e);
      return rpcErr(id, new SunlightError("STORAGE_UNAVAILABLE"));
    } finally {
      this.end(binding.ledger);
    }
  }
}

/**
 * RPC method dispatch shared by the node gateway and the Durable Object
 * (worker/do.ts).  Authorization has already been decided by the caller;
 * this layer validates params and invokes the service.
 */
export function dispatchRpc(
  service: LedgerService,
  method: string,
  p: Record<string, unknown>,
  requestId: string,
): unknown {
    const needInt = (v: unknown, name: string): number => {
      if (typeof v !== "number" || !Number.isSafeInteger(v) || v < 0) {
        throw new SunlightError("SCHEMA_INVALID");
      }
      return v;
    };
    const needStr = (v: unknown, name: string): string => {
      if (typeof v !== "string") throw new SunlightError("SCHEMA_INVALID");
      return v;
    };
    const needCut = (v: unknown): HeadRef => parseHeadRef(v);
    const needLimit = (v: unknown): number => {
      const n = needInt(v, "limit");
      if (n < 1 || n > 100) throw new SunlightError("SCHEMA_INVALID");
      return n;
    };

    switch (method) {
      case "head.get": {
        const nonce = needStr(p.nonce_hex, "nonce_hex");
        if (!/^[0-9a-f]{64}$/.test(nonce)) throw new SunlightError("SCHEMA_INVALID");
        return service.headGet(nonce);
      }
      case "append": {
        const command = parseCommand(p.command);
        if (command.body.id !== requestId) throw new SunlightError("ID_MISMATCH");
        return service.append(command);
      }
      case "entry.get": {
        const seq = needInt(p.seq, "seq");
        if (seq < 1) throw new SunlightError("SCHEMA_INVALID");
        return service.entryGet(seq);
      }
      case "entries.list": {
        return service.entriesList(needInt(p.after, "after"), needCut(p.cut), needLimit(p.limit));
      }
      case "statement.get": {
        const digest = needStr(p.statement, "statement");
        if (!/^sha256:[0-9a-f]{64}$/.test(digest)) throw new SunlightError("SCHEMA_INVALID");
        return service.statementGet(digest, needCut(p.cut));
      }
      case "artifact.lookup": {
        const art = { profile: p.profile, digest: p.digest, bytes: 0 };
        parseArtifact({ profile: p.profile, digest: p.digest, bytes: 0 });
        return service.artifactLookup(
          (art as { profile: string }).profile,
          needStr(p.digest, "digest"),
          needCut(p.cut),
          needInt(p.after_seq, "after_seq"),
          needLimit(p.limit),
        );
      }
      case "bundle.export": {
        const target = needStr(p.target, "target");
        if (!/^sha256:[0-9a-f]{64}$/.test(target)) throw new SunlightError("SCHEMA_INVALID");
        return service.bundleExport(target, needCut(p.cut));
      }
      default:
        throw new SunlightError("METHOD_UNKNOWN");
    }
}

/** node:http adapter for the self-hosted reference server. */
export function serveHttp(gateway: RegistryGateway, port: number, host = "127.0.0.1"): Promise<Server> {
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    let total = 0;
    req.on("data", (c: Buffer) => {
      total += c.length;
      if (total <= BODY_CAP + 1) chunks.push(c);
    });
    req.on("end", async () => {
      const headers: Record<string, string | string[] | undefined> = {};
      for (const [k, v] of Object.entries(req.headers)) headers[k.toLowerCase()] = v;
      const out = await gateway.handle(req.method ?? "", req.url ?? "", headers, Buffer.concat(chunks));
      res.writeHead(out.status, out.headers);
      res.end(out.body);
    });
    req.on("error", () => {
      res.writeHead(500);
      res.end();
    });
  });
  return new Promise((resolveListen) => {
    server.listen(port, host, () => resolveListen(server));
  });
}
