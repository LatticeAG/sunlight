/**
 * Sunlight registry Worker (spec §6, §8-§9).
 *
 * The Worker validates HTTP/auth/rate limits and routes to LedgerDO — the
 * Durable Object owning ordering, admission replay, reads, and atomic
 * append.  Exactly two routes exist: GET /healthz and POST /v1/rpc.
 *
 * Configuration (provisioned as secrets, never in source control):
 *   SUNLIGHT_DEPLOYMENT      strict-JSON DeploymentConfig
 *   <auth_secret_binding>    strict-JSON TokenBinding array (REGISTRY_TOKENS)
 *   <audit_secret_binding>   64-hex audit Ed25519 seed per ledger
 */

import { parseStrictJson, parseStrictJsonString } from "../src/encoding/strict-json.js";
import { jcsBytes } from "../src/encoding/jcs.js";
import { SunlightError } from "../src/errors.js";
import { isValidId } from "../src/ids.js";
import {
  parseDeploymentConfig, parseTokenBinding,
  type DeploymentConfig, type TokenBinding,
} from "../src/schema.js";
import {
  authenticate, httpError, rpcErr, type HttpResult,
} from "../src/server.js";

const BODY_CAP = 32 * 1024;

interface Deployment {
  cfg: DeploymentConfig;
  tokens: TokenBinding[];
}

function loadDeployment(env: SunlightWorkerEnv): Deployment {
  const raw = env.SUNLIGHT_DEPLOYMENT;
  if (typeof raw !== "string" || raw === "") throw new SunlightError("STORAGE_UNAVAILABLE");
  const dep = parseDeploymentConfig(parseStrictJsonString(raw));
  const tokensJson = env[dep.auth_secret_binding];
  if (typeof tokensJson !== "string" || tokensJson === "") {
    throw new SunlightError("STORAGE_UNAVAILABLE");
  }
  const parsed = parseStrictJsonString(tokensJson);
  if (!Array.isArray(parsed) || parsed.length < 1 || parsed.length > 256) {
    throw new SunlightError("STORAGE_UNAVAILABLE");
  }
  const tokens = parsed.map((t) => parseTokenBinding(t));
  if (new Set(tokens.map((t) => t.token_sha256)).size !== tokens.length) {
    throw new SunlightError("STORAGE_UNAVAILABLE");
  }
  const ledgerIds = new Set(dep.ledgers.map((l) => l.genesis.ledger));
  for (const t of tokens) {
    if (!ledgerIds.has(t.ledger)) throw new SunlightError("STORAGE_UNAVAILABLE");
  }
  return { cfg: dep, tokens };
}

/** Per-isolate token-bucket rate limiting (spec §8 rate_per_token_per_minute). */
const buckets = new Map<string, { allowance: number; lastMs: number }>();
const BURST = 20;

function throttle(tokenHash: string, ratePerMinute: number): number | null {
  const now = Date.now();
  let b = buckets.get(tokenHash);
  if (b === undefined) {
    b = { allowance: BURST, lastMs: now };
    buckets.set(tokenHash, b);
  }
  b.allowance = Math.min(BURST, b.allowance + ((now - b.lastMs) / 60000) * ratePerMinute);
  b.lastMs = now;
  if (b.allowance < 1) return Math.max(1, Math.ceil(60000 / ratePerMinute));
  b.allowance -= 1;
  return null;
}

function respond(r: HttpResult): Response {
  return new Response(new Uint8Array(r.body), {
    status: r.status,
    headers: r.headers,
  });
}

export default {
  async fetch(request: Request, env: SunlightWorkerEnv): Promise<Response> {
    const url = new URL(request.url);
    if (request.method === "GET" && url.pathname === "/healthz") {
      return respond({
        status: 200,
        headers: { "content-type": "application/json" },
        body: jcsBytes({ status: "ok", protocol: "sunlight/1" }),
      });
    }
    if (url.pathname !== "/v1/rpc" || request.method !== "POST") {
      return respond(httpError("NOT_FOUND", 404));
    }
    if (request.headers.get("content-encoding") !== null) {
      return respond(httpError("CONTENT_ENCODING", 415));
    }
    const ct = request.headers.get("content-type");
    if (ct === null || !ct.toLowerCase().startsWith("application/json")) {
      return respond(httpError("CONTENT_TYPE", 415));
    }

    let dep: Deployment;
    try {
      dep = loadDeployment(env);
    } catch {
      return respond(httpError("STORAGE_UNAVAILABLE", 503));
    }

    const auth = request.headers.get("authorization");
    if (auth === null || !auth.startsWith("Bearer ")) {
      return respond(httpError("UNAUTHENTICATED", 401));
    }
    const binding = authenticate(dep.tokens, auth.slice(7));
    if (binding === null) return respond(httpError("UNAUTHENTICATED", 401));

    const raw = new Uint8Array(await request.arrayBuffer());
    if (raw.length > BODY_CAP) return respond(httpError("BODY_LIMIT", 413));

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
    const known = [
      "head.get", "append", "entry.get", "entries.list",
      "statement.get", "artifact.lookup", "bundle.export",
    ];
    if (!known.includes(req.method)) {
      return respond(rpcErr(id, new SunlightError("METHOD_UNKNOWN")));
    }
    const params = req.params;
    if (typeof params !== "object" || params === null || Array.isArray(params)) {
      return respond(rpcErr(id, new SunlightError("SCHEMA_INVALID")));
    }
    const p = params as Record<string, unknown>;
    if (typeof p.ledger !== "string" || p.ledger !== binding.ledger) {
      return respond(rpcErr(id, new SunlightError("NOT_FOUND")));
    }
    if (req.method === "append" && binding.role !== "write") {
      return respond(rpcErr(id, new SunlightError("FORBIDDEN")));
    }
    const retry = throttle(binding.token_sha256, dep.cfg.rate_per_token_per_minute);
    if (retry !== null) return respond(rpcErr(id, new SunlightError("RATE_LIMIT"), retry));

    // Route to the one authoritative DO for this ledger; client-supplied DO
    // IDs are never accepted — only the ledger name maps through idFromName.
    const stubId = env.SUNLIGHT_LEDGERS.idFromName(binding.ledger);
    const stub = env.SUNLIGHT_LEDGERS.get(stubId);
    return stub.fetch("https://sunlight.internal/v1/rpc", {
      method: "POST",
      body: raw,
    });
  },
};

export { LedgerDO } from "./do.js";
