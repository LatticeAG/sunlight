/**
 * TransportApi — the only network surface (spec §6, §7).  verify() never
 * enters it.  POSTs canonical JSON to the configured registry origin only;
 * no redirects are followed and no URLs found in artifacts are resolved.
 */

import { jcsBytes } from "./encoding/jcs.js";
import { parseStrictJson } from "./encoding/strict-json.js";
import { SunlightError, httpStatusFor, type ErrorCode } from "./errors.js";
import { newId } from "./ids.js";
import { RAW } from "./crypto/domains.js";
import type { HeadRef } from "./schema.js";

export interface TransportOptions {
  origin: string;
  bearer: string;
  connectTimeoutMs: number;
  readTimeoutMs: number;
  requestId?: () => string;
}

const BODY_CAP = 32 * 1024;
const KNOWN = new Set([
  "BAD_REQUEST", "SCHEMA_INVALID", "VERSION_UNSUPPORTED", "METHOD_UNKNOWN",
  "ID_MISMATCH", "UNAUTHENTICATED", "FORBIDDEN", "KEY_INACTIVE",
  "ROLE_MISMATCH", "NOT_FOUND", "HEAD_CONFLICT", "CUT_MISMATCH",
  "IDEMPOTENCY_CONFLICT", "STATEMENT_EXISTS", "ID_CONFLICT", "STATE_CONFLICT",
  "BODY_LIMIT", "BUNDLE_LIMIT", "GRAPH_LIMIT", "CONTENT_TYPE",
  "CONTENT_ENCODING", "HASH_MISMATCH", "SIGNATURE_INVALID", "PARENT_MISSING",
  "PARENT_MISMATCH", "PARENT_INACTIVE", "DESCRIPTOR_MISMATCH",
  "STATEMENT_INVALID", "COMMAND_EXPIRED", "CLOCK_AHEAD", "RATE_LIMIT",
  "STORAGE_UNAVAILABLE", "AUDIT_KEY_UNAVAILABLE", "CAPACITY_LIMIT",
]);

export class RegistryTransport {
  constructor(private readonly opts: TransportOptions) {}

  async rpc(method: string, params: unknown, id?: string): Promise<unknown> {
    const requestId = id ?? this.opts.requestId?.() ?? newId("slq");
    const req = { v: "sunlight.rpc/1", id: requestId, method, params };
    const body = jcsBytes(req);
    if (body.length > BODY_CAP) throw new SunlightError("BODY_LIMIT");

    const url = this.opts.origin.replace(/\/$/, "") + "/v1/rpc";
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), this.opts.readTimeoutMs);
    let res: Response;
    try {
      res = await fetch(url, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${this.opts.bearer}`,
        },
        body,
        redirect: "error",
        signal: ctl.signal,
      });
    } catch (e) {
      throw new SunlightError("NETWORK_ERROR", null, e);
    } finally {
      clearTimeout(timer);
    }

    const raw = Buffer.from(await res.arrayBuffer());
    let parsed: unknown;
    try {
      parsed = parseStrictJson(raw);
    } catch {
      throw new SunlightError("NETWORK_ERROR", null, new Error("unparseable response"));
    }
    if (typeof parsed !== "object" || parsed === null) {
      throw new SunlightError("NETWORK_ERROR", null, new Error("non-object response"));
    }
    const obj = parsed as Record<string, unknown>;

    // HTTP-layer error shape: {"error":{code,retryable,head}}
    if ("error" in obj && obj.v === undefined) {
      const err = obj.error as Record<string, unknown>;
      throw new SunlightError(normalizeCode(err?.code), readHead(err));
    }
    // RpcResponse
    if (obj.ok === true) return obj.result;
    if (obj.ok === false) {
      const err = obj.error as Record<string, unknown>;
      throw new SunlightError(normalizeCode(err?.code), readHead(err));
    }
    throw new SunlightError("NETWORK_ERROR", null, new Error("malformed response"));
  }
}

function normalizeCode(c: unknown): ErrorCode {
  return typeof c === "string" && KNOWN.has(c) ? (c as ErrorCode) : "NETWORK_ERROR";
}

function readHead(err: unknown): HeadRef | null {
  const h = (err as { head?: unknown })?.head;
  if (
    typeof h === "object" && h !== null &&
    typeof (h as { seq?: unknown }).seq === "number" &&
    typeof (h as { hash?: unknown }).hash === "string"
  ) {
    return h as HeadRef;
  }
  return null;
}
