/**
 * Protocol error codes, HTTP status mapping, retryability, and CLI exit
 * mapping (spec §6.1, §7).  Codes are a closed set: arbitrary exception
 * messages never become wire codes.
 */

export const ERROR_CODES = [
  // Registry / transport codes (§6.1)
  "BAD_REQUEST", "SCHEMA_INVALID", "VERSION_UNSUPPORTED", "METHOD_UNKNOWN",
  "ID_MISMATCH", "UNAUTHENTICATED", "FORBIDDEN", "KEY_INACTIVE",
  "ROLE_MISMATCH", "NOT_FOUND", "HEAD_CONFLICT", "CUT_MISMATCH",
  "IDEMPOTENCY_CONFLICT", "STATEMENT_EXISTS", "ID_CONFLICT", "STATE_CONFLICT",
  "BODY_LIMIT", "BUNDLE_LIMIT", "GRAPH_LIMIT", "CONTENT_TYPE",
  "CONTENT_ENCODING", "HASH_MISMATCH", "SIGNATURE_INVALID", "PARENT_MISSING",
  "PARENT_MISMATCH", "PARENT_INACTIVE", "DESCRIPTOR_MISMATCH",
  "STATEMENT_INVALID", "COMMAND_EXPIRED", "CLOCK_AHEAD", "RATE_LIMIT",
  "STORAGE_UNAVAILABLE", "AUDIT_KEY_UNAVAILABLE", "CAPACITY_LIMIT",
  // Verification-only reasons usable as failure codes
  "UNTRUSTED_GENESIS", "CHAIN_MISMATCH", "AUDIT_BINDING_MISMATCH",
  "MINIMUM_HEAD_MISMATCH", "RETRACTED_ANCESTOR", "REVOKED_ANCESTOR",
  "DENIED_KEY", "MISSING_TRAINING", "ARTIFACT_MISMATCH", "STALE_HEAD",
  "TARGET_MISSING",
  // Local-only codes
  "USAGE", "CONFIG_INVALID", "KEY_PERMISSIONS", "KEY_ERROR", "NETWORK_ERROR",
  "OUTPUT_EXISTS", "ARTIFACT_CHANGED", "IO_ERROR", "INTERRUPTED",
] as const;

export type ErrorCode = (typeof ERROR_CODES)[number];

export interface ErrorBody {
  code: string;
  retryable: boolean;
  head: { seq: number; hash: string } | null;
}

const HTTP_STATUS: Record<ErrorCode, number> = {
  BAD_REQUEST: 400,
  SCHEMA_INVALID: 400,
  VERSION_UNSUPPORTED: 400,
  METHOD_UNKNOWN: 400,
  ID_MISMATCH: 400,
  UNAUTHENTICATED: 401,
  FORBIDDEN: 403,
  KEY_INACTIVE: 403,
  ROLE_MISMATCH: 403,
  NOT_FOUND: 404,
  HEAD_CONFLICT: 409,
  CUT_MISMATCH: 409,
  IDEMPOTENCY_CONFLICT: 409,
  STATEMENT_EXISTS: 409,
  ID_CONFLICT: 409,
  STATE_CONFLICT: 409,
  BODY_LIMIT: 413,
  BUNDLE_LIMIT: 413,
  GRAPH_LIMIT: 413,
  CONTENT_TYPE: 415,
  CONTENT_ENCODING: 415,
  HASH_MISMATCH: 422,
  SIGNATURE_INVALID: 422,
  PARENT_MISSING: 422,
  PARENT_MISMATCH: 422,
  PARENT_INACTIVE: 422,
  DESCRIPTOR_MISMATCH: 422,
  STATEMENT_INVALID: 422,
  COMMAND_EXPIRED: 422,
  CLOCK_AHEAD: 422,
  RATE_LIMIT: 429,
  STORAGE_UNAVAILABLE: 503,
  AUDIT_KEY_UNAVAILABLE: 503,
  CAPACITY_LIMIT: 503,
  // Verification/local codes are not emitted by the registry; map anyway.
  UNTRUSTED_GENESIS: 400,
  CHAIN_MISMATCH: 422,
  AUDIT_BINDING_MISMATCH: 422,
  MINIMUM_HEAD_MISMATCH: 422,
  RETRACTED_ANCESTOR: 422,
  REVOKED_ANCESTOR: 422,
  DENIED_KEY: 422,
  MISSING_TRAINING: 422,
  ARTIFACT_MISMATCH: 422,
  STALE_HEAD: 422,
  TARGET_MISSING: 404,
  USAGE: 400,
  CONFIG_INVALID: 400,
  KEY_PERMISSIONS: 403,
  KEY_ERROR: 403,
  NETWORK_ERROR: 503,
  OUTPUT_EXISTS: 409,
  ARTIFACT_CHANGED: 422,
  IO_ERROR: 500,
  INTERRUPTED: 500,
};

const RETRYABLE = new Set<ErrorCode>([
  "RATE_LIMIT", "STORAGE_UNAVAILABLE", "AUDIT_KEY_UNAVAILABLE",
  "CAPACITY_LIMIT", "NETWORK_ERROR",
]);

export function httpStatusFor(code: ErrorCode): number {
  return HTTP_STATUS[code];
}

export function isRetryableCode(code: ErrorCode): boolean {
  return RETRYABLE.has(code);
}

export class SunlightError extends Error {
  readonly body: ErrorBody;

  constructor(code: ErrorCode, head: { seq: number; hash: string } | null = null, cause?: unknown) {
    super(code);
    this.name = "SunlightError";
    this.body = { code, retryable: isRetryableCode(code), head };
    if (cause !== undefined) this.cause = cause;
  }

  get code(): ErrorCode {
    return this.body.code as ErrorCode;
  }
}

/** Map a thrown value to a SunlightError without leaking upstream text. */
export function toSunlightError(e: unknown, fallback: ErrorCode = "IO_ERROR"): SunlightError {
  if (e instanceof SunlightError) return e;
  return new SunlightError(fallback);
}

export function errorBody(e: unknown): ErrorBody {
  if (e instanceof SunlightError) return e.body;
  return { code: "IO_ERROR", retryable: false, head: null };
}

/**
 * CLI exit-code mapping (spec §7 table): schema/usage 2, evidence-invalid 3,
 * untrusted/insufficient evidence 4, authz/key 5, retryable network 6,
 * state/idempotency conflict 7, resource/IO 8, interrupt 130.
 */
export function cliExitFor(code: string): number {
  switch (code) {
    case "USAGE":
    case "CONFIG_INVALID":
    case "BAD_REQUEST":
    case "SCHEMA_INVALID":
    case "VERSION_UNSUPPORTED":
    case "STATEMENT_INVALID":
    case "CONTENT_TYPE":
    case "CONTENT_ENCODING":
    case "METHOD_UNKNOWN":
    case "ID_MISMATCH":
    case "CLOCK_AHEAD":
      return 2;
    case "HASH_MISMATCH":
    case "SIGNATURE_INVALID":
    case "PARENT_MISSING":
    case "PARENT_MISMATCH":
    case "PARENT_INACTIVE":
    case "DESCRIPTOR_MISMATCH":
    case "CHAIN_MISMATCH":
    case "AUDIT_BINDING_MISMATCH":
    case "ARTIFACT_MISMATCH":
      return 3;
    case "NOT_FOUND":
    case "TARGET_MISSING":
    case "UNTRUSTED_GENESIS":
    case "MINIMUM_HEAD_MISMATCH":
    case "RETRACTED_ANCESTOR":
    case "REVOKED_ANCESTOR":
    case "DENIED_KEY":
    case "MISSING_TRAINING":
    case "STALE_HEAD":
      return 4;
    case "UNAUTHENTICATED":
    case "FORBIDDEN":
    case "ROLE_MISMATCH":
    case "KEY_INACTIVE":
    case "KEY_PERMISSIONS":
    case "KEY_ERROR":
      return 5;
    case "RATE_LIMIT":
    case "STORAGE_UNAVAILABLE":
    case "AUDIT_KEY_UNAVAILABLE":
    case "CAPACITY_LIMIT":
    case "NETWORK_ERROR":
      return 6;
    case "HEAD_CONFLICT":
    case "CUT_MISMATCH":
    case "IDEMPOTENCY_CONFLICT":
    case "ID_CONFLICT":
    case "STATEMENT_EXISTS":
    case "STATE_CONFLICT":
    case "COMMAND_EXPIRED":
      return 7;
    case "BODY_LIMIT":
    case "BUNDLE_LIMIT":
    case "GRAPH_LIMIT":
    case "OUTPUT_EXISTS":
    case "ARTIFACT_CHANGED":
    case "IO_ERROR":
      return 8;
    case "INTERRUPTED":
      return 130;
    default:
      return 1;
  }
}
