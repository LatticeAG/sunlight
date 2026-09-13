/**
 * Minimal ambient types for the Cloudflare Worker adapter.
 *
 * These describe only the surface this package uses; deploy with the
 * `nodejs_compat` flag (workerd provides node:crypto + Buffer) and a pinned
 * `@cloudflare/workers-types` package for richer typing in real deployments.
 */

interface SqlStorageCursor {
  toArray(): Record<string, unknown>[];
}

interface SqlStorage {
  exec(query: string, ...params: unknown[]): SqlStorageCursor;
}

interface DurableObjectStorage {
  sql: SqlStorage;
  transactionSync<T>(fn: () => T): T;
}

interface DurableObjectState {
  id: unknown;
  storage: DurableObjectStorage;
  blockConcurrencyWhile<T>(fn: () => Promise<T>): void;
}

interface DurableObjectStub {
  fetch(input: string | Request, init?: RequestInit): Promise<Response>;
}

interface DurableObjectNamespace {
  idFromName(name: string): unknown;
  get(id: unknown): DurableObjectStub;
}

interface SunlightWorkerEnv {
  /** DeploymentConfig as a strict-JSON string (provisioned as a secret). */
  SUNLIGHT_DEPLOYMENT?: string;
  /** Durable Object namespace binding — the authoritative per-ledger store. */
  SUNLIGHT_LEDGERS: DurableObjectNamespace;
  [name: string]: unknown;
}
