/**
 * Durable Object SqlStorage-backed Store — the same Store interface the
 * node:sqlite reference store implements, so the identical LedgerEngine
 * runs in both runtimes (spec §9: one authoritative SQLite-backed store per
 * ledger, keyed by ledger id).
 */

import type { SqlParam, Store } from "../src/ledger/store.js";

export class SqlStorageStore implements Store {
  private depth = 0;
  constructor(private readonly storage: DurableObjectStorage) {}

  private bind(params: SqlParam[]): unknown[] {
    return params.map((p) =>
      p instanceof Uint8Array ? p.slice().buffer : p,
    );
  }

  query(sql: string, params: SqlParam[] = []): Record<string, unknown>[] {
    return this.storage.sql.exec(sql, ...this.bind(params)).toArray();
  }

  run(sql: string, params: SqlParam[] = []): void {
    this.storage.sql.exec(sql, ...this.bind(params)).toArray();
  }

  /**
   * Serialized transaction boundary.  Durable Objects are single-threaded
   * and transactionSync is the atomic commit gate; nested calls join the
   * outer transaction.
   */
  tx<T>(fn: () => T): T {
    if (this.depth > 0) return fn();
    this.depth++;
    try {
      return this.storage.transactionSync(fn);
    } finally {
      this.depth--;
    }
  }
}
