/**
 * Ledger persistence (spec §9).  The Store interface is deliberately minimal
 * so the identical engine runs on node:sqlite (self-hosted reference server)
 * and on a Durable Object's SqlStorage (worker/) — one authoritative
 * SQLite-backed store per ledger, keyed by ledger id.
 *
 * meta holds: canonical genesis, current HeadRef, schema_version=1,
 * last_commit_ms (seq-0 admission_time base = genesis.created_at_ms), and the
 * write-disabled reason when the service is READ_ONLY.
 */

import { DatabaseSync } from "node:sqlite";

export type SqlParam = string | number | bigint | null | Uint8Array;

export interface Store {
  query(sql: string, params?: SqlParam[]): Record<string, unknown>[];
  run(sql: string, params?: SqlParam[]): void;
  /** Serialized transaction boundary — the single-writer commit gate. */
  tx<T>(fn: () => T): T;
}

export const SCHEMA_VERSION = 1;

export const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS meta (name TEXT PRIMARY KEY, value BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS entries (
  seq INTEGER PRIMARY KEY,
  entry_id TEXT NOT NULL UNIQUE,
  entry_hash TEXT NOT NULL UNIQUE,
  command_id TEXT NOT NULL UNIQUE,
  canonical_entry BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS commands (
  command_id TEXT PRIMARY KEY,
  command_hash TEXT NOT NULL,
  canonical_result BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS statements (
  statement_hash TEXT PRIMARY KEY,
  statement_id TEXT NOT NULL UNIQUE,
  recorded_seq INTEGER NOT NULL UNIQUE,
  signer_key TEXT NOT NULL,
  subject_kind TEXT NOT NULL,
  artifact_profile TEXT NOT NULL,
  artifact_digest TEXT NOT NULL,
  artifact_bytes INTEGER NOT NULL,
  retract_seq INTEGER
);
CREATE INDEX IF NOT EXISTS artifact_lookup ON statements(artifact_profile, artifact_digest, recorded_seq);
CREATE TABLE IF NOT EXISTS keys (
  key_id TEXT PRIMARY KEY,
  public_hex TEXT NOT NULL UNIQUE,
  added_seq INTEGER NOT NULL,
  retired_seq INTEGER,
  revoked_seq INTEGER
);
CREATE TABLE IF NOT EXISTS descriptor_ids (
  kind TEXT NOT NULL,
  object_id TEXT NOT NULL,
  statement_hash TEXT NOT NULL,
  PRIMARY KEY(kind, object_id)
);
`;

export function applySchema(store: Store): void {
  for (const stmt of SCHEMA_SQL.split(";").map((s) => s.trim()).filter(Boolean)) {
    store.run(stmt);
  }
  store.run(
    "INSERT INTO meta(name,value) VALUES('schema_version',?) ON CONFLICT(name) DO NOTHING",
    [String(SCHEMA_VERSION)],
  );
}

/** node:sqlite-backed Store for the self-hosted reference server. */
export class NodeSqliteStore implements Store {
  private db: DatabaseSync;
  private depth = 0;
  constructor(path: string) {
    this.db = new DatabaseSync(path);
    this.db.exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;");
  }

  private bind(params: SqlParam[]): (string | number | bigint | null | Buffer)[] {
    return params.map((p) => (p instanceof Uint8Array ? Buffer.from(p) : p));
  }

  query(sql: string, params: SqlParam[] = []): Record<string, unknown>[] {
    const st = this.db.prepare(sql);
    return st.all(...this.bind(params)) as Record<string, unknown>[];
  }

  run(sql: string, params: SqlParam[] = []): void {
    const st = this.db.prepare(sql);
    st.run(...this.bind(params));
  }

  tx<T>(fn: () => T): T {
    if (this.depth > 0) return fn(); // nested: join the outer transaction
    this.db.exec("BEGIN IMMEDIATE");
    this.depth++;
    try {
      const out = fn();
      this.db.exec("COMMIT");
      return out;
    } catch (e) {
      try {
        this.db.exec("ROLLBACK");
      } catch { /* already rolled back */ }
      throw e;
    } finally {
      this.depth--;
    }
  }

  close(): void {
    this.db.close();
  }
}
