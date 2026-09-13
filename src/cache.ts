/**
 * Local cache layout (spec §9):
 *
 *   objects/sha256/<64hex>.json    canonical signed objects/manifests
 *   evidence/sha256/<64hex>.bin    explicitly imported raw evidence
 *   bundles/<64hex>.json           exported bundles
 *   pending/<slq_id>.json          durable commands awaiting a receipt
 *   pins/<sll_id>.json             largest verified SignedHead per ledger
 *   journal.ndjson                 local.* lifecycle records
 *
 * Directories are 0700, files 0600; temp files are fsynced and atomically
 * renamed; content-hash filenames are derived internally.
 */

import { mkdirSync, appendFileSync, existsSync, readdirSync, unlinkSync, chmodSync } from "node:fs";
import { join } from "node:path";
import { SunlightError } from "./errors.js";
import { jcsBytes } from "./encoding/jcs.js";
import { parseStrictJson } from "./encoding/strict-json.js";
import { RAW } from "./crypto/domains.js";
import { parseSignedHead, type LocalJournalRecord, type SignedHead } from "./schema.js";
import { readFileBytesSync, writeFileAtomic } from "./fsutil.js";

export class Cache {
  readonly dir: string;
  constructor(dir: string) {
    this.dir = dir;
  }

  private ensure(): void {
    for (const sub of ["objects/sha256", "evidence/sha256", "bundles", "pending", "pins"]) {
      mkdirSync(join(this.dir, sub), { recursive: true, mode: 0o700 });
    }
    try {
      // Tighten in case umask was permissive.
      chmodSync(this.dir, 0o700);
    } catch { /* best effort */ }
  }

  private hexOf(digest: string): string {
    return RAW(digest).toString("hex");
  }

  storeObject(digest: string, obj: unknown): string {
    this.ensure();
    const p = join(this.dir, "objects/sha256", `${this.hexOf(digest)}.json`);
    if (!existsSync(p)) writeFileAtomic(p, jcsBytes(obj));
    return p;
  }

  loadObject(digest: string): unknown | null {
    const p = join(this.dir, "objects/sha256", `${this.hexOf(digest)}.json`);
    if (!existsSync(p)) return null;
    return parseStrictJson(readFileBytesSync(p));
  }

  storeEvidence(digest: string, raw: Buffer): string {
    this.ensure();
    const p = join(this.dir, "evidence/sha256", `${this.hexOf(digest)}.bin`);
    if (!existsSync(p)) writeFileAtomic(p, raw);
    return p;
  }

  storeBundle(digest: string, bundle: unknown): string {
    this.ensure();
    const p = join(this.dir, "bundles", `${this.hexOf(digest)}.json`);
    if (!existsSync(p)) writeFileAtomic(p, jcsBytes(bundle));
    return p;
  }

  /** Persist a command durably before its first network attempt. */
  storePending(commandId: string, command: unknown): string {
    this.ensure();
    if (!/^slq_[A-Za-z0-9_-]{21}$/.test(commandId)) throw new SunlightError("SCHEMA_INVALID");
    const p = join(this.dir, "pending", `${commandId}.json`);
    if (!existsSync(p)) writeFileAtomic(p, jcsBytes(command));
    return p;
  }

  dropPending(commandId: string): void {
    const p = join(this.dir, "pending", `${commandId}.json`);
    if (existsSync(p)) unlinkSync(p);
  }

  listPending(): string[] {
    const d = join(this.dir, "pending");
    if (!existsSync(d)) return [];
    return readdirSync(d)
      .filter((f) => f.endsWith(".json"))
      .map((f) => f.slice(0, -5));
  }

  loadPending(commandId: string): unknown | null {
    const p = join(this.dir, "pending", `${commandId}.json`);
    if (!existsSync(p)) return null;
    return parseStrictJson(readFileBytesSync(p));
  }

  /** Largest verified head pin per ledger; conflicts quarantine (caller). */
  loadPin(ledger: string): SignedHead | null {
    const p = join(this.dir, "pins", `${ledger}.json`);
    if (!existsSync(p)) return null;
    return parseSignedHead(parseStrictJson(readFileBytesSync(p)));
  }

  storePin(ledger: string, head: SignedHead): void {
    this.ensure();
    if (!/^sll_[A-Za-z0-9_-]{21}$/.test(ledger)) throw new SunlightError("SCHEMA_INVALID");
    writeFileAtomic(join(this.dir, "pins", `${ledger}.json`), jcsBytes(head));
  }

  journal(event: string, command: string | null, statement: string | null, atMs: number): void {
    this.ensure();
    const rec: LocalJournalRecord = {
      v: "sunlight.local/1",
      command,
      statement,
      event,
      at_ms: atMs,
    };
    appendFileSync(join(this.dir, "journal.ndjson"), jcsBytes(rec).toString("utf8") + "\n", { mode: 0o600 });
  }
}
