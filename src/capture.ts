/**
 * Cooperative creation-hook capture (spec §4.2, §5).
 *
 * State machine:
 *   NEW → STAGING → FINALIZED → HASHED → SIGNED → PUBLISHED
 *   NEW/STAGING/FINALIZED/HASHED → FAILED        (local.CaptureFailed)
 *   SIGNED → FAILED                             (local.PublishFailed)
 *   SIGNED → PUBLICATION_UNKNOWN → PUBLISHED|FAILED
 *   FAILED → STAGING only via an explicit new capture() call.
 *
 * The wrapper returns the immutable published path and the signed statement
 * together; sign precedes exposing the artifact through the publication path.
 * `recorded` is always false here: registry acknowledgement is a separate
 * state, never a fabricated timestamp.
 */

import {
  mkdirSync, lstatSync, renameSync, openSync, closeSync, writeSync,
  fsyncSync, readSync, statSync, rmSync,
} from "node:fs";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { SunlightError } from "./errors.js";
import { jcsBytes } from "./encoding/jcs.js";
import { parseStrictJson } from "./encoding/strict-json.js";
import { B } from "./crypto/domains.js";
import { enumerateTree, hashFileBytes, manifestArtifact } from "./artifact.js";
import {
  parseStatementBody, parseTreeManifest,
  type Artifact, type ArtifactProfile, type Statement, type StatementBody,
} from "./schema.js";
import { signStatement, type Signer } from "./objects.js";

export type CaptureState =
  | "NEW" | "STAGING" | "FINALIZED" | "HASHED" | "SIGNED"
  | "PUBLISHED" | "FAILED" | "PUBLICATION_UNKNOWN";

export type Journal = (event: string, detail?: Record<string, unknown>) => void;

export interface CaptureTemplate {
  v: "sunlight.statement/1";
  id: string;
  ledger: string;
  signer: string;
  claimed_at_ms: number;
  kind: "dataset" | "model" | "evidence";
  parents: StatementBody["parents"];
  details: StatementBody["details"];
  evidence: StatementBody["evidence"];
}

export interface CaptureRequest {
  staging_parent: string;
  publish_path: string;
  profile: ArtifactProfile;
  template: CaptureTemplate;
}

export interface CaptureResult {
  published_path: string;
  statement: Statement;
  recorded: false;
}

const STAGED_NAME = "staged";

function writeFileSyncExclusive(path: string, data: Buffer): void {
  const fd = openSync(path, "wx", 0o600);
  try {
    writeSync(fd, data);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

function readAll(path: string): Buffer {
  const st = statSync(path);
  const fd = openSync(path, "r");
  try {
    const b = Buffer.allocUnsafe(st.size);
    let off = 0;
    while (off < st.size) {
      const n = readSync(fd, b, off, st.size - off, null);
      if (n === 0) break;
      off += n;
    }
    return b.subarray(0, off);
  } finally {
    closeSync(fd);
  }
}

function dirFsync(path: string): void {
  const fd = openSync(path, "r");
  try {
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

/** Byte-compare two files without loading either fully. */
export function filesIdentical(a: string, b: string): boolean {
  const sa = lstatSync(a);
  const sb = lstatSync(b);
  if (!sa.isFile() || !sb.isFile() || sa.size !== sb.size) return false;
  return hashFileBytes(a).digest === hashFileBytes(b).digest;
}

export async function capture(
  request: CaptureRequest,
  produce: (stagedPath: string) => Promise<void>,
  signer: Signer,
  journal: Journal = () => {},
): Promise<CaptureResult> {
  const { staging_parent, publish_path, profile, template } = request;
  let state: CaptureState = "NEW";

  const parentStat = lstatSync(staging_parent);
  if (!parentStat.isDirectory()) {
    throw new SunlightError("USAGE", null, new Error("staging_parent is not a directory"));
  }
  if (lstatSync(publish_path, { throwIfNoEntry: false }) !== undefined) {
    throw new SunlightError("OUTPUT_EXISTS");
  }

  const staging = join(
    staging_parent,
    `.sunlight-stage-${randomBytes(8).toString("hex")}`,
  );

  // NEW → STAGING
  try {
    mkdirSync(staging, { mode: 0o700 });
  } catch (e) {
    journal("local.CaptureFailed");
    throw new SunlightError("IO_ERROR", null, e);
  }
  state = "STAGING";
  journal("local.CaptureStarted");

  const stagedPath = join(staging, STAGED_NAME);
  const cleanup = (): void => {
    try {
      rmSync(staging, { recursive: true, force: true });
    } catch { /* best-effort cleanup */ }
  };

  // STAGING → FINALIZED: the producer fills the staged path exclusively.
  try {
    if (profile === "tree/1") {
      mkdirSync(stagedPath, { mode: 0o700 });
    }
    await produce(stagedPath);
    if (profile === "tree/1") {
      if (!lstatSync(stagedPath).isDirectory()) {
        throw new SunlightError("IO_ERROR", null, new Error("producer did not create a directory"));
      }
    } else if (!lstatSync(stagedPath).isFile()) {
      throw new SunlightError("IO_ERROR", null, new Error("producer did not create a file"));
    }
  } catch (e) {
    state = "FAILED";
    journal("local.CaptureFailed");
    cleanup();
    throw e instanceof SunlightError ? e : new SunlightError("IO_ERROR", null, e);
  }
  state = "FINALIZED";
  journal("local.BytesFinalized");

  // FINALIZED → HASHED
  let artifact: Artifact;
  let publishBytes: Buffer | null = null; // jcs/1 publishes canonical bytes
  try {
    if (profile === "bytes/1") {
      const r = hashFileBytes(stagedPath);
      artifact = { profile, digest: r.digest, bytes: r.bytes };
    } else if (profile === "jcs/1") {
      const st = lstatSync(stagedPath);
      if (st.size > 1024 * 1024) throw new SunlightError("BODY_LIMIT");
      let value: unknown;
      try {
        value = parseStrictJson(readAll(stagedPath));
      } catch (e) {
        throw new SunlightError("SCHEMA_INVALID", null, e);
      }
      publishBytes = jcsBytes(value);
      artifact = { profile, digest: B(publishBytes), bytes: publishBytes.length };
    } else {
      // tree/1 — the producer populated the staged directory directly; the
      // staged files are already the private copies, so manifest them in place.
      const rels = enumerateTree(stagedPath);
      const files = rels.map((rel) => {
        const { digest, bytes } = hashFileBytes(join(stagedPath, ...rel.split("/")));
        return { path: rel, digest, bytes };
      });
      const manifest = parseTreeManifest({ v: "sunlight.tree/1", files });
      artifact = manifestArtifact(manifest);
    }
  } catch (e) {
    state = "FAILED";
    journal("local.CaptureFailed");
    cleanup();
    throw e instanceof SunlightError ? e : new SunlightError("IO_ERROR", null, e);
  }
  state = "HASHED";
  journal("local.ArtifactHashed", { digest: artifact.digest });

  // HASHED → SIGNED
  let statement: Statement;
  try {
    const body = parseStatementBody({
      v: template.v,
      id: template.id,
      ledger: template.ledger,
      signer: template.signer,
      claimed_at_ms: template.claimed_at_ms,
      capture: "creation_hook",
      subject: { kind: template.kind, artifact },
      parents: template.parents,
      details: template.details,
      evidence: template.evidence,
    });
    statement = await signStatement(body, signer);
    // Persist the signed statement durably inside staging before publication.
    writeFileSyncExclusive(join(staging, "statement.json"), jcsBytes(statement));
  } catch (e) {
    state = "FAILED";
    journal("local.CaptureFailed");
    cleanup();
    throw e instanceof SunlightError ? e : new SunlightError("IO_ERROR", null, e);
  }
  state = "SIGNED";
  journal("local.StatementSigned", { statement: statement.hash });

  // SIGNED → PUBLISHED: atomic rename of the staged artifact.
  try {
    if (publishBytes !== null) {
      writeFileSyncExclusive(publish_path, publishBytes);
    } else {
      renameSync(stagedPath, publish_path);
    }
    dirFsync(join(publish_path, ".."));
  } catch (e) {
    // Publication may or may not have completed.
    const published = lstatSync(publish_path, { throwIfNoEntry: false });
    if (published === undefined) {
      state = "FAILED";
      journal("local.PublishFailed");
      // The signed statement is retained in staging as the recovery object.
      throw new SunlightError("IO_ERROR", null, e);
    }
    state = "PUBLICATION_UNKNOWN";
    journal("local.PublicationUncertain");
    // Recovery: reopen the destination and verify it carries the exact
    // staged bytes and that the statement is durable.
    try {
      if (profile !== "tree/1") {
        const expected = publishBytes ?? readAll(stagedPath);
        const got = readAll(publish_path);
        if (!expected.equals(got)) throw new SunlightError("ARTIFACT_CHANGED");
      } else if (!lstatSync(publish_path).isDirectory()) {
        throw new SunlightError("ARTIFACT_CHANGED");
      }
      lstatSync(join(staging, "statement.json"));
      state = "PUBLISHED";
      journal("local.PublicationRecovered");
      return { published_path: publish_path, statement, recorded: false };
    } catch (e2) {
      state = "FAILED";
      journal("local.PublishFailed");
      throw e2 instanceof SunlightError ? e2 : new SunlightError("IO_ERROR", null, e2);
    }
  }
  state = "PUBLISHED";
  journal("local.ArtifactPublished", { path: publish_path });
  return { published_path: publish_path, statement, recorded: false };
}
