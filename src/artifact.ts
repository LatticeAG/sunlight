/**
 * Artifact profiles (spec §2.1): bytes/1 streams exact bytes; jcs/1 digests
 * B(J(value)) of a strictly parsed document (1 MiB raw cap); tree/1 digests
 * B(J(TreeManifest)) over a deterministic directory manifest.
 *
 * Tree capture rejects symlinks, multiply-hardlinked names, device files,
 * sockets, and filesystem changes during capture.  Files are hashed from
 * private staged copies; before/after stat checks detect ordinary races.
 */

import { createHash } from "node:crypto";
import {
  openSync, closeSync, readSync, fstatSync, lstatSync, readdirSync, statSync,
  mkdirSync, writeSync, fsyncSync,
} from "node:fs";
import { join, relative, sep } from "node:path";
import { SunlightError } from "./errors.js";
import { jcsBytes } from "./encoding/jcs.js";
import { parseStrictJson } from "./encoding/strict-json.js";
import { B } from "./crypto/domains.js";
import {
  parseTreeManifest, isValidTreePath,
  MAX_MANIFEST_BYTES, MAX_MANIFEST_FILES,
  type Artifact, type ArtifactProfile, type TreeFile, type TreeManifest,
} from "./schema.js";

const HASH_BUF = 4 * 1024 * 1024; // 4 MiB streaming cap (spec §10)
const JCS_RAW_CAP = 1024 * 1024;  // 1 MiB raw input cap for jcs/1 (spec §2.1)

/** Stream a single file's raw bytes through SHA-256 with a bounded buffer. */
export function hashFileBytes(path: string): { digest: string; bytes: number } {
  const fd = openSync(path, "r");
  try {
    const st = fstatSync(fd);
    if (!st.isFile()) throw new SunlightError("ARTIFACT_CHANGED");
    const h = createHash("sha256");
    const buf = Buffer.allocUnsafe(Math.min(HASH_BUF, Math.max(st.size, 4096)));
    let total = 0;
    for (;;) {
      const n = readSync(fd, buf, 0, buf.length, null);
      if (n === 0) break;
      h.update(buf.subarray(0, n));
      total += n;
    }
    return { digest: "sha256:" + h.digest("hex"), bytes: total };
  } finally {
    closeSync(fd);
  }
}

/** jcs/1 over an explicitly canonicalized JSON file. */
export function hashJcsFile(path: string): Artifact {
  const st = lstatSync(path);
  if (!st.isFile() || st.isSymbolicLink()) throw new SunlightError("ARTIFACT_CHANGED");
  if (st.size > JCS_RAW_CAP) throw new SunlightError("BODY_LIMIT");
  const raw = readFileBytes(path);
  let value: unknown;
  try {
    value = parseStrictJson(raw);
  } catch (e) {
    throw new SunlightError("SCHEMA_INVALID", null, e);
  }
  const canon = jcsBytes(value);
  return { profile: "jcs/1", digest: B(canon), bytes: canon.length };
}

function readFileBytes(path: string): Buffer {
  const fd = openSync(path, "r");
  try {
    const st = fstatSync(fd);
    const out = Buffer.allocUnsafe(st.size);
    let off = 0;
    while (off < st.size) {
      const n = readSync(fd, out, off, st.size - off, null);
      if (n === 0) break;
      off += n;
    }
    return out.subarray(0, off);
  } finally {
    closeSync(fd);
  }
}

interface FileSnap {
  dev: bigint;
  ino: bigint;
  size: bigint;
  mtimeNs: bigint;
}

function snap(path: string): FileSnap {
  const st = lstatSync(path, { bigint: true });
  return { dev: st.dev, ino: st.ino, size: st.size, mtimeNs: st.mtimeNs };
}

function sameSnap(a: FileSnap, b: FileSnap): boolean {
  return a.dev === b.dev && a.ino === b.ino && a.size === b.size && a.mtimeNs === b.mtimeNs;
}

/** Enumerate a directory into validated relative paths (source order). */
export function enumerateTree(root: string): string[] {
  const out: string[] = [];
  const walk = (dir: string, rel: string): void => {
    let names: string[];
    try {
      names = readdirSync(dir);
    } catch (e) {
      throw new SunlightError("IO_ERROR", null, e);
    }
    for (const name of names) {
      const full = join(dir, name);
      const r = rel === "" ? name : rel + "/" + name;
      const st = lstatSync(full);
      if (st.isSymbolicLink()) {
        throw new SunlightError("SCHEMA_INVALID", null, new Error(`symlink rejected: ${r}`));
      }
      if (st.isDirectory()) {
        walk(full, r);
        continue;
      }
      if (!st.isFile()) {
        throw new SunlightError("SCHEMA_INVALID", null, new Error(`non-regular file rejected: ${r}`));
      }
      if (st.nlink > 1) {
        throw new SunlightError("SCHEMA_INVALID", null, new Error(`multiply-linked file rejected: ${r}`));
      }
      if (!isValidTreePath(r)) {
        throw new SunlightError("SCHEMA_INVALID", null, new Error(`invalid tree path: ${r}`));
      }
      out.push(r);
    }
  };
  const rootStat = lstatSync(root);
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) {
    throw new SunlightError("USAGE", null, new Error("tree root is not a directory"));
  }
  walk(root, "");
  out.sort();
  if (out.length > MAX_MANIFEST_FILES) {
    throw new SunlightError("BODY_LIMIT", null, new Error("tree over 10000 files"));
  }
  const fold = new Set<string>();
  for (const p of out) {
    const f = p.toLowerCase();
    if (fold.has(f)) throw new SunlightError("SCHEMA_INVALID", null, new Error(`case collision: ${p}`));
    fold.add(f);
  }
  return out;
}

/**
 * Stage a directory into `stagingDir` (created 0700 by caller), hash every
 * staged file, and produce the sorted manifest.  Copies into private staging
 * first so the hashed bytes are exactly the bytes downstream consumers see.
 */
export function stageTree(root: string, stagingDir: string): { manifest: TreeManifest; stagedFiles: Map<string, string> } {
  const rels = enumerateTree(root);
  const staged = new Map<string, string>();
  const before = new Map<string, FileSnap>();
  for (const rel of rels) {
    const src = join(root, ...rel.split("/"));
    const dst = join(stagingDir, ...rel.split("/"));
    mkdirSync(join(stagingDir, ...rel.split("/").slice(0, -1)), { recursive: true, mode: 0o700 });
    before.set(rel, snap(src));
    const data = readFileBytes(src);
    const fd = openSync(dst, "wx", 0o600);
    try {
      writeSync(fd, data);
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    staged.set(rel, dst);
    // Post-copy race check on the source handle identity.
    const after = snap(src);
    if (!sameSnap(before.get(rel)!, after)) {
      throw new SunlightError("ARTIFACT_CHANGED", null, new Error(`file changed during capture: ${rel}`));
    }
  }
  const files: TreeFile[] = rels.map((rel) => {
    const { digest, bytes } = hashFileBytes(staged.get(rel)!);
    return { path: rel, digest, bytes };
  });
  const manifest = parseTreeManifest({ v: "sunlight.tree/1", files });
  if (jcsBytes(manifest).length > MAX_MANIFEST_BYTES) {
    throw new SunlightError("BODY_LIMIT");
  }
  return { manifest, stagedFiles: staged };
}

/** tree/1 artifact for a manifest value already built from staged files. */
export function manifestArtifact(manifest: TreeManifest): Artifact {
  const canon = jcsBytes(manifest);
  return { profile: "tree/1", digest: B(canon), bytes: canon.length };
}

/**
 * hashArtifact: bytes/1 streams the file; jcs/1 parses and canonicalizes;
 * tree/1 stages + manifests a directory.
 */
export async function hashArtifact(input: { profile: ArtifactProfile; path: string }): Promise<Artifact> {
  const { profile, path } = input;
  if (profile === "bytes/1") {
    const st = lstatSync(path);
    if (!st.isFile() || st.isSymbolicLink()) {
      throw new SunlightError("USAGE", null, new Error("artifact path is not a regular file"));
    }
    const before = snap(path);
    const r = hashFileBytes(path);
    const after = snap(path);
    if (!sameSnap(before, after)) throw new SunlightError("ARTIFACT_CHANGED");
    return { profile: "bytes/1", digest: r.digest, bytes: r.bytes };
  }
  if (profile === "jcs/1") {
    return hashJcsFile(path);
  }
  // tree/1 — stage into a private temp dir alongside the source, hash staged.
  const { mkdtempSync, rmSync, chmodSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const staging = mkdtempSync(join(tmpdir(), "sunlight-tree-"));
  chmodSync(staging, 0o700);
  try {
    const { manifest } = stageTree(path, staging);
    return manifestArtifact(manifest);
  } finally {
    rmSync(staging, { recursive: true, force: true });
  }
}
