/** Filesystem helpers: bounded reads, exclusive 0600 writes, fsync+rename. */

import { openSync, closeSync, readSync, writeSync, fsyncSync, fstatSync, mkdirSync, renameSync } from "node:fs";
import { dirname } from "node:path";
import { SunlightError } from "./errors.js";

export function readFileBytesSync(path: string, max = 32 * 1024 * 1024): Buffer {
  const fd = openSync(path, "r");
  try {
    const st = fstatSync(fd);
    if (!st.isFile()) throw new SunlightError("IO_ERROR");
    if (st.size > max) throw new SunlightError("BODY_LIMIT");
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

/** Exclusive-create write (no overwrite flag in v1) with fsync. */
export function writeFileExclusive(path: string, data: Buffer | string, mode = 0o600): void {
  mkdirSync(dirname(path), { recursive: true });
  const fd = openSync(path, "wx", mode);
  try {
    const buf = typeof data === "string" ? Buffer.from(data, "utf8") : data;
    let off = 0;
    while (off < buf.length) off += writeSync(fd, buf, off, buf.length - off);
    fsyncSync(fd);
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "EEXIST") throw new SunlightError("OUTPUT_EXISTS");
    throw e;
  } finally {
    closeSync(fd);
  }
}

/** fsync a temp file then atomically rename it into place. */
export function writeFileAtomic(path: string, data: Buffer, mode = 0o600): void {
  mkdirSync(dirname(path), { recursive: true });
  const tmp = `${path}.tmp-${process.pid}`;
  const fd = openSync(tmp, "w", mode);
  try {
    let off = 0;
    while (off < data.length) off += writeSync(fd, data, off, data.length - off);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  renameSync(tmp, path);
}
