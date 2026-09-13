/**
 * Key custody (spec §7 KeyApi, §8 LocalKeyFile).
 *
 * Local key files are encrypted PKCS#8 PEM inside a LocalKeyFile JSON wrapper.
 * Files require owner-only permissions (0600); passphrases come from an
 * interactive terminal or SUNLIGHT_KEY_PASSPHRASE_FD — never argv.  The
 * derived public key must equal the stored PublicKey record, whose immutable
 * key ID is the signer identity.
 */

import { createPrivateKey, createPublicKey, randomBytes } from "node:crypto";
import { lstatSync, openSync, readSync, closeSync, writeSync, fsyncSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { SunlightError } from "./errors.js";
import { newId } from "./ids.js";
import { parseStrictJson } from "./encoding/strict-json.js";
import { jcsBytes } from "./encoding/jcs.js";
import { parseLocalKeyFile, parsePublicKey, type LocalKeyFile, type PublicKey } from "./schema.js";
import { ed25519PublicFromSeed, privateKeyFromSeed } from "./crypto/ed25519.js";
import { seedSigner, type Signer } from "./objects.js";
import { readFileBytesSync, writeFileExclusive } from "./fsutil.js";

const PKCS8_ED25519_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

export function derToSeed(der: Buffer): Buffer {
  if (der.length !== 48 || !der.subarray(0, 16).equals(PKCS8_ED25519_PREFIX)) {
    throw new SunlightError("KEY_ERROR");
  }
  return der.subarray(16);
}

function readPassphrase(): string {
  // SUNLIGHT_KEY_PASSPHRASE_FD supplies the passphrase on a file descriptor;
  // otherwise an interactive terminal prompt is required (never argv).
  const fdStr = process.env.SUNLIGHT_KEY_PASSPHRASE_FD;
  if (fdStr !== undefined && fdStr !== "") {
    const fd = Number(fdStr);
    if (!Number.isInteger(fd) || fd < 0) throw new SunlightError("USAGE");
    const chunks: Buffer[] = [];
    const buf = Buffer.allocUnsafe(4096);
    for (;;) {
      const n = readSync(fd, buf, 0, buf.length, null);
      if (n <= 0) break;
      chunks.push(buf.subarray(0, n));
      if (Buffer.concat(chunks).includes(0x0a)) break;
    }
    const line = Buffer.concat(chunks).toString("utf8").split("\n")[0]!;
    return line.replace(/\r$/, "");
  }
  if (process.stdin.isTTY) {
    // Minimal hidden prompt: read one line from the controlling terminal.
    process.stderr.write("key passphrase: ");
    const fd = openSync("/dev/tty", "r");
    try {
      const chunks: Buffer[] = [];
      const buf = Buffer.allocUnsafe(1);
      for (;;) {
        const n = readSync(fd, buf, 0, 1, null);
        if (n <= 0 || buf[0] === 0x0a) break;
        chunks.push(Buffer.from([buf[0]!]));
      }
      return Buffer.concat(chunks).toString("utf8");
    } finally {
      closeSync(fd);
    }
  }
  throw new SunlightError("KEY_ERROR", null, new Error("no passphrase source (set SUNLIGHT_KEY_PASSPHRASE_FD)"));
}

export function generateKey(
  passphrase: string,
  entropy: Uint8Array | null,
): { key: PublicKey; file: LocalKeyFile; seed: Buffer } {
  // Entropy stream: first 32 bytes are the seed; further bytes drive the
  // nanoid rejection sampler so conformance runs are fully deterministic.
  const stream = entropy === null ? null : Buffer.from(entropy);
  let offset = 0;
  const next = (n: number): Buffer => {
    if (stream === null) return randomBytes(n);
    const out = Buffer.allocUnsafe(n);
    for (let i = 0; i < n; i++) {
      if (offset < stream.length) out[i] = stream[offset++]!;
      else out[i] = randomBytes(1)[0]!; // stream exhausted: continue randomly
    }
    return out;
  };
  const seed = next(32);
  const publicKey = ed25519PublicFromSeed(seed);
  const keyId = newId("slk", (n) => next(n));
  const key: PublicKey = { id: keyId, public_hex: publicKey.toString("hex") };
  const pem = privateKeyFromSeed(seed).export({
    format: "pem",
    type: "pkcs8",
    cipher: "aes-256-cbc",
    passphrase,
  }) as string;
  const file: LocalKeyFile = {
    v: "sunlight.keyfile/1",
    key,
    encrypted_pkcs8_pem: pem,
  };
  return { key, file, seed };
}

/** Load + decrypt a LocalKeyFile and verify the derived public key. */
export function loadKeyFile(path: string, passphrase: string | null): Signer {
  const st = lstatSync(path);
  if (!st.isFile()) throw new SunlightError("KEY_ERROR");
  // Owner-only permissions required (group/other bits forbidden).
  if ((st.mode & 0o077) !== 0) throw new SunlightError("KEY_PERMISSIONS");
  let parsed: LocalKeyFile;
  try {
    parsed = parseLocalKeyFile(parseStrictJson(readFileBytesSync(path)));
  } catch (e) {
    // Any malformed key file (bad JSON, wrong shape) is a key-custody error.
    throw new SunlightError("KEY_ERROR", null, e);
  }
  const pass = passphrase ?? readPassphrase();
  let seed: Buffer;
  try {
    const priv = createPrivateKey({ key: parsed.encrypted_pkcs8_pem, passphrase: pass });
    const der = priv.export({ format: "der", type: "pkcs8" });
    seed = derToSeed(der);
  } catch (e) {
    throw new SunlightError("KEY_ERROR", null, e);
  }
  const derived = ed25519PublicFromSeed(seed).toString("hex");
  if (derived !== parsed.key.public_hex) throw new SunlightError("KEY_ERROR");
  return seedSigner(parsed.key, seed);
}

export function writeKeyFile(path: string, file: LocalKeyFile): void {
  writeFileExclusive(path, jcsBytes(file), 0o600);
}

export function writePublicKeyFile(path: string, key: PublicKey): void {
  writeFileExclusive(path, jcsBytes(parsePublicKey(key)), 0o600);
}

export function keyFileFromSeed(id: string, seed: Buffer, passphrase: string): LocalKeyFile {
  const key: PublicKey = { id, public_hex: ed25519PublicFromSeed(seed).toString("hex") };
  const pem = privateKeyFromSeed(seed).export({
    format: "pem", type: "pkcs8", cipher: "aes-256-cbc", passphrase,
  }) as string;
  return { v: "sunlight.keyfile/1", key, encrypted_pkcs8_pem: pem };
}
