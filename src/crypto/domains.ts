/**
 * Sunlight hash and signature domains (spec §2).
 *
 *   B(b)      = "sha256:" + lowercase_hex(SHA256(b))
 *   D(tag,x)  = B(UTF8(tag + "\n") || J(x))
 *   RAW(h)    = the 32 digest bytes after "sha256:"
 *   sig msg   = UTF8(signature_domain + "\n") || RAW(object_hash)
 */

import { createHash } from "node:crypto";
import { jcsBytes } from "../encoding/jcs.js";
import { ed25519Sign, ed25519Verify } from "./ed25519.js";

export const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
export const HEX32_RE = /^[0-9a-f]{64}$/;
export const HEX64_RE = /^[0-9a-f]{128}$/;

export function sha256(b: Buffer | Uint8Array): Buffer {
  return createHash("sha256").update(b).digest();
}

export function B(b: Buffer | Uint8Array): string {
  return "sha256:" + createHash("sha256").update(b).digest("hex");
}

/** D(tag, x): domain-separated hash of a canonical JSON object. */
export function D(tag: string, x: unknown): string {
  return B(Buffer.concat([Buffer.from(tag + "\n", "utf8"), jcsBytes(x)]));
}

/** RAW(h): decode the 32 digest bytes after the "sha256:" prefix. */
export function RAW(h: string): Buffer {
  if (!DIGEST_RE.test(h)) throw new Error("not a sunlight digest");
  return Buffer.from(h.slice(7), "hex");
}

export type ObjectKind = "genesis" | "statement" | "command" | "receipt" | "head";

export function hashDomain(kind: ObjectKind): string {
  return `sunlight.${kind}/1`;
}

export function signatureDomain(kind: ObjectKind): string {
  return `sunlight.${kind}.signature/1`;
}

/** The exact message signed for an object: domain + LF + raw object hash. */
export function signatureMessage(kind: ObjectKind, objectHash: string): Buffer {
  return Buffer.concat([Buffer.from(signatureDomain(kind) + "\n", "utf8"), RAW(objectHash)]);
}

export function signObject(
  kind: "statement" | "command" | "receipt" | "head",
  body: unknown,
  seed: Buffer | Uint8Array,
): { body: unknown; hash: string; signature_hex: string } {
  const hash = D(hashDomain(kind), body);
  return { body, hash, signature_hex: ed25519Sign(seed, signatureMessage(kind, hash)).toString("hex") };
}

/** Verify hash recomputation then signature; returns false on either. */
export function verifyObject(
  kind: "statement" | "command" | "receipt" | "head",
  signed: { body: unknown; hash: string; signature_hex: string },
  publicKey: Buffer | Uint8Array,
): boolean {
  if (D(hashDomain(kind), signed.body) !== signed.hash) return false;
  return ed25519Verify(
    publicKey,
    signatureMessage(kind, signed.hash),
    Buffer.from(signed.signature_hex, "hex"),
  );
}

export function isDigest(v: unknown): v is string {
  return typeof v === "string" && DIGEST_RE.test(v);
}
export function isHex32(v: unknown): v is string {
  return typeof v === "string" && HEX32_RE.test(v);
}
export function isHex64(v: unknown): v is string {
  return typeof v === "string" && HEX64_RE.test(v);
}
