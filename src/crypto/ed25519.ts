/**
 * Pure Ed25519 (not Ed25519ph) with strict canonicality enforcement (spec §2):
 *  - signatures decode to exactly 64 bytes; S < L; R is a canonical point.
 *  - public keys decode to exactly 32 bytes; canonical (y < p); not small-order.
 *
 * The signature equation itself is evaluated by OpenSSL via node:crypto.
 */

import {
  createPrivateKey, createPublicKey, sign as nodeSign, verify as nodeVerify,
  generateKeyPairSync, randomBytes,
} from "node:crypto";

const P = 2n ** 255n - 19n;
const L = 2n ** 252n + 27742317777372353535851937790883648493n;
const D = (-121665n * modInv(121666n)) % P;
const SQRT_M1 = modPow(2n, (P - 1n) / 4n);

function modInv(a: bigint): bigint {
  let [x, y] = [a % P, P];
  let [u, v] = [1n, 0n];
  while (y !== 0n) {
    const q = x / y;
    [x, y] = [y, x - q * y];
    [u, v] = [v, u - q * v];
  }
  return ((u % P) + P) % P;
}

function modPow(base: bigint, exp: bigint): bigint {
  let r = 1n;
  let b = base % P;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) r = (r * b) % P;
    b = (b * b) % P;
    e >>= 1n;
  }
  return r;
}

/** Known small-order / non-canonical Ed25519 encodings (libsodium blocklist). */
const SMALL_ORDER_ENC: ReadonlySet<string> = new Set([
  "0000000000000000000000000000000000000000000000000000000000000000",
  "0100000000000000000000000000000000000000000000000000000000000000",
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "26e8958fc2b227945045b3fea6db724b4032548b1f06741d3fc8c992420b5af12d6c",
  "c7176a703d4dd84fba3c0b760438106f1a0e50c8b8962b2d58aa3d5fe1aee4b4",
]);

function leInt(b: Buffer | Uint8Array): bigint {
  let v = 0n;
  for (let i = b.length - 1; i >= 0; i--) v = (v << 8n) | BigInt(b[i]!);
  return v;
}

/** Check canonical point encoding: y < p and x must exist on the curve. */
export function isCanonicalPointEncoding(enc: Buffer | Uint8Array): boolean {
  if (enc.length !== 32) return false;
  const signBit = (enc[31]! & 0x80) !== 0;
  const yBytes = Buffer.from(enc);
  yBytes[31] = yBytes[31]! & 0x7f;
  const y = leInt(yBytes);
  if (y >= P) return false;
  const y2 = (y * y) % P;
  const u = (y2 - 1n + P) % P;
  const v = (D * y2 + 1n) % P;
  const x2 = (u * modInv(v)) % P;
  let x = modPow(x2, (P + 3n) / 8n);
  if ((x * x - x2) % P !== 0n) {
    x = (x * SQRT_M1) % P;
    if ((x * x - x2) % P !== 0n) return false;
  }
  if ((x & 1n) !== (signBit ? 1n : 0n)) x = P - x;
  return true;
}

export function isValidPublicKey(pub: Buffer | Uint8Array): boolean {
  if (pub.length !== 32) return false;
  if (!isCanonicalPointEncoding(pub)) return false;
  if (SMALL_ORDER_ENC.has(Buffer.from(pub).toString("hex"))) return false;
  return true;
}

export function isCanonicalSignature(sig: Buffer | Uint8Array): boolean {
  if (sig.length !== 64) return false;
  const s = leInt(sig.subarray(32));
  if (s >= L) return false;
  return isCanonicalPointEncoding(sig.subarray(0, 32));
}

/** PKCS8 DER prefix for an Ed25519 private key carrying a raw 32-byte seed. */
const PKCS8_ED25519_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

export function privateKeyFromSeed(seed: Buffer | Uint8Array): ReturnType<typeof createPrivateKey> {
  if (seed.length !== 32) throw new Error("ed25519 seed must be 32 bytes");
  return createPrivateKey({
    key: Buffer.concat([PKCS8_ED25519_PREFIX, Buffer.from(seed)]),
    format: "der",
    type: "pkcs8",
  });
}

export function ed25519PublicFromSeed(seed: Buffer | Uint8Array): Buffer {
  const pub = createPublicKey(privateKeyFromSeed(seed));
  const jwk = pub.export({ format: "jwk" }) as { x: string };
  return Buffer.from(jwk.x, "base64url");
}

export function ed25519Generate(random: (n: number) => Buffer = randomBytes): { seed: Buffer; publicKey: Buffer } {
  // Node's generateKeyPairSync uses OS entropy; the injectable random source is
  // used only by conformance tooling to derive a deterministic seed.
  const seed = random(32);
  return { seed, publicKey: ed25519PublicFromSeed(seed) };
}

export function ed25519Sign(seed: Buffer | Uint8Array, message: Buffer | Uint8Array): Buffer {
  return nodeSign(null, Buffer.from(message), privateKeyFromSeed(seed));
}

/** Strict verify: rejects malformed keys/signatures before OpenSSL. */
export function ed25519Verify(
  publicKey: Buffer | Uint8Array,
  message: Buffer | Uint8Array,
  signature: Buffer | Uint8Array,
): boolean {
  if (!isValidPublicKey(publicKey)) return false;
  if (!isCanonicalSignature(signature)) return false;
  const key = createPublicKey({
    key: { kty: "OKP", crv: "Ed25519", x: Buffer.from(publicKey).toString("base64url") },
    format: "jwk",
  });
  try {
    return nodeVerify(null, Buffer.from(message), key, Buffer.from(signature));
  } catch {
    return false;
  }
}
