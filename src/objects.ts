/**
 * Object construction and signing (spec §7 CoreApi primitives).
 *
 * signStatement/signCommand are the low-level cryptographic primitives: they
 * sign exact canonical bodies and cannot prove capture occurred.  Only the
 * cooperative capture path (capture.ts) may label a statement creation_hook.
 */

import {
  D, hashDomain, signatureMessage, type ObjectKind,
} from "./crypto/domains.js";
import { ed25519Sign, ed25519Verify } from "./crypto/ed25519.js";
import { jcsBytes } from "./encoding/jcs.js";
import { SunlightError } from "./errors.js";
import {
  parseStatementBody, parseCommandBody, parseReceiptBody, parseHeadBody,
  type Command, type CommandBody, type PublicKey, type Receipt,
  type ReceiptBody, type SignedHead, type HeadBody, type Statement,
  type StatementBody,
} from "./schema.js";

export interface Signer {
  key: PublicKey;
  sign(message: Uint8Array): Promise<Uint8Array>;
}

/** In-process signer over a raw 32-byte seed (test + keyfile path). */
export function seedSigner(key: PublicKey, seed: Buffer): Signer {
  return {
    key,
    sign: async (message: Uint8Array) => ed25519Sign(seed, Buffer.from(message)),
  };
}

async function signBody<K extends "statement" | "command" | "receipt" | "head">(
  kind: K,
  body: unknown,
  signer: Signer,
): Promise<{ hash: string; signature_hex: string }> {
  const hash = D(hashDomain(kind), body);
  const sig = await signer.sign(signatureMessage(kind, hash));
  if (sig.length !== 64) throw new SunlightError("SIGNATURE_INVALID");
  return { hash, signature_hex: Buffer.from(sig).toString("hex") };
}

export async function signStatement(body: StatementBody, signer: Signer): Promise<Statement> {
  const b = parseStatementBody(body);
  if (b.signer !== signer.key.id) throw new SunlightError("ROLE_MISMATCH");
  const { hash, signature_hex } = await signBody("statement", b, signer);
  return { body: b, hash, signature_hex };
}

export async function signCommand(body: CommandBody, signer: Signer): Promise<Command> {
  const b = parseCommandBody(body);
  if (b.signer !== signer.key.id) throw new SunlightError("ROLE_MISMATCH");
  const { hash, signature_hex } = await signBody("command", b, signer);
  return { body: b, hash, signature_hex };
}

export async function signReceipt(body: ReceiptBody, signer: Signer): Promise<Receipt> {
  const b = parseReceiptBody(body);
  const { hash, signature_hex } = await signBody("receipt", b, signer);
  return { body: b, hash, signature_hex };
}

export async function signHead(body: HeadBody, signer: Signer): Promise<SignedHead> {
  const b = parseHeadBody(body);
  const { hash, signature_hex } = await signBody("head", b, signer);
  return { body: b, hash, signature_hex };
}

/** Verify a signed object's hash recomputation and signature. */
export function verifySignedObject(
  kind: "statement" | "command" | "receipt" | "head",
  obj: { body: unknown; hash: string; signature_hex: string },
  publicKeyHex: string,
): boolean {
  if (D(hashDomain(kind), obj.body) !== obj.hash) return false;
  return ed25519Verify(
    Buffer.from(publicKeyHex, "hex"),
    signatureMessage(kind, obj.hash),
    Buffer.from(obj.signature_hex, "hex"),
  );
}
