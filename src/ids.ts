/**
 * Locked ID prefixes and nanoid generation (spec §2).
 *
 * Every ID is `<prefix>` + `_` + exactly 21 characters from the 64-symbol
 * alphabet [A-Za-z0-9_-].  Generation uses cryptographic rejection sampling
 * (nanoid algorithm).  Prefixes are wire constraints, not display
 * conventions.
 */

import { randomBytes } from "node:crypto";

export const ID_SUFFIX_LENGTH = 21;
export const ID_ALPHABET =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";

export const ID_PREFIXES = [
  "sll", // LedgerId
  "slk", // KeyId
  "sls", // StatementId
  "slq", // RequestId / CommandId
  "sle", // EntryId
  "slr", // RunId
  "sla", // ActionId
] as const;

export type IdPrefix = (typeof ID_PREFIXES)[number];

const PREFIX_SET = new Set<string>(ID_PREFIXES);

export function isValidId(value: unknown, prefix?: IdPrefix): value is string {
  if (typeof value !== "string") return false;
  const sep = value.indexOf("_");
  if (sep <= 0) return false;
  const p = value.slice(0, sep);
  if (!PREFIX_SET.has(p)) return false;
  if (prefix !== undefined && p !== prefix) return false;
  const suffix = value.slice(sep + 1);
  if (suffix.length !== ID_SUFFIX_LENGTH) return false;
  for (const ch of suffix) {
    if (ID_ALPHABET.indexOf(ch) < 0) return false;
  }
  return true;
}

/**
 * Cryptographic nanoid with rejection sampling. The 64-symbol alphabet divides
 * 256 evenly, so the mask path never discards; the sampler is still the
 * standard rejection loop and remains correct if the alphabet ever changes.
 */
export function newId(prefix: IdPrefix, random: (n: number) => Buffer = randomBytes): string {
  const alphabet = ID_ALPHABET;
  const size = alphabet.length;
  let mask = 1;
  while (mask < size - 1) mask = (mask << 1) | 1;
  const bound = Math.floor(256 / size) * size;
  const out = new Array<string>(ID_SUFFIX_LENGTH);
  let filled = 0;
  while (filled < ID_SUFFIX_LENGTH) {
    const bytes = random(ID_SUFFIX_LENGTH);
    for (let i = 0; i < bytes.length && filled < ID_SUFFIX_LENGTH; i++) {
      const b = bytes[i]! & mask;
      if (b < size && bytes[i]! < bound) {
        out[filled++] = alphabet[b]!;
      }
    }
  }
  return `${prefix}_${out.join("")}`;
}

/** Lowercase hex of `n` random bytes (head.get nonces etc.). */
export function randomHex(n: number, random: (n: number) => Buffer = randomBytes): string {
  return random(n).toString("hex");
}
