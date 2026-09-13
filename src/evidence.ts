/**
 * Foreign evidence import (spec §10 / INTERFACES.md).  Imports hash the
 * supplied bytes as bytes/1 and attach exactly one OPAQUE EvidenceRef; no
 * foreign validation, fetching, or execution is performed or implied.
 *
 * Only vislineage-bundle/1 carries source_commitment — the bundle's own
 * `hash` field (its native canonical commitment), checked to be consistent
 * with the actual bundle document.  Every other v1 format uses null.
 */

import { SunlightError } from "./errors.js";
import { parseStrictJson } from "./encoding/strict-json.js";
import { B, DIGEST_RE } from "./crypto/domains.js";
import type { EvidenceRef, ForeignFormat } from "./schema.js";

export function computeEvidenceRef(rawInput: Buffer, format: ForeignFormat): EvidenceRef {
  const artifact = { profile: "bytes/1" as const, digest: B(rawInput), bytes: rawInput.length };
  let sourceCommitment: string | null = null;
  if (format === "vislineage-bundle/1") {
    let parsed: unknown;
    try {
      parsed = parseStrictJson(rawInput);
    } catch (e) {
      throw new SunlightError("SCHEMA_INVALID", null, e);
    }
    const bh = (parsed as Record<string, unknown>).hash;
    if (typeof bh !== "string" || !DIGEST_RE.test(bh)) {
      throw new SunlightError("SCHEMA_INVALID");
    }
    sourceCommitment = bh;
  }
  return {
    artifact,
    format,
    source_commitment: sourceCommitment,
    assessment: "OPAQUE",
  };
}
