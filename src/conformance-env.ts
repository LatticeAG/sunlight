/**
 * Conformance-only deterministic hooks (spec §7).  Honored exclusively when
 * the binary is built/launched with SUNLIGHT_CONFORMANCE=1; production
 * operation MUST ignore them.  Every honored variable is reported on stderr.
 */

const reported = new Set<string>();

function report(name: string): void {
  if (!reported.has(name)) {
    process.stderr.write(`sunlight: conformance override ${name} in use\n`);
    reported.add(name);
  }
}

export function conformanceEnabled(): boolean {
  return process.env.SUNLIGHT_CONFORMANCE === "1";
}

export function fixedNowMs(): number | null {
  if (!conformanceEnabled()) return null;
  const v = process.env.SUNLIGHT_FIXED_NOW_MS;
  if (v === undefined || v === "") return null;
  const n = Number(v);
  if (!Number.isSafeInteger(n) || n < 0) return null;
  report("SUNLIGHT_FIXED_NOW_MS");
  return n;
}

export function fixedRequestId(): string | null {
  if (!conformanceEnabled()) return null;
  const v = process.env.SUNLIGHT_FIXED_REQUEST_ID;
  if (v === undefined || v === "") return null;
  report("SUNLIGHT_FIXED_REQUEST_ID");
  return v;
}

export function fixedNonceHex(): string | null {
  if (!conformanceEnabled()) return null;
  const v = process.env.SUNLIGHT_FIXED_NONCE_HEX;
  if (v === undefined || v === "") return null;
  report("SUNLIGHT_FIXED_NONCE_HEX");
  return v;
}

export function keyEntropyHex(): string | null {
  if (!conformanceEnabled()) return null;
  const v = process.env.SUNLIGHT_KEY_ENTROPY_HEX;
  if (v === undefined || v === "") return null;
  report("SUNLIGHT_KEY_ENTROPY_HEX");
  return v;
}

/** Wall clock with the conformance override applied. */
export function nowMs(): number {
  return fixedNowMs() ?? Date.now();
}

/** Fresh 32-byte nonce; replaced by SUNLIGHT_FIXED_NONCE_HEX in conformance. */
export function freshNonceHex(randomHex: () => string): string {
  return fixedNonceHex() ?? randomHex();
}
