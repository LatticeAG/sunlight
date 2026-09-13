/**
 * Client configuration (spec §8).  Strict closed JSON; relative paths resolve
 * against the containing config file; only referenced secret environment
 * variables are read; loopback HTTP only for literal 127.0.0.1 / [::1].
 */

import { dirname, isAbsolute, resolve } from "node:path";
import { existsSync } from "node:fs";
import { SunlightError } from "./errors.js";
import { parseStrictJson } from "./encoding/strict-json.js";
import { parseClientConfig, type ClientConfig } from "./schema.js";
import { readFileBytesSync } from "./fsutil.js";

export const DEFAULT_CONFIG_PATH = "./sunlight.json";

export function loadConfig(path: string): ClientConfig {
  let raw: Buffer;
  try {
    raw = readFileBytesSync(path, 1024 * 1024);
  } catch (e) {
    throw new SunlightError("CONFIG_INVALID", null, e);
  }
  let cfg: ClientConfig;
  try {
    cfg = parseClientConfig(parseStrictJson(raw));
  } catch (e) {
    if (e instanceof SunlightError) throw new SunlightError("CONFIG_INVALID", null, e);
    throw e;
  }
  // Validate origins: https required unless the literal loopback exception
  // applies; no path, query, fragment, or embedded credentials.
  for (const r of cfg.registries) {
    let u: URL;
    try {
      u = new URL(r.origin);
    } catch {
      throw new SunlightError("CONFIG_INVALID");
    }
    if (u.pathname !== "/" || u.search !== "" || u.hash !== "" || u.username !== "" || u.password !== "") {
      throw new SunlightError("CONFIG_INVALID");
    }
    const host = u.hostname;
    const loopback = host === "127.0.0.1" || host === "[::1]" || host === "::1";
    if (u.protocol === "http:") {
      if (!(cfg.allow_loopback_http && loopback)) throw new SunlightError("CONFIG_INVALID");
    } else if (u.protocol !== "https:") {
      throw new SunlightError("CONFIG_INVALID");
    }
  }
  return cfg;
}

/** Resolve a config-relative path (trust_file, cache_dir) to absolute. */
export function configPath(configFile: string, p: string): string {
  if (isAbsolute(p)) return p;
  return resolve(dirname(configFile), p);
}

export interface ResolvedRegistry {
  ledger: string;
  origin: string;
  bearer: string;
  trust_file: string;
}

export function resolveRegistry(
  cfg: ClientConfig,
  configFile: string,
  ledger: string | null,
): ResolvedRegistry {
  const id = ledger ?? cfg.default_ledger;
  const reg = cfg.registries.find((r) => r.ledger === id);
  if (reg === undefined) throw new SunlightError("CONFIG_INVALID");
  const bearer = process.env[reg.bearer_env];
  if (bearer === undefined || bearer === "") {
    throw new SunlightError("CONFIG_INVALID", null, new Error(`missing env ${reg.bearer_env}`));
  }
  return {
    ledger: reg.ledger,
    origin: reg.origin,
    bearer,
    trust_file: configPath(configFile, reg.trust_file),
  };
}
