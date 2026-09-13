/**
 * Self-hosted reference registry (spec §8 deployment).  Loads a
 * DeploymentConfig plus its two secret bindings from the environment:
 *
 *   - `auth_secret_binding` names an env var holding a strict-JSON
 *     TokenBinding array (1–256 entries, unique token hashes, ledgers drawn
 *     from the deployment).
 *   - each ledger's `audit_secret_binding` names an env var holding the
 *     audit Ed25519 seed as exactly 64 lowercase hex characters.
 *
 * Storage is one SQLite file per ledger under --db-dir.  The same gateway +
 * engine run inside the Cloudflare Worker adapter (worker/), whose store is
 * backed by Durable Object SqlStorage instead of node:sqlite.
 */

import { mkdirSync } from "node:fs";
import { join, dirname, resolve } from "node:path";
import { SunlightError } from "./errors.js";
import { parseStrictJsonString } from "./encoding/strict-json.js";
import { readFileBytesSync } from "./fsutil.js";
import { parseDeploymentConfig, parseTokenBinding, type TokenBinding } from "./schema.js";
import { NodeSqliteStore, applySchema } from "./ledger/store.js";
import { LedgerService } from "./ledger/service.js";
import { RegistryGateway, serveHttp } from "./server.js";
import type { Server } from "node:http";

export interface RegistryInfo {
  listening: string;
  ledgers: string[];
}

export function loadDeployment(deploymentPath: string): {
  tokens: TokenBinding[];
  ledgers: { genesis: unknown; auditSeed: Buffer | null }[];
  ratePerMinute: number;
  maxInflightPerLedger: number;
} {
  const raw = readFileBytesSync(deploymentPath, 256 * 1024);
  const dep = parseDeploymentConfig(parseStrictJsonString(raw.toString("utf8")));

  const tokensJson = process.env[dep.auth_secret_binding];
  if (tokensJson === undefined || tokensJson === "") {
    throw new SunlightError("CONFIG_INVALID", null, new Error(`missing env ${dep.auth_secret_binding}`));
  }
  const parsedTokens = parseStrictJsonString(tokensJson);
  if (!Array.isArray(parsedTokens) || parsedTokens.length < 1 || parsedTokens.length > 256) {
    throw new SunlightError("CONFIG_INVALID");
  }
  const tokens = parsedTokens.map((t) => parseTokenBinding(t));
  const tokenHashes = new Set(tokens.map((t) => t.token_sha256));
  if (tokenHashes.size !== tokens.length) throw new SunlightError("CONFIG_INVALID");
  const ledgerIds = new Set(dep.ledgers.map((l) => l.genesis.ledger));
  for (const t of tokens) {
    if (!ledgerIds.has(t.ledger)) throw new SunlightError("CONFIG_INVALID");
  }

  const ledgers = dep.ledgers.map((l) => {
    const seedHex = process.env[l.audit_secret_binding];
    if (seedHex === undefined || !/^[0-9a-f]{64}$/.test(seedHex)) {
      // Malformed/missing audit secret → that ledger boots READ_ONLY.
      return { genesis: l.genesis, auditSeed: null as Buffer | null };
    }
    return { genesis: l.genesis, auditSeed: Buffer.from(seedHex, "hex") as Buffer | null };
  });
  return {
    tokens,
    ledgers,
    ratePerMinute: dep.rate_per_token_per_minute,
    maxInflightPerLedger: dep.max_inflight_per_ledger,
  };
}

export async function startRegistryFromDeployment(
  deploymentPath: string,
  opts: { dbDir?: string; listen?: string } = {},
): Promise<RegistryInfo> {
  const loaded = loadDeployment(deploymentPath);
  const dbDir = opts.dbDir ?? join(dirname(resolve(deploymentPath)), ".sunlight-registry");
  mkdirSync(dbDir, { recursive: true, mode: 0o700 });

  const services = new Map<string, LedgerService>();
  for (const l of loaded.ledgers) {
    const genesis = l.genesis as { ledger: string };
    const store = new NodeSqliteStore(join(dbDir, `${genesis.ledger}.sqlite`));
    applySchema(store);
    const service = new LedgerService(store, l.genesis, l.auditSeed ?? null);
    services.set(genesis.ledger, service);
  }

  const gateway = new RegistryGateway({
    services,
    tokens: loaded.tokens,
    ratePerMinute: loaded.ratePerMinute,
    maxInflightPerLedger: loaded.maxInflightPerLedger,
  });

  const listen = opts.listen ?? "127.0.0.1:8787";
  const [host, portStr] = listen.includes(":")
    ? [listen.slice(0, listen.lastIndexOf(":")), listen.slice(listen.lastIndexOf(":") + 1)]
    : [listen, "8787"];
  const port = Number(portStr);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new SunlightError("USAGE");

  const server = await serveHttp(gateway, port, host);
  void server;
  return { listening: `${host}:${port}`, ledgers: [...services.keys()] };
}
