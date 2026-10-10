/**
 * Development genesis fixture generator (`sunlight genesis`).
 *
 * Mints a complete local deployment in one shot: a fresh ledger id, fresh
 * admin/audit/producer Ed25519 key files, a genesis stamped at the real
 * clock (or --created-at-ms), the matching trust pin, a deployment config
 * wired to secret-binding env vars, a write bearer token, and a worked
 * signable example — everything `registry serve` + `init` need.
 *
 * The golden conformance fixture (tests/fixtures.json, spec §6.2) keeps its
 * pinned created_at_ms — its vectors are byte-exact known answers and a
 * future-dated genesis is correct there because the suite drives the engine
 * with a fixed clock.  A *live* registry instead seeds its admission clock
 * floor from genesis.created_at_ms, so a deployment meant for real use must
 * be stamped at or before now.  This generator exists so users never have
 * to hand-edit the conformance genesis to try the protocol.
 *
 * All emitted material is development-only: real seeds, a real bearer
 * token, and passphrase-encrypted key files, written exclusive 0600.
 */

import { randomBytes } from "node:crypto";
import { join } from "node:path";
import { B, D } from "./crypto/domains.js";
import { jcsBytes } from "./encoding/jcs.js";
import { writeFileExclusive } from "./fsutil.js";
import { newId } from "./ids.js";
import { generateKey } from "./keys.js";
import type {
  DeploymentConfig, Genesis, StatementBody, TokenBinding, Trust,
} from "./schema.js";

export const GENESIS_ENV = {
  ledger: "SUNLIGHT_LEDGER",
  auditSeed: "SUNLIGHT_AUDIT_SEED",
  tokens: "SUNLIGHT_REGISTRY_TOKENS",
  bearer: "SUNLIGHT_REGISTRY_TOKEN",
} as const;

export interface GenesisEmit {
  ledger: string;
  created_at_ms: number;
  out: string;
  files: Record<string, string>;
  env: Record<string, string>;
}

/**
 * Write the full development fixture set into `outDir` (created if needed;
 * existing files are never overwritten).  Returns paths + env var names —
 * secret values stay inside the 0600 files, never in the result.
 */
export function emitGenesis(outDir: string, passphrase: string, createdAtMs: number): GenesisEmit {
  const admin = generateKey(passphrase, null);
  const audit = generateKey(passphrase, null);
  const producer = generateKey(passphrase, null);

  const ledger = newId("sll");
  const genesis: Genesis = {
    v: "sunlight.genesis/1",
    ledger,
    created_at_ms: createdAtMs,
    admin: admin.key,
    audit: audit.key,
    producers: [producer.key],
  };
  const genesisHash = D("sunlight.genesis/1", genesis);
  const head0 = { seq: 0, hash: genesisHash };

  const trust: Trust = {
    v: "sunlight.trust/1",
    ledger,
    genesis_hash: genesisHash,
    minimum_head: head0,
    denied_keys: [],
    require_training: true,
    max_head_age_ms: 30000,
  };

  // Bearer = base64url(32 raw random bytes); the deployment binds B(raw).
  const tokenRaw = randomBytes(32);
  const tokens: TokenBinding[] = [
    { token_sha256: B(tokenRaw), ledger, role: "write" },
  ];

  const deployment: DeploymentConfig = {
    v: "sunlight.deployment/1",
    ledgers: [{ genesis, audit_secret_binding: GENESIS_ENV.auditSeed }],
    auth_secret_binding: GENESIS_ENV.tokens,
    rate_per_token_per_minute: 120,
    max_inflight_per_ledger: 8,
    protocol: "sunlight/1",
  };

  // A worked example: one tiny artifact plus its ready-to-sign posthoc body.
  const dataset = Buffer.from("sunlight development dataset\n", "utf8");
  const statementBody: StatementBody = {
    v: "sunlight.statement/1",
    id: newId("sls"),
    ledger,
    signer: producer.key.id,
    claimed_at_ms: createdAtMs,
    capture: "posthoc",
    subject: {
      kind: "dataset",
      artifact: { profile: "bytes/1", digest: B(dataset), bytes: dataset.length },
    },
    parents: [],
    details: { type: "creation" },
    evidence: [],
  };

  const auditSeedHex = audit.seed.toString("hex");
  const bearer = tokenRaw.toString("base64url");
  const tokensJson = JSON.stringify(tokens);
  const envSh = [
    "# sunlight development environment — source from the genesis output directory.",
    `# ${GENESIS_ENV.ledger} is a convenience for --ledger flags; the other three`,
    "# are the bindings named by deployment.json / the client config.",
    `export ${GENESIS_ENV.ledger}='${ledger}'`,
    `export ${GENESIS_ENV.auditSeed}='${auditSeedHex}'`,
    `export ${GENESIS_ENV.tokens}='${tokensJson}'`,
    `export ${GENESIS_ENV.bearer}='${bearer}'`,
    "",
  ].join("\n");

  const files: Record<string, string> = {
    genesis: "genesis.json",
    trust: "trust.json",
    deployment: "deployment.json",
    tokens: "tokens.json",
    env: "env.sh",
    bearer: "bearer.txt",
    audit_seed: "audit.seed",
    admin_key: "admin.key.json",
    producer_key: "producer.key.json",
    producer_pub: "producer.pub.json",
    dataset: "dataset.bin",
    statement_body: "statement-body.json",
  };
  const p = (name: keyof typeof files): string => join(outDir, files[name]!);

  writeFileExclusive(p("genesis"), jcsBytes(genesis));
  writeFileExclusive(p("trust"), jcsBytes(trust));
  writeFileExclusive(p("deployment"), jcsBytes(deployment));
  writeFileExclusive(p("tokens"), jcsBytes(tokens));
  writeFileExclusive(p("env"), envSh);
  writeFileExclusive(p("bearer"), bearer + "\n");
  writeFileExclusive(p("audit_seed"), auditSeedHex + "\n");
  writeFileExclusive(p("admin_key"), jcsBytes(admin.file));
  writeFileExclusive(p("producer_key"), jcsBytes(producer.file));
  writeFileExclusive(p("producer_pub"), jcsBytes(producer.key));
  writeFileExclusive(p("dataset"), dataset);
  writeFileExclusive(p("statement_body"), jcsBytes(statementBody));

  const paths: Record<string, string> = {};
  for (const k of Object.keys(files) as (keyof typeof files)[]) paths[k] = p(k);
  return {
    ledger,
    created_at_ms: createdAtMs,
    out: outDir,
    files: paths,
    env: { ...GENESIS_ENV },
  };
}
