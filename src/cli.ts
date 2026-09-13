/**
 * `sunlight` CLI (spec §7).  Every mutating operation goes through the same
 * signed-command admission path as the network protocol; the CLI never
 * mutates a ledger directly.
 *
 * Exit codes (spec §7 table):
 *   0 ok · 2 usage/config/schema · 3 well-formed evidence invalid ·
 *   4 untrusted/insufficient evidence · 5 authn/authz/key-file ·
 *   6 retryable network/service · 7 state/idempotency conflict ·
 *   8 I/O/resource · 130 interrupt.
 */

import { readFileSync, readSync } from "node:fs";
import { jcsBytes } from "./encoding/jcs.js";
import { parseStrictJson } from "./encoding/strict-json.js";
import { SunlightError, errorBody, cliExitFor, type ErrorCode } from "./errors.js";
import { newId, randomHex } from "./ids.js";
import { B, D } from "./crypto/domains.js";
import {
  parseBundle, parseGenesis, parsePublicKey, parseSignedHead, parseStatement,
  parseStatementBody, parseTrust, parseCommand,
  type ClientConfig, type CommandBody, type EvidenceRef,
  type ForeignFormat, type HeadRef, type Operation,
  type SignedHead, type StatementBody,
  type Verification, type FreshnessEvidence, type ArtifactObservation,
} from "./schema.js";
import { hashArtifact } from "./artifact.js";
import { signCommand, signStatement, type Signer } from "./objects.js";
import { generateKey, loadKeyFile, writeKeyFile, writePublicKeyFile } from "./keys.js";
import { writeFileExclusive } from "./fsutil.js";
import { loadConfig, resolveRegistry, configPath, DEFAULT_CONFIG_PATH } from "./config.js";
import { Cache } from "./cache.js";
import { RegistryTransport } from "./transport.js";
import { verify } from "./verify.js";
import {
  nowMs, freshNonceHex, fixedRequestId, keyEntropyHex, conformanceEnabled,
} from "./conformance-env.js";
import { runConformance } from "./conformance.js";

const ENV_NAME_RE = /^[A-Z][A-Z0-9_]{0,63}$/;
const FOREIGN_FORMATS = new Set([
  "c2pa/opaque", "fv.sunlight-export/1", "vislineage-bundle/1",
  "world/opaque", "mint/opaque", "treaty/opaque", "generic/opaque",
]);

interface Flags {
  positional: string[];
  opts: Record<string, string | boolean>;
}

function parseArgv(argv: string[]): Flags {
  const positional: string[] = [];
  const opts: Record<string, string | boolean> = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a.startsWith("--")) {
      const eq = a.indexOf("=");
      if (eq !== -1) {
        opts[a.slice(2, eq)] = a.slice(eq + 1);
      } else {
        const next = argv[i + 1];
        if (next !== undefined && !next.startsWith("--")) {
          opts[a.slice(2)] = next;
          i++;
        } else {
          opts[a.slice(2)] = true;
        }
      }
    } else {
      positional.push(a);
    }
  }
  return { positional, opts };
}

function needOpt(f: Flags, name: string): string {
  const v = f.opts[name];
  if (typeof v !== "string" || v === "") throw new SunlightError("USAGE");
  return v;
}
function optStr(f: Flags, name: string): string | null {
  const v = f.opts[name];
  return typeof v === "string" && v !== "" ? v : null;
}

function readJsonFile(path: string): unknown {
  let raw: Buffer;
  try {
    raw = readFileSync(path);
  } catch (e) {
    throw new SunlightError("IO_ERROR", null, e);
  }
  return parseStrictJson(raw);
}

/** --cut PATH accepts a bare HeadRef or a SignedHead emitted by `sunlight head`. */
function cutFrom(flags: Flags): HeadRef | null {
  const p = optStr(flags, "cut");
  if (p === null) return null;
  const v = readJsonFile(p);
  if (typeof v !== "object" || v === null || Array.isArray(v)) {
    throw new SunlightError("SCHEMA_INVALID");
  }
  const o = v as Record<string, unknown>;
  if (typeof o.seq === "number" && typeof o.hash === "string") {
    return { seq: o.seq, hash: o.hash };
  }
  const head = parseSignedHead(v);
  return head.body.head;
}

interface Ctx {
  flags: Flags;
  configPath: string;
  cfg: ClientConfig;
  registry: { ledger: string; origin: string; bearer: string; trust_file: string };
  transport: RegistryTransport;
  cache: Cache;
}

/** Load config + resolve the ledger registry + build transport/cache. */
function clientCtx(flags: Flags, forWrite: boolean): Ctx {
  if (flags.opts.offline === true) {
    // --offline conflicts with network-required commands; fail USAGE before
    // any private key is read.
    throw new SunlightError("USAGE");
  }
  const configPath = optStr(flags, "config") ?? DEFAULT_CONFIG_PATH;
  const cfg = loadConfig(configPath);
  // --ledger is allowed only on read commands and must match a configured
  // registry entry; writes always use default_ledger.
  const ledgerFlag = optStr(flags, "ledger");
  const registry = resolveRegistry(cfg, configPath, forWrite ? null : ledgerFlag);
  const timeout = optStr(flags, "timeout-ms");
  let readTimeout = cfg.read_timeout_ms;
  if (timeout !== null) {
    const n = Number(timeout);
    if (!Number.isSafeInteger(n) || n < 100 || n > 30000) throw new SunlightError("USAGE");
    readTimeout = n;
  }
  const transport = new RegistryTransport({
    origin: registry.origin,
    bearer: registry.bearer,
    connectTimeoutMs: cfg.connect_timeout_ms,
    readTimeoutMs: readTimeout,
    requestId: () => fixedRequestId() ?? newId("slq"),
  });
  const cache = new Cache(configPath2Dir(configPath, cfg.cache_dir));
  return { flags, configPath, cfg, registry, transport, cache };
}

function configPath2Dir(cfgPath: string, cacheDir: string): string {
  return configPath(cfgPath, cacheDir);
}

/** Fetch a fresh challenged head (conformance nonce when enabled). */
async function fetchHead(ctx: Ctx): Promise<SignedHead> {
  const nonce = freshNonceHex(() => randomHex(32));
  const res = await ctx.transport.rpc("head.get", {
    ledger: ctx.registry.ledger,
    nonce_hex: nonce,
  });
  return parseSignedHead(res);
}

function readCutOrHead(ctx: Ctx, flags: Flags): Promise<HeadRef> | HeadRef {
  const cut = cutFrom(flags);
  if (cut !== null) return cut;
  return fetchHead(ctx).then((h) => h.body.head);
}

/** sign + persist + submit a command for the given operation. */
async function submitOperation(
  ctx: Ctx,
  signer: Signer,
  operation: Operation,
): Promise<unknown> {
  const head = await fetchHead(ctx);
  const body: CommandBody = {
    v: "sunlight.command/1",
    id: fixedRequestId() ?? newId("slq"),
    ledger: ctx.registry.ledger,
    signer: signer.key.id,
    expected_head: head.body.head,
    issued_at_ms: nowMs(),
    expires_at_ms: nowMs() + 300_000,
    operation,
  };
  const command = await signCommand(body, signer);
  ctx.cache.storePending(command.body.id, command);
  ctx.cache.journal("local.CommandDurable", null, null, nowMs());
  try {
    const result = await ctx.transport.rpc("append", {
      ledger: ctx.registry.ledger,
      command,
    }, command.body.id);
    ctx.cache.dropPending(command.body.id);
    return result;
  } catch (e) {
    // Leave the pending command for `command submit` recovery.
    throw e;
  }
}

export async function runCli(argv: string[]): Promise<{ code: number; result?: unknown; human?: string; served?: boolean }> {
  const flags = parseArgv(argv);
  const pos = flags.positional;
  const cmd = pos[0];

  switch (cmd) {
    case "init": {
      const ledger = needOpt(flags, "ledger");
      const genesisPath = needOpt(flags, "genesis");
      const trustPath = needOpt(flags, "trust");
      const origin = needOpt(flags, "origin");
      const bearerEnv = needOpt(flags, "bearer-env");
      const out = needOpt(flags, "out");
      if (!ENV_NAME_RE.test(bearerEnv)) throw new SunlightError("USAGE");
      const genesis = parseGenesis(readJsonFile(genesisPath));
      if (genesis.ledger !== ledger) throw new SunlightError("UNTRUSTED_GENESIS");
      const trust = parseTrust(readJsonFile(trustPath));
      if (trust.ledger !== genesis.ledger || trust.genesis_hash !== D("sunlight.genesis/1", genesis)) {
        throw new SunlightError("UNTRUSTED_GENESIS");
      }
      let url: URL;
      try {
        url = new URL(origin);
      } catch {
        throw new SunlightError("USAGE");
      }
      const loopback = url.hostname === "127.0.0.1" || url.hostname === "[::1]" || url.hostname === "::1";
      const allowLoopback = url.protocol === "http:" && loopback;
      if (url.protocol !== "https:" && !allowLoopback) throw new SunlightError("USAGE");
      const cfg: ClientConfig = {
        v: "sunlight.config/1",
        default_ledger: ledger,
        registries: [{ ledger, origin, bearer_env: bearerEnv, trust_file: trustPath }],
        cache_dir: "./.sunlight-cache",
        connect_timeout_ms: 3000,
        read_timeout_ms: 10000,
        allow_loopback_http: allowLoopback,
      };
      writeFileExclusive(out, jcsBytes(cfg), 0o600);
      return { code: 0, result: { config: out, ledger } };
    }

    case "key": {
      const sub = pos[1];
      if (sub === "generate") {
        const out = needOpt(flags, "out");
        const publicOut = needOpt(flags, "public-out");
        const entropyHex = keyEntropyHex();
        const entropy = entropyHex === null ? null : Buffer.from(entropyHex, "hex");
        const { key, file } = generateKey(passphraseForKey(flags), entropy);
        writeKeyFile(out, file);
        writePublicKeyFile(publicOut, key);
        return { code: 0, result: { private_path: out, public_path: publicOut, key } };
      }
      const ctx = clientCtx(flags, true);
      const adminKey = loadKeyFile(needOpt(flags, "admin-key"), null);
      let operation: Operation;
      if (sub === "add") {
        const pub = parsePublicKey(readJsonFile(needOpt(flags, "public")));
        operation = { type: "key_add", key: pub };
      } else if (sub === "retire") {
        operation = { type: "key_retire", key: needOpt(flags, "id") };
      } else if (sub === "revoke") {
        const reason = needOpt(flags, "reason");
        if (reason !== "compromise" && reason !== "withdrawn") throw new SunlightError("USAGE");
        operation = { type: "key_revoke", key: needOpt(flags, "id"), reason };
      } else {
        throw new SunlightError("USAGE");
      }
      return { code: 0, result: await submitOperation(ctx, adminKey, operation) };
    }

    case "hash": {
      const file = pos[1] ?? optStr(flags, "file");
      if (file === null || file === undefined) throw new SunlightError("USAGE");
      const profile = needOpt(flags, "profile");
      if (profile !== "bytes/1" && profile !== "tree/1" && profile !== "jcs/1") {
        throw new SunlightError("USAGE");
      }
      return { code: 0, result: await hashArtifact({ profile, path: file }) };
    }

    case "sign": {
      const bodyPath = needOpt(flags, "body");
      const artifactPath = needOpt(flags, "artifact");
      const keyPath = needOpt(flags, "key");
      const out = optStr(flags, "out");
      const body = parseStatementBody(readJsonFile(bodyPath));
      if (body.capture !== "posthoc") throw new SunlightError("USAGE");
      const artifact = await hashArtifact({ profile: body.subject.artifact.profile, path: artifactPath });
      const want = body.subject.artifact;
      if (
        artifact.digest !== want.digest ||
        artifact.bytes !== want.bytes ||
        artifact.profile !== want.profile
      ) {
        throw new SunlightError("HASH_MISMATCH");
      }
      const signer = loadKeyFile(keyPath, null);
      const statement = await signStatement(body, signer);
      if (out !== null) writeFileExclusive(out, jcsBytes(statement), 0o600);
      return { code: 0, result: statement };
    }

    case "submit": {
      const ctx = clientCtx(flags, true);
      const statement = parseStatement(readJsonFile(needOpt(flags, "statement")));
      const signer = loadKeyFile(needOpt(flags, "key"), null);
      const head = await fetchHead(ctx);
      const body: CommandBody = {
        v: "sunlight.command/1",
        id: fixedRequestId() ?? newId("slq"),
        ledger: ctx.registry.ledger,
        signer: signer.key.id,
        expected_head: head.body.head,
        issued_at_ms: nowMs(),
        expires_at_ms: nowMs() + 300_000,
        operation: { type: "claim", statement },
      };
      const command = await signCommand(body, signer);
      ctx.cache.storePending(command.body.id, command);
      const commandOut = optStr(flags, "command-out");
      if (commandOut !== null) writeFileExclusive(commandOut, jcsBytes(command), 0o600);
      try {
        const result = await ctx.transport.rpc("append", {
          ledger: ctx.registry.ledger, command,
        }, command.body.id);
        ctx.cache.dropPending(command.body.id);
        return { code: 0, result };
      } catch (e) {
        throw e;
      }
    }

    case "command": {
      if (pos[1] !== "submit") throw new SunlightError("USAGE");
      const ctx = clientCtx(flags, true);
      const command = parseCommand(readJsonFile(needOpt(flags, "command")));
      const result = await ctx.transport.rpc("append", {
        ledger: ctx.registry.ledger, command,
      }, command.body.id);
      ctx.cache.dropPending(command.body.id);
      return { code: 0, result };
    }

    case "retract": {
      const ctx = clientCtx(flags, true);
      const signer = loadKeyFile(needOpt(flags, "key"), null);
      const reason = needOpt(flags, "reason");
      if (reason !== "incorrect" && reason !== "withdrawn") throw new SunlightError("USAGE");
      const operation: Operation = {
        type: "retract",
        statement: needOpt(flags, "statement"),
        reason,
      };
      return { code: 0, result: await submitOperation(ctx, signer, operation) };
    }

    case "head": {
      const ctx = clientCtx(flags, false);
      return { code: 0, result: await fetchHead(ctx) };
    }

    case "lookup": {
      const ctx = clientCtx(flags, false);
      const artifactPath = needOpt(flags, "artifact");
      const profile = needOpt(flags, "profile");
      if (profile !== "bytes/1" && profile !== "tree/1" && profile !== "jcs/1") {
        throw new SunlightError("USAGE");
      }
      const artifact = await hashArtifact({ profile, path: artifactPath });
      const cut = await readCutOrHead(ctx, flags);
      const limit = Number(optStr(flags, "limit") ?? "100");
      const afterSeq = Number(optStr(flags, "after-seq") ?? "0");
      const result = await ctx.transport.rpc("artifact.lookup", {
        ledger: ctx.registry.ledger,
        profile,
        digest: artifact.digest,
        cut,
        after_seq: afterSeq,
        limit,
      });
      return { code: 0, result };
    }

    case "statement": {
      const ctx = clientCtx(flags, false);
      const cut = await readCutOrHead(ctx, flags);
      const result = await ctx.transport.rpc("statement.get", {
        ledger: ctx.registry.ledger,
        statement: needOpt(flags, "hash"),
        cut,
      });
      return { code: 0, result };
    }

    case "entries": {
      const ctx = clientCtx(flags, false);
      const cut = await readCutOrHead(ctx, flags);
      const limit = Number(optStr(flags, "limit") ?? "100");
      const result = await ctx.transport.rpc("entries.list", {
        ledger: ctx.registry.ledger,
        after: Number(needOpt(flags, "after")),
        cut,
        limit,
      });
      return { code: 0, result };
    }

    case "export": {
      const ctx = clientCtx(flags, false);
      const out = needOpt(flags, "out");
      const cut = await readCutOrHead(ctx, flags);
      const res = await ctx.transport.rpc("bundle.export", {
        ledger: ctx.registry.ledger,
        target: needOpt(flags, "statement"),
        cut,
      }) as { bundle: unknown; digest: string };
      const bundle = parseBundle(res.bundle);
      writeFileExclusive(out, jcsBytes(bundle), 0o600);
      ctx.cache.storeBundle(res.digest, bundle);
      return { code: 0, result: { output: out, digest: res.digest, head: bundle.head.body.head } };
    }

    case "verify": {
      const bundle = parseBundle(readJsonFile(needOpt(flags, "bundle")));
      const trust = parseTrust(readJsonFile(needOpt(flags, "trust")));
      let observation: ArtifactObservation | null = null;
      const artifactPath = optStr(flags, "artifact");
      if (artifactPath !== null) {
        const profile = needOpt(flags, "profile");
        if (profile !== "bytes/1" && profile !== "tree/1" && profile !== "jcs/1") {
          throw new SunlightError("USAGE");
        }
        observation = { artifact: await hashArtifact({ profile, path: artifactPath }) };
      }
      let freshness: FreshnessEvidence | null = null;
      let bundleToVerify = bundle;
      if (flags.opts.online === true) {
        if (flags.opts.offline === true) throw new SunlightError("USAGE");
        const ctx = clientCtx(flags, false);
        // Challenged head → export at that cut → second challenged head.
        // A moved head retries at most three times, then HEAD_CONFLICT.
        let done = false;
        for (let attempt = 0; attempt < 3 && !done; attempt++) {
          const nonce0 = freshNonceHex(() => randomHex(32));
          const sent0 = nowMs();
          const h0raw = await ctx.transport.rpc("head.get", {
            ledger: ctx.registry.ledger, nonce_hex: nonce0,
          });
          const h0 = parseSignedHead(h0raw);
          const recv0 = nowMs();
          const remote = await ctx.transport.rpc("bundle.export", {
            ledger: ctx.registry.ledger,
            target: bundle.target,
            cut: h0.body.head,
          }) as { bundle: unknown };
          const candidate = parseBundle(remote.bundle);
          const nonce1 = freshNonceHex(() => randomHex(32));
          const h1 = parseSignedHead(await ctx.transport.rpc("head.get", {
            ledger: ctx.registry.ledger, nonce_hex: nonce1,
          }));
          if (h1.body.head.seq === h0.body.head.seq && h1.body.head.hash === h0.body.head.hash) {
            bundleToVerify = candidate;
            freshness = {
              head: h0,
              expected_nonce_hex: nonce0,
              sent_at_ms: sent0,
              received_at_ms: recv0,
            };
            done = true;
          }
        }
        if (!done) throw new SunlightError("HEAD_CONFLICT");
      }
      const v = verify({ bundle: bundleToVerify, trust, observation, freshness });
      // Verification result is the command result; the exit code classifies it.
      let code = 0;
      if (v.overall === "INVALID") code = 3;
      else if (v.overall === "UNVERIFIED") code = 4;
      return { code, result: v, human: humanVerify(v) };
    }

    case "import": {
      if (pos[1] !== "evidence") throw new SunlightError("USAGE");
      const input = needOpt(flags, "input");
      const format = needOpt(flags, "format");
      if (!FOREIGN_FORMATS.has(format)) throw new SunlightError("USAGE");
      const bodyPath = needOpt(flags, "body");
      const keyPath = needOpt(flags, "key");
      const out = optStr(flags, "out");
      let rawInput: Buffer;
      try {
        rawInput = readFileSync(input);
      } catch (e) {
        throw new SunlightError("IO_ERROR", null, e);
      }
      const artifact = { profile: "bytes/1" as const, digest: B(rawInput), bytes: rawInput.length };
      // Only vislineage-bundle/1 carries a native commitment: the bundle's own
      // `hash` field, checked for consistency against actual bytes per spec.
      let sourceCommitment: string | null = null;
      if (format === "vislineage-bundle/1") {
        let bundleJson: unknown;
        try {
          bundleJson = parseStrictJson(rawInput);
        } catch (e) {
          throw new SunlightError("SCHEMA_INVALID", null, e);
        }
        const bh = (bundleJson as Record<string, unknown>).hash;
        if (typeof bh !== "string" || !/^sha256:[0-9a-f]{64}$/.test(bh)) {
          throw new SunlightError("SCHEMA_INVALID");
        }
        sourceCommitment = bh;
      }
      const computed: EvidenceRef = {
        artifact,
        format: format as ForeignFormat,
        source_commitment: sourceCommitment,
        assessment: "OPAQUE",
      };
      const body = parseStatementBody(readJsonFile(bodyPath));
      if (body.capture !== "posthoc") throw new SunlightError("USAGE");
      // The requested EvidenceRef in the body must match the recomputed one.
      const requested = body.evidence;
      if (requested.length > 1) throw new SunlightError("SCHEMA_INVALID");
      if (requested.length === 1) {
        const r = requested[0]!;
        if (
          r.format !== computed.format ||
          r.source_commitment !== computed.source_commitment ||
          r.assessment !== "OPAQUE" ||
          r.artifact.profile !== computed.artifact.profile ||
          r.artifact.digest !== computed.artifact.digest ||
          r.artifact.bytes !== computed.artifact.bytes
        ) {
          throw new SunlightError("HASH_MISMATCH");
        }
      }
      const signedBody: StatementBody = { ...body, evidence: [computed] };
      const signer = loadKeyFile(keyPath, null);
      const statement = await signStatement(signedBody, signer);
      if (out !== null) writeFileExclusive(out, jcsBytes(statement), 0o600);
      return { code: 0, result: statement };
    }

    case "audit": {
      if (pos[1] !== "verify") throw new SunlightError("USAGE");
      const bundle = parseBundle(readJsonFile(needOpt(flags, "bundle")));
      const trust = parseTrust(readJsonFile(needOpt(flags, "trust")));
      const v = verify({ bundle, trust, observation: null, freshness: null });
      if (v.integrity !== "VALID" || v.authority === "UNTRUSTED" || v.authority === "UNKNOWN") {
        const code = (v.reasons[0] ?? "HASH_MISMATCH") as ErrorCode;
        throw new SunlightError(code === "UNTRUSTED_GENESIS" ? code : code);
      }
      // Revoked/denied authority and incomplete lineage are reportable but the
      // audit verdict itself is integrity+pin only.
      return { code: 0, result: { integrity: "VALID", head: v.head } };
    }

    case "conformance": {
      const suite = optStr(flags, "suite") ?? "TV-S";
      if (suite !== "TV-S") throw new SunlightError("USAGE");
      const report = await runConformance();
      const out = optStr(flags, "out");
      if (out !== null) {
        writeFileExclusive(out, Buffer.from(JSON.stringify(report, null, 2) + "\n"), 0o600);
      }
      return {
        code: 0,
        result: {
          suite: "TV-S",
          vectors: report.vectors.length,
          passed: report.vectors.filter((v) => v.pass).length,
          failed: report.vectors.filter((v) => !v.pass).length,
        },
      };
    }

    case "registry": {
      if (pos[1] !== "serve") throw new SunlightError("USAGE");
      const deploymentPath = needOpt(flags, "deployment");
      const listen = optStr(flags, "listen") ?? undefined;
      const { startRegistryFromDeployment } = await import("./registry.js");
      const info = await startRegistryFromDeployment(deploymentPath, { listen });
      // Emit the listening report, then serve until interrupted.
      const asJson = flags.opts.json === true;
      process.stdout.write(
        asJson ? JSON.stringify(info) + "\n" : JSON.stringify(info, null, 2) + "\n",
      );
      await new Promise<void>((resolve) => {
        process.on("SIGINT", resolve);
        process.on("SIGTERM", resolve);
      });
      return { code: 0, result: null, served: true };
    }

    default:
      throw new SunlightError("USAGE");
  }
}

function passphraseForKey(_flags: Flags): string {
  // Passphrases come from SUNLIGHT_KEY_PASSPHRASE_FD or a TTY (keys.ts);
  // for generation the same rules apply — never argv.
  const fd = process.env.SUNLIGHT_KEY_PASSPHRASE_FD;
  if (fd !== undefined && fd !== "") {
    const fdN = Number(fd);
    if (!Number.isInteger(fdN) || fdN < 0) throw new SunlightError("USAGE");
    const chunks: Buffer[] = [];
    const buf = Buffer.allocUnsafe(4096);
    for (;;) {
      const n = readSync(fdN, buf, 0, buf.length, null);
      if (n <= 0) break;
      chunks.push(buf.subarray(0, n));
      if (Buffer.concat(chunks).includes(0x0a)) break;
    }
    return Buffer.concat(chunks).toString("utf8").split("\n")[0]!.replace(/\r$/, "");
  }
  throw new SunlightError("KEY_ERROR", null, new Error("passphrase required via SUNLIGHT_KEY_PASSPHRASE_FD"));
}

function humanVerify(v: Verification): string {
  const lines = [
    `DECLARED LINEAGE — ledger verification result`,
    `  integrity:    ${v.integrity}`,
    `  lineage:      ${v.lineage}`,
    `  authority:    ${v.authority}`,
    `  freshness:    ${v.freshness}`,
    `  artifact:     ${v.artifact}`,
    `  claim truth:  ${v.claim_truth}`,
    `  overall:      ${v.overall}`,
  ];
  if (v.head !== null) lines.push(`  head:         seq ${v.head.seq} ${v.head.hash}`);
  if (v.reasons.length > 0) lines.push(`  reasons:      ${v.reasons.join(", ")}`);
  lines.push("", "  TRAINING/OWNERSHIP NOT PROVEN — a signature attests the");
  lines.push("  declared lineage, not the factual truth of its claims.");
  return lines.join("\n");
}

/** Process entry: renders the result/error and resolves the exit code. */
export async function main(argv: string[]): Promise<number> {
  const flags = parseArgv(argv);
  const json = flags.opts.json === true;
  try {
    const r = await runCli(argv);
    if (r.served === true) {
      // `registry serve` already emitted its listening report.
      return r.code;
    }
    if (json) {
      process.stdout.write(JSON.stringify(r.result) + "\n");
    } else if (r.human !== undefined) {
      process.stdout.write(r.human + "\n");
      process.stdout.write(JSON.stringify(r.result, null, 2) + "\n");
    } else {
      process.stdout.write(JSON.stringify(r.result, null, 2) + "\n");
    }
    return r.code;
  } catch (e) {
    const body = errorBody(e);
    const exit = e instanceof SunlightError ? cliExitFor(e.code) : 1;
    process.stderr.write(JSON.stringify({ error: body }) + "\n");
    return exit;
  }
}
