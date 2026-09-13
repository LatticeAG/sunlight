/**
 * Closed-shape validators for every protocol and persistence object (spec §3).
 *
 * All shapes are closed: unknown properties, missing required properties, and
 * unrecognized enum values are errors.  Arrays that carry a sorting rule are
 * REJECTED when unsorted — validators never silently reorder signed payloads.
 * Failures throw SunlightError(SCHEMA_INVALID), or VERSION_UNSUPPORTED when a
 * present `v` string names an unknown object version.
 */

import { SunlightError } from "./errors.js";
import { isValidId } from "./ids.js";
import { jcsBytes } from "./encoding/jcs.js";
import { DIGEST_RE, HEX32_RE, HEX64_RE } from "./crypto/domains.js";
import { isValidPublicKey } from "./crypto/ed25519.js";

export const MAX_TEXT_UTF8 = 1024;
export const MAX_PARENTS = 64;
export const MAX_EVIDENCE = 16;
export const MAX_STATEMENT_BYTES = 16 * 1024;
export const MAX_COMMAND_BYTES = 24 * 1024;
export const MAX_ENTRY_BYTES = 32 * 1024;
export const MAX_BUNDLE_ENTRIES = 4096;
export const MAX_BUNDLE_BYTES = 16 * 1024 * 1024;
export const MAX_MANIFEST_BYTES = 1024 * 1024;
export const MAX_MANIFEST_FILES = 10000;
export const MAX_HEAD_AGE_MS = 30000;
export const MAX_COMMAND_TTL_MS = 300000;

// ---- spec §3 type aliases ------------------------------------------------

export type Digest = string;
export type Hex32 = string;
export type Hex64 = string;
export type LedgerId = string;
export type KeyId = string;
export type StatementId = string;
export type RequestId = string;
export type EntryId = string;
export type RunId = string;
export type ActionId = string;

export interface PublicKey {
  id: KeyId;
  public_hex: Hex32;
}
export interface HeadRef {
  seq: number;
  hash: Digest;
}
export type ArtifactProfile = "bytes/1" | "jcs/1" | "tree/1";
export interface Artifact {
  profile: ArtifactProfile;
  digest: Digest;
  bytes: number;
}
export interface TreeFile {
  path: string;
  digest: Digest;
  bytes: number;
}
export interface TreeManifest {
  v: "sunlight.tree/1";
  files: TreeFile[];
}
export interface Genesis {
  v: "sunlight.genesis/1";
  ledger: LedgerId;
  created_at_ms: number;
  admin: PublicKey;
  audit: PublicKey;
  producers: PublicKey[];
}
export type ParentRelation = "source" | "dataset" | "base_model" | "run" | "model";
export interface Parent {
  statement: Digest;
  artifact: Digest;
  relation: ParentRelation;
}
export type ForeignFormat =
  | "c2pa/opaque" | "fv.sunlight-export/1" | "vislineage-bundle/1"
  | "world/opaque" | "mint/opaque" | "treaty/opaque" | "generic/opaque";
export interface EvidenceRef {
  artifact: Artifact;
  format: ForeignFormat;
  source_commitment: Digest | null;
  assessment: "OPAQUE";
}
export type Details =
  | { type: "creation" }
  | { type: "transform"; procedure: Digest }
  | { type: "training"; run_id: RunId; code: Digest; environment: Digest; parameters: Digest; seed: string | null }
  | { type: "model" }
  | { type: "action"; action_id: ActionId; input: Digest; output: Digest | null; outcome: "attempted" | "completed" | "failed"; context: Digest | null };
export type SubjectKind = "dataset" | "run" | "model" | "action" | "evidence";
export type CaptureMode = "creation_hook" | "posthoc";
export interface StatementBody {
  v: "sunlight.statement/1";
  id: StatementId;
  ledger: LedgerId;
  signer: KeyId;
  claimed_at_ms: number;
  capture: CaptureMode;
  subject: { kind: SubjectKind; artifact: Artifact };
  parents: Parent[];
  details: Details;
  evidence: EvidenceRef[];
}
export interface Statement {
  body: StatementBody;
  hash: Digest;
  signature_hex: Hex64;
}
export interface Descriptor {
  v: "sunlight.descriptor/1";
  kind: "run" | "action";
  parents: Parent[];
  details: Details;
}
export type Operation =
  | { type: "claim"; statement: Statement }
  | { type: "key_add"; key: PublicKey }
  | { type: "key_retire"; key: KeyId }
  | { type: "key_revoke"; key: KeyId; reason: "compromise" | "withdrawn" }
  | { type: "retract"; statement: Digest; reason: "incorrect" | "withdrawn" };
export interface CommandBody {
  v: "sunlight.command/1";
  id: RequestId;
  ledger: LedgerId;
  signer: KeyId;
  expected_head: HeadRef;
  issued_at_ms: number;
  expires_at_ms: number;
  operation: Operation;
}
export interface Command {
  body: CommandBody;
  hash: Digest;
  signature_hex: Hex64;
}
export type Event = "StatementRecorded" | "KeyAdded" | "KeyRetired" | "KeyRevoked" | "StatementRetracted";
export interface ReceiptBody {
  v: "sunlight.receipt/1";
  id: EntryId;
  ledger: LedgerId;
  seq: number;
  previous_hash: Digest;
  command_hash: Digest;
  statement_hash: Digest | null;
  event: Event;
  committed_at_ms: number;
}
export interface Receipt {
  body: ReceiptBody;
  hash: Digest;
  signature_hex: Hex64;
}
export interface Entry {
  command: Command;
  receipt: Receipt;
}
export interface HeadBody {
  v: "sunlight.head/1";
  ledger: LedgerId;
  genesis_hash: Digest;
  head: HeadRef;
  observed_at_ms: number;
  nonce_hex: Hex32 | null;
}
export interface SignedHead {
  body: HeadBody;
  hash: Digest;
  signature_hex: Hex64;
}
export interface Bundle {
  v: "sunlight.bundle/1";
  genesis: Genesis;
  entries: Entry[];
  head: SignedHead;
  target: Digest;
}
export interface Trust {
  v: "sunlight.trust/1";
  ledger: LedgerId;
  genesis_hash: Digest;
  minimum_head: HeadRef;
  denied_keys: KeyId[];
  require_training: boolean;
  max_head_age_ms: number;
}
export interface FreshnessEvidence {
  head: SignedHead;
  expected_nonce_hex: Hex32;
  sent_at_ms: number;
  received_at_ms: number;
}
export interface ArtifactObservation {
  artifact: Artifact;
}
export interface Verification {
  integrity: "VALID" | "INVALID";
  lineage: "COMPLETE_DECLARED" | "INCOMPLETE" | "INVALID";
  authority: "TRUSTED_AT_HEAD" | "UNTRUSTED" | "REVOKED" | "UNKNOWN";
  freshness: "CURRENT" | "STALE" | "OFFLINE";
  artifact: "MATCH" | "MISMATCH" | "NOT_SUPPLIED" | "UNCHECKED";
  claim_truth: "NOT_PROVEN";
  overall: "VERIFIED" | "UNVERIFIED" | "INVALID";
  reasons: string[];
  head: HeadRef | null;
}
export interface AppendResult {
  entry: Entry;
  head: HeadRef;
}
export interface LookupItem {
  statement: Digest;
  id: StatementId;
  kind: SubjectKind;
  signer: KeyId;
  capture: CaptureMode;
  retracted: boolean;
  key_status: "ACTIVE" | "RETIRED" | "REVOKED";
}
export interface StatementResult {
  statement: Statement;
  recorded_at: number;
  retracted: boolean;
  key_status: "ACTIVE" | "RETIRED" | "REVOKED";
  head: HeadRef;
}
export interface ErrorBody {
  code: string;
  retryable: boolean;
  head: HeadRef | null;
}
export interface RpcRequest {
  v: "sunlight.rpc/1";
  id: RequestId;
  method: string;
  params: unknown;
}
export type RpcResponse =
  | { v: "sunlight.rpc/1"; id: RequestId; ok: true; result: unknown }
  | { v: "sunlight.rpc/1"; id: RequestId; ok: false; error: ErrorBody };

export interface ClientConfig {
  v: "sunlight.config/1";
  default_ledger: LedgerId;
  registries: { ledger: LedgerId; origin: string; bearer_env: string; trust_file: string }[];
  cache_dir: string;
  connect_timeout_ms: number;
  read_timeout_ms: number;
  allow_loopback_http: boolean;
}
export interface LocalKeyFile {
  v: "sunlight.keyfile/1";
  key: PublicKey;
  encrypted_pkcs8_pem: string;
}
export interface TokenBinding {
  token_sha256: Digest;
  ledger: LedgerId;
  role: "read" | "write";
}
export interface DeploymentConfig {
  v: "sunlight.deployment/1";
  ledgers: { genesis: Genesis; audit_secret_binding: string }[];
  auth_secret_binding: string;
  rate_per_token_per_minute: number;
  max_inflight_per_ledger: number;
  protocol: "sunlight/1";
}
export interface LocalJournalRecord {
  v: "sunlight.local/1";
  command: Digest | null;
  statement: Digest | null;
  event: string;
  at_ms: number;
}

// ---- primitives ------------------------------------------------------------

function bad(msg: string): never {
  throw new SunlightError("SCHEMA_INVALID", null, new Error(msg));
}

function unsupported(): never {
  throw new SunlightError("VERSION_UNSUPPORTED");
}

function isObj(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Closed-shape check: exactly the named keys, all present. */
function keys(v: Record<string, unknown>, required: string[]): void {
  for (const k of required) {
    if (!(k in v)) bad(`missing property ${k}`);
  }
  for (const k of Object.keys(v)) {
    if (!required.includes(k)) bad(`unknown property ${k}`);
  }
}

function isInt(v: unknown): v is number {
  return typeof v === "number" && Number.isSafeInteger(v) && v >= 0;
}

function needInt(v: unknown, name: string): number {
  if (!isInt(v)) bad(`${name} not an integer`);
  return v;
}

function needStr(v: unknown, name: string): string {
  if (typeof v !== "string") bad(`${name} not a string`);
  if (Buffer.byteLength(v, "utf8") > MAX_TEXT_UTF8) bad(`${name} exceeds text limit`);
  return v;
}

function needBool(v: unknown, name: string): boolean {
  if (typeof v !== "boolean") bad(`${name} not a boolean`);
  return v;
}

function needDigest(v: unknown, name: string): Digest {
  const s = needStr(v, name);
  if (!DIGEST_RE.test(s)) bad(`${name} not a digest`);
  return s;
}

function needHex32(v: unknown, name: string): Hex32 {
  const s = needStr(v, name);
  if (!HEX32_RE.test(s)) bad(`${name} not 64-hex`);
  return s;
}

function needHex64(v: unknown, name: string): Hex64 {
  const s = needStr(v, name);
  if (!HEX64_RE.test(s)) bad(`${name} not 128-hex`);
  return s;
}

function needId(v: unknown, prefix: "sll" | "slk" | "sls" | "slq" | "sle" | "slr" | "sla", name: string): string {
  const s = needStr(v, name);
  if (!isValidId(s, prefix)) bad(`${name} not a ${prefix}_ id`);
  return s;
}

function needEnum<T extends string>(v: unknown, name: string, allowed: readonly T[]): T {
  const s = needStr(v, name);
  if (!allowed.includes(s as T)) bad(`${name} not in enum`);
  return s as T;
}

function needArr(v: unknown, name: string): unknown[] {
  if (!Array.isArray(v)) bad(`${name} not an array`);
  return v;
}

function asciiCompare(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

/** Reject arrays that violate an ascending order or carry duplicate keys. */
function requireSortedUnique<T>(arr: T[], key: (t: T) => string, name: string): void {
  let prev: string | null = null;
  for (const item of arr) {
    const k = key(item);
    if (prev !== null && asciiCompare(prev, k) >= 0) {
      bad(`${name} not strictly sorted/unique`);
    }
    prev = k;
  }
}

// ---- object validators -----------------------------------------------------

export function parsePublicKey(v: unknown): PublicKey {
  if (!isObj(v)) bad("public key not object");
  keys(v, ["id", "public_hex"]);
  const key = { id: needId(v.id, "slk", "key.id"), public_hex: needHex32(v.public_hex, "key.public_hex") };
  if (!isValidPublicKey(Buffer.from(key.public_hex, "hex"))) {
    bad("key.public_hex not a canonical Ed25519 key");
  }
  return key;
}

export function parseHeadRef(v: unknown): HeadRef {
  if (!isObj(v)) bad("head ref not object");
  keys(v, ["seq", "hash"]);
  return { seq: needInt(v.seq, "head.seq"), hash: needDigest(v.hash, "head.hash") };
}

const ARTIFACT_PROFILES = ["bytes/1", "jcs/1", "tree/1"] as const;

export function parseArtifact(v: unknown): Artifact {
  if (!isObj(v)) bad("artifact not object");
  keys(v, ["profile", "digest", "bytes"]);
  return {
    profile: needEnum(v.profile, "artifact.profile", ARTIFACT_PROFILES),
    digest: needDigest(v.digest, "artifact.digest"),
    bytes: needInt(v.bytes, "artifact.bytes"),
  };
}

const TREE_PATH_RE = /^[A-Za-z0-9._\-/]+$/;

export function isValidTreePath(p: string): boolean {
  const n = Buffer.byteLength(p, "ascii");
  if (n < 1 || n > 240 || n !== Buffer.byteLength(p, "utf8")) return false;
  if (!TREE_PATH_RE.test(p)) return false;
  if (p.startsWith("/") || p.endsWith("/")) return false;
  if (p.includes("\\")) return false;
  for (const comp of p.split("/")) {
    if (comp === "" || comp === "." || comp === "..") return false;
  }
  return true;
}

export function parseTreeManifest(v: unknown): TreeManifest {
  if (!isObj(v)) bad("manifest not object");
  keys(v, ["v", "files"]);
  if (v.v !== "sunlight.tree/1") {
    if (typeof v.v === "string") unsupported();
    bad("manifest v");
  }
  const files = needArr(v.files, "manifest.files");
  if (files.length > MAX_MANIFEST_FILES) bad("manifest file count");
  const out: TreeFile[] = files.map((f, i) => {
    if (!isObj(f)) bad(`manifest.files[${i}] not object`);
    keys(f, ["path", "digest", "bytes"]);
    const path = needStr(f.path, `manifest.files[${i}].path`);
    if (!isValidTreePath(path)) bad(`manifest.files[${i}].path invalid`);
    return {
      path,
      digest: needDigest(f.digest, `manifest.files[${i}].digest`),
      bytes: needInt(f.bytes, `manifest.files[${i}].bytes`),
    };
  });
  requireSortedUnique(out, (f) => f.path, "manifest.files");
  const seenFold = new Set<string>();
  for (const f of out) {
    const fold = f.path.toLowerCase();
    if (seenFold.has(fold)) bad("manifest case-insensitive path collision");
    seenFold.add(fold);
  }
  const m: TreeManifest = { v: "sunlight.tree/1", files: out };
  if (jcsBytes(m).length > MAX_MANIFEST_BYTES) bad("manifest over 1 MiB");
  return m;
}

export function parseGenesis(v: unknown): Genesis {
  if (!isObj(v)) bad("genesis not object");
  keys(v, ["v", "ledger", "created_at_ms", "admin", "audit", "producers"]);
  if (v.v !== "sunlight.genesis/1") {
    if (typeof v.v === "string") unsupported();
    bad("genesis v");
  }
  const producers = needArr(v.producers, "genesis.producers").map((p) => parsePublicKey(p));
  if (producers.length > 32) bad("genesis producers > 32");
  requireSortedUnique(producers, (p) => p.id, "genesis.producers");
  const pubSeen = new Set<string>();
  for (const p of producers) {
    if (pubSeen.has(p.public_hex)) bad("genesis producer duplicate public key");
    pubSeen.add(p.public_hex);
  }
  const g: Genesis = {
    v: "sunlight.genesis/1",
    ledger: needId(v.ledger, "sll", "genesis.ledger"),
    created_at_ms: needInt(v.created_at_ms, "genesis.created_at_ms"),
    admin: parsePublicKey(v.admin),
    audit: parsePublicKey(v.audit),
    producers,
  };
  const ids = new Set(producers.map((p) => p.id));
  const pubs = new Set(producers.map((p) => p.public_hex));
  if (g.admin.id === g.audit.id || g.admin.public_hex === g.audit.public_hex) {
    bad("genesis admin/audit keys not distinct");
  }
  if (ids.has(g.admin.id) || pubs.has(g.admin.public_hex) ||
      ids.has(g.audit.id) || pubs.has(g.audit.public_hex)) {
    bad("genesis admin/audit collide with producers");
  }
  return g;
}

const RELATIONS = ["source", "dataset", "base_model", "run", "model"] as const;

export function parseParent(v: unknown): Parent {
  if (!isObj(v)) bad("parent not object");
  keys(v, ["statement", "artifact", "relation"]);
  return {
    statement: needDigest(v.statement, "parent.statement"),
    artifact: needDigest(v.artifact, "parent.artifact"),
    relation: needEnum(v.relation, "parent.relation", RELATIONS),
  };
}

const FOREIGN_FORMATS = [
  "c2pa/opaque", "fv.sunlight-export/1", "vislineage-bundle/1",
  "world/opaque", "mint/opaque", "treaty/opaque", "generic/opaque",
] as const;

export function parseEvidenceRef(v: unknown): EvidenceRef {
  if (!isObj(v)) bad("evidence not object");
  keys(v, ["artifact", "format", "source_commitment", "assessment"]);
  const format = needEnum(v.format, "evidence.format", FOREIGN_FORMATS);
  const sc = v.source_commitment === null ? null : needDigest(v.source_commitment, "evidence.source_commitment");
  if (format !== "vislineage-bundle/1" && sc !== null) {
    bad("evidence.source_commitment only for vislineage-bundle/1");
  }
  if (format === "vislineage-bundle/1" && sc === null) {
    bad("vislineage evidence requires source_commitment");
  }
  if (v.assessment !== "OPAQUE") bad("evidence.assessment not OPAQUE");
  return { artifact: parseArtifact(v.artifact), format, source_commitment: sc, assessment: "OPAQUE" };
}

const SEED_RE = /^(?:0|[1-9][0-9]{0,127})$/;

export function parseDetails(v: unknown): Details {
  if (!isObj(v)) bad("details not object");
  const t = v.type;
  if (typeof t !== "string") bad("details.type");
  switch (t) {
    case "creation":
      keys(v, ["type"]);
      return { type: "creation" };
    case "transform":
      keys(v, ["type", "procedure"]);
      return { type: "transform", procedure: needDigest(v.procedure, "details.procedure") };
    case "training": {
      keys(v, ["type", "run_id", "code", "environment", "parameters", "seed"]);
      const seed = v.seed;
      if (seed !== null) {
        const s = needStr(seed, "details.seed");
        if (!SEED_RE.test(s)) bad("details.seed not a decimal seed");
      }
      return {
        type: "training",
        run_id: needId(v.run_id, "slr", "details.run_id"),
        code: needDigest(v.code, "details.code"),
        environment: needDigest(v.environment, "details.environment"),
        parameters: needDigest(v.parameters, "details.parameters"),
        seed: seed as string | null,
      };
    }
    case "model":
      keys(v, ["type"]);
      return { type: "model" };
    case "action": {
      keys(v, ["type", "action_id", "input", "output", "outcome", "context"]);
      const outcome = needEnum(v.outcome, "details.outcome", ["attempted", "completed", "failed"] as const);
      const output = v.output === null ? null : needDigest(v.output, "details.output");
      const context = v.context === null ? null : needDigest(v.context, "details.context");
      return {
        type: "action",
        action_id: needId(v.action_id, "sla", "details.action_id"),
        input: needDigest(v.input, "details.input"),
        output,
        outcome,
        context,
      };
    }
    default:
      bad("details.type unknown");
  }
}

const SUBJECT_KINDS = ["dataset", "run", "model", "action", "evidence"] as const;
const CAPTURES = ["creation_hook", "posthoc"] as const;

export function parseStatementBody(v: unknown): StatementBody {
  if (!isObj(v)) bad("statement body not object");
  keys(v, ["v", "id", "ledger", "signer", "claimed_at_ms", "capture", "subject", "parents", "details", "evidence"]);
  if (v.v !== "sunlight.statement/1") {
    if (typeof v.v === "string") unsupported();
    bad("statement v");
  }
  const subject = v.subject;
  if (!isObj(subject)) bad("statement.subject not object");
  keys(subject, ["kind", "artifact"]);
  const parents = needArr(v.parents, "statement.parents").map((p) => parseParent(p));
  if (parents.length > MAX_PARENTS) bad("statement parents > 64");
  requireSortedUnique(parents, (p) => `${p.relation}${p.statement}`, "statement.parents");
  const evidence = needArr(v.evidence, "statement.evidence").map((e) => parseEvidenceRef(e));
  if (evidence.length > MAX_EVIDENCE) bad("statement evidence > 16");
  requireSortedUnique(evidence, (e) => `${e.format}${e.artifact.digest}`, "statement.evidence");
  return {
    v: "sunlight.statement/1",
    id: needId(v.id, "sls", "statement.id"),
    ledger: needId(v.ledger, "sll", "statement.ledger"),
    signer: needId(v.signer, "slk", "statement.signer"),
    claimed_at_ms: needInt(v.claimed_at_ms, "statement.claimed_at_ms"),
    capture: needEnum(v.capture, "statement.capture", CAPTURES),
    subject: {
      kind: needEnum(subject.kind, "statement.subject.kind", SUBJECT_KINDS),
      artifact: parseArtifact(subject.artifact),
    },
    parents,
    details: parseDetails(v.details),
    evidence,
  };
}

export function parseStatement(v: unknown): Statement {
  if (!isObj(v)) bad("statement not object");
  keys(v, ["body", "hash", "signature_hex"]);
  const s: Statement = {
    body: parseStatementBody(v.body),
    hash: needDigest(v.hash, "statement.hash"),
    signature_hex: needHex64(v.signature_hex, "statement.signature_hex"),
  };
  if (jcsBytes(s).length > MAX_STATEMENT_BYTES) bad("statement over 16 KiB");
  return s;
}

export function parseDescriptor(v: unknown): Descriptor {
  if (!isObj(v)) bad("descriptor not object");
  keys(v, ["v", "kind", "parents", "details"]);
  if (v.v !== "sunlight.descriptor/1") {
    if (typeof v.v === "string") unsupported();
    bad("descriptor v");
  }
  const kind = needEnum(v.kind, "descriptor.kind", ["run", "action"] as const);
  const parents = needArr(v.parents, "descriptor.parents").map((p) => parseParent(p));
  if (parents.length > MAX_PARENTS) bad("descriptor parents > 64");
  requireSortedUnique(parents, (p) => `${p.relation}${p.statement}`, "descriptor.parents");
  return { v: "sunlight.descriptor/1", kind, parents, details: parseDetails(v.details) };
}

export function parseOperation(v: unknown): Operation {
  if (!isObj(v)) bad("operation not object");
  const t = v.type;
  if (typeof t !== "string") bad("operation.type");
  switch (t) {
    case "claim":
      keys(v, ["type", "statement"]);
      return { type: "claim", statement: parseStatement(v.statement) };
    case "key_add":
      keys(v, ["type", "key"]);
      return { type: "key_add", key: parsePublicKey(v.key) };
    case "key_retire":
      keys(v, ["type", "key"]);
      return { type: "key_retire", key: needId(v.key, "slk", "operation.key") };
    case "key_revoke":
      keys(v, ["type", "key", "reason"]);
      return {
        type: "key_revoke",
        key: needId(v.key, "slk", "operation.key"),
        reason: needEnum(v.reason, "operation.reason", ["compromise", "withdrawn"] as const),
      };
    case "retract":
      keys(v, ["type", "statement", "reason"]);
      return {
        type: "retract",
        statement: needDigest(v.statement, "operation.statement"),
        reason: needEnum(v.reason, "operation.reason", ["incorrect", "withdrawn"] as const),
      };
    default:
      bad("operation.type unknown");
  }
}

export function parseCommandBody(v: unknown): CommandBody {
  if (!isObj(v)) bad("command body not object");
  keys(v, ["v", "id", "ledger", "signer", "expected_head", "issued_at_ms", "expires_at_ms", "operation"]);
  if (v.v !== "sunlight.command/1") {
    if (typeof v.v === "string") unsupported();
    bad("command v");
  }
  return {
    v: "sunlight.command/1",
    id: needId(v.id, "slq", "command.id"),
    ledger: needId(v.ledger, "sll", "command.ledger"),
    signer: needId(v.signer, "slk", "command.signer"),
    expected_head: parseHeadRef(v.expected_head),
    issued_at_ms: needInt(v.issued_at_ms, "command.issued_at_ms"),
    expires_at_ms: needInt(v.expires_at_ms, "command.expires_at_ms"),
    operation: parseOperation(v.operation),
  };
}

export function parseCommand(v: unknown): Command {
  if (!isObj(v)) bad("command not object");
  keys(v, ["body", "hash", "signature_hex"]);
  const c: Command = {
    body: parseCommandBody(v.body),
    hash: needDigest(v.hash, "command.hash"),
    signature_hex: needHex64(v.signature_hex, "command.signature_hex"),
  };
  if (jcsBytes(c).length > MAX_COMMAND_BYTES) bad("command over 24 KiB");
  return c;
}

const EVENTS = ["StatementRecorded", "KeyAdded", "KeyRetired", "KeyRevoked", "StatementRetracted"] as const;

export function parseReceiptBody(v: unknown): ReceiptBody {
  if (!isObj(v)) bad("receipt body not object");
  keys(v, ["v", "id", "ledger", "seq", "previous_hash", "command_hash", "statement_hash", "event", "committed_at_ms"]);
  if (v.v !== "sunlight.receipt/1") {
    if (typeof v.v === "string") unsupported();
    bad("receipt v");
  }
  return {
    v: "sunlight.receipt/1",
    id: needId(v.id, "sle", "receipt.id"),
    ledger: needId(v.ledger, "sll", "receipt.ledger"),
    seq: needInt(v.seq, "receipt.seq"),
    previous_hash: needDigest(v.previous_hash, "receipt.previous_hash"),
    command_hash: needDigest(v.command_hash, "receipt.command_hash"),
    statement_hash: v.statement_hash === null ? null : needDigest(v.statement_hash, "receipt.statement_hash"),
    event: needEnum(v.event, "receipt.event", EVENTS),
    committed_at_ms: needInt(v.committed_at_ms, "receipt.committed_at_ms"),
  };
}

export function parseReceipt(v: unknown): Receipt {
  if (!isObj(v)) bad("receipt not object");
  keys(v, ["body", "hash", "signature_hex"]);
  return {
    body: parseReceiptBody(v.body),
    hash: needDigest(v.hash, "receipt.hash"),
    signature_hex: needHex64(v.signature_hex, "receipt.signature_hex"),
  };
}

export function parseEntry(v: unknown): Entry {
  if (!isObj(v)) bad("entry not object");
  keys(v, ["command", "receipt"]);
  const e: Entry = { command: parseCommand(v.command), receipt: parseReceipt(v.receipt) };
  if (jcsBytes(e).length > MAX_ENTRY_BYTES) bad("entry over 32 KiB");
  return e;
}

export function parseHeadBody(v: unknown): HeadBody {
  if (!isObj(v)) bad("head body not object");
  keys(v, ["v", "ledger", "genesis_hash", "head", "observed_at_ms", "nonce_hex"]);
  if (v.v !== "sunlight.head/1") {
    if (typeof v.v === "string") unsupported();
    bad("head v");
  }
  return {
    v: "sunlight.head/1",
    ledger: needId(v.ledger, "sll", "head.ledger"),
    genesis_hash: needDigest(v.genesis_hash, "head.genesis_hash"),
    head: parseHeadRef(v.head),
    observed_at_ms: needInt(v.observed_at_ms, "head.observed_at_ms"),
    nonce_hex: v.nonce_hex === null ? null : needHex32(v.nonce_hex, "head.nonce_hex"),
  };
}

export function parseSignedHead(v: unknown): SignedHead {
  if (!isObj(v)) bad("signed head not object");
  keys(v, ["body", "hash", "signature_hex"]);
  return {
    body: parseHeadBody(v.body),
    hash: needDigest(v.hash, "head.hash"),
    signature_hex: needHex64(v.signature_hex, "head.signature_hex"),
  };
}

export function parseBundle(v: unknown): Bundle {
  if (!isObj(v)) bad("bundle not object");
  keys(v, ["v", "genesis", "entries", "head", "target"]);
  if (v.v !== "sunlight.bundle/1") {
    if (typeof v.v === "string") unsupported();
    bad("bundle v");
  }
  const entries = needArr(v.entries, "bundle.entries").map((e) => parseEntry(e));
  if (entries.length > MAX_BUNDLE_ENTRIES) bad("bundle over 4096 entries");
  const b: Bundle = {
    v: "sunlight.bundle/1",
    genesis: parseGenesis(v.genesis),
    entries,
    head: parseSignedHead(v.head),
    target: needDigest(v.target, "bundle.target"),
  };
  if (jcsBytes(b).length > MAX_BUNDLE_BYTES) bad("bundle over 16 MiB");
  return b;
}

export function parseTrust(v: unknown): Trust {
  if (!isObj(v)) bad("trust not object");
  keys(v, ["v", "ledger", "genesis_hash", "minimum_head", "denied_keys", "require_training", "max_head_age_ms"]);
  if (v.v !== "sunlight.trust/1") {
    if (typeof v.v === "string") unsupported();
    bad("trust v");
  }
  const denied = needArr(v.denied_keys, "trust.denied_keys").map((k) => needId(k, "slk", "trust.denied_keys"));
  requireSortedUnique(denied, (k) => k, "trust.denied_keys");
  const maxAge = needInt(v.max_head_age_ms, "trust.max_head_age_ms");
  if (maxAge < 1 || maxAge > MAX_HEAD_AGE_MS) bad("trust.max_head_age_ms out of range");
  return {
    v: "sunlight.trust/1",
    ledger: needId(v.ledger, "sll", "trust.ledger"),
    genesis_hash: needDigest(v.genesis_hash, "trust.genesis_hash"),
    minimum_head: parseHeadRef(v.minimum_head),
    denied_keys: denied,
    require_training: needBool(v.require_training, "trust.require_training"),
    max_head_age_ms: maxAge,
  };
}

export function parseFreshnessEvidence(v: unknown): FreshnessEvidence {
  if (!isObj(v)) bad("freshness not object");
  keys(v, ["head", "expected_nonce_hex", "sent_at_ms", "received_at_ms"]);
  return {
    head: parseSignedHead(v.head),
    expected_nonce_hex: needHex32(v.expected_nonce_hex, "freshness.expected_nonce_hex"),
    sent_at_ms: needInt(v.sent_at_ms, "freshness.sent_at_ms"),
    received_at_ms: needInt(v.received_at_ms, "freshness.received_at_ms"),
  };
}

export function parseArtifactObservation(v: unknown): ArtifactObservation {
  if (!isObj(v)) bad("observation not object");
  keys(v, ["artifact"]);
  return { artifact: parseArtifact(v.artifact) };
}

const ENV_NAME_RE = /^[A-Z][A-Z0-9_]{0,63}$/;
const SECRET_BINDING_RE = /^[A-Z][A-Z0-9_]{0,63}$/;

export function parseClientConfig(v: unknown): ClientConfig {
  if (!isObj(v)) bad("config not object");
  keys(v, ["v", "default_ledger", "registries", "cache_dir", "connect_timeout_ms", "read_timeout_ms", "allow_loopback_http"]);
  if (v.v !== "sunlight.config/1") {
    if (typeof v.v === "string") unsupported();
    bad("config v");
  }
  const regs = needArr(v.registries, "config.registries").map((r, i) => {
    if (!isObj(r)) bad(`config.registries[${i}] not object`);
    keys(r, ["ledger", "origin", "bearer_env", "trust_file"]);
    const origin = needStr(r.origin, "config.registries.origin");
    const bearer = needStr(r.bearer_env, "config.registries.bearer_env");
    if (!ENV_NAME_RE.test(bearer)) bad("config bearer_env invalid");
    const tf = needStr(r.trust_file, "config.registries.trust_file");
    if (Buffer.byteLength(tf, "utf8") > 1024) bad("trust_file path too long");
    return {
      ledger: needId(r.ledger, "sll", "config.registries.ledger"),
      origin,
      bearer_env: bearer,
      trust_file: tf,
    };
  });
  if (regs.length < 1 || regs.length > 32) bad("config registries count");
  const seen = new Set<string>();
  for (const r of regs) {
    if (seen.has(r.ledger)) bad("config duplicate ledger");
    seen.add(r.ledger);
  }
  const def = needId(v.default_ledger, "sll", "config.default_ledger");
  if (!seen.has(def)) bad("config default_ledger not in registries");
  const ct = needInt(v.connect_timeout_ms, "config.connect_timeout_ms");
  const rt = needInt(v.read_timeout_ms, "config.read_timeout_ms");
  if (ct < 100 || ct > 30000 || rt < 100 || rt > 30000) bad("config timeout out of range");
  const cache = needStr(v.cache_dir, "config.cache_dir");
  if (Buffer.byteLength(cache, "utf8") > 1024) bad("cache_dir path too long");
  return {
    v: "sunlight.config/1",
    default_ledger: def,
    registries: regs,
    cache_dir: cache,
    connect_timeout_ms: ct,
    read_timeout_ms: rt,
    allow_loopback_http: needBool(v.allow_loopback_http, "config.allow_loopback_http"),
  };
}

export function parseLocalKeyFile(v: unknown): LocalKeyFile {
  if (!isObj(v)) bad("key file not object");
  keys(v, ["v", "key", "encrypted_pkcs8_pem"]);
  if (v.v !== "sunlight.keyfile/1") {
    if (typeof v.v === "string") unsupported();
    bad("keyfile v");
  }
  const pem = needStr(v.encrypted_pkcs8_pem, "keyfile.encrypted_pkcs8_pem");
  if (Buffer.byteLength(pem, "ascii") > 4096 ||
      !pem.startsWith("-----BEGIN ENCRYPTED PRIVATE KEY-----") ||
      !pem.trimEnd().endsWith("-----END ENCRYPTED PRIVATE KEY-----")) {
    bad("keyfile pem invalid");
  }
  return { v: "sunlight.keyfile/1", key: parsePublicKey(v.key), encrypted_pkcs8_pem: pem };
}

export function parseTokenBinding(v: unknown): TokenBinding {
  if (!isObj(v)) bad("token binding not object");
  keys(v, ["token_sha256", "ledger", "role"]);
  return {
    token_sha256: needDigest(v.token_sha256, "token.token_sha256"),
    ledger: needId(v.ledger, "sll", "token.ledger"),
    role: needEnum(v.role, "token.role", ["read", "write"] as const),
  };
}

export function parseDeploymentConfig(v: unknown): DeploymentConfig {
  if (!isObj(v)) bad("deployment not object");
  keys(v, ["v", "ledgers", "auth_secret_binding", "rate_per_token_per_minute", "max_inflight_per_ledger", "protocol"]);
  if (v.v !== "sunlight.deployment/1") {
    if (typeof v.v === "string") unsupported();
    bad("deployment v");
  }
  if (v.protocol !== "sunlight/1") bad("deployment protocol");
  const ledgers = needArr(v.ledgers, "deployment.ledgers").map((l, i) => {
    if (!isObj(l)) bad(`deployment.ledgers[${i}] not object`);
    keys(l, ["genesis", "audit_secret_binding"]);
    const binding = needStr(l.audit_secret_binding, "deployment.audit_secret_binding");
    if (!SECRET_BINDING_RE.test(binding)) bad("audit_secret_binding invalid");
    return { genesis: parseGenesis(l.genesis), audit_secret_binding: binding };
  });
  if (ledgers.length < 1 || ledgers.length > 32) bad("deployment ledgers count");
  const seen = new Set<string>();
  for (const l of ledgers) {
    if (seen.has(l.genesis.ledger)) bad("deployment duplicate ledger");
    seen.add(l.genesis.ledger);
  }
  const auth = needStr(v.auth_secret_binding, "deployment.auth_secret_binding");
  if (!SECRET_BINDING_RE.test(auth)) bad("auth_secret_binding invalid");
  const rate = needInt(v.rate_per_token_per_minute, "deployment.rate");
  const inflight = needInt(v.max_inflight_per_ledger, "deployment.max_inflight");
  if (rate < 1 || rate > 10000) bad("deployment rate out of range");
  if (inflight < 1 || inflight > 32) bad("deployment inflight out of range");
  return {
    v: "sunlight.deployment/1",
    ledgers,
    auth_secret_binding: auth,
    rate_per_token_per_minute: rate,
    max_inflight_per_ledger: inflight,
    protocol: "sunlight/1",
  };
}
