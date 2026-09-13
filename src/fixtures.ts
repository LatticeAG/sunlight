/**
 * Normative fixture values — a byte-exact TypeScript port of spec §6.2.
 *
 * Seeds are PUBLIC TEST VECTORS ONLY and MUST never be used by a production
 * signer.  Every symbol here is constructed identically to the spec's Python
 * generator so emitted objects (including signatures) are byte-identical.
 */

import { ed25519Sign, ed25519PublicFromSeed } from "./crypto/ed25519.js";
import { B, D, signatureMessage } from "./crypto/domains.js";
import { jcsBytes } from "./encoding/jcs.js";
import type {
  Artifact, Bundle, Command, CommandBody, Details, Entry, Genesis,
  HeadRef, Operation, Parent, PublicKey, ReceiptBody, SignedHead,
  Statement, StatementBody, Trust,
} from "./schema.js";

export function fid(prefix: string, n: number): string {
  return prefix + String(n).padStart(21, "0");
}

export interface FixtureKey {
  seed: Buffer;
  key: PublicKey;
}

export function makeKey(n: number): FixtureKey {
  const seed = Buffer.alloc(32, n);
  return { seed, key: { id: fid("slk_", n), public_hex: ed25519PublicFromSeed(seed).toString("hex") } };
}

export const KA = makeKey(1);   // admin
export const KL = makeKey(2);   // audit (ledger)
export const KP = makeKey(3);   // producer
export const KN = makeKey(4);   // new producer (added by C5)
export const L = fid("sll_", 1);
export const T = 1800000000000;
export const NONCE = "11".repeat(32);

export const G: Genesis = {
  v: "sunlight.genesis/1",
  ledger: L,
  created_at_ms: T,
  admin: KA.key,
  audit: KL.key,
  producers: [KP.key],
};
export const H0: HeadRef = { seq: 0, hash: D("sunlight.genesis/1", G) };

export function signed<K extends "statement" | "command" | "receipt" | "head">(
  kind: K,
  body: unknown,
  seed: Buffer,
): { body: never; hash: string; signature_hex: string } {
  const hash = D(`sunlight.${kind}/1`, body);
  return {
    body: body as never,
    hash,
    signature_hex: ed25519Sign(seed, signatureMessage(kind, hash)).toString("hex"),
  };
}

export function artifact(data: Buffer | Uint8Array, profile: Artifact["profile"] = "bytes/1"): Artifact {
  return { profile, digest: B(data), bytes: data.length };
}

export const A = artifact(Buffer.from("abc"));
export const Z = artifact(Buffer.alloc(0));
export const M = artifact(Buffer.from("model-v1\n"));

export function parent(statement: Statement, relation: Parent["relation"]): Parent {
  return {
    statement: statement.hash,
    artifact: statement.body.subject.artifact.digest,
    relation,
  };
}

export function claim(
  n: number,
  kind: StatementBody["subject"]["kind"],
  art: Artifact | null,
  parents: Parent[],
  details: Details,
  capture: StatementBody["capture"] = "creation_hook",
  evidence: StatementBody["evidence"] = [],
): Statement {
  const sorted = [...parents].sort(
    (a, b) => a.relation.localeCompare(b.relation) || a.statement.localeCompare(b.statement),
  );
  let subject = art;
  if (kind === "run" || kind === "action") {
    const descriptor = { v: "sunlight.descriptor/1", kind, parents: sorted, details };
    subject = artifact(jcsBytes(descriptor), "jcs/1");
  }
  const body: StatementBody = {
    v: "sunlight.statement/1",
    id: fid("sls_", n),
    ledger: L,
    signer: KP.key.id,
    claimed_at_ms: T,
    capture,
    subject: { kind, artifact: subject! },
    parents: sorted,
    details,
    evidence,
  };
  return signed("statement", body, KP.seed) as unknown as Statement;
}

export const S1 = claim(1, "dataset", A, [], { type: "creation" });
export const S2 = claim(2, "run", null, [parent(S1, "dataset")], {
  type: "training",
  run_id: fid("slr_", 1),
  code: B(Buffer.from("code")),
  environment: B(Buffer.from("env")),
  parameters: B(Buffer.from("params")),
  seed: "17",
});
export const S3 = claim(3, "model", M, [parent(S2, "run")], { type: "model" });
export const S4 = claim(4, "action", null, [parent(S3, "model")], {
  type: "action",
  action_id: fid("sla_", 1),
  input: B(Buffer.from("input")),
  output: B(Buffer.from("output")),
  outcome: "completed",
  context: null,
});

export function command(
  n: number,
  head: HeadRef,
  operation: Operation,
  admin = false,
): Command {
  const key = admin ? KA : KP;
  const body: CommandBody = {
    v: "sunlight.command/1",
    id: fid("slq_", n),
    ledger: L,
    signer: key.key.id,
    expected_head: head,
    issued_at_ms: T,
    expires_at_ms: T + 300000,
    operation,
  };
  return signed("command", body, key.seed) as unknown as Command;
}

const EVENTS: Record<string, string> = {
  claim: "StatementRecorded",
  key_add: "KeyAdded",
  key_retire: "KeyRetired",
  key_revoke: "KeyRevoked",
  retract: "StatementRetracted",
};

export function entry(n: number, cmd: Command): Entry {
  const op = cmd.body.operation;
  const sh = op.type === "claim" ? op.statement.hash : null;
  const body: ReceiptBody = {
    v: "sunlight.receipt/1",
    id: fid("sle_", n),
    ledger: L,
    seq: n,
    previous_hash: cmd.body.expected_head.hash,
    command_hash: cmd.hash,
    statement_hash: sh,
    event: EVENTS[op.type] as Entry["receipt"]["body"]["event"],
    committed_at_ms: T,
  };
  return { command: cmd, receipt: signed("receipt", body, KL.seed) as unknown as Entry["receipt"] };
}

export function ref(e: Entry): HeadRef {
  return { seq: e.receipt.body.seq, hash: e.receipt.hash };
}

export const C1 = command(1, H0, { type: "claim", statement: S1 });
export const E1 = entry(1, C1);
export const H1 = ref(E1);
export const C2 = command(2, H1, { type: "claim", statement: S2 });
export const E2 = entry(2, C2);
export const H2 = ref(E2);
export const C3 = command(3, H2, { type: "claim", statement: S3 });
export const E3 = entry(3, C3);
export const H3 = ref(E3);
export const C4 = command(4, H3, { type: "claim", statement: S4 });
export const E4 = entry(4, C4);
export const H4 = ref(E4);
export const C5 = command(5, H4, { type: "key_add", key: KN.key }, true);
export const E5 = entry(5, C5);
export const H5 = ref(E5);
export const C6 = command(6, H5, { type: "key_retire", key: KN.key.id }, true);
export const E6 = entry(6, C6);
export const H6 = ref(E6);
export const C7 = command(7, H6, { type: "key_revoke", key: KP.key.id, reason: "compromise" }, true);
export const E7 = entry(7, C7);
export const H7 = ref(E7);
export const C8 = command(8, H7, { type: "retract", statement: S1.hash, reason: "incorrect" }, true);
export const E8 = entry(8, C8);
export const H8 = ref(E8);
export const ENTRIES = [E1, E2, E3, E4, E5, E6, E7, E8];

export function head(h: HeadRef, nonce: string | null = null): SignedHead {
  const body = {
    v: "sunlight.head/1" as const,
    ledger: L,
    genesis_hash: H0.hash,
    head: h,
    observed_at_ms: T,
    nonce_hex: nonce,
  };
  return signed("head", body, KL.seed) as unknown as SignedHead;
}

export function bundle(entries: Entry[], target: Statement): Bundle {
  const h = entries.length > 0 ? ref(entries[entries.length - 1]!) : H0;
  return { v: "sunlight.bundle/1", genesis: G, entries, head: head(h), target: target.hash };
}

export const F4 = bundle(ENTRIES.slice(0, 4), S4);
export const F7 = bundle(ENTRIES.slice(0, 7), S4);
export const F8 = bundle(ENTRIES, S4);

export const TRUST: Trust = {
  v: "sunlight.trust/1",
  ledger: L,
  genesis_hash: H0.hash,
  minimum_head: H0,
  denied_keys: [],
  require_training: true,
  max_head_age_ms: 30000,
};

export const OBS4 = { artifact: S4.body.subject.artifact };
export const FRESH4 = {
  head: head(H4, NONCE),
  expected_nonce_hex: NONCE,
  sent_at_ms: T,
  received_at_ms: T + 1,
};

export const V4 = {
  integrity: "VALID",
  lineage: "COMPLETE_DECLARED",
  authority: "TRUSTED_AT_HEAD",
  freshness: "OFFLINE",
  artifact: "NOT_SUPPLIED",
  claim_truth: "NOT_PROVEN",
  overall: "VERIFIED",
  reasons: [],
  head: H4,
};

export const CLIENT_CONFIG = {
  v: "sunlight.config/1",
  default_ledger: L,
  registries: [{ ledger: L, origin: "http://127.0.0.1:8787", bearer_env: "SUNLIGHT_REGISTRY_TOKEN", trust_file: "./trust.json" }],
  cache_dir: "./.sunlight-cache",
  connect_timeout_ms: 3000,
  read_timeout_ms: 10000,
  allow_loopback_http: true,
};

export const DEPLOY_CONFIG = {
  v: "sunlight.deployment/1",
  ledgers: [{ genesis: G, audit_secret_binding: "AUDIT_L1" }],
  auth_secret_binding: "REGISTRY_TOKENS",
  rate_per_token_per_minute: 120,
  max_inflight_per_ledger: 8,
  protocol: "sunlight/1",
};
