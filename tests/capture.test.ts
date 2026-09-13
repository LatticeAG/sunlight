/** Cooperative capture (spec §4.2 / §7): the staged sign-then-publish flow. */

import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, existsSync, symlinkSync, lstatSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { capture, type CaptureTemplate } from "../src/capture.js";
import { seedSigner } from "../src/objects.js";
import { SunlightError } from "../src/errors.js";
import * as F from "../src/fixtures.js";

function tmp(): string {
  return mkdtempSync(join(tmpdir(), "sunlight-cap-"));
}

test("spec §7 capture example returns exactly S1", async () => {
  const dir = tmp();
  try {
    const stage = join(dir, "stage");
    const release = join(dir, "release");
    mkdirSync(stage);
    mkdirSync(release);
    const template: CaptureTemplate = {
      v: F.S1.body.v,
      id: F.S1.body.id,
      ledger: F.S1.body.ledger,
      signer: F.S1.body.signer,
      claimed_at_ms: F.S1.body.claimed_at_ms,
      kind: "dataset",
      parents: F.S1.body.parents,
      details: F.S1.body.details,
      evidence: F.S1.body.evidence,
    };
    const res = await capture(
      {
        staging_parent: stage,
        publish_path: join(release, "data.bin"),
        profile: "bytes/1",
        template,
      },
      async (stagedPath) => {
        writeFileSync(stagedPath, Buffer.from("616263", "hex"));
      },
      seedSigner(F.KP.key, F.KP.seed),
    );
    assert.equal(res.published_path, join(release, "data.bin"));
    assert.equal(res.recorded, false);
    assert.deepEqual(res.statement, F.S1);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("existing publish destination is OUTPUT_EXISTS, never overwritten", async () => {
  const dir = tmp();
  try {
    const stage = join(dir, "stage");
    mkdirSync(stage);
    const target = join(dir, "taken.bin");
    writeFileSync(target, "taken");
    const template: CaptureTemplate = {
      v: "sunlight.statement/1", id: "sls_" + "9".repeat(21), ledger: F.L,
      signer: F.KP.key.id, claimed_at_ms: F.T, kind: "dataset",
      parents: [], details: { type: "creation" }, evidence: [],
    };
    await assert.rejects(
      capture(
        { staging_parent: stage, publish_path: target, profile: "bytes/1", template },
        async (p) => writeFileSync(p, "x"),
        seedSigner(F.KP.key, F.KP.seed),
      ),
      (e) => e instanceof SunlightError && e.code === "OUTPUT_EXISTS",
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("tree capture rejects symlinks", async () => {
  const dir = tmp();
  try {
    const stage = join(dir, "stage");
    mkdirSync(stage);
    const template: CaptureTemplate = {
      v: "sunlight.statement/1", id: "sls_" + "8".repeat(21), ledger: F.L,
      signer: F.KP.key.id, claimed_at_ms: F.T, kind: "dataset",
      parents: [], details: { type: "creation" }, evidence: [],
    };
    await assert.rejects(
      capture(
        { staging_parent: stage, publish_path: join(dir, "treeout"), profile: "tree/1", template },
        async (stagedPath) => {
          writeFileSync(join(stagedPath, "real.txt"), "data");
          symlinkSync("real.txt", join(stagedPath, "link.txt"));
        },
        seedSigner(F.KP.key, F.KP.seed),
      ),
      (e) => e instanceof SunlightError,
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
