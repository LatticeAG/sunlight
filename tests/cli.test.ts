/** CLI-level checks: hash output, strict exits, and the conformance command. */

import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runCli } from "../src/cli.js";
import * as F from "../src/fixtures.js";
import { jcsBytes } from "../src/encoding/jcs.js";
import { writeFileSync as wf } from "node:fs";

function tmp(): string {
  return mkdtempSync(join(tmpdir(), "sunlight-cli-"));
}

test("sunlight hash returns the exact artifact JSON", async () => {
  const dir = tmp();
  try {
    const p = join(dir, "data.bin");
    writeFileSync(p, Buffer.from("abc"));
    const r = await runCli(["hash", p, "--profile", "bytes/1"]);
    assert.equal(r.code, 0);
    assert.deepEqual(r.result, F.A);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("sunlight conformance executes all 58 vectors", async () => {
  const dir = tmp();
  try {
    const out = join(dir, "report.json");
    const r = await runCli(["conformance", "--suite", "TV-S", "--out", out]);
    assert.equal(r.code, 0);
    assert.deepEqual(r.result, { suite: "TV-S", vectors: 58, passed: 58, failed: 0 });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("sign requires posthoc capture (exit 2 before key read)", async () => {
  const dir = tmp();
  try {
    const body = { ...F.S1.body, capture: "creation_hook" };
    const bodyPath = join(dir, "body.json");
    const artPath = join(dir, "a.bin");
    wf(bodyPath, jcsBytes(body));
    wf(artPath, Buffer.from("abc"));
    try {
      await runCli(["sign", "--body", bodyPath, "--artifact", artPath, "--key", join(dir, "k.json")]);
      assert.fail("should have thrown");
    } catch (e) {
      assert.equal((e as { code?: string }).code ?? (e as { body?: { code: string } }).body?.code, "USAGE");
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("offline verify of F4 returns V4", async () => {
  const dir = tmp();
  try {
    const bundlePath = join(dir, "b.json");
    const trustPath = join(dir, "trust.json");
    wf(bundlePath, jcsBytes(F.F4));
    wf(trustPath, jcsBytes(F.TRUST));
    const r = await runCli(["verify", "--bundle", bundlePath, "--trust", trustPath]);
    assert.equal(r.code, 0);
    assert.deepEqual(r.result, F.V4);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
