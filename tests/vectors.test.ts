/** TV-S-01..58 — the full conformance suite, executed for real. */

import test from "node:test";
import assert from "node:assert/strict";
import { runConformance } from "../src/conformance.js";

test("all 58 TV-S conformance vectors pass", async () => {
  const report = await runConformance();
  assert.equal(report.vectors.length, 58, "vector count");
  const failed = report.vectors.filter((v) => !v.pass);
  assert.deepEqual(
    failed.map((f) => `${f.id}: ${f.detail ?? ""}`),
    [],
  );
});
