#!/usr/bin/env node
import { main } from "./cli.js";

main(process.argv.slice(2))
  .then((code) => process.exit(code))
  .catch((e) => {
    process.stderr.write(`sunlight: internal error\n`);
    process.exit(1);
  });
