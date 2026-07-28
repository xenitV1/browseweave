#!/usr/bin/env node

import { main } from "./cli/application.js";
import { isDirectExecution } from "./core/entrypoint.js";

if (isDirectExecution(import.meta.url)) {
  void main().catch((error: unknown) => {
    process.stderr.write(`BrowseWeave error: ${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
