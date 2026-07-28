#!/usr/bin/env node

import { isDirectExecution } from "./core/entrypoint.js";
import { main } from "./daemon/runtime.js";

export * from "./daemon/runtime.js";

if (isDirectExecution(import.meta.url)) {
  void main().catch((error: unknown) => {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`BrowseWeave could not start: ${message}`);
    process.exitCode = 1;
  });
}
