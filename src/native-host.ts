#!/usr/bin/env node

import { isDirectExecution } from "./core/entrypoint.js";
import { main, reportNativeHostFailure } from "./native/host.js";

if (isDirectExecution(import.meta.url)) {
  void main().catch(reportNativeHostFailure);
}
