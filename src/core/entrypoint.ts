import { realpathSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export function isDirectExecution(moduleUrl: string, entryPoint = process.argv[1]): boolean {
  if (entryPoint === undefined) return false;
  try {
    return realpathSync(fileURLToPath(moduleUrl)) === realpathSync(path.resolve(entryPoint));
  } catch {
    return false;
  }
}
