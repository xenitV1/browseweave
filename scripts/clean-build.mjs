import { lstat, rm } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const projectDirectory = path.resolve(scriptDirectory, "..");
const outputDirectory = path.join(projectDirectory, "dist");

try {
  const info = await lstat(outputDirectory);
  if (!info.isDirectory() || info.isSymbolicLink()) {
    throw new Error("Refusing to clean a non-directory or symbolic-link dist path.");
  }
  if (typeof process.getuid === "function" && info.uid !== process.getuid()) {
    throw new Error("Refusing to clean a dist directory not owned by the current user.");
  }
  await rm(outputDirectory, { recursive: true, force: false, maxRetries: 2, retryDelay: 100 });
} catch (error) {
  if (error?.code !== "ENOENT") throw error;
}
