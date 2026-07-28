import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  createExtensionArchive,
  packageVersion,
  projectDirectory
} from "./make-xpi.mjs";

const scriptPath = fileURLToPath(import.meta.url);

async function main() {
  const version = await packageVersion();
  const sourceDirectory = path.join(projectDirectory, "extension", "dist", "chromium-mv3");
  const target = path.join(projectDirectory, "web-ext-artifacts", `browseweave-${version}-chromium-mv3.zip`);
  await createExtensionArchive(sourceDirectory, target);
  console.error(`BrowseWeave Chromium ZIP ready: ${target}`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === scriptPath) await main();
