import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const fixtureDirectory = path.resolve(scriptDirectory, "..", "tests", "fixtures");
const files = new Map([
  ["/", "evaluation.html"],
  ["/evaluation.html", "evaluation.html"],
  ["/evaluation-notes.html", "evaluation-notes.html"],
  ["/interaction.html", "interaction.html"],
  ["/interaction-frame.html", "interaction-frame.html"]
]);

const server = createServer(async (request, response) => {
  const pathname = new URL(request.url || "/", "http://127.0.0.1").pathname;
  const filename = files.get(pathname);
  if (!filename) {
    response.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
    response.end("Not found");
    return;
  }
  try {
    const body = await readFile(path.join(fixtureDirectory, filename));
    response.writeHead(200, {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff"
    });
    response.end(body);
  } catch (error) {
    response.writeHead(500, { "content-type": "text/plain; charset=utf-8" });
    response.end(error instanceof Error ? error.message : "Fixture error");
  }
});

server.listen(41731, "127.0.0.1", () => {
  console.error("Fixed evaluation page: http://127.0.0.1:41731/evaluation.html");
  console.error("Safe interaction page: http://127.0.0.1:41731/interaction.html");
});

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.once(signal, () => server.close(() => process.exit(0)));
}
