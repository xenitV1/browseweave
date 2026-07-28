import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const projectDirectory = path.resolve(scriptDirectory, "..");
const serverRoot = path.join(projectDirectory, "src");
const extensionRoot = path.join(projectDirectory, "extension", "src");
const maximumModuleLines = 3_600;
const maximumEntrypointLines = 30;

const layouts = [
  {
    name: "server",
    root: serverRoot,
    entrypoints: new Map([
      ["cli.ts", "cli"],
      ["daemon.ts", "daemon"],
      ["mcp.ts", "mcp"],
      ["native-host.ts", "native"]
    ]),
    modules: new Set(["bridge", "cli", "clients", "core", "daemon", "mcp", "native", "setup"]),
    allowed: new Map([
      ["bridge", new Set(["bridge", "core"])],
      ["cli", new Set(["bridge", "cli", "clients", "core", "daemon", "mcp", "native", "setup"])],
      ["clients", new Set(["clients", "core"])],
      ["core", new Set(["core"])],
      ["daemon", new Set(["bridge", "core", "daemon"])],
      ["mcp", new Set(["bridge", "core", "mcp"])],
      ["native", new Set(["bridge", "clients", "core", "native"])],
      ["setup", new Set(["core", "setup"])]
    ])
  },
  {
    name: "extension",
    root: extensionRoot,
    entrypoints: new Map([
      ["background.ts", "background"],
      ["content.ts", "content"],
      ["options.ts", "ui"],
      ["popup.ts", "ui"]
    ]),
    modules: new Set(["background", "content", "security", "setup", "shared", "ui"]),
    allowed: new Map([
      ["background", new Set(["background", "security", "server:core", "setup", "shared"])],
      ["content", new Set(["content", "security", "server:core", "setup", "shared"])],
      ["security", new Set(["security", "server:core", "shared"])],
      ["setup", new Set(["security", "server:core", "setup", "shared"])],
      ["shared", new Set(["server:core", "shared"])],
      ["ui", new Set(["shared", "ui"])]
    ])
  }
];

function fail(message) {
  throw new Error(`Module boundary check failed: ${message}`);
}

async function sourceTree(directory) {
  const files = [];
  const entries = await readdir(directory, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.isSymbolicLink()) fail(`source symlink is forbidden: ${path.relative(projectDirectory, path.join(directory, entry.name))}`);
    const candidate = path.join(directory, entry.name);
    if (entry.isDirectory()) files.push(...await sourceTree(candidate));
    else files.push(candidate);
  }
  return files;
}

function sourceImportSpecifiers(source) {
  const specifiers = new Set();
  const patterns = [
    /\b(?:import|export)\s+(?:type\s+)?[\s\S]*?\sfrom\s+["'](\.\.?\/[^"']+)["']/gu,
    /\bimport\s+["'](\.\.?\/[^"']+)["']/gu,
    /\bimport\s*\(\s*["'](\.\.?\/[^"']+)["']\s*\)/gu
  ];
  for (const pattern of patterns) {
    for (const match of source.matchAll(pattern)) {
      if (match[1]) specifiers.add(match[1]);
    }
  }
  return specifiers;
}

function typescriptTarget(importer, specifier) {
  const rawTarget = path.resolve(path.dirname(importer), specifier);
  if (rawTarget.endsWith(".js")) return `${rawTarget.slice(0, -3)}.ts`;
  if (rawTarget.endsWith(".ts")) return rawTarget;
  return `${rawTarget}.ts`;
}

function moduleName(layout, file) {
  const relative = path.relative(layout.root, file);
  const segments = relative.split(path.sep);
  return segments.length === 1 ? "entrypoints" : segments[0];
}

function assertNoDependencyCycles(layout, edges) {
  const visiting = new Set();
  const visited = new Set();
  const visit = (module, trail) => {
    if (visiting.has(module)) fail(`${layout.name} module dependency cycle: ${[...trail, module].join(" -> ")}`);
    if (visited.has(module)) return;
    visiting.add(module);
    for (const target of edges.get(module) ?? []) visit(target, [...trail, module]);
    visiting.delete(module);
    visited.add(module);
  };
  for (const module of layout.modules) visit(module, []);
}

async function inspectLayout(layout, allSourceFiles) {
  const rootEntries = await readdir(layout.root, { withFileTypes: true });
  const rootFiles = new Set(rootEntries.filter((entry) => entry.isFile()).map((entry) => entry.name));
  const rootDirectories = new Set(rootEntries.filter((entry) => entry.isDirectory()).map((entry) => entry.name));
  if (JSON.stringify([...rootFiles].sort()) !== JSON.stringify([...layout.entrypoints.keys()].sort())) {
    fail(`${layout.name} root must contain only the declared entrypoint facades`);
  }
  if (JSON.stringify([...rootDirectories].sort()) !== JSON.stringify([...layout.modules].sort())) {
    fail(`${layout.name} module directories differ from the declared architecture`);
  }

  const edges = new Map();
  const files = [...allSourceFiles].filter((file) => file.startsWith(`${layout.root}${path.sep}`));
  for (const file of files) {
    if (!file.endsWith(".ts")) fail(`non-TypeScript source file is forbidden: ${path.relative(projectDirectory, file)}`);
    const source = await readFile(file, "utf8");
    const lines = source.split(/\r?\n/u).length;
    const fromModule = moduleName(layout, file);
    const lineBudget = fromModule === "entrypoints" ? maximumEntrypointLines : maximumModuleLines;
    if (lines > lineBudget) {
      fail(`${path.relative(projectDirectory, file)} has ${lines} lines; the ${lineBudget}-line module budget was exceeded`);
    }

    for (const specifier of sourceImportSpecifiers(source)) {
      const target = typescriptTarget(file, specifier);
      if (!allSourceFiles.has(target)) {
        fail(`${path.relative(projectDirectory, file)} imports missing source ${specifier}`);
      }
      let targetModule;
      let targetLayout;
      if (target.startsWith(`${layout.root}${path.sep}`)) {
        targetLayout = layout;
        targetModule = moduleName(layout, target);
      } else if (layout.name === "extension" && target.startsWith(`${serverRoot}${path.sep}`)) {
        targetLayout = layouts[0];
        targetModule = `server:${moduleName(layouts[0], target)}`;
        const allowedSharedServerFiles = new Set([
          path.join(serverRoot, "core", "protocol.ts"),
          path.join(serverRoot, "core", "version.ts")
        ]);
        if (!allowedSharedServerFiles.has(target)) {
          fail(`extension source may import only the shared server protocol/version contract: ${path.relative(projectDirectory, target)}`);
        }
      } else {
        fail(`${path.relative(projectDirectory, file)} imports across an undeclared source boundary: ${specifier}`);
      }

      if (fromModule === "entrypoints") {
        const expected = layout.entrypoints.get(path.basename(file));
        const sharedEntrypointHelper = layout.name === "server" && target === path.join(serverRoot, "core", "entrypoint.ts");
        if (!sharedEntrypointHelper && (targetLayout !== layout || targetModule !== expected)) {
          fail(`${path.relative(projectDirectory, file)} may import only its ${expected} implementation module`);
        }
        continue;
      }
      if (!layout.allowed.get(fromModule)?.has(targetModule)) {
        fail(`${layout.name} dependency ${fromModule} -> ${targetModule} is not allowed`);
      }
      if (targetLayout === layout && targetModule !== fromModule && targetModule !== "entrypoints") {
        const targets = edges.get(fromModule) ?? new Set();
        targets.add(targetModule);
        edges.set(fromModule, targets);
      }
    }
  }
  assertNoDependencyCycles(layout, edges);
  return files.length;
}

const sourceFiles = new Set([
  ...await sourceTree(serverRoot),
  ...await sourceTree(extensionRoot)
]);
let checkedFiles = 0;
for (const layout of layouts) checkedFiles += await inspectLayout(layout, sourceFiles);
process.stderr.write(`Module boundary check passed: ${checkedFiles} source files across ${layouts.length} acyclic module graphs.\n`);
