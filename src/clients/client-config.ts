import { constants as fsConstants, type FileHandle, link, lstat, mkdir, open, readFile, rename, rm } from "node:fs/promises";
import path from "node:path";
import { randomBytes } from "node:crypto";
import {
  applyEdits,
  modify as modifyJsonc,
  parse as parseJsonc,
  parseTree as parseJsoncTree,
  type Node as JsoncNode,
  type ParseError
} from "jsonc-parser";
import { trustedNpmInvocation } from "./npm-invocation.js";

export const MCP_SERVER_NAME = "browseweave" as const;

export type SupportedMcpClient = "codex" | "claude-code" | "cursor" | "opencode" | "generic";
export type RegistrationState = "absent" | "exact" | "foreign";

export interface McpLaunchSpec {
  command: string;
  args: string[];
  env: Record<string, string>;
}

export interface ClientSetup {
  client: SupportedMcpClient;
  command?: string[];
  config: Record<string, unknown>;
  note: string;
}

export interface ConfigMergeResult {
  path: string;
  status: "created" | "updated" | "unchanged";
  opencodeVersion?: 1 | 2;
}

export interface OpenCodeExecutableAvailability {
  v1: boolean;
  v2: boolean;
}

interface ReadJsonResult {
  exists: boolean;
  contents: string;
  value: unknown;
  identity?: { dev: number; ino: number };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function portableAbsolutePath(value: string): boolean {
  return path.posix.isAbsolute(value) || path.win32.isAbsolute(value);
}

export function validateMcpLaunchSpec(spec: McpLaunchSpec): McpLaunchSpec {
  if (!portableAbsolutePath(spec.command) || /[\0\r\n]/u.test(spec.command)) {
    throw new Error("The MCP executable must be a safe absolute path.");
  }
  if (!Array.isArray(spec.args) || spec.args.some((argument) => typeof argument !== "string" || /[\0\r\n]/u.test(argument))) {
    throw new Error("MCP arguments must be strings without control characters.");
  }
  if (!isRecord(spec.env) || Object.keys(spec.env).length !== 0) {
    throw new Error("BrowseWeave does not write environment variables into MCP client configuration.");
  }
  return {
    command: spec.command,
    args: [...spec.args],
    env: {}
  };
}

/** Resolve a trusted npm beside the active Node runtime and always launch the current latest package. */
export async function defaultMcpLaunchSpec(): Promise<McpLaunchSpec> {
  const invocation = await trustedNpmInvocation([
    "exec",
    "--yes",
    "--package=browseweave@latest",
    "--",
    "browseweave",
    "mcp"
  ]);
  return validateMcpLaunchSpec({ command: invocation.command, args: invocation.args, env: {} });
}

function stdioEntry(spec: McpLaunchSpec): Record<string, unknown> {
  return { command: spec.command, args: [...spec.args], env: {} };
}

function openCodeEntry(spec: McpLaunchSpec, version: 1 | 2): Record<string, unknown> {
  return {
    type: "local",
    command: [spec.command, ...spec.args],
    ...(version === 1 ? { enabled: true } : { disabled: false })
  };
}

export function clientSetup(
  client: SupportedMcpClient,
  rawSpec: McpLaunchSpec,
  opencodeVersion?: 1 | 2
): ClientSetup {
  const spec = validateMcpLaunchSpec(rawSpec);
  const entry = stdioEntry(spec);
  if (client === "codex") {
    return {
      client,
      command: ["codex", "mcp", "add", MCP_SERVER_NAME, "--", spec.command, ...spec.args],
      config: { mcp_servers: { [MCP_SERVER_NAME]: entry } },
      note: "Use the Codex CLI command. Codex CLI, the IDE extension, and the desktop app share this host configuration."
    };
  }
  if (client === "claude-code") {
    return {
      client,
      command: [
        "claude",
        "mcp",
        "add",
        "--transport",
        "stdio",
        "--scope",
        "user",
        MCP_SERVER_NAME,
        "--",
        spec.command,
        ...spec.args
      ],
      config: {
        mcpServers: {
          [MCP_SERVER_NAME]: { type: "stdio", ...entry }
        }
      },
      note: "Use user scope so BrowseWeave is available across Claude Code projects."
    };
  }
  if (client === "cursor") {
    return {
      client,
      config: { mcpServers: { [MCP_SERVER_NAME]: entry } },
      note: "BrowseWeave can atomically merge this exact entry into the global Cursor mcp.json without replacing other servers."
    };
  }
  if (client === "opencode") {
    if (opencodeVersion !== 1 && opencodeVersion !== 2) {
      throw new Error("Choose OpenCode schema V1 or V2 explicitly when printing configuration.");
    }
    return {
      client,
      config: opencodeVersion === 2
        ? { mcp: { servers: { [MCP_SERVER_NAME]: openCodeEntry(spec, 2) } } }
        : { mcp: { [MCP_SERVER_NAME]: openCodeEntry(spec, 1) } },
      note: opencodeVersion === 2
        ? "OpenCode V2 stores named servers under mcp.servers and uses disabled=false."
        : "OpenCode V1 stores named servers directly under mcp and uses enabled=true."
    };
  }
  return {
    client,
    config: { mcpServers: { [MCP_SERVER_NAME]: entry } },
    note: "Use this local stdio MCP entry in any compatible client. It contains no pairing credential."
  };
}

export function selectOpenCodeVersion(
  availability: OpenCodeExecutableAvailability,
  requestedVersion?: 1 | 2
): 1 | 2 {
  const installedVersion = availability.v1 === availability.v2
    ? undefined
    : availability.v1 ? 1 : 2;

  if (installedVersion !== undefined) {
    if (requestedVersion !== undefined && requestedVersion !== installedVersion) {
      const executable = installedVersion === 1 ? "opencode" : "opencode2";
      throw new Error(
        `${executable} identifies OpenCode V${installedVersion}, but OpenCode V${requestedVersion} was selected. ` +
        `Use --opencode-v${installedVersion} or install the matching executable.`
      );
    }
    return installedVersion;
  }

  if (requestedVersion !== undefined) return requestedVersion;
  if (availability.v1 && availability.v2) {
    throw new Error(
      "Both opencode (V1) and opencode2 (V2) are installed. Choose --opencode-v1 or --opencode-v2."
    );
  }
  throw new Error(
    "No OpenCode executable was detected. Choose --opencode-v1 or --opencode-v2 before creating its configuration."
  );
}

export function serializeClientSetup(setup: ClientSetup): string {
  return `${JSON.stringify({ client: setup.client, command: setup.command, config: setup.config, note: setup.note }, null, 2)}\n`;
}

class StrictJsonScanner {
  private index = 0;

  constructor(private readonly source: string, private readonly label: string) {}

  scan(): void {
    this.skipWhitespace();
    this.scanValue();
    this.skipWhitespace();
    if (this.index !== this.source.length) this.fail("unexpected trailing data");
  }

  private fail(message: string): never {
    throw new Error(`${this.label} is not safe strict JSON: ${message} at character ${this.index}.`);
  }

  private skipWhitespace(): void {
    while (/[\t\n\r ]/u.test(this.source[this.index] ?? "")) this.index += 1;
  }

  private scanValue(): void {
    const character = this.source[this.index];
    if (character === "{") return this.scanObject();
    if (character === "[") return this.scanArray();
    if (character === '"') {
      this.scanString();
      return;
    }
    for (const literal of ["true", "false", "null"]) {
      if (this.source.startsWith(literal, this.index)) {
        this.index += literal.length;
        return;
      }
    }
    const number = this.source.slice(this.index).match(/^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/u)?.[0];
    if (!number) this.fail("expected a JSON value");
    this.index += number.length;
  }

  private scanObject(): void {
    this.index += 1;
    this.skipWhitespace();
    const keys = new Set<string>();
    if (this.source[this.index] === "}") {
      this.index += 1;
      return;
    }
    while (true) {
      if (this.source[this.index] !== '"') this.fail("expected an object key");
      const key = this.scanString();
      if (keys.has(key)) this.fail(`duplicate object key ${JSON.stringify(key)}`);
      keys.add(key);
      this.skipWhitespace();
      if (this.source[this.index] !== ":") this.fail("expected a colon after an object key");
      this.index += 1;
      this.skipWhitespace();
      this.scanValue();
      this.skipWhitespace();
      if (this.source[this.index] === "}") {
        this.index += 1;
        return;
      }
      if (this.source[this.index] !== ",") this.fail("expected a comma between object entries");
      this.index += 1;
      this.skipWhitespace();
    }
  }

  private scanArray(): void {
    this.index += 1;
    this.skipWhitespace();
    if (this.source[this.index] === "]") {
      this.index += 1;
      return;
    }
    while (true) {
      this.scanValue();
      this.skipWhitespace();
      if (this.source[this.index] === "]") {
        this.index += 1;
        return;
      }
      if (this.source[this.index] !== ",") this.fail("expected a comma between array entries");
      this.index += 1;
      this.skipWhitespace();
    }
  }

  private scanString(): string {
    const start = this.index;
    this.index += 1;
    while (this.index < this.source.length) {
      const character = this.source[this.index]!;
      if (character === '"') {
        this.index += 1;
        return JSON.parse(this.source.slice(start, this.index)) as string;
      }
      if (character === "\\") {
        this.index += 1;
        const escape = this.source[this.index];
        if (escape === "u") {
          if (!/^[0-9a-f]{4}$/iu.test(this.source.slice(this.index + 1, this.index + 5))) {
            this.fail("invalid Unicode escape");
          }
          this.index += 5;
          continue;
        }
        if (!escape || !/["\\/bfnrt]/u.test(escape)) this.fail("invalid string escape");
        this.index += 1;
        continue;
      }
      if (character.charCodeAt(0) < 0x20) this.fail("unescaped control character in string");
      this.index += 1;
    }
    this.fail("unterminated string");
  }
}

export function parseStrictJson(contents: string, label = "Configuration"): unknown {
  if (contents.charCodeAt(0) === 0xfeff) throw new Error(`${label} must not contain a byte-order mark.`);
  new StrictJsonScanner(contents, label).scan();
  return JSON.parse(contents) as unknown;
}

function assertNoDuplicateJsoncKeys(node: JsoncNode, label: string): void {
  if (node.type === "object") {
    const keys = new Set<string>();
    for (const property of node.children ?? []) {
      const keyNode = property.children?.[0];
      const valueNode = property.children?.[1];
      if (typeof keyNode?.value !== "string" || !valueNode) {
        throw new Error(`${label} contains an invalid JSONC object property.`);
      }
      if (keys.has(keyNode.value)) throw new Error(`${label} contains a duplicate object key: ${keyNode.value}.`);
      keys.add(keyNode.value);
      assertNoDuplicateJsoncKeys(valueNode, label);
    }
    return;
  }
  if (node.type === "array") {
    for (const child of node.children ?? []) assertNoDuplicateJsoncKeys(child, label);
  }
}

function parseJsoncConfiguration(contents: string, label: string): unknown {
  if (contents.charCodeAt(0) === 0xfeff) throw new Error(`${label} must not contain a byte-order mark.`);
  const options = { allowTrailingComma: true, disallowComments: false };
  const errors: ParseError[] = [];
  const value = parseJsonc(contents, errors, options) as unknown;
  const treeErrors: ParseError[] = [];
  const tree = parseJsoncTree(contents, treeErrors, options);
  const firstError = errors[0] ?? treeErrors[0];
  if (firstError || !tree) {
    throw new Error(`${label} is not safe JSONC${firstError ? ` near character ${firstError.offset}` : ""}.`);
  }
  assertNoDuplicateJsoncKeys(tree, label);
  return value;
}

function deepExact(left: unknown, right: unknown): boolean {
  if (Object.is(left, right)) return true;
  if (Array.isArray(left) || Array.isArray(right)) {
    return Array.isArray(left)
      && Array.isArray(right)
      && left.length === right.length
      && left.every((value, index) => deepExact(value, right[index]));
  }
  if (!isRecord(left) || !isRecord(right)) return false;
  const leftKeys = Object.keys(left).sort();
  const rightKeys = Object.keys(right).sort();
  return leftKeys.length === rightKeys.length
    && leftKeys.every((key, index) => key === rightKeys[index] && deepExact(left[key], right[key]));
}

function emptyOrMissingRecord(value: unknown): boolean {
  return value === undefined || value === null || (isRecord(value) && Object.keys(value).length === 0);
}

export function codexRegistrationState(value: unknown, rawSpec: McpLaunchSpec): RegistrationState {
  const spec = validateMcpLaunchSpec(rawSpec);
  if (!Array.isArray(value)) throw new Error("Codex returned an unexpected MCP list response.");
  const matches = value.filter((entry) => isRecord(entry) && entry.name === MCP_SERVER_NAME);
  if (matches.length === 0) return "absent";
  if (matches.length !== 1) return "foreign";
  const entry = matches[0]!;
  const transport = isRecord(entry.transport) ? entry.transport : null;
  return transport
    && transport.type === "stdio"
    && transport.command === spec.command
    && deepExact(transport.args, spec.args)
    && emptyOrMissingRecord(transport.env)
    && (transport.env_vars === undefined || deepExact(transport.env_vars, []))
    ? "exact"
    : "foreign";
}

function claudeEntryState(value: unknown, spec: McpLaunchSpec): RegistrationState {
  if (!isRecord(value)) return "foreign";
  const servers = value.mcpServers;
  if (servers === undefined) return "absent";
  if (!isRecord(servers)) return "foreign";
  const entry = servers[MCP_SERVER_NAME];
  if (entry === undefined) return "absent";
  if (!isRecord(entry)) return "foreign";
  return entry.type === "stdio"
    && entry.command === spec.command
    && deepExact(entry.args, spec.args)
    && emptyOrMissingRecord(entry.env)
    && Object.keys(entry).every((key) => ["type", "command", "args", "env"].includes(key))
    ? "exact"
    : "foreign";
}

export function claudeProjectRegistrationState(value: unknown, rawSpec: McpLaunchSpec): RegistrationState {
  const spec = validateMcpLaunchSpec(rawSpec);
  if (!isRecord(value)) throw new Error("Claude Code configuration root must be an object.");
  return claudeEntryState(value, spec);
}

export function claudeRegistrationState(value: unknown, rawSpec: McpLaunchSpec): RegistrationState {
  const spec = validateMcpLaunchSpec(rawSpec);
  if (!isRecord(value)) throw new Error("Claude Code configuration root must be an object.");
  if (value.projects !== undefined) {
    if (!isRecord(value.projects)) return "foreign";
    for (const project of Object.values(value.projects)) {
      if (!isRecord(project)) continue;
      if (claudeEntryState(project, spec) !== "absent") return "foreign";
    }
  }
  return claudeEntryState(value, spec);
}

async function readJsonFileSafely(filePath: string, allowMissing: boolean): Promise<ReadJsonResult> {
  if (!path.isAbsolute(filePath) || /[\0\r\n]/u.test(filePath)) {
    throw new Error("Client configuration path must be a safe absolute path.");
  }
  try {
    const info = await lstat(filePath);
    if (!info.isFile() || info.isSymbolicLink()) {
      throw new Error(`Refusing a non-regular client configuration file: ${filePath}`);
    }
    if (process.platform !== "win32" && typeof process.getuid === "function" && info.uid !== process.getuid()) {
      throw new Error(`Client configuration is not owned by the current user: ${filePath}`);
    }
    const contents = await readFile(filePath, "utf8");
    const jsonc = path.extname(filePath).toLowerCase() === ".jsonc";
    return {
      exists: true,
      contents,
      value: jsonc ? parseJsoncConfiguration(contents, filePath) : parseStrictJson(contents, filePath),
      identity: { dev: info.dev, ino: info.ino }
    };
  } catch (error) {
    if (allowMissing && (error as NodeJS.ErrnoException).code === "ENOENT") {
      return { exists: false, contents: "", value: {} };
    }
    throw error;
  }
}

async function ensureSafeConfigDirectory(directory: string): Promise<void> {
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const info = await lstat(directory);
  if (!info.isDirectory() || info.isSymbolicLink()) {
    throw new Error(`Refusing an unsafe client configuration directory: ${directory}`);
  }
  if (process.platform !== "win32" && typeof process.getuid === "function" && info.uid !== process.getuid()) {
    throw new Error(`Client configuration directory is not owned by the current user: ${directory}`);
  }
}

async function atomicWriteContents(filePath: string, nextContents: string, original: ReadJsonResult): Promise<void> {
  const directory = path.dirname(filePath);
  await ensureSafeConfigDirectory(directory);

  if (original.exists) {
    const current = await lstat(filePath);
    if (!current.isFile() || current.isSymbolicLink()
      || current.dev !== original.identity?.dev || current.ino !== original.identity?.ino
      || await readFile(filePath, "utf8") !== original.contents) {
      throw new Error(`Client configuration changed while BrowseWeave was preparing the update: ${filePath}`);
    }
  } else {
    try {
      await lstat(filePath);
      throw new Error(`Client configuration appeared while BrowseWeave was preparing the update: ${filePath}`);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
  }

  const temporaryPath = path.join(
    directory,
    `.${path.basename(filePath)}.browseweave-${process.pid}-${randomBytes(8).toString("hex")}.tmp`
  );
  let handle: FileHandle | undefined;
  try {
    handle = await open(temporaryPath, fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY, 0o600);
    await handle.writeFile(nextContents.endsWith("\n") ? nextContents : `${nextContents}\n`, "utf8");
    await handle.sync();
    await handle.close();
    handle = undefined;
    if (original.exists) {
      await rename(temporaryPath, filePath);
    } else {
      await link(temporaryPath, filePath);
      await rm(temporaryPath);
    }

    if (process.platform !== "win32") {
      const directoryHandle = await open(directory, fsConstants.O_RDONLY);
      try {
        await directoryHandle.sync();
      } finally {
        await directoryHandle.close();
      }
    }
  } catch (error) {
    await handle?.close();
    await rm(temporaryPath, { force: true });
    throw error;
  }
}

async function atomicWriteJson(filePath: string, value: Record<string, unknown>, original: ReadJsonResult): Promise<void> {
  await atomicWriteContents(filePath, `${JSON.stringify(value, null, 2)}\n`, original);
}

export async function readStrictJsonConfig(filePath: string): Promise<unknown> {
  return (await readJsonFileSafely(filePath, false)).value;
}

export async function mergeCursorConfig(
  filePath: string,
  rawSpec: McpLaunchSpec,
  replaceableSpecs: readonly McpLaunchSpec[] = []
): Promise<ConfigMergeResult> {
  const spec = validateMcpLaunchSpec(rawSpec);
  const original = await readJsonFileSafely(filePath, true);
  if (!isRecord(original.value)) throw new Error("Cursor configuration root must be an object.");
  const currentServers = original.value.mcpServers;
  if (currentServers !== undefined && !isRecord(currentServers)) {
    throw new Error("Cursor mcpServers must be an object.");
  }
  const servers = currentServers ?? {};
  const expected = stdioEntry(spec);
  const existing = servers[MCP_SERVER_NAME];
  const replaceable = replaceableSpecs.some((candidate) => deepExact(existing, stdioEntry(validateMcpLaunchSpec(candidate))));
  if (existing !== undefined && !deepExact(existing, expected) && !replaceable) {
    throw new Error("Cursor already contains a foreign browseweave MCP entry; it was not changed.");
  }
  if (deepExact(existing, expected)) return { path: filePath, status: "unchanged" };

  const next = {
    ...original.value,
    mcpServers: { ...servers, [MCP_SERVER_NAME]: expected }
  };
  await atomicWriteJson(filePath, next, original);
  return { path: filePath, status: original.exists ? "updated" : "created" };
}

function assertOpenCodeServerEntry(value: unknown, version: 1 | 2, label: string): void {
  if (!isRecord(value)) {
    throw new Error(`${label} does not match the selected OpenCode V${version} MCP schema.`);
  }
  if (version === 1 && value.disabled !== undefined) {
    throw new Error(`${label} uses the OpenCode V2 disabled field in a V1 configuration.`);
  }
  if (version === 2 && value.enabled !== undefined) {
    throw new Error(`${label} uses the OpenCode V1 enabled field in a V2 configuration.`);
  }
  const enablement = version === 1 ? value.enabled : value.disabled;
  if (enablement !== undefined && typeof enablement !== "boolean") {
    throw new Error(`${label} has an invalid OpenCode V${version} enablement value.`);
  }

  if (value.type === "local") {
    if (!Array.isArray(value.command) || value.command.length === 0
      || value.command.some((part) => typeof part !== "string" || part.length === 0)) {
      throw new Error(`${label} has an invalid OpenCode V${version} local command.`);
    }
    return;
  }
  if (value.type === "remote") {
    if (typeof value.url !== "string" || value.url.length === 0) {
      throw new Error(`${label} has an invalid OpenCode V${version} remote URL.`);
    }
    return;
  }
  if (value.type !== undefined) {
    throw new Error(`${label} has an invalid OpenCode V${version} server type.`);
  }

  // V1 permits a local entry containing only `enabled` to override an
  // organization-provided server. V2 server definitions are replacements and
  // therefore still require their local/remote type.
  if (version === 1 && typeof value.enabled === "boolean") return;
  throw new Error(`${label} is not an OpenCode V${version} MCP server entry.`);
}

function assertOpenCodeTimeout(value: unknown): void {
  if (!isRecord(value)) throw new Error("OpenCode V2 mcp.timeout must be an object.");
  for (const [key, timeout] of Object.entries(value)) {
    if (!["startup", "catalog", "execution"].includes(key)
      || !Number.isSafeInteger(timeout) || (timeout as number) <= 0) {
      throw new Error("OpenCode V2 mcp.timeout contains an unsupported or invalid timeout.");
    }
  }
}

function openCodeServersForVersion(value: Record<string, unknown>, version: 1 | 2): Record<string, unknown> {
  const rawMcp = value.mcp;
  if (rawMcp === undefined) return {};
  if (!isRecord(rawMcp)) throw new Error(`OpenCode mcp must be an object for V${version}.`);

  if (version === 1) {
    for (const [name, entry] of Object.entries(rawMcp)) {
      assertOpenCodeServerEntry(entry, 1, `OpenCode V1 mcp.${name}`);
    }
    return rawMcp;
  }

  const unsupportedKeys = Object.keys(rawMcp).filter((key) => key !== "servers" && key !== "timeout");
  if (unsupportedKeys.length > 0) {
    throw new Error(
      `OpenCode configuration does not match V2: unexpected direct mcp key ${JSON.stringify(unsupportedKeys[0])}.`
    );
  }
  if (rawMcp.timeout !== undefined) assertOpenCodeTimeout(rawMcp.timeout);
  if (rawMcp.servers === undefined) return {};
  if (!isRecord(rawMcp.servers)) throw new Error("OpenCode V2 mcp.servers must be an object.");
  for (const [name, entry] of Object.entries(rawMcp.servers)) {
    assertOpenCodeServerEntry(entry, 2, `OpenCode V2 mcp.servers.${name}`);
  }
  return rawMcp.servers;
}

export async function mergeOpenCodeConfig(
  filePath: string,
  rawSpec: McpLaunchSpec,
  version: 1 | 2,
  replaceableSpecs: readonly McpLaunchSpec[] = []
): Promise<ConfigMergeResult> {
  if (version !== 1 && version !== 2) {
    throw new Error("OpenCode V1 or V2 must be selected before configuration is written.");
  }
  const spec = validateMcpLaunchSpec(rawSpec);
  const original = await readJsonFileSafely(filePath, true);
  if (!isRecord(original.value)) throw new Error("OpenCode configuration root must be an object.");
  const mcp = isRecord(original.value.mcp) ? original.value.mcp : {};
  const servers = openCodeServersForVersion(original.value, version);
  const expected = openCodeEntry(spec, version);
  const existing = servers[MCP_SERVER_NAME];
  const replaceable = replaceableSpecs.some((candidate) => (
    deepExact(existing, openCodeEntry(validateMcpLaunchSpec(candidate), version))
  ));
  if (existing !== undefined && !deepExact(existing, expected) && !replaceable) {
    throw new Error("OpenCode already contains a foreign browseweave MCP entry; it was not changed.");
  }
  if (deepExact(existing, expected)) {
    return { path: filePath, status: "unchanged", opencodeVersion: version };
  }

  const nextServers = { ...servers, [MCP_SERVER_NAME]: expected };
  const next = version === 2
    ? { ...original.value, mcp: { ...mcp, servers: nextServers } }
    : { ...original.value, mcp: nextServers };
  if (original.exists && path.extname(filePath).toLowerCase() === ".jsonc") {
    const entryPath = version === 2
      ? ["mcp", "servers", MCP_SERVER_NAME]
      : ["mcp", MCP_SERVER_NAME];
    const eol = original.contents.includes("\r\n") ? "\r\n" : "\n";
    const edits = modifyJsonc(original.contents, entryPath, expected, {
      formattingOptions: { insertSpaces: true, tabSize: 2, eol }
    });
    await atomicWriteContents(filePath, applyEdits(original.contents, edits), original);
  } else {
    await atomicWriteJson(filePath, next, original);
  }
  return { path: filePath, status: original.exists ? "updated" : "created", opencodeVersion: version };
}
