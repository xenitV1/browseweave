import {
  createHash,
  createHmac,
  randomBytes,
  randomUUID,
  timingSafeEqual
} from "node:crypto";
import { createConnection } from "node:net";
import {
  DEFAULT_IPC_HOST,
  DEFAULT_IPC_PORT,
  getIpcToken,
  getRuntimePaths
} from "./config.js";
import {
  PROTOCOL_VERSION,
  canonicalJson,
  ipcClientProofPayload,
  ipcServerProofPayload,
  isJsonObject,
  isJsonValue,
  type IpcClientHello,
  type IpcRequest,
  type IpcResponse,
  type IpcServerChallenge,
  type JsonObject
} from "./protocol.js";

const DEFAULT_TIMEOUT_MS = 45_000;
const MAX_RESPONSE_BYTES = 25 * 1024 * 1024;
const BASE64URL_256_PATTERN = /^[A-Za-z0-9_-]{43}$/u;
const DAEMON_INSTANCE_PATTERN = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/u;

export interface IpcEndpoint {
  host: typeof DEFAULT_IPC_HOST;
  port: number;
}

function configuredPort(env: NodeJS.ProcessEnv = process.env): number {
  const value = env.BROWSER_MCP_BRIDGE_IPC_PORT;
  if (!value) return DEFAULT_IPC_PORT;
  if (!/^\d{1,5}$/u.test(value)) {
    throw new Error("BROWSER_MCP_BRIDGE_IPC_PORT must be an integer port.");
  }
  const port = Number(value);
  if (port < 1 || port > 65_535) {
    throw new Error("BROWSER_MCP_BRIDGE_IPC_PORT must be between 1 and 65535.");
  }
  return port;
}

export function bridgeIpcEndpoint(env: NodeJS.ProcessEnv = process.env): IpcEndpoint {
  return { host: DEFAULT_IPC_HOST, port: configuredPort(env) };
}

function hmacProof(secret: string, payload: string): string {
  return createHmac("sha256", Buffer.from(secret, "utf8")).update(payload, "utf8").digest("base64url");
}

function proofMatches(candidate: unknown, expected: string): candidate is string {
  if (typeof candidate !== "string" || !BASE64URL_256_PATTERN.test(candidate)) return false;
  const candidateBytes = Buffer.from(candidate, "base64url");
  const expectedBytes = Buffer.from(expected, "base64url");
  return candidateBytes.byteLength === expectedBytes.byteLength && timingSafeEqual(candidateBytes, expectedBytes);
}

function parseChallenge(value: unknown, clientNonce: string): IpcServerChallenge | undefined {
  if (!isJsonObject(value)) return undefined;
  if (
    value.type !== "ipc_challenge" ||
    value.protocol_version !== PROTOCOL_VERSION ||
    value.endpoint_role !== "ipc" ||
    value.client_nonce !== clientNonce ||
    typeof value.server_nonce !== "string" ||
    !BASE64URL_256_PATTERN.test(value.server_nonce) ||
    typeof value.daemon_instance_id !== "string" ||
    !DAEMON_INSTANCE_PATTERN.test(value.daemon_instance_id) ||
    typeof value.server_proof !== "string"
  ) return undefined;
  return value as unknown as IpcServerChallenge;
}

function parseResponse(value: unknown, requestId: string): IpcResponse | undefined {
  if (!isJsonObject(value) || value.id !== requestId || typeof value.ok !== "boolean") return undefined;
  if (value.ok === true && !isJsonValue(value.result)) return undefined;
  if (value.ok === false && typeof value.error !== "string") return undefined;
  return value as unknown as IpcResponse;
}

export async function callBridge(
  method: string,
  params: Record<string, unknown> = {},
  timeoutMs = DEFAULT_TIMEOUT_MS,
  env: NodeJS.ProcessEnv = process.env
): Promise<unknown> {
  if (typeof method !== "string" || method.length < 1 || method.length > 64) {
    throw new Error("BrowseWeave IPC method is invalid.");
  }
  if (!isJsonObject(params) || !isJsonValue(params)) {
    throw new Error("BrowseWeave IPC parameters must be finite JSON values.");
  }
  const jsonParams = params as JsonObject;
  const requestId = randomUUID();
  const clientNonce = randomBytes(32).toString("base64url");
  const endpoint = bridgeIpcEndpoint(env);
  const ipcToken = await getIpcToken(getRuntimePaths(env), env);

  return await new Promise<unknown>((resolve, reject) => {
    const socket = createConnection(endpoint);
    let settled = false;
    let buffer = Buffer.alloc(0);
    let state: "awaiting_challenge" | "awaiting_response" = "awaiting_challenge";

    const finish = (error?: Error, result?: unknown): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      if (error) reject(error);
      else resolve(result);
    };

    const timer = setTimeout(() => {
      finish(new Error(`BrowseWeave did not respond within ${Math.round(timeoutMs / 1000)} seconds.`));
    }, timeoutMs);
    timer.unref();

    socket.once("connect", () => {
      const hello: IpcClientHello = {
        type: "ipc_client_hello",
        protocol_version: PROTOCOL_VERSION,
        endpoint_role: "ipc",
        client_nonce: clientNonce
      };
      socket.write(`${JSON.stringify(hello)}\n`);
    });

    const handleLine = (line: Buffer): void => {
      let parsed: unknown;
      try {
        parsed = JSON.parse(line.toString("utf8").replace(/\r$/u, "")) as unknown;
      } catch {
        finish(new Error("BrowseWeave returned an invalid authenticated protocol message."));
        return;
      }

      if (state === "awaiting_challenge") {
        const challenge = parseChallenge(parsed, clientNonce);
        if (challenge === undefined) {
          finish(new Error("The local endpoint could not prove that it is the BrowseWeave service."));
          return;
        }
        const serverPayload = ipcServerProofPayload({
          clientNonce,
          serverNonce: challenge.server_nonce,
          daemonInstanceId: challenge.daemon_instance_id
        });
        const expectedServerProof = hmacProof(ipcToken, serverPayload);
        if (!proofMatches(challenge.server_proof, expectedServerProof)) {
          finish(new Error("The local endpoint could not prove that it is the BrowseWeave service."));
          return;
        }

        const paramsSha256 = `sha256:${createHash("sha256")
          .update(canonicalJson(jsonParams), "utf8")
          .digest("hex")}`;
        const clientProof = hmacProof(ipcToken, ipcClientProofPayload({
          clientNonce,
          serverNonce: challenge.server_nonce,
          daemonInstanceId: challenge.daemon_instance_id,
          serverProof: challenge.server_proof,
          requestId,
          method,
          paramsSha256
        }));
        const request: IpcRequest = {
          type: "ipc_request",
          protocol_version: PROTOCOL_VERSION,
          endpoint_role: "ipc",
          id: requestId,
          method,
          params: jsonParams,
          client_nonce: clientNonce,
          server_nonce: challenge.server_nonce,
          daemon_instance_id: challenge.daemon_instance_id,
          client_proof: clientProof
        };
        state = "awaiting_response";
        socket.write(`${JSON.stringify(request)}\n`);
        return;
      }

      const response = parseResponse(parsed, requestId);
      if (response === undefined) {
        finish(new Error("BrowseWeave response identity validation failed."));
        return;
      }
      if (!response.ok) {
        finish(new Error(response.error.slice(0, 500) || "BrowseWeave could not complete the operation."));
        return;
      }
      finish(undefined, response.result);
    };

    socket.on("data", (chunk: Buffer) => {
      if (settled) return;
      buffer = Buffer.concat([buffer, chunk]);
      if (buffer.byteLength > MAX_RESPONSE_BYTES) {
        finish(new Error("BrowseWeave exceeded the safe response-size limit."));
        return;
      }
      while (!settled) {
        const newlineIndex = buffer.indexOf(0x0a);
        if (newlineIndex < 0) return;
        const line = buffer.subarray(0, newlineIndex);
        buffer = buffer.subarray(newlineIndex + 1);
        handleLine(line);
      }
    });

    socket.once("error", (error: NodeJS.ErrnoException) => {
      if (error.code === "ECONNREFUSED" || error.code === "EHOSTUNREACH") {
        finish(new Error("The local BrowseWeave service is not running. Start BrowseWeave, then retry."));
        return;
      }
      finish(new Error(`Could not connect to BrowseWeave: ${error.message}`));
    });

    socket.once("end", () => {
      if (!settled) finish(new Error("BrowseWeave closed the connection without an authenticated response."));
    });
  });
}
