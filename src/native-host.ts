#!/usr/bin/env node
import { callBridge } from "./ipc-client.js";
import { createNativeSetupOperations } from "./native-bootstrap.js";
import { nativeCallerPolicyFromInstalledRegistration } from "./native-host-config.js";
import { nativeServiceEnvironment, ensureManagedNativeServiceReady } from "./native-service.js";
import {
  SingleNativeMessageDecoder,
  createNativeSetupFailure,
  encodeNativeSetupResponseFrame,
  processNativeSetupFrame
} from "./native-setup-protocol.js";

const INPUT_TIMEOUT_MS = 15_000;

function genericFailureFrame(): Buffer {
  return encodeNativeSetupResponseFrame(createNativeSetupFailure("invalid_request"));
}

async function writeFrame(frame: Buffer): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    process.stdout.write(frame, (error) => error ? reject(error) : resolve());
  });
}

async function main(): Promise<void> {
  const decoder = new SingleNativeMessageDecoder();
  const chunks: Buffer[] = [];
  let completed = false;
  let totalBytes = 0;
  const finish = async (frame: Buffer): Promise<void> => {
    if (completed) return;
    completed = true;
    globalThis.clearTimeout(timeout);
    process.stdin.pause();
    process.stdin.removeAllListeners("data");
    process.stdin.removeAllListeners("end");
    await writeFrame(frame);
  };
  const fail = async (): Promise<void> => {
    await finish(genericFailureFrame()).catch(() => undefined);
  };
  const timeout = globalThis.setTimeout(() => { void fail(); }, INPUT_TIMEOUT_MS);

  process.stdin.on("data", (chunk: Buffer) => {
    if (completed) return;
    try {
      const payload = decoder.push(chunk);
      totalBytes += chunk.byteLength;
      chunks.push(Buffer.from(chunk));
      if (payload === undefined) return;
      const frame = Buffer.concat(chunks, totalBytes);
      const argv = process.argv.slice(2);
      void nativeCallerPolicyFromInstalledRegistration(argv)
        .then(async (policy) => {
          const env = nativeServiceEnvironment();
          const operations = createNativeSetupOperations({
            ensureServiceReady: ensureManagedNativeServiceReady,
            call: async (method, params, timeoutMs) => await callBridge(method, params, timeoutMs, env)
          });
          return await processNativeSetupFrame({ frame, argv, caller_policy: policy, operations });
        })
        .then(finish, fail);
    } catch {
      void fail();
    }
  });
  process.stdin.once("end", () => {
    if (completed) return;
    try {
      decoder.finish();
    } catch {
      void fail();
    }
  });
  process.stdin.resume();
}

void main().catch(async () => {
  await writeFrame(genericFailureFrame()).catch(() => undefined);
  process.exitCode = 1;
});
