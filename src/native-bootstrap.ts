import { randomBytes } from "node:crypto";
import { callBridge } from "./ipc-client.js";
import {
  MAX_NATIVE_SETUP_TTL_MS,
  type NativeBrowserFamily,
  type NativeSetupOperations
} from "./native-setup-protocol.js";

export const NATIVE_SETUP_TTL_MS = 2 * 60_000;

interface NativeBootstrapDependencies {
  ensureServiceReady(): Promise<void>;
  call(method: string, params: Record<string, unknown>, timeoutMs: number): Promise<unknown>;
  now(): number;
  randomHex(bytes: number): string;
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  return Object.keys(value).sort().join(",") === [...expected].sort().join(",");
}

function exactObject(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("The local service returned an invalid native setup result.");
  }
  return value as Record<string, unknown>;
}

export function createNativeSetupOperations(
  overrides: Partial<NativeBootstrapDependencies> & Pick<NativeBootstrapDependencies, "ensureServiceReady"> 
): NativeSetupOperations {
  const dependencies: NativeBootstrapDependencies = {
    ensureServiceReady: overrides.ensureServiceReady,
    call: overrides.call ?? (async (method, params, timeoutMs) => await callBridge(method, params, timeoutMs)),
    now: overrides.now ?? Date.now,
    randomHex: overrides.randomHex ?? ((bytes) => randomBytes(bytes).toString("hex"))
  };

  return {
    beginSetup: async (browserFamily: NativeBrowserFamily) => {
      await dependencies.ensureServiceReady();
      const setupId = dependencies.randomHex(12);
      const setupSecret = dependencies.randomHex(32);
      if (!/^[a-f0-9]{24}$/u.test(setupId) || !/^[a-f0-9]{64}$/u.test(setupSecret)) {
        throw new Error("The operating system random source returned an invalid setup capability.");
      }
      const now = dependencies.now();
      const expiresAt = new Date(now + NATIVE_SETUP_TTL_MS).toISOString();
      if (NATIVE_SETUP_TTL_MS > MAX_NATIVE_SETUP_TTL_MS) {
        throw new Error("The native setup lifetime exceeds the protocol limit.");
      }
      const raw = exactObject(await dependencies.call("setup_pairing_begin", {
        setup_id: setupId,
        setup_secret: setupSecret,
        expires_at: expiresAt,
        browser_family: browserFamily
      }, 5_000));
      if (
        !exactKeys(raw, ["setup_pairing_ready", "setup_id", "expires_at", "browser_family"]) ||
        raw.setup_pairing_ready !== true || raw.setup_id !== setupId ||
        raw.expires_at !== expiresAt || raw.browser_family !== browserFamily
      ) throw new Error("The local service did not accept the exact native setup session.");
      return {
        setup_id: setupId,
        setup_secret: setupSecret,
        expires_at: expiresAt,
        browser_family: browserFamily
      };
    },
    cancelSetup: async (setupId: string) => {
      await dependencies.ensureServiceReady();
      const raw = exactObject(await dependencies.call("setup_pairing_cancel", { setup_id: setupId }, 3_000));
      if (
        !exactKeys(raw, ["setup_pairing_cancelled", "setup_id"]) ||
        raw.setup_pairing_cancelled !== true || raw.setup_id !== setupId
      ) throw new Error("The local service did not confirm exact native setup cleanup.");
      return {
        setup_id: setupId,
        setup_pairing_cancelled: true
      };
    }
  };
}
