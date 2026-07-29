/**
 * Per-installation identity and the non-exportable P-256 signing key that
 * authenticates this browser and signs approval decisions. The private key is
 * generated in the browser and never leaves it.
 */
import { INSTALLATION_ID_STORAGE_KEY, normalizeText, selectChromiumBrand } from "../shared/pure";
import { isInstallationId, isP256PublicJwk, type BrowserIdentity, type P256PublicJwk } from "../../../src/core/protocol";
import { APP_VERSION } from "../../../src/core/version";
import { extensionBrowser } from "./environment";

const SECURITY_DATABASE_NAME = "browseweave-security-v1";
const SECURITY_DATABASE_VERSION = 1;
const SECURITY_STORE_NAME = "device-keys";
const SECURITY_KEY_ID = "installation-signing-key";

let deviceKeyPromise: Promise<{ privateKey: CryptoKey; publicKey: P256PublicJwk }> | undefined;
let installationIdPromise: Promise<string> | undefined;

function randomInstallationId(): string {
  if (typeof globalThis.crypto.randomUUID === "function") return globalThis.crypto.randomUUID().toLowerCase();
  const bytes = globalThis.crypto.getRandomValues(new Uint8Array(16));
  bytes[6] = ((bytes[6] ?? 0) & 0x0f) | 0x40;
  bytes[8] = ((bytes[8] ?? 0) & 0x3f) | 0x80;
  const hex = [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

export async function installationId(): Promise<string> {
  installationIdPromise ??= (async () => {
    const stored = await extensionBrowser.storage.local.get(INSTALLATION_ID_STORAGE_KEY);
    const existing = stored[INSTALLATION_ID_STORAGE_KEY];
    if (isInstallationId(existing)) return existing;
    const created = randomInstallationId();
    if (!isInstallationId(created)) throw new Error("BrowseWeave could not create a valid installation ID.");
    await extensionBrowser.storage.local.set({ [INSTALLATION_ID_STORAGE_KEY]: created });
    return created;
  })();
  return installationIdPromise;
}

function openSecurityDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = globalThis.indexedDB.open(SECURITY_DATABASE_NAME, SECURITY_DATABASE_VERSION);
    request.onupgradeneeded = () => {
      const database = request.result;
      if (!database.objectStoreNames.contains(SECURITY_STORE_NAME)) database.createObjectStore(SECURITY_STORE_NAME);
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("The BrowseWeave security database could not be opened."));
    request.onblocked = () => reject(new Error("The BrowseWeave security database upgrade was blocked."));
  });
}

function idbRequest<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("A BrowseWeave security database operation failed."));
  });
}

function transactionCompleted(transaction: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(transaction.error ?? new Error("The BrowseWeave security database transaction failed."));
    transaction.onabort = () => reject(transaction.error ?? new Error("The BrowseWeave security database transaction was aborted."));
  });
}

function validPrivateSigningKey(value: unknown): value is CryptoKey {
  if (!(value instanceof CryptoKey)) return false;
  const algorithm = value.algorithm as EcKeyAlgorithm;
  return value.type === "private" && value.extractable === false && value.usages.length === 1 &&
    value.usages[0] === "sign" && algorithm.name === "ECDSA" && algorithm.namedCurve === "P-256";
}

export async function deviceSigningKey(): Promise<{ privateKey: CryptoKey; publicKey: P256PublicJwk }> {
  deviceKeyPromise ??= (async () => {
    const database = await openSecurityDatabase();
    try {
      const readTransaction = database.transaction(SECURITY_STORE_NAME, "readonly");
      const existing = await idbRequest(readTransaction.objectStore(SECURITY_STORE_NAME).get(SECURITY_KEY_ID));
      await transactionCompleted(readTransaction);
      if (existing !== undefined) {
        if (!existing || typeof existing !== "object") throw new Error("The stored BrowseWeave signing key is invalid.");
        const record = existing as Record<string, unknown>;
        if (!validPrivateSigningKey(record.privateKey) || !isP256PublicJwk(record.publicKey)) {
          throw new Error("The stored BrowseWeave signing key failed integrity checks. Remove and pair the extension again.");
        }
        return { privateKey: record.privateKey, publicKey: record.publicKey };
      }

      const generated = await globalThis.crypto.subtle.generateKey(
        { name: "ECDSA", namedCurve: "P-256" },
        false,
        ["sign", "verify"]
      ) as CryptoKeyPair;
      if (!validPrivateSigningKey(generated.privateKey)) {
        throw new Error("The browser did not create a non-extractable BrowseWeave signing key.");
      }
      const exported = await globalThis.crypto.subtle.exportKey("jwk", generated.publicKey);
      const publicKey = {
        kty: exported.kty,
        crv: exported.crv,
        x: exported.x,
        y: exported.y,
        ext: true,
        key_ops: ["verify"]
      };
      if (!isP256PublicJwk(publicKey)) throw new Error("The browser produced an invalid BrowseWeave public key.");
      const writeTransaction = database.transaction(SECURITY_STORE_NAME, "readwrite");
      writeTransaction.objectStore(SECURITY_STORE_NAME).put(
        { privateKey: generated.privateKey, publicKey },
        SECURITY_KEY_ID
      );
      await transactionCompleted(writeTransaction);
      return { privateKey: generated.privateKey, publicKey };
    } finally {
      database.close();
    }
  })();
  return deviceKeyPromise;
}

export function toBase64Url(value: ArrayBuffer): string {
  const bytes = new Uint8Array(value);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return globalThis.btoa(binary).replace(/\+/gu, "-").replace(/\//gu, "_").replace(/=+$/gu, "");
}

export async function signPayload(payload: string): Promise<string> {
  const { privateKey } = await deviceSigningKey();
  const signature = await globalThis.crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    privateKey,
    new TextEncoder().encode(payload)
  );
  return toBase64Url(signature);
}

export async function browserIdentity(): Promise<BrowserIdentity> {
  const id = await installationId();
  if (typeof extensionBrowser.runtime.getBrowserInfo === "function") {
    const info = await extensionBrowser.runtime.getBrowserInfo();
    return {
      installation_id: id,
      browser_family: "firefox",
      browser_name: normalizeText(info.name || "Firefox-compatible browser", 80),
      browser_version: normalizeText(info.version || "unknown", 80),
      extension_version: APP_VERSION
    };
  }

  const navigatorRecord = globalThis.navigator as Navigator & {
    userAgentData?: { brands?: Array<{ brand: string; version: string }> };
    brave?: { isBrave?: () => Promise<boolean> };
  };
  const userAgent = navigatorRecord.userAgent || "";
  let browserName = "Chromium";
  let browserVersion = "unknown";
  const branded = selectChromiumBrand(navigatorRecord.userAgentData?.brands);
  const edgeMatch = /Edg\/([\d.]+)/u.exec(userAgent);
  const vivaldiMatch = /Vivaldi\/([\d.]+)/u.exec(userAgent);
  const operaMatch = /OPR\/([\d.]+)/u.exec(userAgent);
  if (edgeMatch?.[1]) {
    browserName = "Microsoft Edge";
    browserVersion = edgeMatch[1];
  } else if (vivaldiMatch?.[1]) {
    browserName = "Vivaldi";
    browserVersion = vivaldiMatch[1];
  } else if (operaMatch?.[1]) {
    browserName = "Opera";
    browserVersion = operaMatch[1];
  } else if (navigatorRecord.brave?.isBrave && await navigatorRecord.brave.isBrave().catch(() => false)) {
    browserName = "Brave";
    browserVersion = /Chrome\/([\d.]+)/u.exec(userAgent)?.[1] ?? branded?.version ?? "unknown";
  } else {
    browserName = branded?.brand || "Chromium";
    browserVersion = /Chrome\/([\d.]+)/u.exec(userAgent)?.[1] ?? branded?.version ?? "unknown";
  }
  return {
    installation_id: id,
    browser_family: "chromium",
    browser_name: normalizeText(browserName, 80),
    browser_version: normalizeText(browserVersion, 80),
    extension_version: APP_VERSION
  };
}
