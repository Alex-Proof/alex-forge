/**
 * Forge's own trust anchor for signing evidence.json so an exported repair package stays
 * verifiable by someone who did not just watch Forge build it -- without that, evidence.json
 * inside a catalog ZIP is a plain text file anyone could rewrite after the fact.
 *
 * Deliberately not shared with anything outside this package (no import from packages/panzer or
 * any other process's keystore): a signer and verifier that import the same key-handling code
 * can both be blinded by the same bug in it.
 */
import { generateKeyPairSync, sign, verify, createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";

export interface ForgeKeypair {
  privateKeyPem: string;
  publicKeyPem: string;
  createdAt: string;
}

/**
 * Loads the persisted keypair from `<keystoreDir>/forge-trust-anchor.json`, generating one on
 * first use. Caller decides the directory (default: `<repairOutputRoot>/.forge/keystore`,
 * already gitignored) so tests can point this at a disposable temp dir instead of a shared file.
 */
export function loadOrCreateKeypair(keystoreDir: string): ForgeKeypair {
  const keyFile = path.join(keystoreDir, "forge-trust-anchor.json");
  fs.mkdirSync(keystoreDir, { recursive: true });
  if (fs.existsSync(keyFile)) {
    const raw = JSON.parse(fs.readFileSync(keyFile, "utf8")) as ForgeKeypair;
    if (!raw.privateKeyPem || !raw.publicKeyPem) {
      throw new Error(`${keyFile} is corrupt (missing key fields)`);
    }
    return raw;
  }
  const pair = generateKeyPairSync("ed25519", {
    privateKeyEncoding: { format: "pem", type: "pkcs8" },
    publicKeyEncoding: { format: "pem", type: "spki" },
  });
  const persisted: ForgeKeypair = {
    privateKeyPem: pair.privateKey,
    publicKeyPem: pair.publicKey,
    createdAt: new Date().toISOString(),
  };
  // 0600: best available minimum for a file-based trust anchor outside an HSM.
  fs.writeFileSync(keyFile, JSON.stringify(persisted, null, 2), { mode: 0o600 });
  return persisted;
}

export function forgeKeyId(publicKeyPem: string): string {
  return "ed25519-pub-forge-" + createHash("sha256").update(publicKeyPem).digest("hex").slice(0, 16);
}

export function forgeSign(privateKeyPem: string, data: Buffer): string {
  return sign(null, data, privateKeyPem).toString("base64");
}

export function forgeVerify(publicKeyPem: string, data: Buffer, signatureBase64: string): boolean {
  try {
    return verify(null, data, publicKeyPem, Buffer.from(signatureBase64, "base64"));
  } catch {
    // A malformed signature/key must be rejected, not thrown past the caller.
    return false;
  }
}
