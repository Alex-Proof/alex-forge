import { rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { forgeKeyId, forgeSign, forgeVerify, loadOrCreateKeypair } from "./keystore.js";

let tempDirs: string[] = [];
function tempKeystoreDir(): string {
  const dir = path.join(os.tmpdir(), `forge-keystore-test-${Math.random().toString(36).slice(2)}`);
  tempDirs.push(dir);
  return dir;
}

afterEach(async () => {
  await Promise.all(tempDirs.map((dir) => rm(dir, { recursive: true, force: true })));
  tempDirs = [];
});

describe("keystore", () => {
  it("generates a keypair on first use and persists it for later calls", () => {
    const dir = tempKeystoreDir();
    const first = loadOrCreateKeypair(dir);
    const second = loadOrCreateKeypair(dir);
    expect(second.privateKeyPem).toBe(first.privateKeyPem);
    expect(second.publicKeyPem).toBe(first.publicKeyPem);
  });

  it("signs data such that it verifies against the matching public key", () => {
    const dir = tempKeystoreDir();
    const keypair = loadOrCreateKeypair(dir);
    const data = Buffer.from("evidence payload bytes");
    const signature = forgeSign(keypair.privateKeyPem, data);
    expect(forgeVerify(keypair.publicKeyPem, data, signature)).toBe(true);
  });

  it("rejects a signature checked against a different keystore's public key", () => {
    const dirA = tempKeystoreDir();
    const dirB = tempKeystoreDir();
    const keypairA = loadOrCreateKeypair(dirA);
    const keypairB = loadOrCreateKeypair(dirB);
    const data = Buffer.from("evidence payload bytes");
    const signature = forgeSign(keypairA.privateKeyPem, data);
    expect(forgeVerify(keypairB.publicKeyPem, data, signature)).toBe(false);
  });

  it("rejects a signature when even one byte of the signed data changed", () => {
    const dir = tempKeystoreDir();
    const keypair = loadOrCreateKeypair(dir);
    const signature = forgeSign(keypair.privateKeyPem, Buffer.from("original"));
    expect(forgeVerify(keypair.publicKeyPem, Buffer.from("tampered"), signature)).toBe(false);
  });

  it("never throws on a malformed signature, just reports false", () => {
    const dir = tempKeystoreDir();
    const keypair = loadOrCreateKeypair(dir);
    expect(forgeVerify(keypair.publicKeyPem, Buffer.from("x"), "not-valid-base64-signature")).toBe(false);
  });

  it("derives a stable keyId from the public key alone", () => {
    const dir = tempKeystoreDir();
    const keypair = loadOrCreateKeypair(dir);
    expect(forgeKeyId(keypair.publicKeyPem)).toBe(forgeKeyId(keypair.publicKeyPem));
    expect(forgeKeyId(keypair.publicKeyPem)).toMatch(/^ed25519-pub-forge-[0-9a-f]{16}$/);
  });
});
