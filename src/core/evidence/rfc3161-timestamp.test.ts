import { afterEach, describe, expect, it, vi } from "vitest";
import { createHash } from "node:crypto";
import { AsnSerializer, AsnParser, OctetString } from "@peculiar/asn1-schema";
import { TSTInfo, MessageImprint, TimeStampReq, TimeStampResp, PKIStatusInfo, TimeStampToken } from "@peculiar/asn1-tsp";
import { AlgorithmIdentifier, Name } from "@peculiar/asn1-x509";
import {
  ContentInfo,
  SignedData,
  EncapsulatedContentInfo,
  EncapsulatedContent,
  SignerInfo,
  SignerInfos,
  IssuerAndSerialNumber,
  SignerIdentifier,
  DigestAlgorithmIdentifiers,
} from "@peculiar/asn1-cms";
import {
  requestRfc3161Timestamp,
  attachRfc3161Timestamp,
  verifyRfc3161Binding,
  verifyRfc3161TsaChain,
  type Rfc3161Timestamp,
} from "./rfc3161-timestamp.js";
import { buildEvidence } from "./evidence.js";

/**
 * A real, unaltered FreeTSA response token, frozen from the exact same live capture alex-core's
 * own `rfc3161-tsa-chain.test.ts` uses (adapters/mrtb/, 05.09.2026) -- this ported module checks
 * the identical CMS structure against the identical pinned root CA, so re-using the same
 * real-world fixture proves the port, not a synthetic mock. The embedded TSA certificate runs
 * until 2040.
 */
const REAL_FREETSA_TOKEN_BASE64 =
  "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";

function buildEvidenceObject() {
  return buildEvidence({
    artifactId: "forge-repair-test-rfc3161",
    artifactFileName: "repair.sh",
    artifactFormat: "cli",
    artifactContent: new TextEncoder().encode("#!/bin/sh\necho hello\n"),
    sourceLogRedactedText: "service exited with code 1",
    targetOS: "linux",
    sandboxImage: "alpine:3.20",
    verification: { status: "passed", level: "L2_sandbox_executed", checks: [{ name: "check", status: "passed", exitCode: 0 }] },
    forgeVersion: "0.0.1",
    templateVersion: "1.0.0",
  });
}

/** Builds a structurally valid but UNSIGNED RFC3161 token whose TSTInfo.messageImprint carries
 * exactly the given hash. Ported from alex-core's rfc3161-timestamp-binding.test.ts helper --
 * sufficient for verifyRfc3161Binding/requestRfc3161Timestamp, which only check the token's hash
 * content, never its signature/chain (that's verifyRfc3161TsaChain's job, tested separately
 * against a real FreeTSA token above). */
function buildUnsignedTokenForHash(hash: Buffer): Buffer {
  const tstInfo = new TSTInfo({
    version: 1,
    policy: "1.2.3.4",
    messageImprint: new MessageImprint({
      hashAlgorithm: new AlgorithmIdentifier({ algorithm: "2.16.840.1.101.3.4.2.1" }),
      hashedMessage: new OctetString(hash),
    }),
    serialNumber: new Uint8Array([1]),
    genTime: new Date("2026-09-05T09:32:37.000Z"),
  });
  const tstInfoBytes = Buffer.from(AsnSerializer.serialize(tstInfo));
  const dummySigner = new SignerInfo({
    version: 1,
    sid: new SignerIdentifier({ issuerAndSerialNumber: new IssuerAndSerialNumber({ issuer: new Name(), serialNumber: new Uint8Array([1]) }) }),
    digestAlgorithm: new AlgorithmIdentifier({ algorithm: "2.16.840.1.101.3.4.2.1" }),
    signatureAlgorithm: new AlgorithmIdentifier({ algorithm: "1.2.840.10045.4.3.2" }),
    signature: new OctetString(new Uint8Array([0])),
  });
  const signedData = new SignedData({
    version: 3,
    digestAlgorithms: new DigestAlgorithmIdentifiers([new AlgorithmIdentifier({ algorithm: "2.16.840.1.101.3.4.2.1" })]),
    encapContentInfo: new EncapsulatedContentInfo({
      eContentType: "1.2.840.113549.1.9.16.1.4",
      eContent: new EncapsulatedContent({ single: new OctetString(tstInfoBytes) }),
    }),
    signerInfos: new SignerInfos([dummySigner]),
  });
  const contentInfo = new ContentInfo({
    contentType: "1.2.840.113549.1.7.2",
    content: new Uint8Array(Buffer.from(AsnSerializer.serialize(signedData))),
  });
  return Buffer.from(AsnSerializer.serialize(contentInfo));
}

function buildGrantedTsaResponseBytes(hash: Buffer): Buffer {
  const tokenBytes = buildUnsignedTokenForHash(hash);
  // TimeStampToken extends ContentInfo -- re-parse the serialized bytes into that exact subtype
  // so asn1-schema's serializer encodes it correctly as part of TimeStampResp.
  const resp = new TimeStampResp({
    status: new PKIStatusInfo({ status: 0 }),
    timeStampToken: AsnParser.parse(tokenBytes, TimeStampToken),
  });
  return Buffer.from(AsnSerializer.serialize(resp));
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("requestRfc3161Timestamp", () => {
  it("returns a timestamp when the TSA grants a token bound to the requested hash", async () => {
    const fetchMock = vi.fn(async (_url: string, init: RequestInit) => {
      const body = init.body as Buffer;
      const req = parseTimeStampReq(body);
      const respBytes = buildGrantedTsaResponseBytes(Buffer.from(req.messageImprint.hashedMessage.buffer));
      return new Response(respBytes, { status: 200 });
    });
    vi.stubGlobal("fetch", fetchMock);

    const hash = createHash("sha256").update("hello").digest();
    const result = await requestRfc3161Timestamp(hash);

    expect(result).not.toBeNull();
    expect(result?.timestamped_sha256).toBe(hash.toString("hex"));
    expect(result?.tsa_url).toBe("https://freetsa.org/tsr");
  });

  it("returns null when the TSA HTTP response is not ok", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("", { status: 503 })));
    const result = await requestRfc3161Timestamp(createHash("sha256").update("x").digest());
    expect(result).toBeNull();
  });

  it("returns null when the network request itself fails", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new Error("ECONNREFUSED");
      }),
    );
    const result = await requestRfc3161Timestamp(createHash("sha256").update("x").digest());
    expect(result).toBeNull();
  });

  it("returns null when the TSA response is bound to a different hash than requested", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        const wrongHash = createHash("sha256").update("not-what-was-asked").digest();
        return new Response(buildGrantedTsaResponseBytes(wrongHash), { status: 200 });
      }),
    );
    const result = await requestRfc3161Timestamp(createHash("sha256").update("x").digest());
    expect(result).toBeNull();
  });
});

function parseTimeStampReq(der: Buffer) {
  return AsnParser.parse(der, TimeStampReq);
}

describe("attachRfc3161Timestamp -- best-effort, never blocks the pipeline", () => {
  it("attaches a timestamp bound to the already-signed evidence content when the TSA responds", async () => {
    vi.stubGlobal("fetch", async (_url: string, init: RequestInit) => {
      const req = parseTimeStampReq(init.body as Buffer);
      const respBytes = buildGrantedTsaResponseBytes(Buffer.from(req.messageImprint.hashedMessage.buffer));
      return new Response(respBytes, { status: 200 });
    });

    const evidence = buildEvidenceObject();
    const result = await attachRfc3161Timestamp(evidence);

    expect(result.rfc3161_timestamp).toBeDefined();
    const { rfc3161_timestamp: _ts, ...withoutTimestamp } = result;
    const expectedHash = createHash("sha256").update(JSON.stringify(withoutTimestamp)).digest("hex");
    expect(result.rfc3161_timestamp?.timestamped_sha256).toBe(expectedHash);
  });

  it("returns the evidence unchanged when the TSA is unreachable, never throwing or failing", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new Error("network down");
      }),
    );

    const evidence = buildEvidenceObject();
    const result = await attachRfc3161Timestamp(evidence);

    expect(result).toEqual(evidence);
    expect(result.rfc3161_timestamp).toBeUndefined();
  });
});

describe("verifyRfc3161Binding", () => {
  it("accepts a timestamp genuinely bound to this evidence content", async () => {
    vi.stubGlobal("fetch", async (_url: string, init: RequestInit) => {
      const req = parseTimeStampReq(init.body as Buffer);
      const respBytes = buildGrantedTsaResponseBytes(Buffer.from(req.messageImprint.hashedMessage.buffer));
      return new Response(respBytes, { status: 200 });
    });
    const signed = await attachRfc3161Timestamp(buildEvidenceObject());
    expect(verifyRfc3161Binding(signed)).toEqual({ ok: true });
  });

  it("reports no_timestamp_present when none is attached", () => {
    expect(verifyRfc3161Binding(buildEvidenceObject())).toEqual({ ok: false, reason: "no_timestamp_present" });
  });

  it("rejects evidence whose content changed after the timestamp was taken", () => {
    const evidence = buildEvidenceObject();
    const declaredHash = createHash("sha256").update(JSON.stringify(evidence)).digest("hex");
    const timestamp: Rfc3161Timestamp = {
      schema_version: "rfc3161-timestamp@1.0",
      tsa_url: "https://freetsa.org/tsr",
      timestamped_sha256: declaredHash,
      gen_time: "2026-09-05T09:32:37.000Z",
      token_der_base64: buildUnsignedTokenForHash(Buffer.from(declaredHash, "hex")).toString("base64"),
    };
    const tampered = { ...evidence, artifactId: "tampered-after-the-fact", rfc3161_timestamp: timestamp };
    expect(verifyRfc3161Binding(tampered)).toEqual({ ok: false, reason: "timestamp_hash_mismatch" });
  });

  it("rejects a real, validly structured token replayed onto a foreign evidence package (forgery)", () => {
    const forged = buildEvidenceObject();
    const forgedDeclaredHash = createHash("sha256").update(JSON.stringify(forged)).digest("hex");
    const realTokenHash = createHash("sha256").update("originales-anderes-bundle").digest();
    const timestamp: Rfc3161Timestamp = {
      schema_version: "rfc3161-timestamp@1.0",
      tsa_url: "https://freetsa.org/tsr",
      // Attacker sets the self-declared field to the forged bundle's own hash -- internally
      // self-consistent, but the token itself cryptographically binds to a DIFFERENT real hash.
      timestamped_sha256: forgedDeclaredHash,
      gen_time: "2026-09-05T09:32:37.000Z",
      token_der_base64: buildUnsignedTokenForHash(realTokenHash).toString("base64"),
    };
    const bundle = { ...forged, rfc3161_timestamp: timestamp };
    expect(verifyRfc3161Binding(bundle)).toEqual({ ok: false, reason: "token_hash_mismatch" });
  });
});

describe("verifyRfc3161TsaChain -- CMS signature + certificate chain against the pinned FreeTSA root", () => {
  function buildTimestamp(tokenDerBase64: string): Rfc3161Timestamp {
    return {
      schema_version: "rfc3161-timestamp@1.0",
      tsa_url: "https://freetsa.org/tsr",
      timestamped_sha256: "5f0f5cd640007e902518e8ab66b502a7a27c36a8850154c1ef1e79725ac8a1cb",
      gen_time: "2026-09-05T09:32:37.000Z",
      token_der_base64: tokenDerBase64,
    };
  }

  it("accepts a real, unaltered FreeTSA token", () => {
    expect(verifyRfc3161TsaChain(buildTimestamp(REAL_FREETSA_TOKEN_BASE64))).toEqual({ ok: true });
  });

  it("rejects a token with tampered signature bytes", () => {
    const tampered = REAL_FREETSA_TOKEN_BASE64.slice(0, -4) + (REAL_FREETSA_TOKEN_BASE64.endsWith("AAAA") ? "BBBB" : "AAAA");
    expect(verifyRfc3161TsaChain(buildTimestamp(tampered))).toEqual({ ok: false, reason: "signature_invalid" });
  });

  it("rejects unparsable DER instead of throwing", () => {
    const result = verifyRfc3161TsaChain(buildTimestamp("!!!not-valid-base64!!!"));
    expect(result.ok).toBe(false);
    expect(result.reason).toMatch(/^parse_error:/);
  });
});
