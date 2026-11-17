/**
 * RFC3161-Zeitstempel für `evidence.json`: eine eigenständige, angepasste Portierung der
 * ausgereiften Logik aus alex-core (`adapters/mrtb/rfc3161Timestamp.server.ts`, Andres
 * Härtungsplan Phase A/B-Grenze), siehe docs/ASSUMPTIONS.md A-002 für die Übernahmebegründung.
 * Kein Live-Import, da alex-core kein npm-Paket ist, das alex-forge als Abhängigkeit einbinden
 * könnte -- die gehärtete Logik (inkl. Token-Hash-Fälschungsschutz) wird hier nachgebaut, nicht
 * neu erfunden.
 *
 * Beweist zusätzlich zur Ed25519-Signatur: "dieser exakte, bereits signierte Bundle-Inhalt
 * existierte spätestens zu diesem Zeitpunkt" -- bestätigt von einer unabhängigen, öffentlichen
 * Zeitstempelstelle (TSA), nicht nur von Forge selbst behauptet. Bewusst best-effort: ein
 * Netzwerkfehler/Timeout/eine abgelehnte Anfrage darf niemals die eigentliche Bundle-Erstellung
 * blockieren oder verwerfen.
 *
 * Ehrlicher Umfang (nicht verschwiegen): geprüft werden die Hash-Bindung
 * (verifyRfc3161Binding) UND die CMS/PKCS7-Signatur der TSA samt Zertifikatskette gegen die
 * gepinnte FreeTSA-Root-CA (verifyRfc3161TsaChain). NICHT geprüft: Sperrlisten-/OCSP-Status der
 * TSA-Zertifikate und eine Ablaufkette über mehr als diese zwei Ebenen (Root -> TSA-Zertifikat).
 * Das rohe Token (`token_der_base64`) ist Standard-RFC3161-DER und bleibt unabhängig von diesem
 * Code mit Standardwerkzeugen prüfbar (z. B. `openssl ts -reply -in token.der -text`).
 */
import { createHash, randomBytes, verify as cryptoVerify, X509Certificate } from "node:crypto";
import { AsnSerializer, AsnParser, OctetString } from "@peculiar/asn1-schema";
import { TimeStampReq, TimeStampResp, MessageImprint, TSTInfo } from "@peculiar/asn1-tsp";
import { AlgorithmIdentifier } from "@peculiar/asn1-x509";
import { ContentInfo, SignedData, SignerInfo, id_messageDigest } from "@peculiar/asn1-cms";
import type { EvidencePackage } from "./schema.js";

const SHA256_OID = "2.16.840.1.101.3.4.2.1";
export const DEFAULT_TSA_URL = "https://freetsa.org/tsr";
const REQUEST_TIMEOUT_MS = 8_000;

export type Rfc3161Timestamp = NonNullable<EvidencePackage["rfc3161_timestamp"]>;

function buildNonce(): ArrayBuffer {
  const nonce = randomBytes(16);
  // Führende 0x00 falls das erste Bit gesetzt ist, sonst liest ASN.1 die INTEGER als negativ.
  const buf = nonce[0]! & 0x80 ? Buffer.concat([Buffer.from([0x00]), nonce]) : nonce;
  return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
}

/** Fragt einen RFC3161-Zeitstempel für einen SHA-256-Hash an. Gibt bei jedem Fehler (Netzwerk,
 *  Timeout, TSA-Ablehnung, Hash-Mismatch in der Antwort) `null` zurück statt zu werfen. */
export async function requestRfc3161Timestamp(hash: Buffer, tsaUrl = DEFAULT_TSA_URL): Promise<Rfc3161Timestamp | null> {
  try {
    const req = new TimeStampReq({
      version: 1,
      messageImprint: new MessageImprint({
        hashAlgorithm: new AlgorithmIdentifier({ algorithm: SHA256_OID }),
        hashedMessage: new OctetString(hash),
      }),
      nonce: buildNonce(),
      certReq: true,
    });
    const reqDer = Buffer.from(AsnSerializer.serialize(req));

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    let respBytes: Buffer;
    try {
      const res = await fetch(tsaUrl, {
        method: "POST",
        headers: { "Content-Type": "application/timestamp-query" },
        body: reqDer,
        signal: controller.signal,
      });
      if (!res.ok) {
        console.warn(`[rfc3161] TSA antwortete mit HTTP ${res.status}`);
        return null;
      }
      respBytes = Buffer.from(await res.arrayBuffer());
    } finally {
      clearTimeout(timeout);
    }

    const resp = AsnParser.parse(respBytes, TimeStampResp);
    // PKIStatus: 0=granted, 1=grantedWithMods -- beides ein gültiges Token.
    if (resp.status.status !== 0 && resp.status.status !== 1) {
      console.warn(`[rfc3161] TSA lehnte Zeitstempel ab, PKIStatus=${resp.status.status}`);
      return null;
    }
    if (!resp.timeStampToken) {
      console.warn("[rfc3161] Keine timeStampToken in der TSA-Antwort.");
      return null;
    }

    const tokenDer = Buffer.from(AsnSerializer.serialize(resp.timeStampToken));
    const signedData = AsnParser.parse(new Uint8Array(resp.timeStampToken.content), SignedData);
    const tstInfoOctets = signedData.encapContentInfo.eContent?.single;
    if (!tstInfoOctets) {
      console.warn("[rfc3161] TSTInfo im Token nicht auffindbar.");
      return null;
    }
    const tstInfo = AsnParser.parse(new Uint8Array(tstInfoOctets.buffer), TSTInfo);

    const returnedHash = Buffer.from(tstInfo.messageImprint.hashedMessage.buffer);
    if (!returnedHash.equals(hash)) {
      console.warn("[rfc3161] TSA-Antwort hängt am falschen Hash -- verworfen, kein Vertrauensgewinn ohne Bindung.");
      return null;
    }

    return {
      schema_version: "rfc3161-timestamp@1.0",
      tsa_url: tsaUrl,
      timestamped_sha256: hash.toString("hex"),
      gen_time: tstInfo.genTime instanceof Date ? tstInfo.genTime.toISOString() : String(tstInfo.genTime),
      token_der_base64: tokenDer.toString("base64"),
    };
  } catch (error) {
    console.warn(
      "[rfc3161] Zeitstempel-Anfrage fehlgeschlagen (best-effort, Bundle bleibt ohne Zeitstempel gültig):",
      error instanceof Error ? error.message : String(error),
    );
    return null;
  }
}

/**
 * Hängt einen RFC3161-Zeitstempel über den kompletten, bereits signierten evidence.json-Inhalt
 * an. Muss NACH signEvidence() aufgerufen werden -- der Zeitstempel bindet sich an Signatur+
 * Inhalt zusammen, beweist also "genau dieses signierte Artefakt existierte spätestens zu
 * Zeitpunkt X". Best-effort: bei jedem Fehler kommt das unveränderte Original zurück.
 */
export async function attachRfc3161Timestamp(evidence: EvidencePackage, tsaUrl = DEFAULT_TSA_URL): Promise<EvidencePackage> {
  const { rfc3161_timestamp: _existing, ...withoutTimestamp } = evidence;
  const hash = createHash("sha256").update(JSON.stringify(withoutTimestamp)).digest();
  const timestamp = await requestRfc3161Timestamp(hash, tsaUrl);
  if (!timestamp) return evidence;
  return { ...evidence, rfc3161_timestamp: timestamp };
}

function extractTokenMessageHashHex(timestamp: Rfc3161Timestamp): { ok: true; hashHex: string } | { ok: false; reason: string } {
  try {
    const tokenDer = Buffer.from(timestamp.token_der_base64, "base64");
    const contentInfo = AsnParser.parse(tokenDer, ContentInfo);
    const signedData = AsnParser.parse(new Uint8Array(contentInfo.content), SignedData);
    const tstInfoOctets = signedData.encapContentInfo.eContent?.single;
    if (!tstInfoOctets) return { ok: false, reason: "no_encapsulated_content" };
    const tstInfo = AsnParser.parse(new Uint8Array(tstInfoOctets.buffer), TSTInfo);
    if (tstInfo.messageImprint.hashAlgorithm.algorithm !== SHA256_OID) {
      return { ok: false, reason: "unsupported_digest_algorithm" };
    }
    return { ok: true, hashHex: Buffer.from(tstInfo.messageImprint.hashedMessage.buffer).toString("hex") };
  } catch (error) {
    return { ok: false, reason: `parse_error:${error instanceof Error ? error.message : "unknown"}` };
  }
}

/**
 * Bindungs-Check: bestätigt, dass der mitgelieferte Zeitstempel tatsächlich zu DIESEM
 * evidence.json-Inhalt gehört -- sowohl über das selbst-deklarierte Feld als auch über den im
 * Token kryptografisch signierten Hash (gegen Token-Hash-Fälschung: ein Angreifer könnte sonst
 * einen echten, gültig signierten Token für Hash A nehmen und ihn an ein fremdes evidence.json
 * mit Hash B hängen). Prüft NICHT die CMS-Signatur der TSA oder deren Zertifikatskette, siehe
 * verifyRfc3161TsaChain.
 */
export function verifyRfc3161Binding(evidence: EvidencePackage): { ok: boolean; reason?: string } {
  if (!evidence.rfc3161_timestamp) return { ok: false, reason: "no_timestamp_present" };
  const { rfc3161_timestamp, ...withoutTimestamp } = evidence;
  const recomputed = createHash("sha256").update(JSON.stringify(withoutTimestamp)).digest("hex");
  if (recomputed !== rfc3161_timestamp.timestamped_sha256) {
    return { ok: false, reason: "timestamp_hash_mismatch" };
  }
  const tokenHash = extractTokenMessageHashHex(rfc3161_timestamp);
  if (!tokenHash.ok) return { ok: false, reason: `token_${tokenHash.reason}` };
  if (tokenHash.hashHex !== rfc3161_timestamp.timestamped_sha256) {
    return { ok: false, reason: "token_hash_mismatch" };
  }
  return { ok: true };
}

// Gepinntes FreeTSA-Root-CA-Zertifikat (https://freetsa.org/files/cacert.pem), übernommen aus
// alex-core (dort am 05.09.2026 per curl+openssl gegengeprüft, SHA-256-Fingerabdruck
// A6:37:9E:7C:EC:C0:5F:AA:3C:BF:07:60:13:D7:45:E3:27:BB:BA:A3:8C:0B:9A:F2:24:69:D4:70:1D:18:AA:BC,
// gültig bis 2041-03-07). FreeTSA signiert Zeitstempel-Tokens mit einem separaten
// TSA-Zertifikat (OU=TSA), direkt von dieser Root-CA ausgestellt, kein Intermediate dazwischen.
export const FREETSA_ROOT_CA_PEM = `-----BEGIN CERTIFICATE-----
MIIH/zCCBeegAwIBAgIJAMHphhYNqOmAMA0GCSqGSIb3DQEBDQUAMIGVMREwDwYD
VQQKEwhGcmVlIFRTQTEQMA4GA1UECxMHUm9vdCBDQTEYMBYGA1UEAxMPd3d3LmZy
ZWV0c2Eub3JnMSIwIAYJKoZIhvcNAQkBFhNidXNpbGV6YXNAZ21haWwuY29tMRIw
EAYDVQQHEwlXdWVyemJ1cmcxDzANBgNVBAgTBkJheWVybjELMAkGA1UEBhMCREUw
HhcNMTYwMzEzMDE1MjEzWhcNNDEwMzA3MDE1MjEzWjCBlTERMA8GA1UEChMIRnJl
ZSBUU0ExEDAOBgNVBAsTB1Jvb3QgQ0ExGDAWBgNVBAMTD3d3dy5mcmVldHNhLm9y
ZzEiMCAGCSqGSIb3DQEJARYTYnVzaWxlemFzQGdtYWlsLmNvbTESMBAGA1UEBxMJ
V3VlcnpidXJnMQ8wDQYDVQQIEwZCYXllcm4xCzAJBgNVBAYTAkRFMIICIjANBgkq
hkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtgKODjAy8REQ2WTNqUudAnjhlCrpE6ql
mQfNppeTmVvZrH4zutn+NwTaHAGpjSGv4/WRpZ1wZ3BRZ5mPUBZyLgq0YrIfQ5Fx
0s/MRZPzc1r3lKWrMR9sAQx4mN4z11xFEO529L0dFJjPF9MD8Gpd2feWzGyptlel
b+PqT+++fOa2oY0+NaMM7l/xcNHPOaMz0/2olk0i22hbKeVhvokPCqhFhzsuhKsm
q4Of/o+t6dI7sx5h0nPMm4gGSRhfq+z6BTRgCrqQG2FOLoVFgt6iIm/BnNffUr7V
DYd3zZmIwFOj/H3DKHoGik/xK3E82YA2ZulVOFRW/zj4ApjPa5OFbpIkd0pmzxzd
EcL479hSA9dFiyVmSxPtY5ze1P+BE9bMU1PScpRzw8MHFXxyKqW13Qv7LWw4sbk3
SciB7GACbQiVGzgkvXG6y85HOuvWNvC5GLSiyP9GlPB0V68tbxz4JVTRdw/Xn/XT
FNzRBM3cq8lBOAVt/PAX5+uFcv1S9wFE8YjaBfWCP1jdBil+c4e+0tdywT2oJmYB
BF/kEt1wmGwMmHunNEuQNzh1FtJY54hbUfiWi38mASE7xMtMhfj/C4SvapiDN837
gYaPfs8x3KZxbX7C3YAsFnJinlwAUss1fdKar8Q/YVs7H/nU4c4Ixxxz4f67fcVq
M2ITKentbCMCAwEAAaOCAk4wggJKMAwGA1UdEwQFMAMBAf8wDgYDVR0PAQH/BAQD
AgHGMB0GA1UdDgQWBBT6VQ2MNGZRQ0z357OnbJWveuaklzCBygYDVR0jBIHCMIG/
gBT6VQ2MNGZRQ0z357OnbJWveuakl6GBm6SBmDCBlTERMA8GA1UEChMIRnJlZSBU
U0ExEDAOBgNVBAsTB1Jvb3QgQ0ExGDAWBgNVBAMTD3d3dy5mcmVldHNhLm9yZzEi
MCAGCSqGSIb3DQEJARYTYnVzaWxlemFzQGdtYWlsLmNvbTESMBAGA1UEBxMJV3Vl
cnpidXJnMQ8wDQYDVQQIEwZCYXllcm4xCzAJBgNVBAYTAkRFggkAwemGFg2o6YAw
MwYDVR0fBCwwKjAooCagJIYiaHR0cDovL3d3dy5mcmVldHNhLm9yZy9yb290X2Nh
LmNybDCBzwYDVR0gBIHHMIHEMIHBBgorBgEEAYHyJAEBMIGyMDMGCCsGAQUFBwIB
FidodHRwOi8vd3d3LmZyZWV0c2Eub3JnL2ZyZWV0c2FfY3BzLmh0bWwwMgYIKwYB
BQUHAgEWJmh0dHA6Ly93d3cuZnJlZXRzYS5vcmcvZnJlZXRzYV9jcHMucGRmMEcG
CCsGAQUFBwICMDsaOUZyZWVUU0EgdHJ1c3RlZCB0aW1lc3RhbXBpbmcgU29mdHdh
cmUgYXMgYSBTZXJ2aWNlIChTYWFTKTA3BggrBgEFBQcBAQQrMCkwJwYIKwYBBQUH
MAGGG2h0dHA6Ly93d3cuZnJlZXRzYS5vcmc6MjU2MDANBgkqhkiG9w0BAQ0FAAOC
AgEAaK9+v5OFYu9M6ztYC+L69sw1omdyli89lZAfpWMMh9CRmJhM6KBqM/ipwoLt
nxyxGsbCPhcQjuTvzm+ylN6VwTMmIlVyVSLKYZcdSjt/eCUN+41K7sD7GVmxZBAF
ILnBDmTGJmLkrU0KuuIpj8lI/E6Z6NnmuP2+RAQSHsfBQi6sssnXMo4HOW5gtPO7
gDrUpVXID++1P4XndkoKn7Svw5n0zS9fv1hxBcYIHPPQUze2u30bAQt0n0iIyRLz
aWuhtpAtd7ffwEbASgzB7E+NGF4tpV37e8KiA2xiGSRqT5ndu28fgpOY87gD3ArZ
DctZvvTCfHdAS5kEO3gnGGeZEVLDmfEsv8TGJa3AljVa5E40IQDsUXpQLi8G+UC4
1DWZu8EVT4rnYaCw1VX7ShOR1PNCCvjb8S8tfdudd9zhU3gEB0rxdeTy1tVbNLXW
99y90xcwr1ZIDUwM/xQ/noO8FRhm0LoPC73Ef+J4ZBdrvWwauF3zJe33d4ibxEcb
8/pz5WzFkeixYM2nsHhqHsBKw7JPouKNXRnl5IAE1eFmqDyC7G/VT7OF669xM6hb
Ut5G21JE4cNK6NNucS+fzg1JPX0+3VhsYZjj7D5uljRvQXrJ8iHgr/M6j2oLHvTA
I2MLdq2qjZFDOCXsxBxJpbmLGBx9ow6ZerlUxzws2AWv2pk=
-----END CERTIFICATE-----`;

const DIGEST_OID_TO_NODE_HASH: Record<string, string> = {
  "1.3.14.3.2.26": "sha1",
  "2.16.840.1.101.3.4.2.1": "sha256",
  "2.16.840.1.101.3.4.2.2": "sha384",
  "2.16.840.1.101.3.4.2.3": "sha512",
};

/** ASN.1-INTEGER-Bytes (ggf. mit führendem 0x00-Vorzeichenpadding) auf den kanonischen,
 *  vorzeichenlosen Hex-String normalisieren -- passend zu Node's `X509Certificate.serialNumber`. */
function normalizeSerialHex(buf: ArrayBuffer): string {
  let bytes = Buffer.from(buf);
  while (bytes.length > 1 && bytes[0] === 0x00) bytes = bytes.subarray(1);
  return bytes.toString("hex").toUpperCase();
}

/** Kodiert eine DER-Länge (kurze ODER lange Form, je nach Größe). */
function encodeDerLength(len: number): Buffer {
  if (len < 0x80) return Buffer.from([len]);
  const bytes: number[] = [];
  let n = len;
  while (n > 0) {
    bytes.unshift(n & 0xff);
    n >>= 8;
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

/** Baut die Bytes nach, über die die CMS-Signatur tatsächlich läuft, wenn `signedAttrs` gesetzt
 *  sind (RFC 5652 §5.4): jedes Attribut einzeln unverändert re-serialisiert, dann in einen
 *  SET-OF-Rahmen (Tag 0x31, UNIVERSAL) verpackt -- NICHT den im Token übertragenen
 *  IMPLICIT-[0]-Rahmen (Tag 0xA0), der für die Signaturprüfung laut Standard durch die explizite
 *  SET-Kodierung ersetzt werden muss. */
function reencodeSignedAttrsForVerification(signedAttrs: SignerInfo["signedAttrs"]): Buffer {
  const content = Buffer.concat((signedAttrs ?? []).map((attr) => Buffer.from(AsnSerializer.serialize(attr))));
  return Buffer.concat([Buffer.from([0x31]), encodeDerLength(content.length), content]);
}

/** Findet unter den im Token mitgelieferten Zertifikaten dasjenige, auf das `signerInfo.sid`
 *  verweist (per IssuerAndSerialNumber-Seriennummer -- FreeTSAs echte Tokens nutzen diese
 *  SignerIdentifier-Variante, nicht SubjectKeyIdentifier). `null` bei jeder Abweichung. */
function findSignerCertificateDer(signedData: SignedData, signerInfo: SignerInfo): Buffer | null {
  const wanted = signerInfo.sid?.issuerAndSerialNumber;
  if (!wanted || !signedData.certificates) return null;
  const wantedSerialHex = normalizeSerialHex(wanted.serialNumber);
  for (const choice of signedData.certificates) {
    if (!choice.certificate) continue;
    let der: Buffer;
    try {
      der = Buffer.from(AsnSerializer.serialize(choice.certificate));
    } catch {
      continue;
    }
    try {
      if (new X509Certificate(der).serialNumber.toUpperCase() === wantedSerialHex) return der;
    } catch {
      // kein gültiges X.509 -- nächsten Kandidaten prüfen
    }
  }
  return null;
}

/**
 * Prüft, was verifyRfc3161Binding bewusst offenlässt: dass der Zeitstempel-Token tatsächlich von
 * FreeTSA signiert wurde (CMS-SignerInfo-Signatur über die TSTInfo bzw. deren signierte
 * Attribute, RFC 5652 §5.4) UND dass das dafür verwendete Zertifikat von der gepinnten
 * FreeTSA-Root-CA ausgestellt ist. Geprüft wird NUR die Signatur- und Ausstellungskette -- keine
 * Sperrlisten/OCSP, kein Ablauf-Check über die reine Gültigkeitsprüfung hinaus. Wie der Rest
 * dieses Moduls: nie werfend, nur `{ ok, reason }`.
 */
export function verifyRfc3161TsaChain(timestamp: Rfc3161Timestamp): { ok: boolean; reason?: string } {
  try {
    const tokenDer = Buffer.from(timestamp.token_der_base64, "base64");
    const contentInfo = AsnParser.parse(tokenDer, ContentInfo);
    const signedData = AsnParser.parse(new Uint8Array(contentInfo.content), SignedData);
    const signerInfo = signedData.signerInfos[0];
    if (!signerInfo) return { ok: false, reason: "no_signer_info" };

    const certDer = findSignerCertificateDer(signedData, signerInfo);
    if (!certDer) return { ok: false, reason: "signer_certificate_not_found" };

    let tsaCert: X509Certificate;
    let rootCert: X509Certificate;
    try {
      tsaCert = new X509Certificate(certDer);
      rootCert = new X509Certificate(FREETSA_ROOT_CA_PEM);
    } catch {
      return { ok: false, reason: "certificate_unparsable" };
    }
    if (!tsaCert.verify(rootCert.publicKey)) return { ok: false, reason: "chain_untrusted" };

    const hashName = DIGEST_OID_TO_NODE_HASH[signerInfo.digestAlgorithm.algorithm];
    if (!hashName) return { ok: false, reason: "unsupported_digest_algorithm" };

    const tstInfoOctets = signedData.encapContentInfo.eContent?.single;
    if (!tstInfoOctets) return { ok: false, reason: "no_encapsulated_content" };
    const tstInfoBytes = Buffer.from(tstInfoOctets.buffer);

    if (!signerInfo.signedAttrs || signerInfo.signedAttrs.length === 0) {
      // Kein signedAttrs -- FreeTSA nutzt diesen Pfad bisher nicht, hier trotzdem korrekt
      // behandelt: Signatur direkt über den Inhalt statt über signierte Attribute.
      const sigOk = cryptoVerify(hashName, tstInfoBytes, tsaCert.publicKey, Buffer.from(signerInfo.signature.buffer));
      return sigOk ? { ok: true } : { ok: false, reason: "signature_invalid" };
    }

    const messageDigestAttr = signerInfo.signedAttrs.find((a) => a.attrType === id_messageDigest);
    if (!messageDigestAttr?.attrValues[0]) return { ok: false, reason: "no_message_digest_attribute" };
    const claimedDigest = Buffer.from(AsnParser.parse(messageDigestAttr.attrValues[0], OctetString).buffer);
    const actualDigest = createHash(hashName).update(tstInfoBytes).digest();
    if (!claimedDigest.equals(actualDigest)) return { ok: false, reason: "message_digest_mismatch" };

    const reencodedAttrs = reencodeSignedAttrsForVerification(signerInfo.signedAttrs);
    const sigOk = cryptoVerify(hashName, reencodedAttrs, tsaCert.publicKey, Buffer.from(signerInfo.signature.buffer));
    return sigOk ? { ok: true } : { ok: false, reason: "signature_invalid" };
  } catch (error) {
    return { ok: false, reason: `parse_error:${error instanceof Error ? error.message : "unknown"}` };
  }
}
