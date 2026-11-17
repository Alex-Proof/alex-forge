# Spec: RFC3161-Zeitstempel für evidence.json

Einstufung: **Groß** (spec-first-gate) — neue externe Schnittstelle (TSA-Netzwerkaufruf) + neue
Abhängigkeit (ASN.1/CMS-Parsing). Von Andre bestätigt (AskUserQuestion, 2026-11-17). Siehe
`docs/ASSUMPTIONS.md` A-002 für die Wiederverwendungsentscheidung.

## Ziel

`evidence.json` erhält einen optionalen, zusätzlichen Beweis: "dieser exakte, bereits signierte
Bundle-Inhalt existierte spätestens zu Zeitpunkt X" — bestätigt von einer unabhängigen, öffentlichen
Zeitstempelstelle (TSA), nicht nur von ALEX selbst behauptet. Ergänzt die Ed25519-Signatur
(`proof`), ersetzt sie nicht.

## Scope

- Neues Modul `src/core/evidence/rfc3161-timestamp.ts`: eigenständige, angepasste Portierung der
  bewährten Logik aus `alex-core/adapters/mrtb/rfc3161Timestamp.server.ts` (kein Live-Import —
  alex-core ist kein npm-Paket, das alex-forge als Abhängigkeit einbinden könnte). Übernommen
  werden: Anfrage-Aufbau (TimeStampReq/Nonce), Antwort-Parsing, Hash-Bindungsprüfung
  (`verifyRfc3161Binding`-Äquivalent) UND CMS-Signatur-/Kettenprüfung gegen die gepinnte
  FreeTSA-Root-CA (`verifyRfc3161TsaChain`-Äquivalent) — inklusive der vier dort dokumentierten,
  live gefundenen Bugfixes (Feld-Ausschluss-Reihenfolge bei späteren Attestations-Feldern entfällt
  hier, da alex-forge keine solchen Felder kennt; Token-Hash-Bindung gegen Fälschung bleibt
  zwingend).
- Default-TSA: FreeTSA (`https://freetsa.org/tsr`), gepinnte Root-CA wie alex-core (SHA-256-
  Fingerabdruck wird übernommen, nicht neu recherchiert).
- Neue Abhängigkeiten in `package.json`: `@peculiar/asn1-schema`, `@peculiar/asn1-tsp`,
  `@peculiar/asn1-x509`, `@peculiar/asn1-cms`.
- Best-effort, optional: Netzwerkfehler/Timeout/TSA-Ablehnung/Hash-Mismatch geben `null` zurück und
  dürfen `forge repair` niemals blockieren oder scheitern lassen — exakt die Philosophie aus
  alex-core.
- Anhängen NACH `signEvidence()`: der Zeitstempel bindet sich an Signatur+Inhalt zusammen (gleiche
  Reihenfolge-Begründung wie bei `finalizeDevTaskEvidence()` in alex-core).
- `independentlyVerify()` erweitert um Bindungs- und Kettenprüfung, wenn ein `rfc3161_timestamp`
  vorhanden ist. Abwesenheit bleibt gültig — kein Fail, volle Rückwärtskompatibilität zu allen
  bestehenden Tests/Katalogeinträgen ohne Zeitstempel.
- Außerhalb des Scope: Rotation/mehrere TSAs, OCSP-/Sperrlisten-Prüfung (wie alex-core bewusst
  auch nicht prüft), Anzeige im `forge verify`-CLI-Output über einen reinen Status-String hinaus.

## Given-When-Then

1. **Given** ein frisch signiertes `evidence.json` (`signEvidence()` bereits gelaufen), **When**
   der Zeitstempel-Anhang aufgerufen wird und die TSA erreichbar antwortet, **Then** trägt
   `evidence.json` ein `rfc3161_timestamp`-Feld, dessen gebundener Hash exakt dem Hash des
   bereits signierten, unveränderten Bundle-Inhalts entspricht.
2. **Given** dieselbe Situation, **When** die TSA nicht erreichbar ist / Timeout / HTTP-Fehler /
   PKIStatus abgelehnt / Hash-Mismatch in der Antwort, **Then** kommt das unveränderte
   `evidence.json` ohne `rfc3161_timestamp` zurück, und `forge repair` schlägt dadurch **nicht**
   fehl — der Exit-Code bleibt ausschließlich vom Verifikationsergebnis abhängig, nie vom
   Zeitstempel.
3. **Given** ein `evidence.json` **mit** `rfc3161_timestamp`, **When** `independentlyVerify()`
   läuft, **Then** wird zusätzlich geprüft: (a) der im Token kryptografisch signierte Hash bindet
   exakt an den Bundle-Inhalt ohne das Zeitstempel-Feld selbst (gegen Token-Hash-Fälschung,
   alex-cores Fix vom 06.11.2026), (b) die CMS-Signatur des Tokens verifiziert gegen die gepinnte
   FreeTSA-Root-CA. Scheitert (a) oder (b), gilt das Paket als nicht verifiziert.
4. **Given** ein `evidence.json` **ohne** `rfc3161_timestamp`, **When** `independentlyVerify()`
   läuft, **Then** bleibt das Ergebnis exakt wie heute — Abwesenheit ist kein Fail.
5. **Given** `forge verify <zip> --public-key <pem>` (bereits gebaut), **When** das Paket einen
   Zeitstempel trägt, **Then** zeigt die Ausgabe zusätzlich zur Signaturprüfung den
   Zeitstempel-Status (verifiziert / fehlend / ungültig); der Exit-Code bleibt an
   `independentlyVerify()` gebunden, nicht an den Zeitstempel allein.
