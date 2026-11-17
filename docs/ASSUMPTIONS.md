# Decision & Assumption Register

Übernommen aus alex-core (`CLAUDE.md` → `assumption-register`), 1:1 gleiches Format. Pflicht-Eintrag
ab Einstufung "mittel" oder "groß" im Spec-First-Gate, nicht für jeden Minimal-Patch.

Status-Werte: `PROPOSED` (noch nicht bestätigt) · `CONFIRMED` (von Andre oder durch echten
Test/Code-Nachweis bestätigt) · `REJECTED` (geprüft und verworfen) · `SUPERSEDED` (durch neuere
Entscheidung ersetzt, alter Eintrag bleibt stehen).

Eine Annahme mit Status `PROPOSED` ist keine bestätigte Architekturentscheidung und darf nicht
als solche behandelt oder zitiert werden.

| ID | Entscheidung/Annahme | Begründung | Status | Quelle | Auswirkungen | Review |
| --- | --- | --- | --- | --- | --- | --- |
| A-001 | Trust-Anchor für `evidence.json` (Ed25519, `src/core/evidence/keystore.ts` + `canonical-json.ts`) wird bewusst unabhängig von Panzers Signier-/Prüf-Code gebaut, kein geteilter Code zwischen Signierer und Prüfer | Panzer hat eigenen `keystore.ts`/`canonicalJson.ts` (`packages/panzer/src/canonicalJson.ts`, Zeile 1-11 kommentiert dasselbe Prinzip). Geteilter Code zwischen Signierer und Prüfer würde einen Bug in beiden Rollen gleichzeitig verstecken — Trennung ist der Punkt der Signatur, nicht Zufall | PROPOSED | Session 2026-11-17, Implementierung in `evidence.ts`/`cli.ts` (`forge repair`) | Kein gemeinsames Paket/Abstraktion mit Panzer für Signieren/Prüfen; künftige Änderungen an einem Verifier dürfen nicht automatisch den anderen mitziehen | Vor Punkt 2 (eigenständiger `forge verify`-Befehl) erneut prüfen, ob die Trennung noch trägt oder ob Drittverifikation einen gemeinsamen, unabhängig auditierten Prüf-Kern rechtfertigt |
| A-002 | RFC3161-Zeitstempel-Logik wird als eigenständige, angepasste Portierung aus `alex-core/adapters/mrtb/rfc3161Timestamp.server.ts` übernommen (Anfrage, Hash-Bindung, CMS-Kettenprüfung gegen gepinnte FreeTSA-Root-CA), nicht von Null neu gebaut und nicht per Live-Import aus alex-core bezogen | alex-core-Modul ist ausgereift (4 dokumentierte, live gefundene Bugfixes, u. a. Token-Hash-Fälschungsschutz vom 06.11.2026) — Neubau würde dieselben ASN.1/CMS-Fallstricke riskieren, erneut zu lösen. Live-Import ist technisch nicht möglich: alex-forge ist ein eigenes, öffentlich zu publizierendes Repo (`private: false`, MIT) ohne alex-core als npm-Abhängigkeit. Einstufung "Groß" (neue externe Schnittstelle + neue Abhängigkeit) von Andre bestätigt | PROPOSED | Session 2026-11-17, AskUserQuestion ("das beste davon" — Entscheidung an Claude delegiert), Spec in `docs/spec-rfc3161-timestamp.md` | Neue Abhängigkeiten `@peculiar/asn1-schema`/`asn1-tsp`/`asn1-x509`/`asn1-cms`; Portierung muss bei künftigen Fixes in alex-cores Original manuell nachgezogen werden (keine automatische Sync) | Implementiert (`src/core/evidence/rfc3161-timestamp.ts`) und 2026-11-17 live gegen echten FreeTSA-Request verifiziert (echter Zeitstempel geholt, Hash-Bindung + CMS-Kettenprüfung bestanden, Smoke-Test danach wieder entfernt, nicht in der committeten Suite). Status bleibt PROPOSED bis Andre das bestätigt |
