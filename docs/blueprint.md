# Forge -- Technische Gesamtanleitung

**Version:** 0.2 · **Stand:** 16.10.2026\
**Zweck:** Umsetzbarer Architektur-, Sicherheits- und
Implementierungsplan für ein eigenständiges Tool zur Erzeugung, Prüfung
und Freigabe von Reparatur-Artefakten.

------------------------------------------------------------------------

## 1. Zusammenfassung

**Forge** ist ein eigenständiges Werkzeug außerhalb der Control Layer.
Es verarbeitet entweder unstrukturierte Fehler-Logs (SysFix) oder -- in
einer späteren Ausbaustufe -- zwei bis fünf vorhandene Tools
(AgentShield). Forge erzeugt daraus Artefakte in drei Zielformaten:

1.  **CLI-Skript** (`.sh`, `.ps1`, `.py`, `.mjs`)
2.  **Standalone-HTML** als einzelne Datei
3.  **VS Code Extension-Projekt** mit Export als `.vsix`

Jedes Artefakt erhält ein Evidence Package. Dieses dokumentiert exakt,
was geprüft wurde, mit welchen Werkzeugen, welchen Ergebnissen und
welchem Hash. **Nur Artefakte, die die für ihren Typ vorgeschriebenen
Gates bestehen, werden in den Katalog aufgenommen.**

Forge installiert nichts automatisch. Es erzeugt überprüfbare Dateien
und Pakete; der Nutzer entscheidet, ob und wo er sie einsetzt.

### Leitprinzipien

-   **Beleg statt Behauptung:** „verifiziert" darf nur verwendet werden,
    wenn die dokumentierten Prüfungen tatsächlich stattgefunden haben.
-   **Fail closed:** Bei Policy-, Validierungs- oder Runner-Fehlern wird
    nicht freigegeben.
-   **Gleiche Policy für Input und Output:** Eingaben, Modellantworten,
    generierter Code, Archive und Metadaten werden geprüft.
-   **Reproduzierbarkeit:** Versionen, Konfiguration, Zeitstempel,
    Hashes und Exit-Codes werden dokumentiert.
-   **Minimale Rechte:** Der Runner läuft mit begrenzten Rechten, ohne
    unnötige Netzwerk- oder Dateisystemzugriffe.
-   **Keine stillen Nebenwirkungen:** Reparaturen benötigen
    standardmäßig explizite Freigabe; `--dry-run` verändert nichts.
-   **Trennung von Generierung und Verifikation:** Ein Modell darf
    Prüfresultate nicht selbst behaupten oder erzeugen.

------------------------------------------------------------------------

## 2. Zielbild und Umfang

### 2.1 Geplante Eingaben

**MVP:** Fehler-Log plus Zielbetriebssystem (`linux`, `windows`, später
`macos`).

**Später:** Auswahl von zwei bis fünf bestehenden Tools, Manifest und
Quellcode. Der Härten-Modus analysiert und härtet diese Tools erst nach
bestandenen Red-Team-Tests der Schutzschichten.

Eingaben können vertrauliche Daten, Zugangsdaten oder
Prompt-Injection-Text enthalten. Sie gelten daher als nicht
vertrauenswürdig.

### 2.2 Ausgaben

  ------------------------------------------------------------------------------
  Format                  Geplantes Ergebnis      Mindestprüfung
  ----------------------- ----------------------- ------------------------------
  CLI                     `.sh`, `.ps1`, `.py`    Policy, Syntax, kontrollierter
                          oder `.mjs` plus README Prozesslauf, Rot-Grün-Nachweis

  HTML                    einzelne, eigenständige Policy, HTML-/JS-Validierung,
                          `.html`-Datei           CSP-/DOM-Sicherheitsprüfung,
                                                  Funktionstest

  Extension               Projektverzeichnis und  Policy, Dependency- und
                          `.vsix`                 Manifestprüfung,
                                                  Build/Package-Test; begrenzte
                                                  Laufzeitprüfung
  ------------------------------------------------------------------------------

### 2.3 Was nicht zum ersten MVP gehört

-   Härten-Modus / AgentShield
-   HTML-Generator
-   VS Code Extension-Generator
-   automatische Installation oder Änderung am Hostsystem
-   Verifikation durch reine Browser-Simulation
-   Ausführung beliebiger, vom Modell vorgeschlagener Befehle auf dem
    Host

------------------------------------------------------------------------

## 3. Architektur

### 3.1 Komponenten

``` text
forge/
├── src/
│   ├── cli.ts
│   ├── server.ts
│   ├── config.ts
│   ├── core/
│   │   ├── policy/
│   │   │   ├── policy.ts
│   │   │   ├── rules.ts
│   │   │   ├── redact.ts
│   │   │   └── injection.ts
│   │   ├── validation/
│   │   │   ├── validate-input.ts
│   │   │   ├── validate-cli.ts
│   │   │   └── validate-artifact.ts
│   │   ├── verification/
│   │   │   ├── process-runner.ts
│   │   │   ├── sandbox.ts
│   │   │   └── verify-cli.ts
│   │   ├── evidence/
│   │   │   ├── evidence.ts
│   │   │   └── schema.ts
│   │   ├── catalog/
│   │   │   ├── catalog.ts
│   │   │   └── storage.ts
│   │   └── export/
│   │       ├── zip-exporter.ts
│   │       └── manifest.ts
│   ├── modes/
│   │   └── repair/
│   │       ├── diagnose.ts
│   │       ├── generate-cli.ts
│   │       └── repair-workflow.ts
│   └── formats/
│       ├── cli.ts
│       ├── html.ts              # Phase 2
│       └── extension.ts         # Phase 3
├── templates/
│   └── cli/
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── security/
│   └── fixtures/
├── docs/
├── package.json
├── tsconfig.json
└── README.md
```

### 3.2 Datenfluss

``` text
Input
  │
  ▼
Input-Limits + Redaction + Policy
  │
  ▼
Diagnose (LLM oder deterministischer Fallback)
  │
  ▼
Strukturiertes Diagnoseobjekt
  │
  ▼
Template-basierte Codegenerierung
  │
  ▼
Output-Policy + Syntax-/AST-Validierung
  │
  ▼
Isolierter Verifikationslauf
  │
  ├── fehlgeschlagen ──► abgelehnt / Diagnosebericht
  │
  ▼
Evidence Package + Hash
  │
  ▼
ZIP-Export
  │
  ▼
Katalogfreigabe (atomar, nur bei bestandenem Gate)
```

### 3.3 Modulverantwortung

-   **policy/**: Regeln für verbotene Inhalte, Pfade, Befehle,
    Geheimnisse und Injection-Indikatoren.
-   **validation/**: Syntax, AST, Schema, Dateityp und Artefaktstruktur.
-   **verification/**: Isolierte Prozessausführung und unabhängige
    Ergebnisprüfung.
-   **evidence/**: Unveränderliche Prüfprotokolle, Hashes und
    Prüfstufen.
-   **catalog/**: Speicherung ausschließlich freigegebener Artefakte.
-   **export/**: reproduzierbare ZIP-Pakete, Manifeste und später
    VSIX-Pakete.
-   **modes/repair/**: Ablauf der Diagnose und Reparatur.
-   **formats/**: formatspezifische Erzeugung und Validierung.

------------------------------------------------------------------------

## 4. Technischer Stack

Empfohlener Start:

-   Node.js LTS + TypeScript; Bun kann optional lokal unterstützt
    werden, sollte aber nicht die einzige Produktionslaufzeit sein.
-   `node:child_process` nur mit sicherem Argument-Array und ohne
    Shell-Interpolation.
-   Docker oder eine vergleichbare Sandbox für Verifikation; in CI
    zusätzlich kurzlebige, isolierte Runner.
-   Zod oder vergleichbare Schema-Validierung für Eingaben und
    Diagnoseobjekte.
-   `node:test` oder Vitest für Tests.
-   ShellCheck für Bash, `python -m py_compile` für Python,
    `node --check` für JavaScript; PowerShell-Parserprüfung auf Windows.
-   Ein ZIP-Paketierer mit reproduzierbaren Metadaten.
-   Gemini oder ein anderes LLM hinter einem austauschbaren
    Provider-Interface; deterministischer Fallback bei fehlendem
    Modellzugriff.

**Wichtige Einschränkung:** Ein Container allein ist keine vollständige
Sicherheitsgarantie. Verwende keine privilegierten Container, mounte
keine Host-Secrets, setze CPU-/RAM-/Zeitlimits, beschränke
Netzwerkzugriff und verwende nach Möglichkeit ein read-only
Root-Dateisystem.

------------------------------------------------------------------------

## 5. CLI-Vertrag

Jedes erzeugte CLI-Artefakt unterstützt dieselben fünf Flags:

  -----------------------------------------------------------------------
  Flag                                Vertrag
  ----------------------------------- -----------------------------------
  `--check`                           Prüft den Zustand nur lesend. Exit
                                      `0` = Zielzustand erfüllt; Exit `1`
                                      = erwarteter Fehlerzustand
                                      vorhanden; Exit `2` = Prüfung
                                      konnte nicht zuverlässig ausgeführt
                                      werden.

  `--dry-run`                         Zeigt geplante Änderungen an,
                                      verändert aber nichts.

  `--fix`                             Führt die freigegebene Reparatur
                                      aus. Destruktive oder mehrdeutige
                                      Aktionen werden blockiert bzw.
                                      benötigen eine gesonderte
                                      Nutzerentscheidung.

  `--verify`                          Prüft nach der Reparatur den
                                      Zielzustand. Exit `0` bedeutet
                                      verifiziert; sonst Fehler.

  `--json`                            Gibt maschinenlesbare Ausgabe aus.
                                      Keine Statusmeldungen auf `stdout`,
                                      die das JSON beschädigen. Diagnosen
                                      gehen nach `stderr`.
  -----------------------------------------------------------------------

Die Kombination `--check --fix` sollte als ungültig abgelehnt werden,
sofern nicht explizit ein dokumentierter Ablauf dafür vorgesehen ist.
Unbekannte Flags liefern Exit `2`.

### 5.1 Exit-Code-Semantik

-   `0`: gewünschter Zustand bestätigt / Aktion erfolgreich
-   `1`: erwarteter Problemzustand vorhanden oder fachliche Prüfung
    fehlgeschlagen
-   `2`: ungültige Eingabe, Policy-Block, Laufzeitfehler oder Ergebnis
    nicht zuverlässig bestimmbar

Die Semantik muss im README jedes erzeugten Artefakts dokumentiert sein.
Der Runner darf Exit-Codes nicht nachträglich „passend machen".

### 5.2 Rot-Grün-Verifikation richtig definieren

Ein allgemeiner Exit-Code `1` ist **kein** ausreichender Beweis für
einen reproduzierbaren Fehlerzustand. Das Skript könnte wegen fehlender
Berechtigungen, eines Tippfehlers oder eines kaputten Interpreters
scheitern.

Daher braucht jeder Reparaturfall einen **unabhängigen
Zustands-Oracle**:

1.  Vorbedingung herstellen oder in einer frischen Testumgebung
    reproduzieren.
2.  Unabhängige Prüfung bestätigt, dass der Zielzustand zunächst
    fehlerhaft ist.
3.  `--check` meldet den Fehlerzustand mit dem definierten Exit-Code.
4.  `--dry-run` zeigt den geplanten Eingriff, ohne den Zustand zu
    ändern.
5.  `--fix` läuft nur in der wegwerfbaren Sandbox und nur bei erlaubten
    Änderungen.
6.  Der unabhängige Oracle bestätigt den Zielzustand.
7.  `--check` und `--verify` melden Erfolg.
8.  Negative Kontrolltests belegen, dass ein defekter Runner nicht als
    erfolgreicher Reparaturfall gewertet wird.

Wenn der Fehlerzustand nicht sicher reproduzierbar ist, lautet das
Ergebnis `not_verified`; es darf nicht in den Katalog.

------------------------------------------------------------------------

## 6. Pipeline des MVP

### Schritt 1 -- Eingabe begrenzen und bereinigen

-   Dateigrößen-, Zeilen- und Zeitlimits setzen.
-   Geheimnisse erkennen und vor Modellaufrufen redigieren.
-   Pfade normalisieren und Traversal-Versuche blockieren.
-   Logs als Daten behandeln, niemals als vertrauenswürdige Anweisungen.
-   Rohdaten nicht standardmäßig in Evidence oder Telemetrie kopieren.

### Schritt 2 -- Policy-Prüfung des Inputs

Prüfe mindestens:

-   `.env`-Dateien und Varianten
-   private Schlüssel, etwa `id_rsa`, `id_ed25519` und PEM-Key-Blöcke
-   Tokens, Passwörter, API-Schlüssel und Zugangsdaten
-   sensible Pfade wie `.ssh/`, Cloud-Credentials und Credential Stores
-   Prompt-Injection-Versuche und Anweisungen, Sicherheitsregeln zu
    ignorieren
-   zu große, binäre oder nicht unterstützte Eingaben

Die Policy soll nicht nur auf Dateinamen prüfen, sondern auch Inhalte
und Kontext. Bei Unsicherheit gilt: blockieren oder redigieren und den
Grund protokollieren.

### Schritt 3 -- Diagnose

Das Modell oder der Fallback liefert ausschließlich ein strukturiertes
Objekt, zum Beispiel:

``` json
{
  "issueTitle": "Beispiel: Dienst startet nicht",
  "rootCause": "Konfigurationswert fehlt",
  "checkPlan": ["Prüfe, ob der Dienst aktiv ist"],
  "fixPlan": ["Setze den dokumentierten Konfigurationswert"],
  "targetOS": "linux",
  "preconditions": ["Testumgebung mit reproduzierbarem Fehler"],
  "riskLevel": "low",
  "needsHumanApproval": true
}
```

Das ist ein Schema-Beispiel, keine fertige Reparatur. Diagnoseobjekte
werden gegen ein Schema geprüft; freie Modelltexte werden nicht direkt
als Shell-Befehle ausgeführt.

### Schritt 4 -- Generierung

-   Bevorzuge feste, getestete Templates.
-   Verwende eine Allowlist unterstützter Reparaturaktionen.
-   Trenne Parameter von Befehlsstruktur.
-   Generiere keine beliebigen Befehlszeilen aus Logtext.
-   Füge Flags, Exit-Code-Semantik, JSON-Ausgabe, README und Metadaten
    hinzu.
-   Lege bei unklaren Fällen keine automatische `--fix`-Aktion an.

### Schritt 5 -- Output-Policy

Prüfe den vollständigen generierten Output erneut:

-   verbotene Pfade und Geheimnisse
-   Shell-Konstrukte, die Befehle verschleiern oder dynamisch nachladen
-   destruktive Operationen und rekursive Löschungen
-   Download-und-Ausführen-Muster
-   Änderungen an Benutzerkonten, SSH-Schlüsseln, Firewall,
    Boot-Konfiguration oder Sicherheitssoftware
-   Netzwerkzugriffe und externe Hosts
-   Schreibzugriffe außerhalb eines explizit erlaubten Arbeitsbereichs

Eine Regex-Blacklist allein reicht nicht. Kombiniere Token-/AST-Analyse,
semantische Regeln, Allowlist und Sandbox. Verschleierte oder nicht
zuverlässig analysierbare Befehle werden abgelehnt.

### Schritt 6 -- Statische Validierung

-   Dateiendung und tatsächlichen Inhalt abgleichen.
-   Parser/Syntaxchecker passend zur Zielsprache ausführen.
-   ShellCheck für Bash verwenden, sofern verfügbar.
-   Policy- und Dependency-Checks durchführen.
-   Bei fehlendem Validator den Prüfschritt als `skipped` ausweisen und
    nicht als bestanden markieren.

### Schritt 7 -- Isolierte Verifikation

Der Runner muss:

-   ein festgelegtes Arbeitsverzeichnis verwenden
-   Programme und Argumente getrennt übergeben, nicht durch
    Shell-String-Konkatenation
-   Timeout, CPU, Speicher und Prozessanzahl begrenzen
-   Standardausgabe und Fehlerausgabe mit Größenlimit erfassen
-   Signale, Timeout und Exit-Code getrennt dokumentieren
-   Netzwerk standardmäßig deaktivieren
-   keine Host-Secrets oder unnötigen Host-Verzeichnisse mounten
-   die Sandbox nach dem Lauf entsorgen

**Keine Ausführung direkt auf dem Entwickler- oder Produktionshost.**
Falls lokale Ausführung für einen ausdrücklich freigegebenen Test
unvermeidbar ist, muss sie als eigener, deutlich riskanter Modus
dokumentiert sein und darf nicht mit der isolierten Verifikation
gleichgesetzt werden.

### Schritt 8 -- Evidence Package

Evidence enthält die Prüfschritte, Ergebnisse, Hashes, Zeitstempel und
verwendete Tool-Versionen. Logs müssen redigiert und begrenzt sein.
Evidence darf keine Geheimnisse oder unnötigen Rohlogs enthalten.

### Schritt 9 -- Export und Katalog

-   Export in ein temporäres Verzeichnis schreiben.
-   ZIP-Inhalte gegen Pfad-Traversal prüfen.
-   Hashes berechnen und Manifest erstellen.
-   Export vollständig validieren.
-   Erst danach atomar in den Katalog übernehmen.
-   Bei jedem Fehler temporäre Artefakte verwerfen und Freigabe
    verweigern.

------------------------------------------------------------------------

## 7. Policy-Modul

### 7.1 API-Vorschlag

``` ts
export type PolicyStage = "input" | "diagnosis" | "generated-code" | "package";

export type PolicyDecision =
  | { allowed: true; findings: PolicyFinding[]; redactions: Redaction[] }
  | { allowed: false; findings: PolicyFinding[]; reason: string };

export interface PolicyFinding {
  ruleId: string;
  severity: "info" | "warning" | "block";
  message: string;
  location?: string;
}

export interface PolicyEngine {
  inspectText(text: string, stage: PolicyStage): PolicyDecision;
  inspectPath(path: string, stage: PolicyStage): PolicyDecision;
  inspectCommand(executable: string, args: string[]): PolicyDecision;
  inspectFiles(files: Array<{ path: string; content: Uint8Array }>, stage: PolicyStage): PolicyDecision;
}
```

### 7.2 Regeln und Prioritäten

-   **Block:** private Schlüssel, bekannte Secret-Muster, nicht erlaubte
    Pfade, eindeutig destruktive Befehle, unerlaubte
    Netzwerk-/Privilegienaktionen.
-   **Review erforderlich:** mehrdeutige Reparatur,
    Systemkonfigurationsänderung, breite Dateisystemänderung, nicht
    unterstützte Syntax.
-   **Warnung:** unkritische Abweichungen, die nachvollziehbar bleiben.
-   **Allow:** bekannte, begrenzte und getestete Aktion.

Eine Warnung darf nicht versehentlich einen Block überstimmen.
Regelprioritäten müssen deterministisch sein und in Tests abgedeckt
werden.

### 7.3 Prompt-Injection-Abwehr

-   Logs und Quelldateien sind Daten, keine Instruktionen.
-   Systemregeln und Nutzerinhalt werden logisch getrennt gehalten.
-   Modellantworten erhalten keinerlei zusätzliche Rechte.
-   Ausgabe wird unabhängig geprüft.
-   Kein Tool-Aufruf darf nur deshalb erlaubt werden, weil das Modell
    ihn empfiehlt.
-   Testfälle enthalten direkte und indirekte Injection-Texte,
    Base64-/Unicode-Varianten und Anweisungen in Kommentaren.

------------------------------------------------------------------------

## 8. Process Runner

### 8.1 Vertrag

``` ts
export interface ProcessRequest {
  executable: string;
  args: string[];
  cwd: string;
  env: Record<string, string>;
  timeoutMs: number;
  maxOutputBytes: number;
}

export interface ProcessResult {
  exitCode: number | null;
  signal: string | null;
  timedOut: boolean;
  stdout: string;
  stderr: string;
  durationMs: number;
}
```

Zusätzliche Regeln:

-   `cwd` muss innerhalb des Sandbox-Arbeitsverzeichnisses liegen.
-   `env` wird aus einer kleinen Allowlist aufgebaut; nicht das gesamte
    Host-Environment übernehmen.
-   `shell: true` ist standardmäßig verboten.
-   stdout/stderr werden während des Streams begrenzt, nicht erst nach
    vollständigem Puffern.
-   Bei Timeout Prozessgruppe beenden und Ergebnis als fehlgeschlagen
    markieren.
-   Runner-Fehler sind keine fachlichen Exit-Codes des Skripts; beide
    werden getrennt gespeichert.
-   Interpreterpfad und Version werden festgelegt und dokumentiert.

### 8.2 Pseudocode

``` ts
async function runIsolated(request: ProcessRequest): Promise<ProcessResult> {
  validateRequestAgainstPolicy(request);

  // Sandbox wird vor dem Prozess erstellt und mit Ressourcenlimits gestartet.
  // Keine Shell-Interpolation; executable und args bleiben getrennt.
  const sandbox = await createSandbox({
    network: "disabled",
    readOnlyRoot: true,
    cpuLimit: "bounded",
    memoryLimitMb: 256,
    processLimit: 32,
  });

  try {
    const result = await sandbox.run(request, {
      timeoutMs: request.timeoutMs,
      maxOutputBytes: request.maxOutputBytes,
    });
    return normalizeResult(result);
  } finally {
    await sandbox.destroy();
  }
}
```

Der Code ist ein Architektur-Skelett. `createSandbox` muss mit einer
tatsächlich isolierenden Laufzeit implementiert und getestet werden;
eine leere Wrapper-Funktion oder ein Mock ist keine echte Sandbox.

------------------------------------------------------------------------

## 9. Verifikationsprotokoll

### 9.1 Ergebniszustände

Verwende explizite Statuswerte:

-   `passed`: alle für die Prüfstufe verpflichtenden Gates bestanden
-   `failed`: mindestens ein Gate fehlgeschlagen
-   `blocked`: Policy hat die Verarbeitung verhindert
-   `not_verified`: kein zuverlässiger Zustandsnachweis möglich
-   `skipped`: bewusst nicht ausgeführt; niemals gleichbedeutend mit
    `passed`

### 9.2 Prüfstufen

  -----------------------------------------------------------------------
  Prüfstufe                           Aussage
  ----------------------------------- -----------------------------------
  `L0_input_screened`                 Input wurde begrenzt, redigiert und
                                      durch die Input-Policy geprüft

  `L1_static_validated`               Syntax-/AST- und
                                      Output-Policy-Prüfungen bestanden

  `L2_sandbox_executed`               Prozess wurde in einer echten
                                      Sandbox ausgeführt

  `L3_state_transition_verified`      Unabhängiger Oracle bestätigte
                                      Rot-Grün-Zustandswechsel

  `L4_package_verified`               Export, Manifest und Hashes wurden
                                      nach dem Verpacken erneut geprüft
  -----------------------------------------------------------------------

Die höchste Prüfstufe wird nur vergeben, wenn alle darunterliegenden
verpflichtenden Gates bestanden wurden. Ein Artefakt kann beispielsweise
L1 erreichen, aber bei fehlendem reproduzierbarem Fehlerzustand nicht
L3.

### 9.3 Anforderungen an den Rot-Grün-Test

Der Test muss in einer wegwerfbaren, bekannten Umgebung laufen. Für
jeden Testfall gibt es:

-   Setup, das den Fehlerzustand deterministisch herstellt
-   unabhängigen Check des Ausgangszustands
-   erwartetes Verhalten von `--check`
-   erwartetes Verhalten von `--dry-run`
-   erlaubte Änderung für `--fix`
-   unabhängigen Check des Zielzustands
-   erwartetes Verhalten von `--verify`
-   Cleanup, der auch bei Fehlern ausgeführt wird

Nicht jede reale Störung lässt sich sicher oder reproduzierbar
nachstellen. In diesen Fällen muss Forge ehrlich `not_verified` melden,
statt einen erfolgreichen Lauf zu simulieren.

------------------------------------------------------------------------

## 10. Evidence Package

### 10.1 Beispiel `evidence.json`

``` json
{
  "schemaVersion": "1.0.0",
  "artifactId": "forge-repair-example-001",
  "createdAt": "2026-10-16T18:00:00.000Z",
  "artifact": {
    "fileName": "repair.py",
    "format": "cli",
    "sha256": "REPLACE_WITH_REAL_SHA256",
    "sizeBytes": 1234
  },
  "source": {
    "kind": "sanitized-log",
    "sha256": "HASH_OF_REDACTED_INPUT",
    "rawInputStored": false
  },
  "environment": {
    "os": "linux",
    "architecture": "x64",
    "runtime": "python",
    "runtimeVersion": "3.x",
    "sandbox": "container",
    "network": "disabled"
  },
  "policy": {
    "version": "1.0.0",
    "input": "passed",
    "generatedOutput": "passed",
    "package": "passed",
    "findings": []
  },
  "checks": [
    {
      "name": "syntax",
      "status": "passed",
      "tool": "python -m py_compile",
      "exitCode": 0
    },
    {
      "name": "precondition_oracle",
      "status": "passed",
      "exitCode": 0,
      "summary": "Expected faulty state confirmed"
    },
    {
      "name": "check_before_fix",
      "status": "passed",
      "exitCode": 1,
      "expectedExitCode": 1
    },
    {
      "name": "dry_run",
      "status": "passed",
      "exitCode": 0,
      "mutatedState": false
    },
    {
      "name": "fix",
      "status": "passed",
      "exitCode": 0
    },
    {
      "name": "postcondition_oracle",
      "status": "passed",
      "exitCode": 0,
      "summary": "Expected target state confirmed"
    },
    {
      "name": "check_after_fix",
      "status": "passed",
      "exitCode": 0,
      "expectedExitCode": 0
    },
    {
      "name": "verify",
      "status": "passed",
      "exitCode": 0
    },
    {
      "name": "package_integrity",
      "status": "passed",
      "exitCode": 0
    }
  ],
  "verification": {
    "status": "passed",
    "level": "L4_package_verified",
    "redGreenOracle": "passed",
    "runnerErrors": [],
    "limitations": []
  },
  "logs": {
    "stdoutExcerpt": "Redacted, bounded excerpt",
    "stderrExcerpt": "",
    "truncated": false
  },
  "provenance": {
    "forgeVersion": "0.1.0",
    "templateVersion": "1.0.0",
    "modelProvider": "gemini-or-fallback",
    "modelVersion": "record-exact-version-or-null"
  }
}
```

**Wichtig:** Dies ist ein Schema-Beispiel, kein echter Prüfbeleg.
Platzhalter-Hashes, nicht ausgeführte Checks und beispielhafte
Exit-Codes müssen vor einer echten Freigabe ersetzt werden. Evidence
wird vom Runner erstellt, nicht vom LLM.

### 10.2 Hashing und Integrität

-   SHA-256 über die endgültigen Artefaktbytes berechnen.
-   Hash nach Export erneut berechnen und vergleichen.
-   Evidence und Manifest nach festgelegtem Verfahren serialisieren.
-   Keine zirkuläre Hashdefinition: Der Artefakt-Hash referenziert das
    Artefakt, nicht das Evidence-Paket, das wiederum den Artefakt-Hash
    enthält.
-   Für manipulationssichere Nachweise Evidence optional signieren und
    Signaturschlüssel getrennt von Forge aufbewahren.
-   Zeitstempel sind Systemzeit-Angaben; ohne vertrauenswürdigen
    Zeitstempeldienst nicht als unabhängiger Zeitnachweis darstellen.

------------------------------------------------------------------------

## 11. Katalog und Export

### 11.1 Katalogregel

Ein Artefakt darf nur aufgenommen werden, wenn:

1.  Input- und Output-Policy bestanden sind.
2.  Alle verpflichtenden statischen Prüfungen bestanden sind.
3.  Die für den Artefakttyp erforderliche Verifikation bestanden ist.
4.  Evidence-Schema gültig ist.
5.  Hashes und Paketinhalt konsistent sind.
6.  Keine verpflichtende Prüfung als `skipped`, `blocked` oder
    `not_verified` markiert ist.

Die Freigabe erfolgt atomar. Ein Artefakt mit unvollständigem Beleg darf
nicht im normalen Katalog erscheinen. Abgelehnte Artefakte können in
einem getrennten, kurzlebigen Diagnosebereich liegen, ohne ausführbare
Dateien oder Geheimnisse zu archivieren.

### 11.2 ZIP-Struktur

``` text
forge-repair-example.zip
├── artifact/
│   └── repair.py
├── evidence.json
├── manifest.json
├── README.md
└── checksums.txt
```

Vor dem Entpacken oder Verpacken Pfade auf absolute Pfade, `..`,
Symlinks und doppelte Namen prüfen. Exporte reproduzierbar gestalten und
unnötige Metadaten vermeiden.

------------------------------------------------------------------------

## 12. CLI-Bedienoberfläche

Vorgeschlagene Kommandos:

``` bash
forge repair --log ./error.log --os linux --output ./out
forge validate ./out/repair.py
forge verify ./out/repair.py --fixture ./tests/fixtures/service-failure
forge evidence ./out/repair.py
forge catalog list
```

Die CLI muss sensible Inhalte nicht standardmäßig in die Konsole
drucken. Für Logs kann zusätzlich `--log-file` angeboten werden; direkte
Inhalte über `--log` sollten nur für kurze, nicht sensible Beispiele
gedacht sein.

### 12.1 Optionen für `forge repair`

-   `--log <path>`: Eingabe-Log
-   `--os <linux|windows|macos>`: Zielsystem
-   `--output <path>`: Zielverzeichnis
-   `--format <sh|ps1|py|mjs>`: gewünschtes CLI-Format
-   `--no-model`: deterministischen Fallback verwenden
-   `--json`: Forge-Ergebnis maschinenlesbar ausgeben
-   `--policy <strict|standard>`: Policy-Profil; `strict` ist Standard
-   `--allow-network` sollte im MVP nicht existieren; Netzwerk bleibt
    standardmäßig deaktiviert.

`--fix` des generierten Skripts ist nicht gleichbedeutend mit
`forge repair`: Forge erzeugt und prüft das Artefakt; das Artefakt führt
die Reparatur nur nach explizitem Aufruf aus.

------------------------------------------------------------------------

## 13. Implementierungsplan

### Phase 0 -- Repository und Sicherheitsgrundlage

1.  Neues eigenständiges Repository `forge` anlegen.
2.  TypeScript, Linter, Formatter, Test-Runner und CI konfigurieren.
3.  Threat Model und Policy-Regeln dokumentieren.
4.  Beispiel-Logs ohne echte Secrets als Fixtures anlegen.
5.  Schnittstellen und Statusmodelle festlegen.

**Abnahmekriterien:** CI läuft; keine echten Zugangsdaten in Fixtures;
Fehlerfälle sind als Tests beschrieben.

### Phase 1 -- Policy extrahieren

1.  Bestehende SysFix-Policy analysieren.
2.  Abhängigkeiten von SysFix entkoppeln.
3.  Regeln in versionierte, testbare Einheiten zerlegen.
4.  Eingabe-, Ausgabe- und Paketprüfung implementieren.
5.  Secret-Redaction und sichere Fehlermeldungen ergänzen.

**Abnahmekriterien:** Unit-Tests für verbotene Dateien, Secrets,
Pfad-Traversal, Injection und erlaubte harmlose Eingaben; keine
Fail-open-Pfade.

### Phase 2 -- Process Runner und Sandbox

1.  Runner-Interface definieren.
2.  Container-/Sandbox-Backend implementieren.
3.  Timeouts, Ressourcenlimits, Output-Limits und Cleanup ergänzen.
4.  Prozessfehler von fachlichen Exit-Codes trennen.
5.  Tests für Timeout, Signal, riesige Ausgabe, fehlenden Interpreter
    und Sandbox-Ausfall ergänzen.

**Abnahmekriterien:** Ein Sandbox-Ausfall führt niemals zu `passed`;
Netzwerk ist standardmäßig deaktiviert; Tests belegen Cleanup.

### Phase 3 -- CLI-Template und Diagnose

1.  Einheitliches CLI-Verhalten für die fünf Flags definieren.
2.  Diagnoseobjekt-Schema implementieren.
3.  Deterministischen Fallback zuerst umsetzen.
4.  LLM-Provider als optionalen Adapter ergänzen.
5.  Modellantworten validieren und nie direkt ausführen.

**Abnahmekriterien:** Fallback funktioniert ohne Netz; ungültige
Modellantworten werden abgelehnt; unbekannte Aktionen führen nicht zu
Codegenerierung.

### Phase 4 -- Rot-Grün-Verifikation

1.  Fixture-basierte Fehlerzustände entwickeln.
2.  Unabhängige Oracles für Vor- und Nachbedingungen schreiben.
3.  `--check`, `--dry-run`, `--fix`, `--verify` testen.
4.  Negative Kontrollfälle ergänzen.
5.  `not_verified` als reguläres, sichtbares Ergebnis behandeln.

**Abnahmekriterien:** Es gibt mindestens einen echten, deterministischen
Rot-Grün-Integrationstest in einer Sandbox. Ein reiner Exit-Code ohne
Zustands-Oracle reicht nicht.

### Phase 5 -- Evidence und Export

1.  Evidence-Schema versionieren.
2.  Runner-Resultate in Evidence übertragen.
3.  Hashing und Paketmanifest implementieren.
4.  ZIP-Integrität und Pfade prüfen.
5.  Export atomar freigeben.

**Abnahmekriterien:** Evidence stimmt mit tatsächlich beobachteten
Resultaten überein; Hash stimmt nach Export; fehlgeschlagene Runs
gelangen nicht in den Katalog.

### Phase 6 -- CLI-MVP abschließen

1.  `forge repair` integrieren.
2.  README und Beispiel-Workflow erstellen.
3.  Security-Regression-Suite in CI integrieren.
4.  Release-Kriterien und bekannte Grenzen veröffentlichen.

**Abnahmekriterien:** Vollständiger End-to-End-Test von Log bis ZIP;
kein automatischer Host-Eingriff; reproduzierbarer Evidence-Beleg.

### Phase 7 -- Standalone-HTML

Erst beginnen, wenn Phase 6 stabil ist.

-   HTML- und JavaScript-Policy
-   DOM-XSS-Prüfungen und sichere Ausgabe-Kodierung
-   Content Security Policy, ohne unsichere Inline-Ausnahmen, soweit mit
    dem Design vereinbar
-   lokale/offline Funktionalität klar dokumentieren
-   Funktionstests und Paket-Hash

### Phase 8 -- VS Code Extension

-   Manifest- und Dependency-Policy
-   minimale Berechtigungen und Commands
-   Build- und Packaging-Tests
-   keine automatische Installation
-   Laufzeitprüfung nur in kontrollierter Testinstanz

Der Evidence-Text muss präzise sein: **„kompiliert und paketiert"**,
**„in Testinstanz gestartet"** oder **„Funktion X getestet"**. Nicht
pauschal „verifiziert" schreiben, wenn keine fachliche
End-to-End-Prüfung stattgefunden hat.

### Phase 9 -- AgentShield / Härten-Modus

Erst nach dokumentiert bestandenem Red-Team-Selbsttest. Dieser Modus
verarbeitet mehrere Tools und hat ein deutlich größeres Risiko durch
unbekannte Abhängigkeiten, Injection und unbeabsichtigte
Verhaltensänderungen.

------------------------------------------------------------------------

## 14. API-Schnittstellen

### 14.1 Diagnose

``` ts
export interface RepairDiagnosis {
  issueTitle: string;
  rootCause: string;
  targetOS: "linux" | "windows" | "macos";
  checkPlan: string[];
  fixPlan: Array<{
    actionId: string;
    parameters: Record<string, string | number | boolean>;
  }>;
  preconditions: string[];
  riskLevel: "low" | "medium" | "high";
  needsHumanApproval: boolean;
}
```

`actionId` muss auf eine registrierte, getestete Aktion zeigen. Freie
Kommandos in `fixPlan` sind nicht zulässig.

### 14.2 Verifikation

``` ts
export interface VerificationCheck {
  name: string;
  status: "passed" | "failed" | "blocked" | "not_verified" | "skipped";
  exitCode: number | null;
  expectedExitCode?: number;
  durationMs?: number;
  stdoutExcerpt?: string;
  stderrExcerpt?: string;
  details?: Record<string, unknown>;
}

export interface VerificationSummary {
  status: "passed" | "failed" | "blocked" | "not_verified";
  level: "L0_input_screened" | "L1_static_validated" |
         "L2_sandbox_executed" | "L3_state_transition_verified" |
         "L4_package_verified" | "none";
  checks: VerificationCheck[];
}
```

### 14.3 Katalog

``` ts
export interface CatalogArtifact {
  artifactId: string;
  artifactHash: string;
  format: "cli" | "html" | "extension";
  status: "approved";
  evidenceHash: string;
  createdAt: string;
  forgeVersion: string;
}
```

Die öffentliche Katalog-API akzeptiert nicht beliebige `status`-Werte.
Nur eine interne Freigabefunktion darf `approved` setzen, nachdem
sämtliche Gates unabhängig geprüft wurden.

------------------------------------------------------------------------

## 15. Red-Team-Selbsttest

Vor Freischaltung des Härten-Modus muss die Schutzschicht mindestens
folgende Angriffsgruppen abdecken:

1.  Direkte Prompt Injection in Logtext.
2.  Indirekte Injection in Kommentaren, Dateinamen und Tool-Readmes.
3.  Versuche, `.env`, SSH-Private-Keys oder Cloud-Credentials
    auszulesen.
4.  Pfad-Traversal und absolute Pfade.
5.  Verschleierte destruktive Befehle und verkettete Befehle.
6.  Download-and-execute, Shell-Pipelines und unerlaubte
    Netzwerkzugriffe.
7.  Manipulierte Archive, doppelte Dateinamen und Symlinks.
8.  Überlange Logs, binäre Inhalte und Ressourcenerschöpfung.
9.  Modellantwort mit ungültigem Schema oder unerlaubter Aktion.
10. Sandbox-Ausfall, Timeout, Prozessabbruch und fehlender Oracle.
11. Gefälschte oder nachträglich veränderte Evidence.
12. Versuch, ein nicht geprüftes Artefakt in den Katalog einzuschleusen.

Für jeden Test werden Angriff, erwartete Blockierung, tatsächliches
Resultat und Regressionstest dokumentiert. Kein Test darf als bestanden
gelten, wenn er nicht wirklich ausgeführt wurde. Bei einem kritischen
Durchbruch bleibt der Härten-Modus gesperrt.

------------------------------------------------------------------------

## 16. Teststrategie

### Unit-Tests

-   Policy-Regeln und Regelprioritäten
-   Redaction und Secret-Erkennung
-   Diagnose-Schema
-   Exit-Code-Normalisierung
-   Evidence-Schema und Hashing
-   Katalog-Gates

### Integrationstests

-   echter Prozessstart in Sandbox
-   Timeout und Cleanup
-   echter Rot-Grün-Zustandswechsel
-   ZIP-Export und Integritätsprüfung
-   End-to-End-Flow vom Log bis zum Artefakt

### Security-Tests

-   Prompt Injection
-   Path traversal
-   Secret leakage
-   gefährliche Shell-Muster
-   Output-Policy-Bypass
-   Archive traversal
-   Ressourcenerschöpfung
-   gefälschte Evidence
-   Katalog-Bypass

### Regressionen

Jeder Sicherheitsfehler wird als minimierter Testfall hinzugefügt.
Policy-Änderungen benötigen Review und dürfen nicht unbemerkt bestehende
Blockregeln lockern.

------------------------------------------------------------------------

## 17. Risiken und Gegenmaßnahmen

  -----------------------------------------------------------------------
  Risiko                              Gegenmaßnahme
  ----------------------------------- -----------------------------------
  Exit `1` wird als echter Fehler     unabhängiger Zustands-Oracle und
  fehlinterpretiert                   Setup-Test

  Modell halluziniert Befehle oder    strukturiertes Schema,
  Ursachen                            Action-Allowlist, Fallback

  Prompt Injection in Logs            Input als Daten behandeln, Policy
                                      vor/nach Generierung

  Secret-Leak in Logs/Evidence        Redaction, Größenlimits, keine
                                      Rohdaten standardmäßig speichern

  Runner führt Host-Schaden aus       echte Sandbox, minimale Rechte,
                                      Netzwerk aus

  Regex-Policy wird umgangen          AST-/Tokenanalyse, Allowlist,
                                      negative Tests, Sandbox

  Fehlerhafter Export landet im       atomare Freigabe, Hash- und
  Katalog                             Schema-Prüfung

  „verifiziert" wird übertrieben      Prüfstufen und präzise
                                      Evidence-Sprache

  Nicht reproduzierbare Störung       `not_verified`, keine
                                      Katalogfreigabe

  Dependency kompromittiert           Lockfile, Dependency-Scan,
                                      minimierte Abhängigkeiten
  -----------------------------------------------------------------------

------------------------------------------------------------------------

## 18. Definition of Done für das MVP

Das MVP ist erst fertig, wenn alle Punkte erfüllt sind:

-   [ ] Forge ist eigenständig und nicht Teil der Control Layer.
-   [ ] Input- und Output-Policy werden ausgeführt.
-   [ ] Secrets werden vor externen Modellaufrufen redigiert.
-   [ ] Deterministischer Fallback funktioniert ohne LLM.
-   [ ] Das CLI-Artefakt unterstützt alle fünf vereinbarten Flags.
-   [ ] Syntaxprüfung wird mit dem passenden realen Validator
    ausgeführt.
-   [ ] Prozessverifikation findet in einer echten Sandbox statt.
-   [ ] Ein echter Rot-Grün-Test verwendet unabhängige Vor- und
    Nachbedingungs-Oracles.
-   [ ] `--dry-run` verändert nachweislich keinen Zustand.
-   [ ] Evidence wird aus beobachteten Resultaten erstellt.
-   [ ] Artefakt-Hash wird nach dem Export erneut geprüft.
-   [ ] Fehlgeschlagene oder unvollständig geprüfte Artefakte bleiben
    außerhalb des freigegebenen Katalogs.
-   [ ] ZIP-Inhalte werden auf Pfad-Traversal und unerlaubte Dateien
    geprüft.
-   [ ] Security- und Regressionstests laufen in CI.
-   [ ] README beschreibt Grenzen, Exit-Codes und sichere Verwendung.
-   [ ] Es gibt keine automatische Installation und keinen
    unaufgeforderten Host-Eingriff.

------------------------------------------------------------------------

## 19. Empfohlene erste zehn Arbeitsschritte

1.  Neues `forge`-Repository anlegen und CI konfigurieren.
2.  Diagnose- und Evidence-Schemas festlegen.
3.  Bestehende SysFix-Policy analysieren und unabhängig testbar
    extrahieren.
4.  Secret-Redaction und Input-Limits implementieren.
5.  Runner-Interface und Sandbox-Anforderungen festlegen.
6.  Einen harmlosen, deterministischen Fixture-Reparaturfall erstellen.
7.  CLI-Template mit den fünf Flags implementieren.
8.  Rot-Grün-Verifikation samt unabhängigem Oracle real ausführen.
9.  Evidence-Generator, Hashing und ZIP-Export implementieren.
10. End-to-End- und Red-Team-Regressionen in CI integrieren.

**Empfehlung:** Beginne mit einem einzigen ungefährlichen, vollständig
reproduzierbaren Reparaturfall. Erst wenn dessen gesamter Weg -- Input,
Policy, Generierung, Sandbox, Rot-Grün, Evidence, Export und
Katalogfreigabe -- belastbar funktioniert, weitere Reparaturtypen
hinzufügen.

------------------------------------------------------------------------

## 20. Abschließende Designentscheidungen

Vor dem Start sollten diese Entscheidungen schriftlich festgehalten
werden:

-   Node.js LTS als unterstützte Produktionslaufzeit; Bun optional.
-   Docker oder alternative Sandbox als Pflicht für L2/L3-Verifikation.
-   Striktes Policy-Profil als Standard.
-   Modell ist optional; Fallback ist verpflichtend.
-   `--check` ist lesend; `--dry-run` ist ohne Nebenwirkungen.
-   Ein Exit-Code allein reicht nie als Beweis für einen
    Zustandswechsel.
-   Katalogfreigabe erfolgt nur über eine zentrale, nicht vom Modell
    kontrollierte Funktion.
-   HTML und Extension folgen erst nach einem stabilen CLI-MVP.
-   AgentShield/Härten bleibt gesperrt, bis der Red-Team-Selbsttest
    bestanden ist.
-   Evidence benennt exakt die ausgeführten Prüfungen und dokumentiert
    übersprungene Prüfungen ausdrücklich.

Damit erhält Forge eine nachvollziehbare Grundlage: zuerst ein eng
begrenztes CLI-Reparaturwerkzeug mit echtem Rot-Grün-Nachweis, danach
schrittweise weitere Formate und zuletzt der risikoreichere
Härten-Modus.


## 21. Präzisierungen aus dem Architektur-Review (Version 0.2)

Diese Punkte sind verbindliche Designregeln und keine optionalen Empfehlungen:

1. **Unabhängiger Oracle:** Der Zustands-Oracle ist separat vom generierten Skript implementiert und verwendet nicht dieselbe Prüf-Logik. Die Methode wird in Evidence benannt.
2. **Echte Isolation:** L2/L3 erfordern Docker mit `--network=none`, Ressourcenlimits, read-only Root und begrenztem Test-Workspace oder eine nachweislich gleichwertige Sandbox. Mocks und unisolierte Host-Prozesse sind ausgeschlossen.
3. **Allowlist vor LLM:** Zuerst wird der deterministische Fallback mit registrierten, getesteten `actionId`-Aktionen gebaut. Das LLM darf später nur bekannte Aktionen auswählen und schema-validierte Parameter liefern.
4. **Präzise Evidence-Sprache:** HTML wird beispielsweise als „Logik mit festen Inputs geprüft“ ausgewiesen. Extensions werden als „kompiliert und paketiert“, „in Testinstanz gestartet“ oder mit der konkret getesteten Funktion beschrieben. Eine stärkere Verifikationsaussage setzt den entsprechenden realen Test voraus.
5. **Fail closed bei Unsicherheit:** Wenn Oracle-Unabhängigkeit, Sandbox-Isolation oder Prüfergebnis nicht belegbar sind, wird nicht freigegeben.

---

## 22. Projektstrategie: mit eigener Extension, Alex und Build in Public

Forge sollte zunächst als eigenständiger Kern entwickelt werden. Eine bestehende Extension kann später die Benutzeroberfläche oder einen Adapter bilden, sollte aber nicht die Sicherheitsgrenze oder die einzige Ausführungsumgebung sein. So bleibt Forge testbar, austauschbar und unabhängig von einem bestimmten Editor.

**Empfohlene Reihenfolge:**

1. **Forge Core separat:** Policy, Action-Allowlist, Sandbox-Runner, Verifikation, Evidence und Katalog in einem eigenständigen Repository.
2. **Eigene Extension als dünner Client:** Sie übermittelt Eingaben, zeigt Prüfergebnisse und Evidence an und startet keine ungeprüften Reparaturen selbst. Der Core bleibt für Policy und Freigabe verantwortlich.
3. **Zusammenarbeit mit Alex:** Wenn Alex am Projekt mitarbeitet, zuerst klar abgrenzen, wer Architektur/Policy, Runner/Tests, UX/Extension und Review verantwortet. Sicherheitskritische Änderungen sollten von einer zweiten Person geprüft werden. Zugangsdaten und Produktionsrechte nicht unnötig teilen.
4. **Build in Public dosiert starten:** Öffentlich über Ziele, Architekturentscheidungen, Fortschritt, Demo-Fixtures und Testergebnisse berichten. Keine echten Logs, Secrets, internen Zugangsdaten, ungepatchten Sicherheitslücken oder ungeprüften Behauptungen veröffentlichen. Red-Team-Ergebnisse erst nach Behebung kritischer Schwächen detailliert publizieren.
5. **Öffentliche Vertrauenssignale:** Ein öffentliches Roadmap-/Threat-Model-Dokument, reproduzierbare Test-Fixtures, CI-Status, versionierte Evidence-Schemas und ehrliche bekannte Einschränkungen schaffen mehr Vertrauen als Marketingaussagen.

**Entscheidung:** Ja, eine eigene Extension kann für UX und Verteilung sinnvoll sein; sie sollte aber auf Forge aufsetzen und nicht Forge ersetzen. Build in Public kann helfen, Feedback und Vertrauen aufzubauen, sofern Sicherheitsdetails kontrolliert veröffentlicht werden. Ob Alex sinnvoll eingebunden wird, hängt davon ab, welche konkrete Rolle, Erfahrung und Verfügbarkeit Alex mitbringt; die Aufgabenverteilung sollte vorab schriftlich festgelegt werden.


---

## 21. Integrationsstrategie mit ALEX Control Layer 0.6.1

### 21.1 Ausgangslage

Die bereitgestellte Datei `alex-control-layer-0.6.1.vsix` wurde als ZIP/VSIX-Paket statisch auf ihre Dateistruktur und ausgewählte Manifest-/Quelltextbestandteile untersucht. Diese Untersuchung ist **kein** vollständiger Security-Audit und bestätigt weder Build noch Laufzeitverhalten.

Die Extension enthält bereits mehrere für Forge relevante Bausteine:

- VS-Code-Webview als Chat-Oberfläche
- Provider-Abstraktion für Anthropic, OpenAI-kompatible Anbieter, DeepSeek, Ollama und LM Studio
- Tool-Schleife zum Lesen, Schreiben und Ausführen nach Nutzerbestätigung
- Berechtigungslogik und harte Sperren für bestimmte gefährliche Befehle
- Datenschutz-/Secret-Redaction-Bausteine
- Audit-Log mit Hash-Kette und separate strukturierte Receipts
- GitHub-Repo-Kontext und VS-Code-Integration

Das ist eine gute Grundlage für eine **Forge-Bedienoberfläche**, aber nicht automatisch ein Ersatz für den Forge-Sicherheitskern.

### 21.2 Empfohlene Aufteilung

```text
ALEX Control Layer (VS Code Extension)
  ├── Chat / Benutzerinteraktion
  ├── Log auswählen und redigierten Kontext anzeigen
  ├── Diagnose und Plan präsentieren
  ├── Explizite Nutzerfreigabe anfordern
  └── Forge-Ergebnis / Evidence anzeigen
                │
                │ definierter, versionierter Vertrag
                ▼
Forge Core (eigenständiges Paket / CLI)
  ├── Input- und Output-Policy
  ├── actionId-Allowlist
  ├── deterministischer Reparatur-Fallback
  ├── Sandbox-Adapter
  ├── unabhängige Zustands-Oracles
  ├── Evidence Builder
  ├── Export und Katalogfreigabe
  └── Tests und Red-Team-Suite
```

**Entscheidung:** Forge bleibt ein eigenständiges Projekt. ALEX integriert Forge über einen schmalen, versionierten Aufrufvertrag. Der Forge-Kern darf nicht von der Webview oder vom LLM kontrolliert werden.

### 21.3 Was ALEX übernehmen sollte – und was nicht

| Bereich | Empfehlung |
|---|---|
| UI, Chat, Nutzerfreigaben | ALEX kann die bestehende Oberfläche weiterverwenden |
| Provider-/Modell-Auswahl | ALEX kann Diagnosevorschläge liefern; das Modell bleibt optional |
| Input-Auswahl und Kontextanzeige | ALEX kann dem Nutzer die Auswahl/Redaction sichtbar machen |
| Policy für Forge-Artefakte | Forge braucht eine eigene, zentrale Policy; nicht nur die vorhandene Terminal-Regex-Prüfung |
| Reparatur-Aktionen | Forge verwendet registrierte `actionId`-Aktionen, keine freien Shell-Befehle aus dem Modell |
| Prozessausführung | Für L2/L3 ausschließlich Forge-Sandbox; ALEX' lokale Terminalausführung ist kein Ersatz |
| Zustands-Oracle | Muss im Test-Fixture unabhängig vom generierten Skript implementiert sein |
| Evidence | Forge erzeugt Evidence aus beobachteten Ergebnissen; ALEX darf sie anzeigen, aber nicht nachträglich als bestanden markieren |
| Katalogfreigabe | Nur Forge nach bestandenen Gates, nicht die Extension oder das Modell |
| Audit | ALEX-Audit und Forge-Evidence bleiben getrennte Artefakte mit klaren Verweisen und Hashes |

### 21.4 Integrationsvertrag

Für die erste Version sollte ALEX Forge als separaten Prozess aufrufen und strukturiertes JSON über stdin/stdout oder eine temporäre Datei austauschen. Nicht einen großen Teil des Forge-Kerns in `controller.js` kopieren.

Beispiel für einen Aufrufvertrag (konzeptionell):

```json
{
  "protocolVersion": "1",
  "operation": "repair.prepare",
  "input": {
    "logPath": "./sanitized-fixtures/service-error.log",
    "targetOS": "linux"
  },
  "policyProfile": "strict",
  "network": "disabled"
}
```

Die Antwort muss Status und Referenzen zurückgeben, keine ungeprüfte Behauptung:

```json
{
  "protocolVersion": "1",
  "operationId": "generated-by-forge",
  "status": "needs_review",
  "diagnosis": {
    "issueTitle": "Beispiel für einen Dienstfehler",
    "rootCause": "hypothesis",
    "confidence": "limited"
  },
  "artifact": null,
  "evidence": null,
  "blockedReasons": []
}
```

Dies sind illustrative Beispiele, keine bereits implementierte API. In der produktiven Schnittstelle sind Eingabepfade zu normalisieren, Workspace-Grenzen durchzusetzen, Größenlimits anzuwenden und Antworten gegen ein Schema zu validieren.

### 21.5 Wichtige Sicherheitsgrenzen bei der Integration

- Forge muss den Eingabepfad selbst prüfen; ein vom Extension-Prozess gelieferter Pfad gilt nicht als vertrauenswürdig.
- Forge darf keine API-Keys, das komplette Host-Environment oder persönliche Verzeichnisse in die Sandbox weiterreichen.
- Die Extension darf keinen Status `passed` aus Modelltext oder UI-Zustand ableiten.
- Der Prozessaufruf muss eine feste Forge-Binärdatei bzw. einen festen Einstiegspunkt und getrennte Argumente verwenden; keine zusammengesetzten Shell-Strings mit Loginhalt.
- Für L2/L3 muss Forge selbst die Sandbox- und Oracle-Prüfungen durchführen. Eine Bestätigungskarte in ALEX ist eine Nutzerfreigabe, aber kein technischer Isolationsnachweis.
- Falls Forge nicht installiert, nicht erreichbar oder inkompatibel ist, wird der Lauf als `not_verified` beendet; kein stiller Rückfall auf lokale Ausführung.
- Die ALEX-Receipts können später einen Verweis auf `artifactHash`, `evidenceHash` und `operationId` aufnehmen. Sie ersetzen Forge-Evidence nicht.
- Vor einer Freigabe müssen Integrationstests zeigen, dass ein manipuliertes JSON, ein abgebrochener Prozess und ein gefälschtes Evidence-Objekt nicht zur Katalogfreigabe führen.

### 21.6 Empfohlene Integrationsphasen

1. **Phase A – Nur anzeigen:** ALEX kann eine Forge-Diagnose und ein vorhandenes Evidence-Paket öffnen; noch keine Reparatur auslösen.
2. **Phase B – Prepare:** ALEX sendet ein redigiertes Log an Forge. Forge liefert Diagnose und vorgeschlagene `actionId`-Aktionen zurück; noch keine Änderungen.
3. **Phase C – Verify im Fixture:** ALEX kann einen Testlauf in einer bekannten, wegwerfbaren Sandbox anfordern und den Fortschritt anzeigen.
4. **Phase D – Export:** ALEX bietet das fertige ZIP und Evidence an. Nichts wird automatisch installiert.
5. **Phase E – spätere Erweiterung:** HTML und Extension-Generierung erst nach stabiler CLI-Pipeline.
6. **Phase F – AgentShield:** bleibt gesperrt, bis der unabhängige Red-Team-Selbsttest bestanden ist.

### 21.7 Build in Public

Build in Public passt zu Forge, wenn öffentlich sichtbare Aussagen den tatsächlichen Reifegrad widerspiegeln.

**Geeignet zu veröffentlichen:**
- Architekturentscheidungen und Roadmap
- harmlose, reproduzierbare Fixture-Demos
- anonymisierte Testergebnisse und bekannte Grenzen
- Prüfstufen und Evidence-Beispiele mit ausdrücklich markierten Platzhaltern
- Security-Regressionen, sobald sie behoben und verantwortungsvoll offengelegt sind

**Nicht veröffentlichen:**
- echte Logs mit Secrets, Tokens, internen Pfaden oder Kundendaten
- API-Keys, private Schlüssel oder `.env`-Dateien
- unredigierte Evidence, die sensible Prozessausgaben enthält
- ungepatchte Sicherheitslücken mit direkt ausnutzbaren Details
- Marketingaussagen wie „sicher“ oder „vollständig verifiziert“, die über die tatsächlich ausgeführten Tests hinausgehen

Ein guter öffentlicher Status verwendet präzise Begriffe: „statische Prüfung bestanden“, „in Sandbox ausgeführt“, „Rot-Grün-Oracle bestanden“ oder „Paketintegrität geprüft“. Eine öffentliche Roadmap sollte klar zwischen geplant, implementiert und getestet unterscheiden.

### 21.8 Entscheidungsempfehlung

Die sinnvollste Richtung ist **nicht**, Forge vollständig in ALEX einzubauen. Stattdessen:

- Forge bleibt ein unabhängiger Core mit eigener CI und eigenem Testsystem.
- ALEX ist ein optionaler VS-Code-Client für Interaktion, Freigabe und Anzeige.
- Forge kann zusätzlich ohne ALEX über die CLI genutzt werden.
- Die Sicherheitsentscheidung liegt bei Forge; die Nutzerentscheidung bleibt beim Menschen.
- Build in Public dokumentiert den Fortschritt, ersetzt aber keine unabhängige Prüfung.

So kann Forge später auch von anderen Editoren oder CI-Systemen genutzt werden, ohne an ALEX gebunden zu sein.
