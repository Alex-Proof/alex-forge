// The extensionTestsPath module for vscode-extension-smoke-runner.mjs: runs *inside* a real VS
// Code Extension Host process (not a mock), loaded via Node's CommonJS require because that is
// what the Extension Host test runner expects. Deliberately independent of
// src/modes/repair/actions.ts -- it only knows the extension's public contract (its id, its
// declared commands, and that invoking the "show details" command opens a labeled panel), never
// its generated source, so it cannot be fooled by a generator bug that merely looks consistent
// with itself.
const vscode = require("vscode");

exports.run = async function run(_testsRoot, callback) {
  try {
    const extensionId = process.env.FORGE_EXTENSION_ID;
    const expectedCommands = JSON.parse(process.env.FORGE_EXPECTED_COMMANDS || "[]");
    const showDetailsCommand = process.env.FORGE_SHOW_DETAILS_COMMAND;
    const expectedWebviewLabelContains = process.env.FORGE_EXPECTED_WEBVIEW_LABEL_CONTAINS;

    if (!extensionId || expectedCommands.length === 0) {
      throw new Error("smoke test misconfigured: FORGE_EXTENSION_ID/FORGE_EXPECTED_COMMANDS not set");
    }

    const extension = vscode.extensions.getExtension(extensionId);
    if (!extension) {
      throw new Error(`extension "${extensionId}" was not discovered by VS Code`);
    }
    await extension.activate();
    if (!extension.isActive) {
      throw new Error(`extension "${extensionId}" did not report isActive=true after activate()`);
    }

    const registeredCommands = await vscode.commands.getCommands(true);
    for (const expected of expectedCommands) {
      if (!registeredCommands.includes(expected)) {
        throw new Error(`expected command "${expected}" was not registered after activation`);
      }
    }

    if (showDetailsCommand && expectedWebviewLabelContains) {
      await vscode.commands.executeCommand(showDetailsCommand);
      // The webview panel is created synchronously by the command handler, but the tab model
      // can lag a tick behind -- a short, bounded wait, not a sleep-and-hope retry loop.
      await new Promise((resolve) => setTimeout(resolve, 500));
      const tabs = vscode.window.tabGroups.all.flatMap((group) => group.tabs);
      const matchingTab = tabs.find((tab) => typeof tab.label === "string" && tab.label.includes(expectedWebviewLabelContains));
      if (!matchingTab) {
        throw new Error(
          `executing "${showDetailsCommand}" did not open a tab whose label contains "${expectedWebviewLabelContains}" ` +
            `(open tab labels: ${tabs.map((t) => t.label).join(", ") || "(none)"})`,
        );
      }
    }

    callback(null);
  } catch (error) {
    callback(error instanceof Error ? error : new Error(String(error)));
  }
};
