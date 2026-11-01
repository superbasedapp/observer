import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

// T-489 (and T-488 for the SSH half): the New Terminal dialog and the copy it
// shows used to send the operator to config.toml and a daemon restart for
// settings the dashboard now edits live (the launch policy, the folder
// allow-list, guided install, the SSH profiles). Every such sentence is gone:
// each one now names the dashboard card instead (D-003: no CLI or config-file
// dead ends). This scans the CODE (comments stripped, since comments may and
// should name the config keys they implement) of every file that renders that
// copy.

const repo = new URL("../../../", import.meta.url);

function codeOnly(path: string): string {
  const src = readFileSync(new URL(path, repo), "utf8");
  return src
    .replace(/\{\/\*[\s\S]*?\*\/\}/g, "") // JSX comments
    .replace(/\/\*[\s\S]*?\*\//g, "") // block comments
    .replace(/^\s*\/\/.*$/gm, ""); // line comments
}

const FILES = [
  "web/src/components/NewTerminalDialog.tsx",
  "web/src/lib/newTerminalSandbox.ts",
  "web/src/lib/toolInstall.ts",
  "web/src/lib/toolUninstall.ts",
  "web/src/lib/remoteTerminal.ts",
];

// A config-file instruction for a [terminal.launch] / [terminal.ssh] setting.
const CONFIG_FILE_DEAD_END = /\[\[?terminal\.(launch|ssh)[^\n]*config\.toml|config\.toml[^\n]*\[\[?terminal\.(launch|ssh)/;

for (const file of FILES) {
  test(`${file} sends no one to config.toml for a terminal launch or SSH setting`, () => {
    const code = codeOnly(file);
    const m = code.match(CONFIG_FILE_DEAD_END);
    assert.equal(m, null, `config.toml dead end in ${file}: ${m?.[0]}`);
  });
}

test("the folder allow-list refusal no longer asks for a restart", () => {
  const code = codeOnly("web/src/lib/remoteTerminal.ts");
  const m = code.match(/isn't allow-listed[^"]*"/);
  assert.ok(m, "project-root refusal copy not found");
  assert.ok(!/restart/i.test(m[0]) || /no restart/i.test(m[0]), m[0]);
  assert.ok(m[0].includes("Folder Selection"), m[0]);
});

test("the dialog's launch policy copy names the dashboard card, not [terminal.launch]", () => {
  const code = codeOnly("web/src/components/NewTerminalDialog.tsx");
  assert.ok(!code.includes("<code className=\"font-mono\">[terminal.launch]</code>"));
  assert.ok(!code.includes("[terminal.launch].allowed_project_roots"));
  assert.ok(!code.includes("[terminal.launch].allowed_tools</code>"));
  assert.ok(code.includes("TERMINALS_LAUNCH_POLICY_HASH_PATH"));
  assert.ok(code.includes("TERMINALS_FOLDERS_HASH_PATH"));
});

test("the System picker's empty and off states point at the Remote systems card, without a restart", () => {
  // The picker's disabled copy lives in lib/newTerminalSandbox.ts since lane
  // sbx-p2b; the dialog links the card.
  const code = codeOnly("web/src/components/NewTerminalDialog.tsx") + codeOnly("web/src/lib/newTerminalSandbox.ts");
  assert.ok(!code.includes("[[terminal.ssh.profiles]] block"));
  assert.ok(!/restart the daemon/i.test(code), "the dialog still asks for a daemon restart");
  assert.ok(code.includes("TERMINALS_REMOTE_SYSTEMS_HASH_PATH"));
  assert.ok(code.includes("Terminals > Settings > Remote systems"));
});
