// Render tests of the microVM panel's image set import (dashboard CLI parity
// lane L3 item B-G7), rendered with react-dom/server
// (scripts/test-components.mjs).

import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { SandboxVMImportView, SandboxVMPanel } from "@/components/SandboxVMPanel";

// React warns that a layout effect does nothing on the server; the chips use
// one, and the warning says nothing about these tests.
const consoleError = console.error;
console.error = (...args: unknown[]) => {
  if (typeof args[0] === "string" && args[0].includes("useLayoutEffect does nothing on the server")) return;
  consoleError(...args);
};

const importView = (over: Partial<Parameters<typeof SandboxVMImportView>[0]> = {}) =>
  renderToStaticMarkup(<SandboxVMImportView dir="" onDir={() => {}} busy={false} err={null} installed={null} onImport={() => {}} {...over} />);

test("the import form names the folder and keeps the debug set a CLI-only step", () => {
  const html = importView();
  assert.match(html, /Import image set/);
  assert.match(html, /--debug-set and --debug-key/);
  assert.match(html, /<button[^>]*disabled=""[^>]*>Import image set/);
});

test("a relative folder is flagged and cannot be imported", () => {
  const html = importView({ dir: "sets/1.0.0" });
  assert.match(html, /absolute path/);
  assert.match(html, /<button[^>]*disabled=""[^>]*>Import image set/);
});

test("an absolute folder can be imported, and what was installed is listed", () => {
  const html = importView({
    dir: "/home/u/Downloads/observer-vm-1.0.0",
    installed: [{ kind: "sandbox.rootfs", version: 3, status: "sandbox.rootfs: version 3, fresh" }],
  });
  assert.doesNotMatch(html, /<button[^>]*disabled=""[^>]*>Import image set/);
  assert.match(html, /Installed <span class="font-mono">sandbox\.rootfs<\/span> version 3/);
});

test("a refusal is shown", () => {
  assert.match(importView({ err: "signature refused" }), /signature refused/);
});

test("the panel no longer sends the user to a terminal for the import", () => {
  const vm = { vmm: "", image_set: "", vcpus: 2, memory_mb: 4096, install_cache: false, workspace_delivery: "", cloud_hypervisor_path: "", virtiofsd_path: "" };
  const view = { configured: true, components: [{ id: "terminals.sandbox.vm", state: "active" }] } as never;
  const html = renderToStaticMarkup(<SandboxVMPanel value={vm} view={view} writable onChange={() => {}} confirmToken="tok" />);
  assert.match(html, /import one below/);
  assert.match(html, /Image set folder/);
  assert.equal(renderToStaticMarkup(<SandboxVMPanel value={vm} view={{ configured: true, components: [] } as never} writable onChange={() => {}} confirmToken="tok" />), "");
});
