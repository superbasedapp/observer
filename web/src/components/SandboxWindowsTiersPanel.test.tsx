// Render tests of the extra Windows rows panel (lane GATES-SBX; dashboard
// CLI parity lane L3 item B-G6).

import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { SandboxWindowsTiersPanel, WINDOWS_TIER_ROWS } from "@/components/SandboxWindowsTiersPanel";

// React warns that a layout effect does nothing on the server; the chips use
// one, and the warning says nothing about these tests.
const consoleError = console.error;
console.error = (...args: unknown[]) => {
  if (typeof args[0] === "string" && args[0].includes("useLayoutEffect does nothing on the server")) return;
  consoleError(...args);
};

const view = (ids: string[]) => ({ configured: true, components: ids.map((id) => ({ id, state: "active" })) }) as never;
const all = view(["terminals.sandbox.mxc.appcontainer", "terminals.sandbox.wslc", "terminals.sandbox.hcs"]);

test("nothing renders while no row's component is selected", () => {
  assert.equal(renderToStaticMarkup(<SandboxWindowsTiersPanel wslc={undefined} hcs={undefined} view={view([])} />), "");
});

test("only the selected rows render, with the weaker tier labelled", () => {
  const html = renderToStaticMarkup(
    <SandboxWindowsTiersPanel wslc={{ path: "", image: "" }} hcs={{ utility_vm_image: "" }} view={view(["terminals.sandbox.mxc.appcontainer", "terminals.sandbox.hcs"])} />,
  );
  assert.match(html, /MXC AppContainer tier/);
  assert.match(html, /Weaker than ProcessContainer/);
  assert.match(html, /Hyper-V isolated containers/);
  assert.doesNotMatch(html, /WSL containers/);
  assert.equal(WINDOWS_TIER_ROWS.length, 3);
});

test("the values are fields, not a pointer at the config file (B-G6)", () => {
  const html = renderToStaticMarkup(
    <SandboxWindowsTiersPanel wslc={{ path: "", image: "" }} hcs={{ utility_vm_image: "" }} windows={{ mxc_tier: "process_container" }} savedTier="process_container" view={all} pinned={new Set()} writable onChange={() => {}} />,
  );
  assert.doesNotMatch(html, /config file/);
  assert.match(html, /MXC tier floor/);
  assert.match(html, /ProcessContainer only/);
  assert.match(html, /wslc\.exe/);
  assert.match(html, /Utility VM image folder/);
  assert.doesNotMatch(html, /<input[^>]*disabled=""/);
  assert.doesNotMatch(html, /This loosens isolation/);
});

test("a move off ProcessContainer is called a loosening", () => {
  const html = renderToStaticMarkup(
    <SandboxWindowsTiersPanel wslc={undefined} hcs={undefined} windows={{ mxc_tier: "appcontainer" }} savedTier="process_container" view={all} pinned={new Set()} writable onChange={() => {}} />,
  );
  assert.match(html, /This loosens isolation/);
});

test("an organization pin makes the floor read-only and says so", () => {
  const html = renderToStaticMarkup(
    <SandboxWindowsTiersPanel wslc={undefined} hcs={undefined} windows={{ mxc_tier: "appcontainer" }} savedTier="process_container" view={all} pinned={new Set(["windows.mxc_tier"])} writable onChange={() => {}} />,
  );
  assert.match(html, /Set by your organization, which may only hold it on ProcessContainer/);
  assert.doesNotMatch(html, /This loosens isolation/);
});

test("a malformed image and a relative path are flagged before the save", () => {
  const html = renderToStaticMarkup(
    <SandboxWindowsTiersPanel wslc={{ path: "bin/wslc.exe", image: "box:latest" }} hcs={undefined} view={view(["terminals.sandbox.wslc"])} pinned={new Set()} writable onChange={() => {}} />,
  );
  assert.match(html, /Use an absolute path/);
  assert.match(html, /Pin the image by its digest/);
});
