// Render tests of the OpenShell sub-panel and the Isolation picker's served
// notes (OpenShell lane O4), rendered with react-dom/server under node's test
// runner (scripts/test-components.mjs). Every sentence about the row comes
// from the probe answer; these tests feed sentinel sentences and check that
// the surfaces render them as served.

import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import {
  SandboxOpenShellPanel,
  openShellDriverSelected,
  openShellModeChange,
  openShellPinChoices,
} from "@/components/SandboxOpenShellPanel";
import { SandboxIsolationPicker } from "@/components/SandboxIsolationPicker";
import { isolationPickerProps } from "@/lib/newTerminalSandbox";
import type { ComponentsView } from "@/lib/componentState";
import type { SandboxAvailability, SandboxBackendAvail } from "@/lib/types";

const view = (state: string): ComponentsView =>
  ({ configured: true, components: [{ id: "terminals.sandbox.openshell", state }] }) as unknown as ComponentsView;

const row: SandboxBackendAvail = {
  id: "openshell",
  label: "OpenShell",
  class: "container",
  location: "local",
  maturity: "preview",
  available: false,
  verdict: "openshell_missing",
  rule: "S2",
  reason: "SENTINEL-REASON the openshell CLI is not on PATH",
  beta: true,
  component: "terminals.sandbox",
  gateway_mode: "managed_local",
  prerequisite: "SENTINEL-PREREQ docker group, which is root-equivalent",
  disclosures: [{ id: "gateway_wide_bind_mounts", text: "SENTINEL-D3 your own gateway config is never read or written" }],
};

const cfg = { gateway_mode: "", endpoint: "", version: "", state_dir: "" };

test("the panel renders nothing unless the openshell component is active", () => {
  assert.equal(openShellDriverSelected(undefined), false);
  assert.equal(openShellDriverSelected(view("inactive")), false);
  const html = renderToStaticMarkup(<SandboxOpenShellPanel value={cfg} row={row} view={view("inactive")} writable onChange={() => {}} />);
  assert.equal(html, "");
});

test("the panel shows the reason, the gateway mode, the prerequisite and the disclosure as served", () => {
  const html = renderToStaticMarkup(<SandboxOpenShellPanel value={cfg} row={row} view={view("active")} writable onChange={() => {}} />);
  assert.match(html, /Not available: SENTINEL-REASON/);
  assert.match(html, /Gateway: Observer&#x27;s private gateway\./);
  assert.match(html, /SENTINEL-PREREQ docker group, which is root-equivalent/);
  assert.match(html, /SENTINEL-D3 your own gateway config is never read or written/);
  // The endpoint field shows only in external mode.
  assert.doesNotMatch(html, /Gateway endpoint/);
  const ext = renderToStaticMarkup(
    <SandboxOpenShellPanel value={{ ...cfg, gateway_mode: "external" }} row={row} view={view("active")} writable onChange={() => {}} />,
  );
  assert.match(ext, /Gateway endpoint/);
});

test("the Isolation picker lists an unavailable row with its reason and the chosen row's served notes", () => {
  const probe: SandboxAvailability = {
    available: true,
    backend: "bwrap",
    default_on: false,
    egress: "proxy_only",
    backends: [
      { ...row, available: true, verdict: undefined, rule: undefined, reason: undefined },
      { id: "oci-runc", label: "Docker or Podman", class: "container", location: "local", maturity: "beta", available: false, reason: "SENTINEL-NO-RUNTIME", beta: true, component: "terminals.sandbox" },
    ],
    tools: { "claude-code": { available: true } },
  } as SandboxAvailability;
  const props = isolationPickerProps("claude-code", probe, true, "openshell");
  assert.deepEqual(props.notes, ["SENTINEL-PREREQ docker group, which is root-equivalent", "SENTINEL-D3 your own gateway config is never read or written"]);
  assert.deepEqual(props.unavailable, [{ id: "oci-runc", label: "Docker or Podman", reason: "SENTINEL-NO-RUNTIME", notes: [] }]);
  const html = renderToStaticMarkup(<SandboxIsolationPicker {...props} onChange={() => {}} />);
  assert.match(html, /gateway: Observer&#x27;s private gateway/);
  assert.match(html, /SENTINEL-PREREQ/);
  assert.match(html, /SENTINEL-D3/);
  assert.match(html, /Not available here \(1\)/);
  assert.match(html, /Docker or Podman<\/span>: SENTINEL-NO-RUNTIME/);
});

test("the Isolation picker shows an unavailable openshell row's prerequisite and disclosure beside its reason", () => {
  const probe: SandboxAvailability = {
    available: true,
    backend: "bwrap",
    default_on: false,
    egress: "proxy_only",
    backends: [row],
    tools: { "claude-code": { available: true } },
  } as SandboxAvailability;
  const props = isolationPickerProps("claude-code", probe, true, "none");
  const html = renderToStaticMarkup(<SandboxIsolationPicker {...props} onChange={() => {}} />);
  assert.match(html, /OpenShell<\/span>: SENTINEL-REASON/);
  assert.match(html, /aria-label="About OpenShell"/);
  assert.match(html, /SENTINEL-PREREQ docker group, which is root-equivalent/);
  assert.match(html, /SENTINEL-D3 your own gateway config is never read or written/);
});

test("switching to managed clears the hidden endpoint, and the version pin is a picker of the served versions", () => {
  let next: typeof cfg | undefined;
  const ext = { ...cfg, gateway_mode: "external", endpoint: "https://127.0.0.1:17670" };
  openShellModeChange(ext, "managed", (v) => (next = v));
  assert.deepEqual(next, { ...ext, gateway_mode: "managed", endpoint: "" });
  openShellModeChange(ext, "", (v) => (next = v));
  assert.deepEqual(next, { ...ext, gateway_mode: "" }, "the default mode keeps a visible endpoint");

  const served = { ...row, version_pins: ["0.1.6"] };
  const html = renderToStaticMarkup(<SandboxOpenShellPanel value={cfg} row={served} view={view("active")} writable onChange={() => {}} />);
  assert.match(html, /<select[^>]*aria-label="Version pin"/);
  assert.match(html, /<option value="" selected="">No pin<\/option>/);
  assert.match(html, /<option value="0.1.6">0.1.6<\/option>/);
  assert.doesNotMatch(html, /<input[^>]*aria-label="Version pin"/);
  // A pin already in config.toml that is not served stays visible and named.
  const stale = renderToStaticMarkup(
    <SandboxOpenShellPanel value={{ ...cfg, version: "0.1.5" }} row={served} view={view("active")} writable onChange={() => {}} />,
  );
  assert.match(stale, /<option value="0.1.5" selected="">0.1.5 \(not a tested version\)<\/option>/);
  // "v0.1.6" in config.toml is the served 0.1.6: selected as it is written,
  // never listed twice.
  assert.deepEqual(openShellPinChoices("v0.1.6", ["0.1.6"]), [
    { value: "", label: "No pin" },
    { value: "v0.1.6", label: "0.1.6" },
  ]);
  assert.deepEqual(openShellPinChoices("", []), [{ value: "", label: "No pin" }]);
  // F-029 V2: a daemon that serves no version_pins cannot check a pin, so
  // even a tested one reads "not checked", never "not a tested version".
  assert.deepEqual(openShellPinChoices("0.1.6", []), [
    { value: "", label: "No pin" },
    { value: "0.1.6", label: "0.1.6 (not checked)" },
  ]);
});
