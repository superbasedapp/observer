// Component test of the Sandbox isolation card's module-off state (lane L2,
// ruling SBXD-9): on a fresh install of the developer edition the Sandboxes
// and VMs module is installed but not turned on, and the card says so in
// plain words, turns it on in place with one click, and keeps the link to
// the one place it is otherwise turned on, never "Loading sandbox
// configuration" forever. One render per button state.

import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router-dom";
import { SandboxModuleOffCard } from "@/components/SandboxSettingsCard";
import type { TurnOnState } from "@/lib/componentTurnOn";

function render(blocked: boolean, state: string, initial?: TurnOnState): string {
  return renderToStaticMarkup(
    <MemoryRouter>
      <SandboxModuleOffCard blocked={blocked} state={state} initial={initial} />
    </MemoryRouter>,
  );
}

test("module off: says it is turned off, offers Turn it on, and keeps the Settings > Components link", () => {
  const html = render(false, "available");
  assert.match(html, /Sandbox isolation/);
  assert.match(html, /installed but turned off on this machine/);
  assert.match(html, /data-testid="sandbox-module-turn-on"[^>]*>Turn it on</);
  assert.match(html, /href="\/settings\/components\?component=terminals\.sandbox"/);
  assert.match(html, /Or open Settings &gt; Components/);
  assert.doesNotMatch(html, /Loading sandbox configuration|probe has not returned/);
  assert.doesNotMatch(html, /role="alert"|role="status"/);
  // The internal names stay behind Technical details.
  assert.match(html, /aria-label="Technical details for the sandbox module"/);
});

test("module off, working: the button says it is turning on and is disabled", () => {
  const html = render(false, "available", { phase: "working" });
  assert.match(html, /<button[^>]*disabled=""[^>]*>[\s\S]*?Turning it on\.\.\./);
});

test("module off, done: says it is turned on and the settings follow here", () => {
  const html = render(false, "available", { phase: "done" });
  assert.match(html, /role="status"[^>]*>Turned on\. Its settings show here next\./);
});

test("module off, needs restart: says background work follows the next restart", () => {
  const html = render(false, "available", { phase: "needs_restart" });
  assert.match(html, /role="status"[^>]*>Turned on\. New commands use it at once; the daemon&#x27;s background work for it starts after the next restart\./);
});

test("module off, refused: the reason shows as an alert and the button stays usable", () => {
  const html = render(false, "available", { phase: "refused", reason: "Acme decides which components run on this machine." });
  assert.match(html, /role="alert"[^>]*>Acme decides which components run on this machine\./);
  assert.match(html, /data-testid="sandbox-module-turn-on"[^>]*>Turn it on</);
  assert.doesNotMatch(html, /<button[^>]*disabled=""[^>]*data-testid="sandbox-module-turn-on"/);
});

test("module blocked: says it is blocked, offers no button, and opens Settings > Components", () => {
  const html = render(true, "blocked");
  assert.match(html, /blocked on this machine/);
  assert.match(html, /Open Settings &gt; Components/);
  assert.doesNotMatch(html, /sandbox-module-turn-on/);
});
