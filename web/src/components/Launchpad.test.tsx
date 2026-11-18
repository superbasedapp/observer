// Component tests of the launchpad (door A): the first-launch consent renders
// exactly the previewed changes with Allow and Cancel, and the docked split's
// meter shows the install / start state with no numbers. The decisions are
// pinned in src/lib/launchpad.test.ts; these prove the components render them.

import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router-dom";
import { FirstLaunchConsent, type FirstLaunchPreview } from "@/components/launchpad/FirstLaunchConsent";
import { LaunchpadMeter } from "@/components/launchpad/LaunchpadMeter";

const consoleError = console.error;
console.error = (...args: unknown[]) => {
  if (typeof args[0] === "string" && args[0].includes("useLayoutEffect does nothing on the server")) return;
  consoleError(...args);
};

const preview: FirstLaunchPreview = {
  dry_run: true,
  would_write: true,
  changed_keys: [
    "terminal.launch.allow_fresh_agent",
    "terminal.launch.allowed_project_roots",
    "terminal.launch.allowed_tools",
  ],
  restart_required: false,
  restart_required_keys: [],
  applied_live_keys: [],
  next_spawn_keys: [],
  comments_preserved: true,
  write_mode: "surgical",
  config_path: "/home/u/.observer/config.toml",
  config_etag: "abc",
  diff: "--- config.toml\n+++ config.toml (after save)\n+allow_fresh_agent = true\n",
  diff_stats: { added: 1, removed: 0 },
  needs_confirm: true,
  secret_warnings: [],
  tool: "claude-code",
  folder: "/home/u/observer-playground",
  changes: ["allow_tool", "allow_fresh", "allow_folder", "create_folder"],
};

test("FirstLaunchConsent shows the heading, one line per change, the settings and Allow / Cancel", () => {
  const html = renderToStaticMarkup(
    <FirstLaunchConsent
      tool="claude-code"
      toolLabel="Claude Code"
      folder="/home/u/observer-playground"
      changes={["allow_tool", "allow_fresh", "allow_folder", "create_folder"]}
      onAllowed={() => undefined}
      onCancel={() => undefined}
      initialPreview={preview}
    />,
  );
  assert.match(html, /To start Claude Code here, Observer will:/);
  assert.match(html, /allow Claude Code to launch from the dashboard/);
  assert.match(html, /allow fresh launches/);
  assert.match(html, /allow the folder \/home\/u\/observer-playground \(created now\)/);
  // The place in plain words; the config keys sit in the technical details.
  assert.match(html, /This changes Terminals &gt; Settings &gt; Fresh-agent launch policy/);
  assert.match(html, /Technical details for the launch policy settings this changes/);
  assert.doesNotMatch(html, /This writes/);
  assert.match(html, /\/home\/u\/\.observer\/config\.toml/);
  assert.match(html, /data-testid="first-launch-allow"/);
  assert.match(html, /data-testid="first-launch-cancel"/);
  assert.match(html, /data-testid="config-preview"/);
});

test("LaunchpadMeter shows the install state with no numbers", () => {
  const html = renderToStaticMarkup(
    <MemoryRouter>
      <LaunchpadMeter token="t1" kind="install" tool="claude-code install" status="open" onOpenDetail={() => undefined} />
    </MemoryRouter>,
  );
  assert.match(html, /Installing\./);
  assert.doesNotMatch(html, /launchpad-meter-numbers/);
});

test("LaunchpadMeter shows the start state with no numbers before the session links", () => {
  const html = renderToStaticMarkup(
    <MemoryRouter>
      <LaunchpadMeter token="t1" kind="agent" tool="claude-code" status="connecting" onOpenDetail={() => undefined} />
    </MemoryRouter>,
  );
  assert.match(html, /Numbers appear after your first prompt lands/);
  assert.doesNotMatch(html, /launchpad-meter-numbers/);
});
