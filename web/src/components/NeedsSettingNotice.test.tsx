// Component tests of the one "needs a setting" renderer
// (components/NeedsSettingNotice.tsx), rendered with react-dom/server under
// node's test runner (scripts/test-components.mjs).

import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router-dom";
import { ApiErrorNotice, NeedsSettingNotice } from "@/components/NeedsSettingNotice";
import { ApiError } from "@/lib/api";
import { errorNote } from "@/lib/needsSetting";

const consoleError = console.error;
console.error = (...args: unknown[]) => {
  if (typeof args[0] === "string" && args[0].includes("useLayoutEffect does nothing on the server")) return;
  consoleError(...args);
};

// The operator's report body (2026-11-18), longer than ApiError's 200-char
// message excerpt.
const REMOTE_BODY = JSON.stringify({
  error: "component_not_installed",
  component: "remote",
  state: "available",
  reason: "not_selected",
  message:
    "Remote dashboard (remote) is installed but inactive on this machine. Turn it on in Settings > Components or with `observer components add remote --yes`.",
  settings: "/settings/components?component=remote",
  settings_label: "Settings > Components",
  command: "observer components add remote --yes",
});

function render(note: Parameters<typeof ApiErrorNotice>[0]["note"]): string {
  return renderToStaticMarkup(
    <MemoryRouter>
      <ApiErrorNotice note={note} />
    </MemoryRouter>,
  );
}

test("a component refusal renders its whole sentence and a button to its row", () => {
  const html = render(errorNote(new ApiError(404, "/api/remote/config", REMOTE_BODY)));
  assert.match(html, /data-testid="needs-setting-text"/);
  assert.match(html, /Turn it on in Settings &gt; Components or with `observer components add remote --yes`\./);
  assert.doesNotMatch(html, /\{&quot;error/, "never raw JSON");
  assert.match(html, /href="\/settings\/components\?component=remote"/);
  assert.match(html, /Turn on remote/);
  // The message already names the command: it is not repeated.
  assert.equal(html.split("observer components add remote --yes").length - 1, 1);
});

test("a settings place renders Open <place>", () => {
  const body = JSON.stringify({
    error: "guided install is off",
    message: "Guided install is off on this machine.",
    settings: "/terminals?tab=settings#launch-policy",
    settings_label: "Terminals > Settings > Fresh-agent launch policy",
  });
  const html = render(errorNote(new ApiError(403, "/api/terminal/install", body)));
  assert.match(html, /Guided install is off on this machine\./);
  assert.match(html, /href="\/terminals\?tab=settings#launch-policy"/);
  assert.match(html, /Open Terminals &gt; Settings &gt; Fresh-agent launch policy/);
});

test("a refusal with no link renders the plain line and no button", () => {
  const html = render(errorNote(new ApiError(400, "/api/x", JSON.stringify({ error: "missing tool" }))));
  assert.match(html, /role="alert"/);
  assert.match(html, />missing tool</);
  assert.doesNotMatch(html, /needs-setting-open/);
});

test("nothing to say renders nothing", () => {
  assert.equal(render(null), "");
  assert.equal(render(""), "");
});

test("an org-only refusal says who can change it and opens the team dashboard in a new tab", () => {
  const body = JSON.stringify({
    error: "org_off",
    message: "Your organization has not turned on session enrichment.",
    org_settings: "https://org.example/intelligence?tab=session-enrichment",
    org_settings_label: "Intelligence > Session enrichment",
  });
  const html = render(errorNote(new ApiError(409, "/api/intel/enrich", body)));
  assert.match(html, /Your organization has not turned on session enrichment\./);
  assert.match(html, /The team&#x27;s admins can turn it on in the team dashboard: Intelligence &gt; Session enrichment\./);
  assert.match(html, /href="https:\/\/org\.example\/intelligence\?tab=session-enrichment"/);
  assert.match(html, /target="_blank"/);
  assert.match(html, /Open session enrichment/);
  assert.doesNotMatch(html, /needs-setting-open"/, "no local button: nothing to change on this machine");
});

test("an org place with no safe address is named in words, with no button", () => {
  const html = renderToStaticMarkup(
    <MemoryRouter>
      <NeedsSettingNotice variant="inline" text="Off." org={{ href: null, label: "Intelligence > Session enrichment" }} />
    </MemoryRouter>,
  );
  assert.match(html, /data-testid="needs-setting-inline"/);
  assert.match(html, /team dashboard: Intelligence &gt; Session enrichment/);
  assert.doesNotMatch(html, /<a /);
});

test("both forms at once: the local button and the org line", () => {
  const html = renderToStaticMarkup(
    <MemoryRouter>
      <NeedsSettingNotice
        variant="inline"
        text="Your organization does not allow a purpose your consent covers."
        link={{ href: "/settings?section=intel", label: "Settings > Team AI summaries", command: null, component: null, componentState: null }}
        org={{ href: "https://org.example/intelligence?tab=session-enrichment", label: "Intelligence > Session enrichment" }}
      />
    </MemoryRouter>,
  );
  assert.match(html, /href="\/settings\?section=intel"/);
  assert.match(html, /Open Settings &gt; Team AI summaries/);
  assert.match(html, /Open session enrichment/);
});

test("a personal dashboard's org form tells the person to turn it on themselves", () => {
  const html = renderToStaticMarkup(
    <MemoryRouter>
      <NeedsSettingNotice
        tone="info"
        text="Your personal dashboard has session enrichment off. Nothing is sent."
        org={{ href: "https://u-abc.superbased.app/intelligence?tab=session-enrichment", label: "Intelligence > Session enrichment", personal: true }}
      />
    </MemoryRouter>,
  );
  assert.match(html, /Turn it on in your personal dashboard: Intelligence &gt; Session enrichment\./);
  assert.doesNotMatch(html, /admins/);
  assert.match(html, /href="https:\/\/u-abc\.superbased\.app\/intelligence\?tab=session-enrichment"/);
  assert.match(html, /Open session enrichment/);
});
