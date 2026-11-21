// Render tests of the Terminals page's refused-connections view (OpenShell
// build plan 05 section 3.5, lane N5), rendered with react-dom/server under
// node's test runner (scripts/test-components.mjs). The view takes the rows
// as a prop.

import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import {
  IncompleteRunsNotice,
  SandboxRefusalsView,
  allowScopeNote,
  droppedLine,
  hostPort,
  incompleteRuns,
  refusalRuleLabel,
  uncertainLine,
  linkLostLine,
  egressClosedLine,
  evictedLine,
  type SandboxRefusal,
} from "@/components/SandboxRefusals";

const consoleError = console.error;
console.error = (...args: unknown[]) => {
  if (typeof args[0] === "string" && args[0].includes("useLayoutEffect does nothing on the server")) return;
  consoleError(...args);
};

const row = (id: number, rule: string, host: string, port = 443): SandboxRefusal => ({
  id,
  run_id: `run00000000000000a${id}`,
  project_root: "/work/proj",
  backend: "bwrap",
  tier: "internet",
  host,
  port,
  rule,
  key: "terminal.sandbox.egress_allow_hosts",
  at: "2026-10-30T12:00:00Z",
});

test("no rows shows the empty state", () => {
  const html = renderToStaticMarkup(<SandboxRefusalsView rows={[]} />);
  assert.match(html, /No refused connections/);
});

test("each row shows its host, port, rule label and deciding key", () => {
  const html = renderToStaticMarkup(
    <SandboxRefusalsView rows={[row(1, "allow-list-miss", "registry.example.com"), row(2, "private-range", "10.0.0.5", 80)]} />,
  );
  assert.match(html, /registry\.example\.com:443/);
  assert.match(html, /10\.0\.0\.5:80/);
  assert.match(html, /Not on the host allow-list/);
  assert.match(html, /Private address range/);
  assert.match(html, /terminal\.sandbox\.egress_allow_hosts/);
  assert.match(html, /data-refusal-id="1"/);
  assert.match(html, /data-refusal-id="2"/);
});

test("every rule of the closed vocabulary has a label; an unknown rule shows its name", () => {
  for (const rule of [
    "allow-list-miss",
    "private-range",
    "provider-host",
    "host-local",
    "tier-none",
    "ssrf-floor",
    "literal-ip",
    "port-not-allowed",
    "tls-server-name",
  ]) {
    assert.notEqual(refusalRuleLabel(rule), rule, rule);
  }
  assert.equal(refusalRuleLabel("future-rule"), "future-rule");
});

test("hostPort brackets an IPv6 literal and leaves a zero port off", () => {
  assert.equal(hostPort("::1", 443), "[::1]:443");
  assert.equal(hostPort("example.com", 0), "example.com");
});

const offer = (id: number, host: string, offerable: boolean, reason: string, message?: string, explain = reason !== "rule_not_offerable") => ({
  refusal_id: id,
  host,
  offerable,
  reason,
  message,
  explain,
});

test("an offerable refusal shows the allow button; nothing else does", () => {
  const rows = [
    row(1, "allow-list-miss", "registry.example.com"),
    row(2, "provider-host", "api.anthropic.com"),
    row(3, "allow-list-miss", "blocked.example.com"),
    row(4, "ssrf-floor", "169.254.169.254"),
  ];
  const offers = new Map([
    [1, offer(1, "registry.example.com", true, "offerable")],
    [2, offer(2, "api.anthropic.com", false, "rule_not_offerable", "Model provider hosts are reached through the model proxy only.")],
    [3, offer(3, "blocked.example.com", false, "org_pin_refuses", "Your organization's host list does not include this host.")],
    [4, offer(4, "169.254.169.254", false, "rule_not_offerable", "Refused under every setting.")],
  ]);
  const html = renderToStaticMarkup(
    <SandboxRefusalsView rows={rows} offers={offers} scopeLabel="every sandboxed run on this computer" onAllow={() => {}} />,
  );
  // Exactly one button, on row 1.
  assert.equal(html.match(/Allow this host/g)?.length, 1);
  assert.match(html, /data-refusal-id="1".*Allow this host/s);
  // The org pin's reason is said on its allow-list miss.
  assert.match(html, /organization&#x27;s host list does not include this host/);
  // A provider-host or SSRF-floor refusal shows no offer text at all.
  assert.doesNotMatch(html, /model proxy only/);
  assert.doesNotMatch(html, /Refused under every setting/);
});

test("no offers (or no handler) offers nothing", () => {
  const rows = [row(1, "allow-list-miss", "registry.example.com")];
  assert.doesNotMatch(renderToStaticMarkup(<SandboxRefusalsView rows={rows} />), /Allow this host/);
  const offers = new Map([[1, offer(1, "registry.example.com", true, "offerable")]]);
  assert.doesNotMatch(renderToStaticMarkup(<SandboxRefusalsView rows={rows} offers={offers} />), /Allow this host/);
});

test("the busy row's button says it is saving", () => {
  const rows = [row(1, "allow-list-miss", "registry.example.com")];
  const offers = new Map([[1, offer(1, "registry.example.com", true, "offerable")]]);
  const html = renderToStaticMarkup(<SandboxRefusalsView rows={rows} offers={offers} busyId={1} onAllow={() => {}} />);
  assert.match(html, /saving\.\.\./);
  assert.match(html, /disabled/);
});

test("the scope note never claims the allow is per project", () => {
  const note = allowScopeNote("every sandboxed run on this computer that starts after the save");
  assert.match(note, /every sandboxed run on this computer/);
  assert.match(note, /not limited to the run&#x27;s project|not limited to the run's project/);
  assert.doesNotMatch(note, /for this project/);
});

// Lane O4 (OC's dropped and uncertain counts, ledger OSH-34): a run with
// either count above zero reads as incomplete, never complete.
test("a run with a dropped or uncertain count reads as incomplete; one absent from both reads as nothing", () => {
  assert.deepEqual(incompleteRuns(null), []);
  assert.deepEqual(incompleteRuns({}), []);
  assert.deepEqual(incompleteRuns({ dropped: { a: 0 }, uncertain: { a: 0 } }), []);
  assert.deepEqual(incompleteRuns({ dropped: { b: 3, a: 1 }, uncertain: { b: 2, c: 5 } }), [
    { runId: "a", dropped: 1, uncertain: 0, linkLost: 0, egressClosed: 0, evicted: 0 },
    { runId: "b", dropped: 3, uncertain: 2, linkLost: 0, egressClosed: 0, evicted: 0 },
    { runId: "c", dropped: 0, uncertain: 5, linkLost: 0, egressClosed: 0, evicted: 0 },
  ]);
});

test("the incomplete notice shows each run's counts with the drafted wording", () => {
  const runs = incompleteRuns({ dropped: { run00000000000000aa: 3 }, uncertain: { run00000000000000aa: 1, run00000000000000bb: 4 } });
  const html = renderToStaticMarkup(<IncompleteRunsNotice runs={runs} />);
  assert.match(html, /data-incomplete-runs="2"/);
  assert.match(html, /incomplete/);
  assert.ok(html.includes("3 refused connections of this run were not recorded (a bound was reached); the rows below are incomplete."));
  assert.ok(html.includes("Up to 1 more refused connection may belong to this run"));
  assert.ok(html.includes("Up to 4 more refused connections may belong to this run"));
  assert.equal(droppedLine(1), "1 refused connection of this run was not recorded (a bound was reached); the rows below are incomplete.");
  assert.match(uncertainLine(2), /^Up to 2 more refused connections may belong to this run/);
  assert.equal(renderToStaticMarkup(<IncompleteRunsNotice runs={[]} />), "");
});

// Tracker F-013 (audit finding N5-A6): the cell branches on the server's
// explain flag, never on the rule name: a not-offered answer with explain
// shows its message whatever the rule, and one without shows nothing.
test("the offer cell follows the server's explain flag, not the rule name", () => {
  const rows = [row(1, "allow-list-miss", "a.example.com"), row(2, "port-not-allowed", "b.example.com")];
  const offers = new Map([
    [1, offer(1, "a.example.com", false, "not_the_host_list", "Refused by another host list than yours.", false)],
    [2, offer(2, "b.example.com", false, "already_allowed", "The current settings already let this host through.", true)],
  ]);
  const html = renderToStaticMarkup(<SandboxRefusalsView rows={rows} offers={offers} onAllow={() => {}} />);
  assert.doesNotMatch(html, /another host list than yours/);
  assert.match(html, /already let this host through/);
});

// Tracker F-012 (audit finding N4-A4): a run whose link to Observer was
// lost shows the lost part of its dropped count and its closed requests.
test("a run whose link was lost shows why", () => {
  const runs = incompleteRuns({ dropped: { aa: 3 }, link_lost: { aa: 2 }, egress_closed: { bb: 5 } });
  assert.deepEqual(runs, [
    { runId: "aa", dropped: 3, uncertain: 0, linkLost: 2, egressClosed: 0, evicted: 0 },
    { runId: "bb", dropped: 0, uncertain: 0, linkLost: 0, egressClosed: 5, evicted: 0 },
  ]);
  const html = renderToStaticMarkup(<IncompleteRunsNotice runs={runs} />).replace(/&#x27;/g, "'");
  assert.ok(html.includes(linkLostLine(2)));
  assert.ok(html.includes(egressClosedLine(5)));
  assert.match(html, /link lost/);
  assert.equal(linkLostLine(1), "1 of them could not be sent to Observer (link down or busy).");
  assert.match(egressClosedLine(1), /^1 request was refused because/);
});

// Tracker F-009 (audit finding N1-A4): a run past its row limit reads as
// incomplete and says its oldest rows were removed.
test("a run past its row limit says its oldest rows were removed", () => {
  const runs = incompleteRuns({ evicted: { cc: 12 } });
  assert.deepEqual(runs, [{ runId: "cc", dropped: 0, uncertain: 0, linkLost: 0, egressClosed: 0, evicted: 12 }]);
  const html = renderToStaticMarkup(<IncompleteRunsNotice runs={runs} />);
  assert.ok(html.includes(evictedLine(12)));
  assert.match(html, />incomplete</);
  assert.equal(evictedLine(1), "The 1 oldest refused connection of this run was removed to keep the run under its row limit; the rows below are the newest.");
});
