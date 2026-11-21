// Component tests of the Scanners card's Go source check row (OS and CI
// vulnerability scanning plan section 14.5 item 3b, 3b-src), rendered with
// react-dom/server under node's test runner (scripts/test-components.mjs).
// The check is off per project until the developer opts in; Run is offered
// only for an opted-in project whose run can be held (isolated, or the
// developer allowed it to run without isolation).

import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { ProjectPicker, ReachSourceView } from "@/components/security/ReachSourceRow";
import { reachSourceCanRun, reachSourceCapsLine, reachSourceRunLine, type ReachSourceStatus } from "@/lib/reachSource";

function status(over: Partial<ReachSourceStatus> = {}): ReachSourceStatus {
  return {
    project: "/p", compiled: true, selected: true, opted_in: false, allow_unisolated: false, isolation_available: true,
    text: "The Go source check runs the project's Go toolchain.", memory_mib: 12288, timeout_seconds: 1200, max_modules: 16,
    running: false, runs: [], ...over,
  };
}

const render = (v: ReachSourceStatus) => renderToStaticMarkup(<ReachSourceView view={v} busy={false} onOptIn={() => {}} onRun={() => {}} />);
const runButtonDisabled = (html: string) => /<button[^>]*disabled=""[^>]*data-testid="scanner-reach-source-run"|<button[^>]*data-testid="scanner-reach-source-run"[^>]*disabled=""/.test(html);

test("off until the developer opts in, and Run is not offered", () => {
  const v = status();
  const html = render(v);
  assert.match(html, /Off for this project/);
  assert.match(html, /The Go source check runs the project&#x27;s Go toolchain\./);
  assert.ok(runButtonDisabled(html));
  assert.equal(reachSourceCanRun(v), false);
});

test("opted in and isolated: Run is offered", () => {
  const v = status({ opted_in: true });
  assert.equal(reachSourceCanRun(v), true);
  const html = render(v);
  assert.match(html, /no-network run/);
  assert.ok(!runButtonDisabled(html));
});

test("no isolation: refused unless the developer allowed it", () => {
  assert.equal(reachSourceCanRun(status({ opted_in: true, isolation_available: false })), false);
  assert.match(render(status({ opted_in: true, isolation_available: false })), /a run is refused unless you allow it/);
  assert.equal(reachSourceCanRun(status({ opted_in: true, isolation_available: false, allow_unisolated: true })), true);
  assert.equal(reachSourceCanRun(status({ opted_in: true, running: true })), false);
});

test("each go.mod's answer and the caps read in words", () => {
  const html = render(status({ opted_in: true, runs: [
    { target: "go.mod", called: 1, not_called: 3, assumed_go: "1.27.0" },
    { target: "tools/go.mod", reason: "out_of_memory", reason_text: "ran out of memory: not checked", called: 0, not_called: 0 },
  ] }));
  assert.equal((html.match(/data-testid="scanner-reach-source-gomod"/g) ?? []).length, 2);
  assert.match(html, /1 package with a listed function called, 3 with none called; standard library evaluated at go1\.27\.0 from the go\.mod/);
  assert.match(html, /not checked: ran out of memory: not checked/);
  assert.equal(reachSourceRunLine({ target: "x", called: 2, not_called: 0 }), "2 packages with a listed function called, 0 with none called");
  assert.match(reachSourceCapsLine(status()), /12 GiB per go\.mod \(GOMEMLIMIT at 90 %\), 1200 s per go\.mod, at most 16 go\.mod files/);
});

test("not compiled or not selected: no switch, and the heading says why", () => {
  assert.match(render(status({ compiled: false })), /not in this build/);
  assert.match(render(status({ selected: false })), /Turn on the Go source check with the scanner switches above/);
});

test("the project field is one searchable picker listing active projects before idle ones", () => {
  const projects = [
    { project_root_hash: "i1", label: "old-tool", active: false },
    { project_root_hash: "a1", label: "live-app", active: true },
  ];
  const html = renderToStaticMarkup(<ProjectPicker projects={projects} value="a1" onChange={() => {}} testId="pp" />);
  assert.match(html, /data-testid="pp"/);
  assert.match(html, /live-app/);
  // A native select is gone.
  assert.ok(!/<select/.test(html));
});
