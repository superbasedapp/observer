// Component tests of the Scanners tab's passive DAST card (component
// security.dast; security coverage gaps plan section 2), rendered with
// react-dom/server under node's test runner (scripts/test-components.mjs):
// the accept text before the accept, the candidates with their listen
// state, Run disabled until accepted, the result line and its Findings link.

import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router-dom";
import { DastCardView, dastErrorText, dastResultLine, type DastRunResult, type DastState } from "@/pages/codesecurity/DastCard";

const projects = [{ project_root_hash: "abcdef0123456789", label: "my-app" }];
const candidates = [
  { url: "http://localhost:5173/", name: "npm run dev (vite)", source: "package.json", listening: "yes" },
  { url: "http://localhost:3000/", name: "", source: "launch.json", listening: "no" },
  { url: "http://localhost:8000/", name: "manage.py runserver", source: "manage.py", listening: "" },
];
const notAccepted: DastState = { selected: true, accepted: false, accept_text: "Observer's local DAST checker sends a few plain GET requests" };
const accepted: DastState = { selected: true, accepted: true, accepted_at: "2026-11-13T10:00:00Z", accepted_on: "dashboard", accept_text: "x" };

function render(state: DastState, extra: { result?: DastRunResult | null; error?: string | null; lastRuns?: { origin: string; at: string; outcome: string; findings: number }[] } = {}) {
  return renderToStaticMarkup(
    <MemoryRouter>
      <DastCardView
        state={state}
        projects={projects}
        project="abcdef0123456789"
        onProject={() => {}}
        candidates={candidates}
        lastRuns={extra.lastRuns ?? []}
        busy={false}
        result={extra.result ?? null}
        error={extra.error ?? null}
        onAccept={() => {}}
        onRun={() => {}}
      />
    </MemoryRouter>,
  );
}

test("before the accept: the accept text and button, Run disabled", () => {
  const html = render(notAccepted);
  assert.match(html, /data-testid="dast-accept"/);
  assert.match(html, /sends a few plain GET requests/);
  assert.match(html, /I have read this, accept/);
  assert.match(html, /<button[^>]*disabled[^>]*>Run</);
});

test("the candidates show their listen state; an unknown state shows no pill", () => {
  const html = render(accepted);
  assert.doesNotMatch(html, /data-testid="dast-accept"/);
  assert.match(html, /http:\/\/localhost:5173\//);
  assert.match(html, />listening</);
  assert.match(html, />not listening</);
  assert.equal((html.match(/listening</g) ?? []).length, 2);
  assert.match(html, /my-app/);
});

test("a run with findings links to the Findings tab filtered to the DAST driver and project", () => {
  const html = render(accepted, { result: { target: "http://localhost:5173/", outcome: "complete", requests: 7, checks: 17, findings: 3, new: 2 } });
  assert.match(html, /data-testid="dast-result"/);
  assert.match(html, /3 findings \(2 new\), 7 requests, 17 checks/);
  assert.match(html, /href="\/code-security\?tab=findings[^"]*scanner=observer-dast/);
  assert.match(html, /project=abcdef0123456789/);
});

test("the last runs per origin are listed", () => {
  const html = render(accepted, { lastRuns: [{ origin: "http://localhost:5173", at: "2026-11-13T10:00:00Z", outcome: "complete", findings: 1 }] });
  assert.match(html, /data-testid="dast-last-runs"/);
  assert.match(html, /complete, 1 finding</);
});

test("an error reads as plain text", () => {
  const html = render(accepted, { error: "<b>busy</b>" });
  assert.match(html, /text-danger">&lt;b&gt;busy&lt;\/b&gt;/);
});

test("dastResultLine: unreachable never reads as clean; partial says nothing was closed", () => {
  assert.equal(
    dastResultLine({ target: "http://localhost:1/", outcome: "unreachable", requests: 1, checks: 0, findings: 0, new: 0, reason: "connection refused" }),
    "The dev server at http://localhost:1/ did not answer: connection refused. Nothing was checked.",
  );
  assert.match(dastResultLine({ target: "t", outcome: "complete", requests: 5, checks: 17, findings: 0, new: 0 }), /no finding/);
  assert.match(dastResultLine({ target: "t", outcome: "partial", requests: 5, checks: 9, findings: 1, new: 1 }), /1 finding \(1 new\).*nothing was closed/);
});

test("dastErrorText reads the route's JSON refusal", () => {
  assert.equal(dastErrorText(409, `{"error":"not_accepted","detail":"the DAST checker is not accepted yet"}`), "the DAST checker is not accepted yet");
  assert.equal(dastErrorText(404, `{"error":"no_inventory"}`), "no_inventory");
  assert.equal(dastErrorText(500, "boom\n"), "boom");
  assert.equal(dastErrorText(502, ""), "HTTP 502");
});
