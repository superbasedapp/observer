// Render tests of the "Create a team" form (plan 07 M6.5): what it shows for
// each slug answer, and that it never offers a host the server did not give.

import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { CreateTeamForm, teamPriceLine } from "./CreateTeamForm";
import { CREATE_ERROR_TEXT, createFormView, teamCapView, type AvailabilityState } from "../../lib/orgsModel";

function render(name: string, slug: string, availability: AvailabilityState, extra: { submitting?: boolean; error?: string | null } = {}) {
  const view = createFormView({ name, slug, availability, submitting: extra.submitting ?? false });
  const noop = () => {};
  return renderToStaticMarkup(
    <CreateTeamForm
      name={name}
      slugInput={slug}
      view={view}
      submitting={extra.submitting ?? false}
      error={extra.error ?? null}
      onName={noop}
      onSlug={noop}
      onSubmit={noop}
    />,
  );
}

const submitDisabled = (html: string) => /<button[^>]*type="submit"[^>]*disabled/.test(html);

test("an available slug shows the server's host and enables Create team", () => {
  const html = render("Acme", "acme", { kind: "answered", answer: { slug: "acme", available: true, host: "acme.superbased.app" } });
  assert.match(html, /Available/);
  assert.match(html, /https:\/\/acme\.superbased\.app/);
  assert.equal(submitDisabled(html), false);
});

test("a taken slug says so, shows no host and disables the submit", () => {
  const html = render("Acme", "acme", { kind: "answered", answer: { slug: "acme", available: false, reason: "taken", host: "acme.superbased.app" } });
  assert.match(html, /That address is taken/);
  assert.doesNotMatch(html, /dashboard will be at/);
  assert.ok(submitDisabled(html));
});

test("a reserved slug and a badly shaped one are refused", () => {
  assert.match(render("A", "admin", { kind: "answered", answer: { slug: "admin", available: false, reason: "reserved" } }), /reserved/);
  const bad = render("A", "u-team", { kind: "idle" });
  assert.match(bad, /cannot start with u-/);
  assert.ok(submitDisabled(bad));
});

test("while checking, the status line says so", () => {
  const html = render("A", "acme", { kind: "checking", slug: "acme" });
  assert.match(html, /Checking the address/);
  assert.ok(submitDisabled(html));
});

test("a create refusal is shown as an alert, and submitting says it is creating", () => {
  const html = render("Acme", "acme", { kind: "answered", answer: { slug: "acme", available: true, host: "acme.superbased.app" } }, {
    submitting: true,
    error: "That address was just taken. Choose another.",
  });
  assert.match(html, /role="alert"/);
  assert.match(html, /just taken/);
  assert.match(html, /Creating the team/);
});

// Wave 15 (C2.front-door-2, W15-D12): the form says a team is managed and
// captures full content before the create, and it honours the team cap.

function renderCap(cap: Parameters<typeof CreateTeamForm>[0]["cap"]) {
  const view = createFormView({
    name: "Acme",
    slug: "acme",
    availability: { kind: "answered", answer: { slug: "acme", available: true, host: "acme.superbased.app" } },
    submitting: false,
  });
  const noop = () => {};
  return renderToStaticMarkup(
    <CreateTeamForm name="Acme" slugInput="acme" view={view} submitting={false} error={null} onName={noop} onSlug={noop} onSubmit={noop} cap={cap} />,
  );
}

test("the form says a team gets full detail, and shows the price", () => {
  const html = render("Acme", "acme", { kind: "answered", answer: { slug: "acme", available: true, host: "acme.superbased.app" } });
  assert.match(html, /Full detail/);
  assert.match(html, /prompts, responses and file paths/);
  assert.match(html, /see the price on the team&#x27;s page|see the price on the team's page/);
  assert.match(html, /role="note"/);
});

test("under the cap the form says how many more, and Create team stays on", () => {
  const html = renderCap(teamCapView({ used: 1, limit: 3, remaining: 2 }));
  assert.match(html, /2 more teams/);
  assert.equal(submitDisabled(html), false);
});

test("at the cap the form says it can be raised on request and turns Create team off", () => {
  const html = renderCap(teamCapView({ used: 3, limit: 3, remaining: 0 }));
  assert.match(html, /the most one account can create \(3\)/);
  assert.match(html, /raise this on request/);
  assert.ok(submitDisabled(html));
});

test("the cap's 409 is worded with the raise on request", () => {
  const html = render("Acme", "acme", { kind: "answered", answer: { slug: "acme", available: true, host: "acme.superbased.app" } }, {
    error: CREATE_ERROR_TEXT.team_org_limit,
  });
  assert.match(html, /role="alert"/);
  assert.match(html, /We can raise this on request/);
});

test("the team price line names the price and its interval", () => {
  assert.equal(teamPriceLine({ display: "$12/seat", interval: "month" }), "Price: $12/seat, billed every month.");
  assert.equal(teamPriceLine({ display: "$12/seat", interval: "" }), "Price: $12/seat.");
  assert.match(teamPriceLine(undefined), /before you subscribe/);
});
