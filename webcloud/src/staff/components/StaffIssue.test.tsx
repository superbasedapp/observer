// Render tests of the issue card, the issue dialog's body and the per-org
// component card (lane fix/sr-17-staff-control): ops and admin get "Review
// and issue", disabled with a reason when there is nothing to issue, a
// request is pending or inputs have problems; support reads the card only;
// a component is off for an org until staff turn it on, and the switch says
// the host changes only once the envelope is issued.

import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router-dom";
import type { ReactElement } from "react";
import { ChangeForm } from "./ChangeDialog";
import { IssueCardView, type IssueCardViewProps } from "./IssueCard";
import { IssueSummary } from "./IssueDialog";
import { OrgComponentCard, type OrgComponentCardProps } from "./OrgComponents";
import { issueBlocking, normalizePreview, type AvailabilityPreview } from "../lib/issue";

const ORG = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
const NOW = new Date("2026-11-23T10:00:30Z");
const noop = () => {};
const html = (el: ReactElement) => renderToStaticMarkup(<MemoryRouter>{el}</MemoryRouter>);

function preview(extra: Partial<AvailabilityPreview> = {}): AvailabilityPreview {
  return normalizePreview({
    base_version: 12,
    inputs_digest: "d".repeat(64),
    body: { issued_at: "2026-11-23T10:00:00Z", components: [{ component: "org.security", reach: "named", orgs: [ORG] }] },
    changes: [
      { section: "components", key: "org.security", kind: "added", before: null, after: { component: "org.security", reach: "named", orgs: [ORG], reason: "pilot" } },
      { section: "org_controls", key: "*", kind: "changed", before: { org: "*", inference: [{ admission: "on", dispatch: "on" }] }, after: { org: "*", inference: [{ admission: "paused", dispatch: "on" }] } },
    ],
    deliveries: [
      { host_id: "app-0", version: 12, state: "delivered", attempts: 1, updated_at: "2026-11-23T09:00:00Z" },
      { host_id: "app-1", version: 12, state: "retry", attempts: 3, error_class: "transport:dial", updated_at: "2026-11-23T10:00:00Z" },
      { host_id: "app-2", version: 12, state: "refused", attempts: 1, error_class: "refused:invalid", updated_at: "2026-11-23T10:00:00Z" },
    ],
    ...extra,
  });
}

function card(extra: Partial<IssueCardViewProps> = {}) {
  return html(<IssueCardView preview={preview()} error={null} mayIssue onReview={noop} self="me" now={NOW} {...extra} />);
}

const reviewButton = (h: string) => h.match(/<button[^>]*>(?:(?!<\/button>).)*Review and issue<\/button>/s)?.[0] ?? null;
const buttonDisabled = (b: string | null) => !!b && /\sdisabled=""/.test(b);

test("ops and admin can review and issue the changes", () => {
  const h = card();
  assert.match(h, /2 changes are not issued yet/);
  const b = reviewButton(h);
  assert.ok(b, "the button is shown");
  assert.equal(buttonDisabled(b), false);
  assert.match(h, /Delivery to hosts/);
  assert.match(h, /holds v12[\s\S]*current/);
  assert.match(h, /sending v12[\s\S]*retrying[\s\S]*could not connect to the host \(transport:dial\), attempt 3/);
  assert.match(h, /refused v12[\s\S]*the host found the envelope invalid/);
  assert.match(h, /A host that is not listed has never been reached/);
});

test("support reads the card without the button", () => {
  const h = card({ mayIssue: false });
  assert.equal(reviewButton(h), null);
  assert.match(h, /ops and admin issue the envelope/);
  assert.match(h, /2 changes are not issued yet/);
});

test("a pending request disables the button, says why and who asked", () => {
  const h = card({
    preview: preview({
      pending: { request_id: "r", requested_by: "staff:me", reason: "hold the route", requested_at: "2026-11-23T10:00:20Z", base_version: 12, state: "pending" },
      last_request: { request_id: "q", requested_by: "operator", reason: "drill", requested_at: "2026-11-23T09:00:00Z", base_version: 11, state: "issued", result_version: 12, done_at: "2026-11-23T09:00:02Z" },
    }),
  });
  assert.ok(buttonDisabled(reviewButton(h)));
  assert.match(h, /An issue is already waiting for the worker/);
  assert.match(h, /Issue request[\s\S]*Waiting for the worker to sign and store the envelope/);
  assert.match(h, /Requested by you 10s ago/);
  assert.match(h, /Reason: hold the route/);
  assert.match(h, /Last request[\s\S]*Issued v12\./);
});

const withdrawButton = (h: string) => h.match(/<button[^>]*>(?:(?!<\/button>).)*Withdraw request<\/button>/s)?.[0] ?? null;

test("ops and admin can withdraw a pending request; support cannot; a finished one has no button", () => {
  const pending = { request_id: "r", requested_by: "staff:other", reason: "hold", requested_at: "2026-11-23T10:00:00Z", base_version: 12, state: "pending" };
  const withCancel = { onCancelPending: noop };
  assert.ok(withdrawButton(card({ ...withCancel, preview: preview({ pending }) })), "ops sees the withdraw button");
  assert.equal(withdrawButton(card({ ...withCancel, mayIssue: false, preview: preview({ pending }) })), null, "support does not");
  assert.equal(withdrawButton(card({ ...withCancel })), null, "no pending request, no button");
  const h = card({
    ...withCancel,
    preview: preview({
      last_request: { request_id: "q", requested_by: "staff:me", reason: "worker off", requested_at: "2026-11-23T09:00:00Z", base_version: 12, state: "failed", error_class: "cancelled", done_at: "2026-11-23T09:05:00Z" },
    }),
  });
  assert.equal(withdrawButton(h), null, "a finished request has no button");
  assert.match(h, /Last request[\s\S]*cancelled[\s\S]*Cancelled by staff before the worker issued it/);
});

test("the withdraw dialog asks for a reason and the check like every change", () => {
  const h = html(
    <ChangeForm
      summary={<span>Withdraw the request</span>}
      blocking={[]}
      reason=""
      onReason={noop}
      confirmed={false}
      onConfirmed={noop}
      ready
      busy={false}
      error={null}
      destructive
      confirmLabel="Withdraw request"
      onSubmit={noop}
      onCancel={noop}
    />,
  );
  const submit = h.match(/<button[^>]*type="submit"[^>]*>(?:(?!<\/button>).)*Withdraw request<\/button>/s)?.[0] ?? null;
  assert.ok(submit, "the submit button carries the label");
  assert.ok(buttonDisabled(submit), "disabled until a reason and the check");
  assert.match(h, /name="reason"/);
});

test("problems block the issue in a danger callout", () => {
  const h = card({ preview: preview({ body: null, problems: ["components/org.security: reach: unknown value"] }), problemsLink: true });
  assert.ok(buttonDisabled(reviewButton(h)));
  assert.match(h, /Issue is blocked until these inputs are fixed or removed/);
  assert.match(h, /components\/org.security: reach: unknown value/);
  assert.match(h, /href="\/availability"/);
});

test("nothing to issue: everything is issued and the button says so", () => {
  const h = card({ preview: preview({ changes: [] }) });
  assert.match(h, /Everything is issued/);
  assert.ok(buttonDisabled(reviewButton(h)));
  assert.match(h, /Nothing to issue/);
});

test("on Org detail, delivery narrows to the org's host", () => {
  const h = card({ orgId: ORG, hostId: "app-1" });
  assert.match(h, /1 naming this org/);
  assert.match(h, /Delivery to this org&#x27;s host \(app-1\)/);
  assert.doesNotMatch(h, />app-0</);
  assert.match(html(<IssueCardView preview={preview()} error={null} mayIssue onReview={noop} now={NOW} orgId={ORG} hostId={null} />), /not placed on a host yet/);
});

test("the issue dialog shows the difference and checks like every change", () => {
  const p = preview();
  const summary = html(<IssueSummary preview={p} names={new Map([[ORG, "Acme"]])} />);
  assert.match(summary, /It replaces v12/);
  assert.match(summary, /Components[\s\S]*org.security[\s\S]*added[\s\S]*not in the envelope[\s\S]*Only 1 named org[\s\S]*Orgs: Acme[\s\S]*Reason: pilot/);
  assert.match(summary, /Every org \(platform-wide\)[\s\S]*changed[\s\S]*admission on[\s\S]*admission paused/);
  assert.match(summary, /Show the full next envelope/);
  const form = (blocking: string[]) =>
    html(
      <ChangeForm
        summary={<IssueSummary preview={p} />}
        blocking={blocking}
        reason="pilot for Acme"
        onReason={noop}
        confirmed
        onConfirmed={noop}
        ready
        busy={false}
        error={null}
        confirmLabel="Issue envelope"
        onSubmit={noop}
        onCancel={noop}
      />,
    );
  const ok = form(issueBlocking(p));
  assert.match(ok, />Issue envelope</);
  assert.doesNotMatch(ok, /<button[^>]*type="submit"[^>]*disabled/);
  const blocked = form(issueBlocking(preview({ problems: ["components/x: reach: unknown value"] })));
  assert.match(blocked, /<button[^>]*type="submit"[^>]*disabled/);
  assert.match(blocked, /Fix or remove the inputs with problems first/);
});

function componentCard(extra: Partial<OrgComponentCardProps> = {}) {
  return html(
    <OrgComponentCard
      row={{
        component: "org.security",
        title: "Code security (org)",
        issued: false,
        next: false,
        input: null,
        toggle: { on: true, value: { reach: "named", orgs: [ORG] }, error: "" },
      }}
      baseVersion={12}
      canWrite
      issueHere
      onToggle={noop}
      {...extra}
    />,
  );
}

test("Code security is off for an org by default, one button turns it on", () => {
  const h = componentCard();
  assert.match(h, /Code security \(org\)/);
  assert.match(h, /Off for this org/);
  assert.match(h, /Issued envelope \(v12\)[\s\S]*not offered/);
  assert.match(h, /Next envelope \(inputs\)[\s\S]*not offered/);
  assert.match(h, />Turn on for this org</);
  assert.doesNotMatch(h, /not issued yet/);
  assert.doesNotMatch(componentCard({ canWrite: false }), /Turn on for this org/);
});

test("a switch not issued yet says so and points at Review and issue", () => {
  const h = componentCard({
    row: {
      component: "org.security",
      title: "Code security (org)",
      issued: false,
      next: true,
      input: { reach: "named", orgs: [ORG] },
      toggle: { on: false, value: null, error: "" },
    },
  });
  assert.match(h, /not issued yet/);
  assert.match(h, />Turn off for this org</);
  assert.match(h, /Only 1 named org/);
  assert.match(h, /host changes only after the envelope is issued[\s\S]*Review and issue/);
  assert.match(componentCard({ issueHere: false, row: { component: "c", title: "C", issued: false, next: true, input: null, toggle: { on: false, value: null, error: "" } } }), /ops or admin issue it/);
});

test("a switch that cannot act is disabled with its reason and a link", () => {
  const h = componentCard({
    row: {
      component: "org.security",
      title: "Code security (org)",
      issued: false,
      next: false,
      input: { reach: "cohort", cohort: "ring-1" },
      toggle: { on: true, value: null, error: "This component reaches a cohort: edit it on Availability." },
    },
  });
  assert.match(h, /<button[^>]*disabled=""[^>]*>(?:(?!<\/button>).)*Turn on for this org/s);
  assert.match(h, /reaches a cohort[\s\S]*href="\/availability"/);
});
