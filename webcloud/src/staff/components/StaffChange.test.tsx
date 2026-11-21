// Render tests of the staff console's write confirmation and tables (lane
// w17/staff-console): every write asks for a reason, a tick and, when the
// passkey check is stale, says it will ask for the passkey first.

import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router-dom";
import { ChangeForm, type ChangeFormProps } from "./ChangeDialog";
import { LogTable } from "./LogTable";
import { OrgTable } from "../pages/Orgs";
import { InputTable, sortInputs } from "../pages/Availability";
import { rowsOf } from "../pages/Optional";
import type { AvailabilityInput, StaffOrg } from "../api";

const noop = () => {};
function form(extra: Partial<ChangeFormProps> = {}) {
  return renderToStaticMarkup(
    <ChangeForm
      summary="Pause ingest for Acme"
      before={{ org: "x" }}
      after={{ org: "x", ingest: { mode: "pause" } }}
      blocking={[]}
      reason="ticket 9"
      onReason={noop}
      confirmed
      onConfirmed={noop}
      ready
      busy={false}
      error={null}
      confirmLabel="Apply"
      onSubmit={noop}
      onCancel={noop}
      {...extra}
    />,
  );
}
const submitDisabled = (html: string) => /<button[^>]*type="submit"[^>]*disabled/.test(html);

test("a complete change can be applied", () => {
  const html = form();
  assert.match(html, /Pause ingest for Acme/);
  assert.match(html, /Reason/);
  assert.match(html, /Now/);
  assert.match(html, /After/);
  assert.equal(submitDisabled(html), false);
  assert.match(html, />Apply</);
});

test("no reason, no tick or a blocking error keeps the submit off", () => {
  assert.ok(submitDisabled(form({ reason: "" })));
  assert.ok(submitDisabled(form({ confirmed: false })));
  const blocked = form({ blocking: ["Ingest is never platform-wide."] });
  assert.ok(submitDisabled(blocked));
  assert.match(blocked, /Ingest is never platform-wide/);
});

test("a stale passkey check says it will ask for the passkey first", () => {
  const html = form({ ready: false });
  assert.match(html, /Verify passkey and apply/);
  assert.match(html, /passkey check from the last 15 minutes/);
});

test("a refusal shows the server's reason", () => {
  assert.match(form({ error: "this staff action is refused: forbidden_role (forbidden_role)" }), /Not applied[\s\S]*forbidden_role/);
});

const ORG: StaffOrg = {
  org_id: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
  kind: "team",
  slug: "acme",
  display_name: "Acme",
  status: "active",
  tenancy: "managed",
  platform_rail_enabled: true,
  lifecycle_gen: 1,
  created_at: "2026-11-10T09:00:00Z",
  updated_at: "2026-11-10T09:00:00Z",
  members: 4,
  grant: { action: "grant", plan_name: "business", plan_version: 3 },
  usage: { day: "2026-11-15", seats: 3, members: 4 },
};

test("the org table names the plan's source and links each org", () => {
  const html = renderToStaticMarkup(
    <MemoryRouter>
      <OrgTable orgs={[ORG]} now={new Date("2026-11-16T12:00:00Z")} />
    </MemoryRouter>,
  );
  assert.match(html, /business v3/);
  assert.match(html, /operator grant/);
  assert.match(html, /href="\/orgs\/aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"/);
  assert.match(html, /none issued/);
  assert.match(html, /3 seats, 2026-11-15/);
});

const INPUTS: AvailabilityInput[] = [
  {
    section: "org_controls",
    key: ORG.org_id,
    value: { org: ORG.org_id, ingest: { mode: "pause" } },
    reason: "abuse",
    author: "staff:me",
    updated_at: "2026-11-16T10:00:00Z",
  },
  {
    section: "org_controls",
    key: "platform",
    value: { org: "*", inference: [{ admission: "off", dispatch: "off" }] },
    reason: "incident",
    author: "operator",
    updated_at: "2026-11-16T09:00:00Z",
  },
];

test("org controls list the platform row first, by org name, read-only for support", () => {
  const sorted = sortInputs(INPUTS);
  assert.equal(sorted[0].key, "platform");
  const props = {
    section: "org_controls" as const,
    rows: sorted,
    issuedAt: "2026-11-16T09:30:00Z",
    names: new Map([[ORG.org_id, "Acme"]]),
    self: "me",
    onAdd: noop,
    onEdit: noop,
    onRemove: noop,
  };
  const ro = renderToStaticMarkup(<InputTable {...props} canWrite={false} />);
  assert.match(ro, /Every org \(platform-wide\)[\s\S]*Acme/);
  assert.match(ro, /Ingest paused/);
  assert.match(ro, /admission off, dispatch off/);
  assert.match(ro, /newer than the envelope/);
  assert.match(ro, /older than the envelope/);
  assert.match(ro, /you/);
  assert.doesNotMatch(ro, />Edit</);
  const rw = renderToStaticMarkup(<InputTable {...props} canWrite />);
  assert.match(rw, />Edit</);
  assert.match(rw, />Remove</);
});

test("the log shows labels, the actor and the result", () => {
  const html = renderToStaticMarkup(
    <LogTable
      self="11111111"
      actions={[
        {
          action_id: "1",
          at: "2026-11-16T10:00:00Z",
          actor: "staff:11111111",
          verb: "support.signin",
          org_id: ORG.org_id,
          target: "acme",
          reason: "ticket 4",
          result: "ok",
        },
        {
          action_id: "2",
          at: "2026-11-16T09:00:00Z",
          actor: "operator",
          verb: "action.refused",
          target: "support.signin",
          reason: "reauth_required",
          result: "refused",
        },
      ]}
    />,
  );
  assert.match(html, /Support sign-in/);
  assert.match(html, /Action refused/);
  assert.match(html, />you</);
  assert.match(html, /aaaaaaaa/);
  assert.match(html, /refused/);
});

test("an optional screen reads its first list of rows generically", () => {
  assert.deepEqual(
    rowsOf({
      entries: [
        { key: "a", note: 1 },
        { key: "b", by: "x" },
      ],
    })?.columns,
    ["key", "note", "by"],
  );
  assert.equal(rowsOf({ count: 3 }), null);
  assert.deepEqual(rowsOf([])?.rows, []);
});
