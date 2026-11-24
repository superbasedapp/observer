// Render tests of the team allow-list page's table and add form (staff
// console e2e finding SC-7): support reads, ops and admin get a Remove
// action per active row, removed rows show who removed them and why, and
// the add form shows the stored spelling and refuses what the server would.

import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { ChangeForm } from "./ChangeDialog";
import { AllowlistFields } from "./AllowlistDialogs";
import { AllowlistTable } from "../pages/TeamAllowlist";
import { addBlocking, type AllowlistEntry } from "../lib/allowlist";

const noop = () => {};
const ENTRIES: AllowlistEntry[] = [
  {
    entry_id: "e-2",
    kind: "account",
    value: "dddddddd-eeee-4fff-8000-111111111111",
    added_by: "staff:me",
    added_reason: "ticket 131",
    added_at: "2026-11-15T14:20:00Z",
  },
  { entry_id: "e-1", kind: "email_domain", value: "superbased.app", added_by: "operator", added_reason: "internal team", added_at: "2026-11-12T10:00:00Z" },
  {
    entry_id: "e-3",
    kind: "email_domain",
    value: "acme.dev",
    added_by: "operator",
    added_reason: "trial",
    added_at: "2026-11-10T09:00:00Z",
    removed_at: "2026-11-14T09:00:00Z",
    removed_by: "staff:33333333-4444",
    removed_reason: "trial ended",
  },
];

const table = (extra: Partial<Parameters<typeof AllowlistTable>[0]> = {}) =>
  renderToStaticMarkup(<AllowlistTable entries={ENTRIES.slice(0, 2)} showRemoved={false} canWrite self="me" onRemove={noop} {...extra} />);

test("the table names each entry's kind, value, who added it and why", () => {
  const h = table();
  assert.match(h, /Account[\s\S]*dddddddd-eeee-4fff-8000-111111111111[\s\S]*you[\s\S]*2026-11-15 14:20 UTC[\s\S]*ticket 131/);
  assert.match(h, /Email domain[\s\S]*superbased.app[\s\S]*operator[\s\S]*internal team/);
  assert.equal((h.match(/aria-label="Actions for /g) ?? []).length, 2, "one action menu per active row");
  assert.doesNotMatch(h, />Removed</);
});

test("support reads the table without actions", () => {
  assert.doesNotMatch(table({ canWrite: false }), /Actions for/);
});

test("removed entries show who removed them and why, with no action", () => {
  const h = table({ entries: ENTRIES, showRemoved: true });
  assert.match(h, />Removed</);
  assert.match(h, /acme.dev[\s\S]*removed[\s\S]*staff 33333333, 2026-11-14 09:00 UTC[\s\S]*trial ended/);
  assert.equal((h.match(/aria-label="Actions for /g) ?? []).length, 2, "no action on the removed row");
});

test("the add form shows the stored spelling and the server's refusals", () => {
  const fields = renderToStaticMarkup(<AllowlistFields kind="email_domain" value="@Acme.COM" onKind={noop} onValue={noop} />);
  assert.match(fields, /Stored as acme.com/);
  assert.match(fields, /Subdomains are not included/);
  assert.match(renderToStaticMarkup(<AllowlistFields kind="account" value="" onKind={noop} onValue={noop} />), /account reference a refused person reads/);
  const form = (value: string) =>
    renderToStaticMarkup(
      <ChangeForm
        summary={<AllowlistFields kind="email_domain" value={value} onKind={noop} onValue={noop} />}
        after={{ kind: "email_domain", value }}
        blocking={addBlocking(ENTRIES, "email_domain", value)}
        reason="design partner"
        onReason={noop}
        confirmed
        onConfirmed={noop}
        ready
        busy={false}
        error={null}
        confirmLabel="Add"
        onSubmit={noop}
        onCancel={noop}
      />,
    );
  const submitDisabled = (h: string) => /<button[^>]*type="submit"[^>]*disabled/.test(h);
  assert.equal(submitDisabled(form("acme.org")), false);
  const address = form("ana@acme.org");
  assert.ok(submitDisabled(address));
  assert.match(address, /not an address: use acme.org/);
  const dup = form("superbased.app");
  assert.ok(submitDisabled(dup));
  assert.match(dup, /already on the allow-list/);
});
