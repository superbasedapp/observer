// Render tests of the account deletion precheck (plan 07 M6.9): each blocking
// team with why and the way out (a link to the team's page), the personal
// organization deleted with the account, and the team memberships removed,
// whose data stays with the team.

import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router-dom";
import type { ReactElement } from "react";
import { AccountDeletionPrecheckPanel } from "./AccountDeletionPrecheck";
import type { AccountDeletionPrecheck } from "../../api";

const html = (el: ReactElement) => renderToStaticMarkup(<MemoryRouter>{el}</MemoryRouter>);

const blocked: AccountDeletionPrecheck = {
  can_delete: false,
  blockers: [
    { code: "pays_for_live_org", org_id: "org_acme", slug: "acme", display_name: "Acme Engineering" },
    { code: "billing_owner", org_id: "org_beta", slug: "beta", display_name: "Beta Labs" },
    { code: "sole_owner_with_members", org_id: "org_gamma", slug: "gamma", display_name: "Gamma" },
    { code: "sole_owner_alone", org_id: "org_solo", slug: "solo", display_name: "" },
  ],
  personal_org: { org_id: "org_me", slug: "u-me", display_name: "Personal" },
  memberships_removed: [{ org_id: "org_delta", slug: "delta", display_name: "Delta Platform" }],
};

test("blockers render with the way out per code, each linking to its team", () => {
  const out = html(<AccountDeletionPrecheckPanel precheck={blocked} />);
  assert.match(out, /Your account cannot be deleted yet/);
  assert.match(out, /Acme Engineering<\/strong>: Your account pays for this team&#x27;s subscription\. Transfer the billing to another owner, or delete the team\./);
  assert.match(out, /Beta Labs<\/strong>: You are this team&#x27;s billing owner\. Transfer the billing/);
  assert.match(out, /Gamma<\/strong>: You are the only owner, and the team has other members\. Make another member an owner first\./);
  // A team with no display name falls back to its slug.
  assert.match(out, /solo<\/strong>: You are the team&#x27;s only member\. Delete the team first\./);
  for (const id of ["org_acme", "org_beta", "org_gamma", "org_solo"]) {
    assert.match(out, new RegExp(`href="/orgs/${id}"`), id);
  }
});

test("the personal org and the memberships removed are named", () => {
  const out = html(<AccountDeletionPrecheckPanel precheck={blocked} />);
  assert.match(out, /Deleted with your account: your personal dashboard <strong[^>]*>Personal<\/strong>/);
  assert.match(out, /You leave this team\. What your machines sent it stays with the team, which controls that data/);
  assert.match(out, /Delta Platform/);
});

test("a clear precheck shows no blocker", () => {
  const out = html(
    <AccountDeletionPrecheckPanel
      precheck={{ can_delete: true, blockers: [], personal_org: null, memberships_removed: [] }}
    />,
  );
  assert.doesNotMatch(out, /cannot be deleted yet/);
  assert.doesNotMatch(out, /href=/);
});
