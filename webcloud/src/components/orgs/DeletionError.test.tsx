// Render tests of the account deletion's refusal line (C2.front-door-5 A):
// a "pays for a live team" refusal links to the teams; an
// account_deletion_blocked refusal (plan 07 M6.9) renders its blockers with
// the way out per team; any other refusal is the server's message alone.

import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router-dom";
import { DeletionError } from "./DeletionError";
import { PAYS_FOR_LIVE_ORG } from "../../lib/orgsModel";
import { ACCOUNT_DELETION_BLOCKED } from "../../lib/deletionModel";

const msg =
  "Your account pays for the team Acme, so it cannot be deleted yet. Cancel that subscription from the team's billing page (or ask support to move the billing to another owner), then delete your account.";

test("a refusal because the account pays for a live team links to the teams", () => {
  const html = renderToStaticMarkup(
    <MemoryRouter>
      <DeletionError message={msg} code={PAYS_FOR_LIVE_ORG} />
    </MemoryRouter>,
  );
  assert.match(html, /role="alert"/);
  assert.match(html, /pays for the team Acme/);
  assert.match(html, /href="\/home"/);
  assert.match(html, /Open your teams/);
});

test("any other refusal shows the server's message with no link", () => {
  const html = renderToStaticMarkup(
    <MemoryRouter>
      <DeletionError message="re-enter your credential to confirm deletion" code="reauth_required" />
    </MemoryRouter>,
  );
  assert.match(html, /re-enter your credential/);
  assert.doesNotMatch(html, /href=/);
});

test("an account_deletion_blocked refusal renders its blockers with the way out", () => {
  const html = renderToStaticMarkup(
    <MemoryRouter>
      <DeletionError
        message="Your account cannot be deleted yet."
        code={ACCOUNT_DELETION_BLOCKED}
        blockers={[
          { code: "sole_owner_with_members", org_id: "org_acme", slug: "acme", display_name: "Acme" },
          { code: "pays_for_live_org", org_id: "org_beta", slug: "beta", display_name: "Beta" },
        ]}
      />
    </MemoryRouter>,
  );
  assert.match(html, /role="alert"/);
  assert.match(html, /cannot be deleted yet/);
  assert.match(html, /Make another member an owner first/);
  assert.match(html, /Transfer the billing to another owner, or delete the team/);
  assert.match(html, /href="\/orgs\/org_acme"/);
  assert.match(html, /href="\/orgs\/org_beta"/);
  assert.doesNotMatch(html, /Open your teams/);
});

test("an account_deletion_blocked refusal with no blockers in its body links to the teams", () => {
  const html = renderToStaticMarkup(
    <MemoryRouter>
      <DeletionError message="Your account cannot be deleted yet." code={ACCOUNT_DELETION_BLOCKED} />
    </MemoryRouter>,
  );
  assert.match(html, /href="\/home"/);
});
