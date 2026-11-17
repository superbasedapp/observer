// Render tests of the "Delete team" danger zone (plan 07 M6.9 /
// M7a.1): an owner sees what deletion does and the type-the-slug form, a
// member does not; the confirm button waits for the exact slug; the status
// panel words every state; Cancel deletion shows only for an owner while the
// server says it can still be canceled; the page slot renders last.

import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router-dom";
import type { ReactElement } from "react";
import { OrgDeletionCard, OrgDeletionForm, OrgDeletionStatusPanel } from "./OrgDeletionCard";
import { OrgDetailView } from "./OrgDetailView";
import type { OrgDeletionPreview, OrgDeletionStatus, OrgDeletionView, OrgDetail, PortalOrg } from "../../api";

const html = (el: ReactElement) => renderToStaticMarkup(<MemoryRouter>{el}</MemoryRouter>);
const noop = async () => {};

function org(over: Partial<PortalOrg> = {}): PortalOrg {
  return {
    org_id: "o1",
    slug: "acme",
    display_name: "Acme Engineering",
    kind: "team",
    status: "active",
    tenancy: "managed",
    console_role: "owner",
    is_billing_owner: true,
    created_at: "2026-11-01T00:00:00Z",
    host: "acme.superbased.app",
    ...over,
  };
}

function preview(over: Partial<OrgDeletionPreview> = {}): OrgDeletionPreview {
  return {
    can_request: true,
    refusal: "",
    cooling_off_days: 30,
    purge_after: "2026-12-16T00:00:00Z",
    live_subscription: true,
    members: 9,
    kept: ["usage_counts", "deletion_record"],
    ...over,
  };
}

function status(over: Partial<OrgDeletionStatus> = {}): OrgDeletionStatus {
  return {
    request_id: "odr_0123456789",
    state: "cooling_off",
    step: "cooling_off",
    origin: "owner",
    requested_at: "2026-11-13T00:00:00Z",
    purge_after: "2026-12-13T00:00:00Z",
    can_cancel: true,
    ...over,
  };
}

function view(over: Partial<OrgDeletionView> = {}): OrgDeletionView {
  return { deletion: null, preview: preview(), ...over };
}

// The confirm button: the one submit button in the form markup.
function confirmButton(out: string): string {
  const m = out.match(/<button[^>]*type="submit"[^>]*>/);
  assert.ok(m, "no submit button");
  return m[0];
}

test("an owner sees what deletion does and the type-the-slug form", () => {
  const out = html(<OrgDeletionCard org={org()} view={view()} onRequest={noop} onCancel={noop} />);
  assert.match(out, /Delete team/);
  assert.match(out, /30-day cooling-off/);
  assert.match(out, /Every member loses access to the team \(9 members\)/);
  assert.match(out, /host and in object storage is purged/);
  assert.match(out, /backups expire within 30 days/);
  assert.match(out, /subscription is canceled: this team has a live subscription/);
  assert.match(out, /kept for 10 years for billing records/);
  assert.match(out, /record that this team was deleted/);
  assert.match(out, /Type <span[^>]*>acme<\/span> to confirm/);
  assert.doesNotMatch(out, /crypto|erasure/i);
});

test("a member and an admin never see the delete control", () => {
  for (const role of ["member", "admin"] as const) {
    const out = html(
      <OrgDeletionCard
        org={org({ console_role: role })}
        view={view({ preview: preview({ can_request: false, refusal: "not_owner" }) })}
        onRequest={noop}
        onCancel={noop}
      />,
    );
    assert.equal(out, "", role);
  }
});

test("a member sees the status of a deletion in progress, without Cancel", () => {
  const out = html(
    <OrgDeletionCard
      org={org({ console_role: "member" })}
      view={view({ deletion: status(), preview: preview({ can_request: false, refusal: "not_owner" }) })}
      onRequest={noop}
      onCancel={noop}
    />,
  );
  assert.match(out, /Deletion scheduled/);
  assert.match(out, /Cooling off until/);
  assert.doesNotMatch(out, /Cancel deletion/);
  assert.doesNotMatch(out, /to confirm/);
});

test("an owner with a refusal reads it in words, with no form", () => {
  const out = html(
    <OrgDeletionCard
      org={org({ kind: "personal" })}
      view={view({ preview: preview({ can_request: false, refusal: "personal_org" }) })}
      onRequest={noop}
      onCancel={noop}
    />,
  );
  assert.match(out, /A personal dashboard is deleted with your account\. Delete your account from Privacy instead\./);
  assert.doesNotMatch(out, /to confirm/);
});

test("a live subscription this deployment cannot cancel is worded, with no form", () => {
  const out = html(
    <OrgDeletionCard
      org={org()}
      view={view({ preview: preview({ can_request: false, refusal: "billing_cancel_unavailable" }) })}
      onRequest={noop}
      onCancel={noop}
    />,
  );
  assert.match(out, /can&#x27;t be canceled automatically right now/);
  assert.match(out, /Cancel it from the team&#x27;s billing page first, then delete the team\./);
  assert.doesNotMatch(out, /to confirm/);
});

test("a dev sign-in re-enters the developer subject", () => {
  for (const [v, mode] of [
    [view({ preview: preview({ reauth: "broker_token" }) }), "workos"],
    [view(), "dev"],
  ] as const) {
    const out = html(<OrgDeletionCard org={org()} view={v} authMode={mode} onRequest={noop} onCancel={noop} />);
    assert.match(out, /Re-enter your developer subject to confirm/, mode);
  }
  const workos = html(
    <OrgDeletionCard org={org()} view={view({ preview: preview({ reauth: "step_up" }) })} authMode="workos" onRequest={noop} onCancel={noop} />,
  );
  assert.doesNotMatch(workos, /developer subject/);
  assert.match(workos, /sign in again to confirm/);
});

test("the dev form's button waits for both the slug and the subject", () => {
  const form = (typed: string, subject: string) =>
    confirmButton(
      html(
        <OrgDeletionForm
          slug="acme"
          typed={typed}
          onTyped={() => {}}
          busy={false}
          error={null}
          onSubmit={() => {}}
          mode="broker_token"
          subject={subject}
          onSubject={() => {}}
        />,
      ),
    );
  assert.match(form("acme", ""), /disabled=""/);
  assert.match(form("", "dev-user"), /disabled=""/);
  assert.doesNotMatch(form("acme", "dev-user"), /disabled=""/);
});

test("a deployment that cannot re-authenticate keeps the explainer and turns the button off", () => {
  const out = html(
    <OrgDeletionCard org={org()} view={view({ preview: preview({ reauth: "unavailable" }) })} onRequest={noop} onCancel={noop} />,
  );
  assert.match(out, /30-day cooling-off/);
  assert.match(out, /Re-authentication isn&#x27;t available on this deployment/);
  assert.match(confirmButton(out), /disabled=""/);
  const typed = html(
    <OrgDeletionForm slug="acme" typed="acme" onTyped={() => {}} busy={false} error={null} onSubmit={() => {}} mode="unavailable" />,
  );
  assert.match(confirmButton(typed), /disabled=""/);
});

test("after re-authentication the stashed request is confirmed with one button", () => {
  const out = html(
    <OrgDeletionCard
      org={org()}
      view={view({ preview: preview({ reauth: "step_up" }) })}
      authMode="workos"
      stepUpId="su_1"
      stepUpStash={{ orgId: "o1", slug: "acme" }}
      onRequest={noop}
      onCancel={noop}
    />,
  );
  assert.match(out, /Re-authentication confirmed: delete Acme Engineering/);
  assert.doesNotMatch(out, /to confirm/);
});

test("a step-up with a missing or foreign stash shows the form again", () => {
  for (const stash of [null, { orgId: "o2", slug: "acme" }]) {
    const out = html(
      <OrgDeletionCard
        org={org()}
        view={view({ preview: preview({ reauth: "step_up" }) })}
        authMode="workos"
        stepUpId="su_1"
        stepUpStash={stash}
        onRequest={noop}
        onCancel={noop}
      />,
    );
    assert.doesNotMatch(out, /Re-authentication confirmed: delete/);
    assert.match(out, /Type <span[^>]*>acme<\/span> to confirm/);
    assert.match(out, /Type the team&#x27;s address again to finish/);
  }
});

test("a blocked deletion's reason is worded", () => {
  const out = html(
    <OrgDeletionStatusPanel
      org={org()}
      deletion={status({ state: "blocked", blocked_reason: "host_purge_overdue", can_cancel: false })}
      onCancel={noop}
    />,
  );
  assert.match(out, /has not confirmed that its data was deleted in time/);
  assert.doesNotMatch(out, /host_purge_overdue/);
});

test("the confirm button is disabled until the typed text is the slug", () => {
  const form = (typed: string) =>
    html(<OrgDeletionForm slug="acme" typed={typed} onTyped={() => {}} busy={false} error={null} onSubmit={() => {}} />);
  assert.match(confirmButton(form("")), /disabled=""/);
  assert.match(confirmButton(form("acm")), /disabled=""/);
  assert.match(confirmButton(form("ACME")), /disabled=""/);
  assert.doesNotMatch(confirmButton(form("acme")), /disabled=""/);
  assert.doesNotMatch(confirmButton(form(" acme ")), /disabled=""/);
  // A fresh card starts disabled.
  assert.match(confirmButton(html(<OrgDeletionCard org={org()} view={view()} onRequest={noop} onCancel={noop} />)), /disabled=""/);
});

test("the form shows the request's refusal under the field", () => {
  const out = html(
    <OrgDeletionForm
      slug="acme"
      typed="acme"
      onTyped={() => {}}
      busy={false}
      error="The name you typed does not match this team's address. Type it exactly."
      onSubmit={() => {}}
    />,
  );
  assert.match(out, /does not match this team/);
});

test("the status panel words every state", () => {
  const cases: [Partial<OrgDeletionStatus>, RegExp[]][] = [
    [{}, [/Deletion scheduled/, /Cooling off until/, /Purge starts/]],
    [{ state: "purging", step: "delete_tables", can_cancel: false }, [/Deletion in progress/, /no longer have access/, /delete_tables/]],
    [{ state: "done", done_at: "2026-11-14T00:00:00Z", can_cancel: false }, [/Deleted/, /was deleted on/, /backups expire within 30 days/]],
    [
      { state: "blocked", blocked_reason: "records still in the ingest log", step: "drain_log", can_cancel: false },
      [/Deletion blocked/, /Blocked because/, /records still in the ingest log/, /drain_log/],
    ],
    [{ state: "canceled", canceled_at: "2026-11-14T00:00:00Z", can_cancel: false }, [/Deletion canceled/, /Nothing was deleted/]],
  ];
  for (const [over, wants] of cases) {
    const out = html(<OrgDeletionStatusPanel org={org()} deletion={status(over)} onCancel={noop} />);
    for (const w of wants) assert.match(out, w, `${over.state ?? "cooling_off"}: ${w}`);
  }
  const staff = html(<OrgDeletionStatusPanel org={org()} deletion={status({ origin: "staff" })} onCancel={noop} />);
  assert.match(staff, /SuperBased support/);
  const acct = html(<OrgDeletionStatusPanel org={org()} deletion={status({ origin: "account_deletion" })} onCancel={noop} />);
  assert.match(acct, /deletion of the owner&#x27;s account/);
});

test("Cancel deletion shows only for an owner while can_cancel", () => {
  const panel = (role: PortalOrg["console_role"], s: OrgDeletionStatus) =>
    html(<OrgDeletionStatusPanel org={org({ console_role: role })} deletion={s} onCancel={noop} />);
  assert.match(panel("owner", status()), /Cancel deletion/);
  assert.doesNotMatch(panel("owner", status({ state: "purging", can_cancel: false })), /Cancel deletion/);
  assert.doesNotMatch(panel("member", status()), /Cancel deletion/);
  assert.doesNotMatch(panel("admin", status()), /Cancel deletion/);
});

test("an owner with a deletion open sees the status and Cancel, not a second form", () => {
  const out = html(
    <OrgDeletionCard
      org={org({ status: "pending_deletion" })}
      view={view({ deletion: status(), preview: preview({ can_request: false, refusal: "deletion_open" }) })}
      onRequest={noop}
      onCancel={noop}
    />,
  );
  assert.match(out, /Cancel deletion/);
  assert.doesNotMatch(out, /to confirm/);
});

test("the org page renders the deletion slot last", () => {
  const detail: OrgDetail = { org: org(), can: { rename: true, view_billing: true, checkout: true } };
  const out = html(<OrgDetailView detail={detail} billing={<div>BILLING-SLOT</div>} deletion={<div>DELETION-SLOT</div>} onRename={noop} />);
  assert.ok(out.indexOf("DELETION-SLOT") > out.indexOf("Team name"), "deletion card comes after rename");
  assert.ok(out.indexOf("DELETION-SLOT") > out.indexOf("BILLING-SLOT"));
});
