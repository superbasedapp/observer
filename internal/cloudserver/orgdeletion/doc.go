// Package orgdeletion is the control plane's pure core of org deletion and of
// account deletion with orgs (managed-SaaS plan 07 M6.9 and the control-plane
// half of M7a.1; plan 06 5.3.10 and 5.4; design
// docs/plans/managed-saas/m6.0-control-plane-design-2026-11-13.md 3.4 and
// 4.10).
//
// It holds the decision tables and the driver. It does no I/O of its own and
// imports no database/sql, pgx, net/http or fsnotify (imports_test.go): the
// store, the deletion journal, the billing seam and the identity seam are
// injected.
//
// # Account deletion: who may leave
//
// [Precheck] walks the precheckRules table over the account's memberships,
// one verdict per org: the personal org is deleted with the account; a team
// org already being deleted only loses the membership; a team org the
// account is the billing owner of, or the only owner of, blocks the deletion
// until billing or ownership is transferred or the team is deleted (plan 06
// 5.4 "A departing billing_owner"); any other membership is removed. The
// account deletion transaction (internal/cloudserver/store) refuses with the
// blockers before it consumes the step-up or writes the journal.
//
// # Account deletion: billing
//
// [DecideBilling] walks the billingRules table over each Paddle subscription
// the account pays for (ORGDEL-7): one that bills nothing is only a record;
// the account's own plan, its personal org's, and an org's already on its way
// out are canceled through the [Billing] seam before the deletion deletes
// anything (the purge deletes their rows); a live team org's refuses the
// deletion (PORTALORG-9). The store cancels outside any transaction and
// re-checks inside its deletion transaction; a cancellation that fails
// refuses the deletion, never the other way round.
//
// # Org deletion: the cooling-off window
//
// [CoolingOff] walks the coolingRules table: a personal org deleted with its
// account has no window (the account deletion "runs to completion
// immediately", which the privacy policy promises); a free org that reported
// no seat in use for [InactiveWindow] gets [InactiveFreeCoolingOff] (14
// days); every other org [DefaultCoolingOff] (30 days, plan 06 5.3.10
// "Pending deletion"). Admin export stays available during the window.
// Nothing here is driven by a cap: plan 06 17.5's "over the cap means
// read-only, nothing deleted for 30 days" is a different path that never
// opens a deletion.
//
// # The org step table
//
// An org deletion request walks [OrgSteps] top-down, one step per driver
// call, each step one store transaction (idempotent: the same step run twice
// does its work once):
//
//	announce        org -> pending_deletion (lifecycle_gen + 1), set_state intent
//	cooling_off     wait until purge_after
//	cancel_billing  cancel the org's subscription through the billing seam while
//	                Paddle may still bill it (refunded and charged back too)
//	fence           journal accepted (kind org) first; then org -> purging
//	                (purge_gen = gen + 1), set_state purging, evict, set_state
//	                purged at purge_gen + 1 queued behind them, the org's OIDC
//	                client disabled and its unused codes deleted
//	await_host      wait until the host acked purged (the host refuses it with
//	                "unavailable" until its fenced purge completed)
//	finalize        org -> purged, memberships removed, journal done
//
// A canceled request (only possible while cooling off) walks restore: the org
// goes back to active at a new generation, and the request finishes.
//
// # The account follow-up step table
//
// The org-side half of an account deletion walks [AccountSteps]:
// personal_org (open an org deletion with no window, or bring an open one
// forward), memberships (remove every membership of the account),
// deactivate (one members_deactivate intent and one admin notice per team org
// the issuer saw the subject sign in to), await_deactivate (until every
// intent is acked; blocked as deactivation_overdue after [DeactivateGrace]),
// delete_identity (the WorkOS user, through the identity seam; not found is
// success) and finish (the subjects are forgotten).
//
// # Outcomes and retries
//
// A step returns an [Outcome]: advance to the next step, wait (try again
// later, nothing wrong), block (a named reason staff can see; the request
// stays where it is) or an error (retried with [Backoff]). The driver records
// the outcome through the store; one request's failure never stops the next.
//
// # Dry run
//
// [Driver.PreviewOrg] reports what the driver would do with an org now (the
// steps left, the window, the facts the steps read) and writes nothing.
package orgdeletion
