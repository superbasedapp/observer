// Package entitlementwork is the worker side of signed entitlements
// (managed-SaaS plan 07 M6.3; design
// docs/plans/managed-saas/m6.0-control-plane-design-2026-11-13.md 4.5
// "Process"; plan 06 5.8.4). It composes each org's entitlements document
// from the org's plan with the catalog's generator (entitlements.Compose),
// has the document signer sign it, verifies the signed document exactly as
// a tenant host will (entitlements.Verify against the signer's published
// entitlements keys), and stores it together with its set_entitlements
// host-API intent in one transaction (store.IssueEntitlementDocument). The
// outbox dispatcher (internal/cloudserver/hostapi/hostclient) delivers the
// intent; the first document also rides in the create_tenant request, read
// at send time by CreateResolver.
//
// Versions are strictly monotonic per org, enforced twice and outside this
// package: by the signer's fsync'd state file before a signature is
// released, and by the store under a per-org lock before a row is written.
// The issuer picks max(last stored + 1, now in Unix seconds): a version the
// signer refuses as not newer (it signed one that never reached the store)
// is bumped and asked again, a bounded number of times; a version the store
// refuses (another issuer stored one first) is left to the next pass.
//
// The org's plan (plans.go, SubscriptionPlans; lead decisions W14-D3 and
// W14-D1a), a rule table walked top-down: the org's live org-scoped Paddle
// subscription, read through OrgPlanReader (the one subscription store,
// which the front-door lane gives an org scope), when its plan is a catalog
// plan of the org's kind; else the org's operator plan grant while it is in
// force (W15-D13, cloud 0095, `observer-cloud grant-plan org`); else, for a
// kind with a launch row (team), the
// launch plan for the launch window (default 14 days, plan 06 5.8.6) after
// the org's create was acked on its host, with the window's end as the
// document's not_after; else the floor of its kind. The worker issues the
// launch document right after the create's ack (EnsureOrg, run by the
// dispatcher's AfterCreate hook), so a new team org never sits on its lapsed
// floor (QUOTA-1). A failed subscription read keeps the document in force.
// FloorPlans, the floor alone, is the issuer's default when no source is
// configured.
//
// The owner identity a create_tenant request also needs comes from
// StoreOwners (lead decision W14-D2): the owner's WorkOS subject through a
// narrow SECURITY DEFINER lookup that answers for one org still being
// created (cloud 0093), chosen by the platform OIDC issuer's own rule, and
// the owner's address, sent as a hint marked verified exactly when WorkOS
// verified it (C2.tenant-cloud-2, cloud 0096), else unverified. A
// missing subject or address is a typed refusal; the create intent stays in
// the outbox and is retried, never sent without an owner and never parked.
// The request also carries the org's current slug and kind (CreateResolver
// Facts, cloud 0092), which a pooled host routes by.
//
// No SQL, HTTP or key here: the store, the signer and the clock are
// injected (imports_test.go pins it).
package entitlementwork
