package update

// autoapply.go owns ONE predicate: what [update].auto_apply defaults to when
// the node's own TOML does not say (§3.9 of
// docs/plans/enterprise-update-management-plan-2026-09-07.md).
//
// It is one function in one place for the same reason
// ShareOptions.shipsRawContent() is: the moment two call sites decide "is
// this fleet managed?" independently, they disagree, and the disagreement
// surfaces as a machine that updated itself when the operator believed it
// would not.

// ManagedPosture is the shape AutoApplyDefault needs from the node's share
// options.
//
// It is two booleans rather than store.ShareOptions because internal/update
// must not import the storage layer — that would pull database/sql in
// transitively, past a pin whose whole purpose is to keep the decision layer
// free of it. cmd/observer maps the real ShareOptions onto this at the one
// wiring point, which is also where a reader can see the mapping.
type ManagedPosture struct {
	// AdminManaged is [org_client.share].admin_managed: the admin provisions
	// this node's config through MDM / managed settings.
	AdminManaged bool
	// EnterpriseGranted is the Plane-B enterprise-posture enrolment grant.
	EnterpriseGranted bool
}

// AutoApplyDefault reports the DEFAULT for [update].auto_apply.
//
// Managed fleets (admin-provisioned config, or an enterprise-posture
// enrolment grant) are zero-touch; BYO nodes are notify-only.
//
// This sets a DEFAULT, never an override. An explicit [update].auto_apply in
// the node's own TOML always wins, which is what keeps the "never
// server-forced" invariant true byte for byte: there is no server-side force
// flag for updates, and adding one would be the same feature mistake as a
// remote full_content toggle. The admin_managed precedent is exact — it
// already flips the default for content-bearing columns, because in that
// deployment "node-side opt-in" is satisfied by the admin AUTHORING the
// node's TOML, not by a remote command.
func AutoApplyDefault(p ManagedPosture) bool {
	return p.AdminManaged || p.EnterpriseGranted
}

// AutoApplyReason explains the effective auto-apply setting in the words a
// surface should print. A status line that says "off" without saying WHO
// decided is something an admin cannot act on.
func AutoApplyReason(explicitSet, effective bool, p ManagedPosture) string {
	switch {
	case explicitSet && effective:
		return "on - set explicitly by [update].auto_apply in this node's config"
	case explicitSet && !effective:
		return "off - set explicitly by [update].auto_apply in this node's config"
	case effective && p.AdminManaged:
		return "on - the managed-fleet default (this node is admin_managed); set [update].auto_apply = false to override"
	case effective && p.EnterpriseGranted:
		return "on - the managed-fleet default (enterprise-posture enrolment); set [update].auto_apply = false to override"
	case effective:
		return "on - the managed-fleet default; set [update].auto_apply = false to override"
	default:
		return "off - the default for a BYO node; set [update].auto_apply = true to make this node zero-touch"
	}
}
