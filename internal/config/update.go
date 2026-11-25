package config

// This file holds the config types of [update]: node self-update.

// DefaultUpdateStateDir is where staged downloads, the preserved rollback
// binary and the pre-apply DB snapshot live.
const DefaultUpdateStateDir = "~/.observer/updates"

// UpdateConfig is the [update] surface — enterprise update management
// (docs/plans/enterprise-update-management-plan-2026-09-07.md §3.4).
//
// LOCAL-ONLY and NEVER DISTRIBUTED, exactly like [routing]. That is a
// standing invariant, not an omission: there is no server-side toggle for
// any key below, and adding one would be the same feature mistake as a
// remote full_content toggle. An org publishes a signed manifest and a
// rollout ring; whether THIS machine restarts itself, and when, is decided
// here and nowhere else.
//
// Same partial-merge rule as CacheTrack/Predict/Loc: an install with no
// [update] section gets the Default() seed, not the zero value.
type UpdateConfig struct {
	// Enabled gates the whole feature. False makes it inert: no manifest is
	// fetched, no banner is shown, no apply is scheduled. Default true —
	// LEARNING about an update is fail-open and costs no new egress class
	// (the manifest rides the push cycle the node already runs); APPLYING
	// one is a separate, fail-closed decision governed by AutoApply.
	Enabled bool `toml:"enabled"`
	// Channel pins this node to a release channel ("stable" / "lts" /
	// "edge"). Empty = whatever the org assigns. A local value overrides the
	// assignment, but it can only ever pin this node BEHIND what the org
	// published — it cannot conjure a manifest the org has not signed.
	Channel string `toml:"channel"`
	// AutoApply is notify-only (false) vs zero-touch (true).
	//
	// It is a *bool, not a bool, because nil and false are genuinely
	// different answers: nil means "this node's operator did not say", and
	// the managed-fleet carve-out (§3.9) then supplies the default —
	// admin_managed / enterprise-granted fleets are zero-touch, BYO nodes
	// are notify-only. An EXPLICIT value always wins, in both directions, so
	// an admin-provisioned node can still be pinned to notify-only by its
	// own TOML. Resolve it with EffectiveAutoApply, never by dereferencing.
	AutoApply *bool `toml:"auto_apply"`
	// Window is the local maintenance window, "HH:MM-HH:MM" in the machine's
	// own timezone (a window that wraps midnight is normal on a fleet spread
	// across timezones and is handled). Empty = any time the quiescence
	// checks pass.
	Window string `toml:"window"`
	// AllowDowngrade is node consent for an admin-minted downgrade manifest.
	// Without it a manifest naming a lower version than the installed one is
	// refused outright (§3.2 rule 7, the TUF rollback defence).
	AllowDowngrade bool `toml:"allow_downgrade"`
	// KeepPreviousDays retains the rollback binary AND the pre-apply DB
	// snapshot. Both, together: a snapshot without its binary cannot roll
	// anything back, and a binary without its snapshot cannot be restored
	// across a schema advance.
	KeepPreviousDays int `toml:"keep_previous_days"`
	// MaxDownloadBytes is the hard artifact ceiling (256 MB). A stream that
	// exceeds it is aborted mid-flight — TUF's endless-data defence, applied
	// on top of the manifest's own declared size_bytes.
	MaxDownloadBytes int64 `toml:"max_download_bytes"`
	// StateDir holds staging, the rollback binary and the DB snapshot.
	StateDir string `toml:"state_dir"`
	// DrainTimeout is how long an apply waits for in-flight proxied requests
	// to reach zero after it stops admitting new ones. Exceeded = resume
	// admission and abort with error_class=drain (ruling R13: there is no
	// state in which a node is left refusing traffic because an apply gave
	// up).
	DrainTimeout string `toml:"drain_timeout"`
	// HandshakeTimeout is how long the OLD daemon waits for the NEW child's
	// self-check before killing it and rolling back. It is the window in
	// which the old process is the supervisor — which is why a supervisor is
	// recommended (ruling R14) but not required.
	HandshakeTimeout string `toml:"handshake_timeout"`
}

// EffectiveAutoApply resolves [update].auto_apply against the managed-fleet
// default, and reports whether the node's own TOML decided it.
//
// managedDefault is update.AutoApplyDefault(...) supplied by the caller;
// internal/config does not import internal/update, so the predicate stays in
// one place and this stays a plain precedence rule.
func (u UpdateConfig) EffectiveAutoApply(managedDefault bool) (effective, explicit bool) {
	if u.AutoApply != nil {
		return *u.AutoApply, true
	}
	return managedDefault, false
}
