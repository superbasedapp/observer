package config

// This file holds the config types of [delivery].

// DeliveryConfig is the [delivery] surface: commit to PR to merge tracking
// (docs/plans/commit-pr-merge-tracking-plan-2026-10-15.md, operator
// decision D-689). LOCAL-ONLY; nothing here is distributed to an org server.
//
// Local landing detection (internal/landingscan) runs after each
// successful commit scan, is read-only and network-free, and never writes
// to the user's repository (no fetch, no merge-tree, no config write). A
// code-host connection (GitHub in this release) is NOT a config switch: it
// is made explicitly from the dashboard or `observer delivery connect`, off
// until then.
//
// Same partial-merge invariant as ProjectsConfig: an install with no
// [delivery] section gets the Default() seed for every field.
type DeliveryConfig struct {
	// Local gates the read-only landing scan (remotes, default branch,
	// FETCH_HEAD age, patch fingerprints, landing rules G and L). Default
	// TRUE. Turning it off stops new local evaluation; stored landings still
	// render.
	Local bool `toml:"local"`
	// PollMinutes is the minimum interval between two landing evaluations of
	// one project when nothing moved (HEAD and FETCH_HEAD unchanged), and the
	// provider service's poll interval while a PR is open. Default 10.
	PollMinutes int `toml:"poll_minutes"`
	// MirrorCapMB caps the total size of Observer-owned mirrors under
	// ~/.observer/delivery/mirrors; a clone that would exceed it is
	// refused. Default 2048.
	MirrorCapMB int `toml:"mirror_cap_mb"`
	// AbandonAfterDays is how long an unpushed commit reads as "in flight"
	// before "local only", and how long a commit rewritten out of HEAD waits
	// before it reads as "abandoned, dropped" (rules L7 and L8). Default 30.
	AbandonAfterDays int `toml:"abandon_after_days"`
	// CountLikely is reserved for "likely landed" (content overlap, rule
	// L5). Default false. Rule L5 is not implemented in this release, so
	// nothing is "likely landed" and this switch has no effect: likely
	// landed is never counted as landed until L5 ships.
	CountLikely bool `toml:"count_likely"`
	// ContentOverlapMin is the added-line overlap rule L5 will require
	// (0 to 1). Default 0.8. Reserved: rule L5 is not implemented in this
	// release.
	ContentOverlapMin float64 `toml:"content_overlap_min"`
}
