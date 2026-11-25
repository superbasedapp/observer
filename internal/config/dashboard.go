package config

// This file holds the config types of [dashboard].

// DashboardConfig controls the local analytics dashboard listener. LOCAL-ONLY
// (never distributed via [org_client.share]). The zero value (no [dashboard]
// section) preserves today's behaviour: `observer start` binds the dashboard on
// the built-in 127.0.0.1:8081 default. Setting Addr makes that address durable
// across daemon/service restarts without the per-run --dashboard-addr flag —
// the config layer sits BELOW the flag and the OBSERVER_DASHBOARD_ADDR env var
// in the precedence ladder (flag > env > config > default), resolved in
// cmd/observer.
type DashboardConfig struct {
	// Addr is the durable dashboard listen address as host:port
	// (e.g. "127.0.0.1:8082"). Empty ⇒ the built-in default is used. An
	// EMPTY host (":8082", i.e. bind-all-interfaces / 0.0.0.0) and any
	// non-loopback host are ACCEPTED at config-load time — the port is the
	// only thing validated for shape (numeric, 1–65535) — because they do
	// NOT bypass the remote-exposure guard: the resolved address still passes
	// through dashboard.CheckRemoteBind, which fails closed unless the
	// [remote] security substrate is armed (mirrors the --dashboard-addr flag
	// path). Validated as host:port with a numeric port at load; the
	// remote-bind policy is enforced separately at bind time.
	Addr string `toml:"addr"`
	// OrgAnnouncements gates rail R3 of the announcements plan (§4):
	// whether the banner shows announcements published by the org this
	// node is enrolled with. Default TRUE — enrolment already implies
	// consent to org communication, so silently swallowing the admin's
	// message would be the dishonest default; and on a solo install the
	// switch is inert (there is no org cache to read).
	//
	// This is the node operator's OWN opt-out and it lives only here:
	// the org admin has no remote toggle for it, the same posture as
	// [org_client.share].full_content. Turning it off never affects
	// push, enrolment, or the release rail — the dashboard simply stops
	// reading the cached document.
	//
	// Default() seeds it true so the loader's partial-merge keeps it
	// true for an existing config that has a [dashboard] section with
	// only `addr` in it (the CacheTrack partial-merge rule) — without
	// that seed, adding the key would have silently disabled the rail
	// for every install that had ever set a dashboard address.
	OrgAnnouncements bool `toml:"org_announcements"`
	// LiveRibbon shows the live ribbon in the local dashboard's shell: the
	// top-bar chip ("No agent running · Start one", or "N live") and the
	// slim strip under the top bar while an agent session is live
	// (docs/plans/local-dashboard-first-run-options-2026-11-18.md §8).
	// Default TRUE. Local-only: the node operator's own display switch,
	// never distributed and with no org toggle (an org that hides the Live
	// page hides the ribbon through page visibility instead). Read on each
	// ribbon request, so a save applies without a restart. Off removes the
	// chip and the strip; the nav's Live count stays. Seeded true in
	// Default() for the same partial-merge reason as OrgAnnouncements.
	LiveRibbon bool `toml:"live_ribbon"`
}
