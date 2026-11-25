package config

// This file holds the config types of [cloud]: the Cloud Intelligence
// personal-service settings.

// CloudConfig is the [cloud] surface — config-file settings for the
// `observer cloud` CLI (Signed-in Free spine, docs/cloud-intelligence.md).
// MANUAL-ONLY, LOCAL-ONLY: nothing here makes the observer/watcher/proxy
// touch the network — the `observer cloud` subcommands remain the sole
// outbound trigger. Values here are the LOWEST-precedence layer: a
// `--base-url` flag beats the SBO_CLOUD_BASE_URL / SBO_CLOUD_LOGIN_PORT
// environment variables, which beat these TOML values, which beat the
// command's built-in default. The zero value (no [cloud] section, or a
// partial section) reproduces today's behaviour exactly — an install with
// no [cloud] block still resolves the base URL from --base-url/env only,
// same as before this section existed.
type CloudConfig struct {
	// BaseURL is the cloud service base URL, used only when neither
	// --base-url nor SBO_CLOUD_BASE_URL is set. Empty means "not
	// configured here" — the command falls through to its own "pass
	// --base-url or set SBO_CLOUD_BASE_URL" error. When set, it must parse
	// as an absolute http:// or https:// URL (see validateCloud).
	BaseURL string `toml:"base_url"`
	// LoginPort is the loopback port `observer cloud login`'s WorkOS PKCE
	// callback listener binds, used only when SBO_CLOUD_LOGIN_PORT is
	// unset. 0 means "not configured here" — the command falls through to
	// its own built-in default (9797). Must be 0 or a valid TCP port
	// (1-65535) — see validateCloud.
	LoginPort int `toml:"login_port"`
	// AutoSync opts INTO the background sync service (arc 2 R2a). When true
	// AND the `observer start` daemon is running, the daemon periodically
	// spawns `observer cloud sync` as a SUBPROCESS (never in-process — the
	// daemon links no cloud network package; see cmd/observer/cloudautosync.go
	// for the zero-egress justification). It stays consent-gated: the spawned
	// sync sends nothing without a live grant, exactly like a manual run.
	// Default false — the plane is manual-only until the operator opts in.
	AutoSync bool `toml:"auto_sync"`
	// AutoSyncIntervalMinutes is how often the background sync service (R2a)
	// spawns `observer cloud sync`. 0 means "use the built-in default"
	// (CloudAutoSyncDefaultMinutes, 15). Read only when AutoSync is true;
	// must be 0 or >= cloudAutoSyncMinMinutes (5) — see validateCloud.
	AutoSyncIntervalMinutes int `toml:"auto_sync_interval_minutes"`
	// AutoEnrich opts INTO automatic per-session enrichment (arc 2 R8: the
	// "automatically enrich my new sessions" toggle, default OFF and prominent
	// on the consent/settings surface). SUPERSEDED as of the value-upgrade
	// plan's W3 (2026-09-15): background enrichment is now governed entirely
	// by internal/store/cloudpolicy.go's cloud_enrich_policy row (`observer
	// cloud enable --no-background` / the dashboard's "Run in the background"
	// switch), which the daemon's auto-enrich loop (cmd/observer/
	// cloudautoenrich.go) reads live on every tick. This key is still parsed
	// (an existing config.toml with `auto_enrich = true` must not fail to
	// load) but has NO behaviour — nothing reads it anymore. Kept only for
	// the TOML key's sake; `observer cloud status` says so explicitly.
	AutoEnrich bool `toml:"auto_enrich"`
	// AutoEnrichIntervalMinutes is how often the background auto-enrich loop
	// (cmd/observer/cloudautoenrich.go) sweeps for quiet, personal-authority
	// sessions to enqueue. 0 means "use the built-in default"
	// (CloudAutoEnrichDefaultMinutes, 5); must be 0 or >=
	// CloudAutoEnrichMinMinutes (1) — see validateCloud. The loop itself is
	// inert unless the developer's cloud_enrich_policy row is on with
	// background enabled; this only tunes the cadence once it is.
	AutoEnrichIntervalMinutes int `toml:"auto_enrich_interval_minutes"`
	// AutoEnrichQuietMinutes is how long a session's newest action must be in
	// the past before the background loop treats it as "ended" and a
	// candidate for auto-enrollment (sessions.ended_at is NULL for practically
	// every captured session, so "ended" is always inferred from quiet, never
	// read off a column). 0 means "use the built-in default"
	// (CloudAutoEnrichQuietDefaultMinutes, 10); must be 0 or >=
	// CloudAutoEnrichMinMinutes (1) — see validateCloud.
	AutoEnrichQuietMinutes int `toml:"auto_enrich_quiet_minutes"`
	// WorkOSClientID is the PUBLIC WorkOS OAuth client id `observer cloud
	// login` builds the AuthKit PKCE authorize URL with (and the refresh
	// broker re-exchanges through). It is NOT a secret — the WorkOS API key
	// is server-side only and never read on the node. Resolution: the
	// WORKOS_CLIENT_ID environment variable first, then this key (same
	// env > [cloud] precedence as base_url / login_port), else the compiled
	// default (DefaultCloudWorkOSClientID) that Default() seeds here. An
	// operator can still opt out entirely by setting
	// `workos_client_id = ""` explicitly in config.toml — an explicit empty
	// value overrides the seeded default (ordinary TOML partial-merge
	// semantics: a key present in the file is always applied, even when its
	// value equals the zero value), landing back in the honest "set
	// [cloud].workos_client_id or WORKOS_CLIENT_ID" state instead of opening
	// a browser to nothing. Editable from the dashboard's Cloud account
	// card; read per `observer cloud` invocation, so no restart.
	WorkOSClientID string `toml:"workos_client_id"`
}

// DefaultCloudWorkOSClientID is the compiled-in default for
// [cloud].workos_client_id: SuperBased's PUBLIC production WorkOS OAuth
// client id for the `observer cloud` PKCE sign-in flow. It is NOT a secret —
// a WorkOS client id is meant to be embedded in a public client the same way
// an OAuth app's client id is. Default() seeds it so a fresh install can sign
// in without any node-side configuration; the WORKOS_CLIENT_ID environment
// variable and an explicit [cloud].workos_client_id in config.toml (staging
// testing uses the staging id client_01M1A55VB1S3JAJQSP79MFEQJ6 this way)
// both still take precedence over it, and an explicit empty TOML value opts
// back out to the unconfigured state.
const DefaultCloudWorkOSClientID = "client_01M1A55VPHXPT59PPZMG2H272X"

const (
	// CloudAutoSyncDefaultMinutes is the background-sync interval used when
	// [cloud].auto_sync_interval_minutes is 0 (arc 2 R2a). Lowered from 60 to
	// 15 by the value-upgrade plan's W3 (2026-09-15): background enrichment
	// results are only useful once a sync has pulled them back, so a sync
	// cadence tighter than an hour is what makes "named a few minutes after
	// the session ends" honest.
	CloudAutoSyncDefaultMinutes = 15
	// CloudAutoSyncMinMinutes is the floor for a configured background-sync
	// interval — a tighter cadence would only re-spawn `observer cloud sync`
	// pointlessly, since a manual run already drains everything sendable.
	CloudAutoSyncMinMinutes = 5
	// CloudAutoEnrichDefaultMinutes is the auto-enrich sweep interval used
	// when [cloud].auto_enrich_interval_minutes is 0 (value-upgrade plan W3).
	CloudAutoEnrichDefaultMinutes = 5
	// CloudAutoEnrichQuietDefaultMinutes is how long a session's newest
	// action must be in the past before the background loop treats it as
	// ended, used when [cloud].auto_enrich_quiet_minutes is 0.
	CloudAutoEnrichQuietDefaultMinutes = 10
	// CloudAutoEnrichMinMinutes is the shared floor for both auto-enrich
	// knobs above.
	CloudAutoEnrichMinMinutes = 1
)

// ResolvedCloudAutoSyncMinutes returns the effective background-sync interval:
// the configured value when set, else the built-in default. It is the ONE place
// the 0-means-default rule is applied, so the daemon scheduler and any status
// echo agree.
func (c CloudConfig) ResolvedCloudAutoSyncMinutes() int {
	if c.AutoSyncIntervalMinutes > 0 {
		return c.AutoSyncIntervalMinutes
	}
	return CloudAutoSyncDefaultMinutes
}

// ResolvedCloudAutoEnrichIntervalMinutes returns the effective auto-enrich
// sweep interval: the configured value when set, else the built-in default.
func (c CloudConfig) ResolvedCloudAutoEnrichIntervalMinutes() int {
	if c.AutoEnrichIntervalMinutes > 0 {
		return c.AutoEnrichIntervalMinutes
	}
	return CloudAutoEnrichDefaultMinutes
}

// ResolvedCloudAutoEnrichQuietMinutes returns the effective "how long since
// the last action counts as ended" window: the configured value when set,
// else the built-in default.
func (c CloudConfig) ResolvedCloudAutoEnrichQuietMinutes() int {
	if c.AutoEnrichQuietMinutes > 0 {
		return c.AutoEnrichQuietMinutes
	}
	return CloudAutoEnrichQuietDefaultMinutes
}
