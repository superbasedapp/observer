package config

import (
	"errors"
	"fmt"
	"math"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/BurntSushi/toml"

	"github.com/marmutapp/superbased-observer/internal/notify/digest"
	"github.com/marmutapp/superbased-observer/internal/notify/email"
	"github.com/marmutapp/superbased-observer/internal/scrub"
	"github.com/marmutapp/superbased-observer/internal/sshprofile"
	"github.com/marmutapp/superbased-observer/internal/update"
)

// Config is the root configuration for the observer. Field defaults are set
// by Default(). Partial TOML files (including missing sections) are supported
// — unspecified fields retain their defaults.
type Config struct {
	Observer     ObserverConfig     `toml:"observer"`
	Proxy        ProxyConfig        `toml:"proxy"`
	Dashboard    DashboardConfig    `toml:"dashboard"`
	Compression  CompressionConfig  `toml:"compression"`
	Intelligence IntelligenceConfig `toml:"intelligence"`
	OrgClient    OrgClientConfig    `toml:"org_client"`
	Exporter     ExporterConfig     `toml:"exporter"`
	Ingest       IngestConfig       `toml:"ingest"`
	CacheTrack   CacheTrackConfig   `toml:"cachetrack"`
	CacheWarm    CacheWarmConfig    `toml:"cachewarm"`
	Predict      PredictConfig      `toml:"predict"`
	Loc          LocConfig          `toml:"loc"`
	Guidance     GuidanceConfig     `toml:"guidance"`
	Update       UpdateConfig       `toml:"update"`
	Tasks        TasksConfig        `toml:"tasks"`
	Browser      BrowserConfig      `toml:"browser"`
	Handoff      HandoffConfig      `toml:"handoff"`
	Terminal     TerminalConfig     `toml:"terminal"`
	Launch       LaunchConfig       `toml:"launch"`
	CodeIntel    CodeIntelConfig    `toml:"codeintel"`
	// Archive is the [archive] surface — cold storage for the corpus
	// archival arc (docs/plans/observer-corpus-archival-lazyload-design-
	// 2026-08-26.md). LOCAL-ONLY, never distributed to an org server, and
	// OPT-IN: with the zero value the retention pass behaves exactly as it
	// did before the arc existed.
	Archive  ArchiveConfig  `toml:"archive"`
	Advisor  AdvisorConfig  `toml:"advisor"`
	Routing  RoutingConfig  `toml:"routing"`
	Guard    GuardConfig    `toml:"guard"`
	Profiles ProfilesConfig `toml:"profiles"`
	// Benchmark is the [benchmark] surface — the Benchmarks Harness
	// (docs/plans/benchmarks-harness-plan-2026-07-11.md). LOCAL-ONLY. Holds
	// only the retention horizon for the node-local benchmark_* tables today;
	// per-run spend caps live in the run spec's [budget] block, not here.
	Benchmark BenchmarkConfig `toml:"benchmark"`
	// Email is the [email] surface — the shared SMTP notification channel
	// (gap-register G9). LOCAL-ONLY, never distributed. OPT-IN: default off
	// (a fired alert makes an outbound SMTP call). Reused by the node-side
	// obs-alert loop; the org server has its own [email] block. See
	// internal/notify/email.
	Email email.Config `toml:"email"`
	// Digest is the [digest] surface — the scheduled personal cost digest
	// (gap-register G13): a weekly/monthly per-tool/per-model spend rollup
	// emailed through the shared [email] channel. LOCAL-ONLY. OPT-IN: default
	// off, and additionally requires [email].enabled. See internal/notify/digest.
	Digest digest.Config `toml:"digest"`
	// Observability is the [observability] surface — the generalized
	// observability subsystem (internal/obs). OPT-IN: default false.
	Observability ObservabilityConfig `toml:"observability"`
	// SelfObs is the [selfobs] surface — Plane-A P1-10 platform self-
	// observability emission (ADR-0004). OPT-IN: default enabled=false.
	// When enabled with endpoint+credential, decision components emit
	// system_agent OTLP runs through emit.Sink to the org gateway.
	SelfObs SelfObsConfig `toml:"selfobs"`
	// AggregateShare is the [aggregate_share] surface — the opt-in aggregate
	// rail (docs/plans/g25-optin-aggregate-rail-design-2026-07-11.md). OPT-IN,
	// default OFF in every path (zero value AND the loader's partial-merge
	// default): it is the product's first first-party network call outside the
	// Teams org-push, so the rail is inert unless the operator explicitly
	// consents via `observer aggregate enable`. Deliberately TOP-LEVEL, not
	// under [org_client], because it is org-independent (works for solo nodes).
	AggregateShare AggregateShareConfig `toml:"aggregate_share"`
	// Remote is the [remote] surface — remote dashboard access
	// (docs/plans/remote-dashboard-access-plan-2026-07-12.md). LOCAL-ONLY,
	// never distributed via [org_client.share] and never a server-forced
	// toggle (the node operator owns exposure entirely — mirrors the org-push
	// posture). OPT-IN, default OFF in every path: exposure is the first
	// network-facing node surface, so it is inert unless the operator
	// configures it. Holds the security substrate settings + the Phase-0
	// [remote.notify] outbound-notification sub-block.
	Remote RemoteConfig `toml:"remote"`
	// Cloud is the [cloud] surface — config-file base-URL/login-port
	// settings for the `observer cloud` CLI (Signed-in Free spine). See
	// CloudConfig for the precedence rule (flag > env > this > built-in
	// default). LOCAL-ONLY; never distributed via the org policy registry.
	Cloud CloudConfig `toml:"cloud"`
	// Pricing is the [pricing] surface — today only the [pricing.feed]
	// sub-block, the standalone-node opt-in pricing feed client (docs/plans/
	// pricing-sync-tokenomics-to-platform-plan-2026-09-11.md §C.4 / D7: a NEW
	// top-level block, kept distinct from [intelligence.pricing] which is the
	// node's OWN authored price table). LOCAL-ONLY, never distributed, and OFF
	// by default in every path — an enrolled node receives prices through its
	// org rail and never consults the public feed (§C.3/D8).
	Pricing PricingSectionConfig `toml:"pricing"`
	// Experiments is the [[experiments]] list — productized profile
	// A/B runs (usability arc P6.4). See experiments.go.
	Experiments []ExperimentConfig `toml:"experiments"`
}

// Device-session lifetime defaults for the [remote] block, in MINUTES. They are
// the config-side spelling of remoteauth.DefaultSessionTTL / DefaultSessionIdle
// — kept here (rather than imported) so this low-level package stays free of a
// dependency on the auth layer; internal/config/continuity_defaults_test.go
// pins the two spellings in lock-step.
//
// 2880 (48h) is the operator's 2026-07-25 decision for the absolute cap: it
// clears one full 24h idle window with a day of headroom, so the idle rule
// decides the common case, without the week-long exposure a 7-day cap carries.
const (
	// DefaultRemoteSessionTTLMinutes is the absolute device-session lifetime
	// (48 hours).
	DefaultRemoteSessionTTLMinutes = 2880
	// DefaultRemoteSessionIdleMinutes is the device-session idle timeout
	// (24 hours).
	DefaultRemoteSessionIdleMinutes = 1440
)

// RemoteConfig is the [remote] surface — the remote-dashboard-access security
// substrate + notification rail (remote-dashboard-access plan §5). LOCAL-ONLY:
// never distributed via [org_client.share], never a server-forced toggle. The
// zero value (no [remote] section) is fully off — loopback-only, today's
// behaviour — and the partial-merge default keeps it that way.
type RemoteConfig struct {
	// Enabled is the master switch. false ⇒ loopback-only (today's
	// behaviour); a non-loopback bind fails closed (plan §4.6). Even when
	// true, no listener binds non-loopback until Phase 2 wires the exposure
	// mode — Phase 1 assembles the substrate without exposing anything.
	Enabled bool `toml:"enabled"`
	// Mode selects the exposure transport: off | tailscale | lan. Never a
	// bare "0.0.0.0" (plan §5). Phase 1 accepts only "off".
	Mode string `toml:"mode"`
	// BindAddr is the EXPLICIT IP:port to bind in lan mode (plan §5 — never
	// 0.0.0.0, never an interface name). Empty in off/tailscale mode.
	BindAddr string `toml:"bind_addr"`
	// TailscaleBackendAddr is the dedicated LOOPBACK IP:port the tailnet-serve
	// backend binds in tailscale mode (plan §4.4 Phase 2). It MUST be a
	// loopback address distinct from the owner-trusted direct dashboard
	// listener: `tailscale serve` terminates TLS remotely and forwards
	// plaintext here, so this listener requires auth for EVERY request (no
	// RemoteAddr bypass) and is the ONLY place forwarded-identity headers are
	// consumed. Empty in off/lan mode; `observer remote enable --tailscale`
	// pins a randomized free loopback port here.
	TailscaleBackendAddr string `toml:"tailscale_backend_addr"`
	// TrustedHosts are extra Host-header allow-list entries for the
	// browserGuard Host check on a remote-exposed bind (plan §4.5). Never
	// "allow any Host".
	TrustedHosts []string `toml:"trusted_hosts"`
	// RequireTLS mandates TLS for ALL remote access (plan §5 — no plain-HTTP
	// data path). Default true; not waivable for a data-bearing view.
	RequireTLS bool `toml:"require_tls"`
	// AllowTerminal gates the execute-tier remote terminal surface (Phase 4).
	// Default false — off even for an execute-capable user until enabled.
	AllowTerminal bool `toml:"allow_terminal"`
	// AllowRemoteTerminalTakeover controls whether a successfully authenticated
	// remote writer may supersede an existing local/native or remote writer.
	// Default true for seamless handoff; false preserves the explicit-yield
	// posture. This changes only post-authorization lease policy: AllowTerminal,
	// device authentication, launch policy, and the capability/standing-secret
	// credential gate remain mandatory and upstream. Local-only; never
	// distributed or server-forced.
	AllowRemoteTerminalTakeover bool `toml:"allow_remote_terminal_takeover"`
	// AllowTerminalView is the independent READ opt-in for remote VIEWING of
	// attach/resume terminals (session-attach design §3.2, Phase 4). It is
	// STRICTLY WEAKER than AllowTerminal (write): an attach/resume PTY binds a
	// daemon-owned terminal to a REAL external transcript whose TUI can echo
	// secrets/customer data, so this controls whether a remote paired device
	// gets the snapshot row AND the websocket subscription for such sessions.
	// Default TRUE — mirroring the AllowRemoteTerminalTakeover default-true
	// precedent. View-by-default is acceptable because the remote surface is
	// ALREADY multi-lever gated: it opens nothing until the operator arms the
	// rail and a paired device authenticates over the tailnet, and the remote
	// WRITE/drive path is UNCHANGED by this default — driving still requires
	// AllowTerminal AND the full execute-tier writer-acquire conjunction
	// (device auth + per-terminal approval / standing secret + takeover). The
	// toggle still exists: setting allow_terminal_view = false restores the
	// deny-read posture. Seeded true in Default(); BurntSushi's field-level
	// decode leaves an absent key untouched, so a legacy [remote] block that
	// predates the key loads as true while an explicit false sticks (the same
	// partial-merge mechanism AllowRemoteTerminalTakeover relies on). Never
	// distributed; never server-forced.
	AllowTerminalView bool `toml:"allow_terminal_view"`
	// AllowStandingTerminalControl is the OPT-IN master switch for the standing
	// terminal-control secret (standing-terminal-access §B): a single durable,
	// hashed-at-rest secret that lets a paired device re-acquire writer control
	// across websocket refreshes WITHOUT a fresh per-terminal owner approval.
	// Default false. It is a STRICT SUPERSET of risk over the single-use flow —
	// anyone holding the secret + a paired session controls EVERY terminal — so
	// it lives beside allow_terminal (which it also requires) and is off until
	// the operator consciously mints a secret from the local dashboard. The raw
	// secret is never stored: its argon2id hash lives in a 0600 sibling file of
	// the pairing secret (remotecfg.StandingTerminalSecretPath).
	AllowStandingTerminalControl bool `toml:"allow_standing_terminal_control"`
	// RevokeStandingOnTakeover is an OPT-IN hardening of standing access.
	// When true, a LOCAL (desktop) writer takeover of a remote writer that
	// held control through the standing credential also revokes that
	// credential itself (the same teardown as the dashboard explicit revoke
	// — verifier hot-disabled, remote writers dropped, credential file
	// removed). Default false — the seamless posture: takeover revokes only
	// the live lease and the paired device may re-acquire later. Local-only;
	// never distributed.
	RevokeStandingOnTakeover bool `toml:"revoke_standing_on_takeover"`
	// WriterLeaseIdleMinutes is the idle lifetime of a remote writer lease
	// (Phase 4 §4.α.2c), refreshed on each Write/Resize. Default 5.
	WriterLeaseIdleMinutes int `toml:"writer_lease_idle_minutes"`
	// WriterLeaseMaxMinutes is the hard cap on a remote writer lease's lifetime
	// (§4.α.2c) after which the holder must re-acquire. Default 30.
	WriterLeaseMaxMinutes int `toml:"writer_lease_max_minutes"`
	// RateLimitPerMin caps auth attempts (code-server-class). Default 6.
	// 0 disables limiting for the PAIRING endpoint only; the standing
	// terminal-control verifier clamps <=0 back to 6/min (each standing attempt
	// costs a 19 MiB argon2 compute, so it is never unlimited).
	RateLimitPerMin int `toml:"rate_limit_per_min"`
	// CapabilityTTLMinutes is the lifetime of a single-use terminal-control
	// execute capability + its bound confirm nonce (plan §4.2). Default 10.
	// Raised from a hard-coded 2 minutes on 2026-07-25: the codes are conveyed
	// out-of-band (email / chat / password manager) and the human round-trip
	// routinely outlasted a 2-minute window, so a code expired in transit and
	// had to be re-issued. This widens EXPOSURE TIME only — the capability stays
	// single-use, session+action+handle-bound, confirm-paired, and owner-loopback
	// minted. 0 uses the package default; set 2 to restore the old window.
	CapabilityTTLMinutes int `toml:"capability_ttl_minutes"`
	// SessionTTLMinutes is the absolute device-session lifetime (plan §4.3).
	// Default 2880 (48 hours); a session older than this is rejected. Raised
	// from 720 (12h) on 2026-07-25 so the 24h idle target below is actually
	// reachable — an absolute cap under the idle bound makes the idle bound
	// unreachable. 48h (not the 7 days first implemented) is the operator's
	// chosen bound: one full idle window plus a day of headroom, at a fraction
	// of the exposure. 0 uses the package default (remoteauth.DefaultSessionTTL);
	// negatives are rejected at load.
	SessionTTLMinutes int `toml:"session_ttl_minutes"`
	// SessionIdleMinutes is the device-session idle timeout. Default 1440 (24h),
	// raised from 60 on 2026-07-25 at the operator's request: a paired phone put
	// down overnight must still be paired in the morning. A live attached
	// terminal viewer now also refreshes the clock, so this measures genuine
	// inactivity rather than time since the last page load. 0 uses the package
	// default (remoteauth.DefaultSessionIdle); negatives are rejected at load,
	// as is an idle window LONGER than SessionTTLMinutes (the absolute cap would
	// silently make it unreachable).
	SessionIdleMinutes int `toml:"session_idle_minutes"`
	// MaxSessions caps concurrent device sessions (plan §4.3). Default 5.
	MaxSessions int `toml:"max_sessions"`
	// Notify is the Phase-0 [remote.notify] outbound-notification sub-block.
	Notify RemoteNotifyConfig `toml:"notify"`
}

// RemoteNotifyConfig is the [remote.notify] sub-block — the Phase-0
// outbound-notification rail (plan §7 Phase 0). Opt-in, default off; the only
// outbound call this plan adds pre-relay, invoked from the dashboard/lifecycle
// layer, never the capture path (pinned by
// tests/invariant/remotenotify_boundary_test.go).
type RemoteNotifyConfig struct {
	// Enabled gates the rail. Default false ⇒ no outbound call.
	Enabled bool `toml:"enabled"`
	// Kind is the transport: webhook | ntfy. Default "webhook".
	Kind string `toml:"kind"`
	// URL is the delivery endpoint (a webhook receiver or an ntfy topic URL).
	URL string `toml:"url"`
	// Events subscribes to lifecycle events. Empty ⇒ all known events.
	// Default ["session_blocked", "session_finished"].
	Events []string `toml:"events"`
}

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
	// (cloudAutoSyncDefaultMinutes, 60). Read only when AutoSync is true;
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

// ObservabilityConfig is the [observability] surface — the generalized
// observability subsystem (internal/obs; plan
// docs/plans/generalized-observability-custom-app-plan-2026-06-27.md). It is
// OPT-IN (default false): unlike CacheTrack/Guard/Advisor, the zero value is
// the intended default, so no partial-merge entry is required — an install
// with no [observability] section keeps the subsystem off and creates no
// obs_* tables. The subsystem is additionally compiled out by the no_obs
// build tag for minimal distributions (decision D2).
// SelfObsConfig is the [selfobs] surface (P1-10 production retrofit,
// docs/plans/plane-a-p1-10-production-retrofit-plan.md). LOCAL-ONLY.
// Default OFF — emission is a credential-bearing OTLP call to the org
// gateway and must never fire without operator consent + keys.
type SelfObsConfig struct {
	// Enabled gates sink construction. false ⇒ emit.Nop().
	Enabled bool `toml:"enabled"`
	// Endpoint is the OTLP/HTTP gateway endpoint (host:port or full URL).
	Endpoint string `toml:"endpoint"`
	// KeyID / Secret compose the ingest credential; Token (if set) wins.
	KeyID  string `toml:"key_id"`
	Secret string `toml:"secret"`
	Token  string `toml:"token"`
	// Insecure permits plaintext http:// (default requires https://).
	Insecure bool `toml:"insecure"`
	// ServiceName overrides the OTLP resource service.name.
	ServiceName string `toml:"service_name"`
	// RoutingSampleN controls routing Decide emission: 0 = off, 1 = every
	// decide, N = 1-of-N sample (plan fork 1; default 32).
	RoutingSampleN int `toml:"routing_sample_n"`
}

type ObservabilityConfig struct {
	// Enabled gates the whole subsystem: the OTLP /v1/traces receiver,
	// the obs_* schema (applied only when true), ingestion, the
	// trajectory API, and the eval plane. Default false.
	Enabled bool `toml:"enabled"`

	// Eval configures the minimal eval plane (plan §8). Zero value = the
	// `observer eval` CLI works on demand with code scorers; no online
	// sampling, no judge.
	Eval ObservabilityEvalConfig `toml:"eval"`

	// Judge is the SHARED judge binding (admission spec §14 Q4 decision,
	// 2026-07-05): a single [observability.judge] block that both the eval
	// plane and admission fall back to when they don't set their own judge
	// fields. Zero value = no shared judge; the pre-existing
	// [observability.eval] judge_* keys still win where set (no break).
	Judge ObservabilityJudgeConfig `toml:"judge"`

	// Admission configures the input-admission gate (admission spec) — an
	// LLM-as-judge that evaluates incoming user requests to a co-resident
	// agentic app against an admin policy. Zero value = admission off (no
	// schema cost beyond the shared obs migration). Engages only in the
	// co-resident-app posture; meaningless at the coding-agent node.
	Admission ObservabilityAdmissionConfig `toml:"admission"`

	// Alerts configures NODE-SIDE alert evaluation (general-observability
	// gap-audit item #9): threshold rules over this node's OWN local obs_*
	// data, so a node with org sharing off still gets error-rate / cost / p95
	// alerting (org-side alerting in internal/orgserver/obsalert only fires on
	// pushed summaries). Zero value = off. Default false because a fired alert
	// makes an outbound webhook call — explicit opt-in keeps the node
	// egress-free by default.
	Alerts ObservabilityAlertsConfig `toml:"alerts"`

	// Egress configures Plane-A policy egress routing (G22): after admission
	// judges a request, a policy layer may route it to an alternate declared
	// upstream, swap to a cheaper same-shape model, degrade effort, or deny —
	// composed on top of the admission verdict. LOCAL-ONLY, DEFAULT OFF (zero
	// value, same partial-merge rule as the other observability blocks). The
	// obs_egress_decisions audit table is node-local, never pushed.
	Egress ObservabilityEgressConfig `toml:"egress"`

	// ProxyTurnTraces is the "gateway rail" (docs/observability.md "proxy
	// turn (automatic)"): when true (and Enabled is true), a proxied LLM
	// turn that arrived on an explicit /up/<id> upstream lane — the lane a
	// co-resident hosted app is pointed at (e.g. Open WebUI via
	// /up/openrouter) — is synthesized into an obs_traces/obs_spans pair
	// (chat.turn/chat.completions) at insert time, so it appears in the org
	// Trajectory explorer without the app instrumenting anything.
	//
	// PLANE BOUNDARY: synthesis covers ONLY /up/<id> lane traffic. The
	// default provider lanes (ANTHROPIC_BASE_URL, codex base_url, gemini)
	// carry Plane-B coding agents, whose rail is api_turns → sessions → the
	// coding-agent org rollups; they must never appear in the Hosted Apps
	// (Plane A) Trajectory explorer. An earlier all-lanes default mixed the
	// two planes (operator-reported, 2026-08-13) and was reversed. Residual:
	// a coding agent deliberately routed through a /up/ lane (hermes →
	// OpenRouter) still synthesizes; disable this key or give that agent a
	// dedicated upstream id if that matters for your deployment.
	//
	// Default() seeds it true so the loader's partial-merge keeps it true
	// for an existing [observability] section that only sets `enabled` (the
	// CacheTrack partial-merge rule); it has no effect while Enabled is
	// false.
	ProxyTurnTraces bool `toml:"proxy_turn_traces"`
}

// ObservabilityEgressConfig is the [observability.egress] surface (G22, design
// §5). LOCAL-ONLY, never distributed; gated under [observability] enabled.
// DEFAULT OFF (zero value Enabled=false). Translated into the pure
// internal/obs/egress engine's PolicyInput AT THE BOUNDARY (obs_wire), so the
// pure package never imports internal/config.
type ObservabilityEgressConfig struct {
	// Enabled gates the whole egress layer. Default false.
	Enabled bool `toml:"enabled"`
	// Mode is off | advise | enforce. advise evaluates + logs the directive but
	// never applies it; enforce applies it on the proxy path. Empty ⇒ off.
	Mode string `toml:"mode"`
	// CooldownSeconds is the hold window for a same-session budget-band model
	// switch (design §3.6 / finding 11) — a cost switch is held within this
	// window; verdict/locality switches never hold. 0 = the boundary default.
	CooldownSeconds int `toml:"cooldown_seconds"`
	// Rules is the first-match-wins rule table.
	Rules []EgressRuleConfig `toml:"rules"`
	// Targets is the typed upstream target table (id + url + shape). A declared
	// shape is REQUIRED for any enforce-mode route_to_upstream (design finding
	// 6) — [proxy.upstreams] entries carry only URLs.
	Targets []EgressTargetConfig `toml:"targets"`
	// Cohorts is an optional end-user → cohort map (LOCAL-ONLY).
	Cohorts map[string]string `toml:"cohorts"`
}

// EgressRuleConfig is one [[observability.egress.rules]] entry.
type EgressRuleConfig struct {
	Name          string             `toml:"name"`
	When          EgressWhenConfig   `toml:"when"`
	Action        EgressActionConfig `toml:"action"`
	OnUnavailable string             `toml:"on_unavailable"` // fail_open | deny
	Reason        string             `toml:"reason"`
	ReasonCode    string             `toml:"reason_code"`
}

// EgressWhenConfig is a rule's matcher set. BudgetBandAtLeast is a pointer so a
// rule can distinguish "0.0 (zero-spend)" from "unset".
type EgressWhenConfig struct {
	VerdictAtLeast    string   `toml:"verdict_at_least"`
	Criterion         string   `toml:"criterion"`
	SeverityAtLeast   string   `toml:"severity_at_least"`
	ContentClass      string   `toml:"content_class"`
	ModelGlob         string   `toml:"model_glob"`
	Provider          string   `toml:"provider"`
	User              string   `toml:"user"`
	UserCohort        string   `toml:"user_cohort"`
	BudgetBandAtLeast *float64 `toml:"budget_band_at_least"`
	MinPromptTokens   int      `toml:"min_prompt_tokens"`
}

// EgressActionConfig is a rule's action — exactly one primary must be set
// (lint/compile-enforced).
type EgressActionConfig struct {
	RouteToUpstream string `toml:"route_to_upstream"`
	RouteToModel    string `toml:"route_to_model"`
	SetEffort       string `toml:"set_effort"`
	Deny            bool   `toml:"deny"`
	NoRoute         bool   `toml:"no_route"`
}

// EgressTargetConfig is one [[observability.egress.targets]] entry.
type EgressTargetConfig struct {
	ID    string `toml:"id"`
	URL   string `toml:"url"`
	Shape string `toml:"shape"` // anthropic | openai
}

// ObservabilityAlertsConfig is the [observability.alerts] surface. LOCAL-ONLY,
// never distributed; gated under [observability] enabled. It reuses the org
// alert-rule dialect (internal/orgserver/obsalert): metric ∈ error_rate |
// cost_usd | latency_p95_ms, a gt/gte comparator, a threshold, and a window —
// but node windows are in MINUTES (finer than the org's day windows). The
// evaluator loop + webhook client live in cmd/observer; the pure evaluation is
// internal/obs/alert; fired events persist to the node-local obs_alert_events
// table. No node-dashboard surface (obs is Plane-A/web2-only) — the CLI
// (`observer obs alerts`) + the webhook are the node surfaces.
type ObservabilityAlertsConfig struct {
	// Enabled gates the evaluator loop. Default false — a fired alert POSTs to
	// WebhookURL (an outbound network call), so alerting is explicit opt-in.
	Enabled bool `toml:"enabled"`
	// WebhookURL receives the fired-alert JSON payload (one POST per crossing).
	// Empty = record fired events (visible via `observer obs alerts`) but send
	// no webhook — the node stays egress-free.
	WebhookURL string `toml:"webhook_url"`
	// Email, when true, ALSO delivers each fired alert as an email through the
	// shared [email] channel (which must itself be enabled). This is the
	// per-consumer opt-in mirroring WebhookURL — an ADDITIONAL delivery target,
	// not a replacement. Default false.
	Email bool `toml:"email"`
	// EmailTo overrides the [email].to default recipients for this node's alert
	// emails. Empty falls back to [email].to.
	EmailTo []string `toml:"email_to"`
	// EvalIntervalMinutes is how often the evaluator ticks. 0 defaults to 5.
	EvalIntervalMinutes int `toml:"eval_interval_minutes"`
	// Rules is the locally-authored rule table.
	Rules []ObservabilityAlertRuleConfig `toml:"rules"`
}

// ObservabilityAlertRuleConfig is one node alert rule. Mirrors the org
// obs_alert_rules row shape (name / metric / comparator / threshold / window /
// cooldown), with the window/cooldown expressed in minutes.
type ObservabilityAlertRuleConfig struct {
	// Name identifies the rule in fired events + the CLI.
	Name string `toml:"name"`
	// Metric ∈ error_rate | cost_usd | latency_p95_ms.
	Metric string `toml:"metric"`
	// Comparator ∈ gt | gte. Empty defaults to gt.
	Comparator string `toml:"comparator"`
	// Threshold is the value the metric is tested against.
	Threshold float64 `toml:"threshold"`
	// WindowMinutes is the lookback the metric is computed over. 0 defaults to
	// 60 at evaluation.
	WindowMinutes int `toml:"window_minutes"`
	// CooldownMinutes is the minimum gap between fires of this rule (dedup). 0
	// defaults to WindowMinutes (a full window must elapse before re-firing).
	CooldownMinutes int `toml:"cooldown_minutes"`
}

// ObservabilityJudgeConfig is one OpenAI-compatible /chat/completions judge
// binding (the eval/admission shared shape, admission spec §5). LOCAL-ONLY.
// The key is NEVER written to disk: APIKeyEnv names the env var holding it
// (the pi/hermes launcher posture). Zero value = judge unbound (llm_judge
// scorer / admission judge criteria are simply unavailable; code / pre-filter
// layers still run offline).
type ObservabilityJudgeConfig struct {
	// Model names the judge model. Empty = judge disabled.
	Model string `toml:"model"`
	// BaseURL is the OpenAI-compatible chat-completions base URL. Empty
	// defaults to OpenRouter (https://openrouter.ai/api/v1) at the binding.
	BaseURL string `toml:"base_url"`
	// APIKeyEnv names the ENV VAR holding the judge API key — never the key
	// itself. Empty defaults to OPENROUTER_API_KEY. Loopback/local judges
	// need no key (the binding treats a loopback base_url as no-egress and
	// allows an empty/unset key).
	APIKeyEnv string `toml:"api_key_env"`
	// TimeoutMS bounds a single judge call. 0 = the binding's default.
	TimeoutMS int `toml:"timeout_ms"`
	// MaxTokens caps the judge REPLY length (the reply is only a short JSON
	// verdict). 0 = the binding's default. A tight cap bounds latency + cost
	// on a hosted judge and stops a chatty local model from streaming forever.
	MaxTokens int `toml:"max_tokens"`
	// NumCtx is an Ollama-style context-window hint passed through ONLY to a
	// loopback/local judge (a hosted OpenAI-compatible API rejects unknown
	// fields, so it is never sent remotely). 0 = omit. Its effect depends on
	// the local host honoring the field on its /v1/chat/completions endpoint.
	NumCtx int `toml:"num_ctx"`
	// UseOrgRelay routes the judge call through the org server's
	// POST /api/agent/judge instead of an OpenAI-compatible endpoint held
	// locally (C1 judge relay, docs/plans/c1-judge-relay-spec-2026-08-15.md
	// §3). The gateway never holds a judge-provider credential in this mode —
	// the org server resolves its own sealed provider credential. Model stays
	// optional under relay: it rides as an optional model_hint (recorded
	// only; the org's provider selection decides the actual model).
	// Validated mutually exclusive with a non-empty BaseURL/APIKeyEnv on the
	// same resolved block (ambiguous transport).
	UseOrgRelay bool `toml:"use_org_relay"`
}

// ObservabilityAdmissionConfig is the [observability.admission] surface
// (admission spec §4). LOCAL-ONLY, never distributed; gated under
// [observability] enabled. Observe-first: Mode defaults to "observe" only
// once Enabled is set — the zero value (Enabled=false) is fully off.
type ObservabilityAdmissionConfig struct {
	// Enabled gates admission WITHIN the obs subsystem. Default false.
	Enabled bool `toml:"enabled"`
	// Mode is off | observe | enforce. P1 ships observe only; enforce is P2.
	// Empty is treated as "observe" when Enabled.
	Mode string `toml:"mode"`
	// Strict = fail-closed on judge error/timeout (Deny). Default false =
	// fail-open (Allow + recorded admission_error). BACK-COMPAT ALIAS: prefer
	// OnJudgeError, which is the explicit posture enum. When OnJudgeError is
	// empty, Strict resolves the posture (strict=true → fail_closed); when
	// OnJudgeError is set, it wins and Strict is ignored.
	Strict bool `toml:"strict"`
	// OnJudgeError is the explicit judge-unavailable posture:
	// "fail_open" (Allow, today's default) or "fail_closed" (Deny). Empty =
	// resolve from Strict. This is the enum form of Strict; the invasive
	// request-queueing posture is deliberately NOT offered here (it would need
	// a new proxy admit-result shape). LOCAL-ONLY, never distributed.
	OnJudgeError string `toml:"on_judge_error"`
	// JudgeRetries is how many EXTRA bounded in-process attempts the admission
	// engine makes on a judge transport error before the posture fires. 0 =
	// no retry (today's behavior). A cheap reliability lever for a flaky or
	// cold-starting judge; it does not change the synchronous verdict contract.
	JudgeRetries int `toml:"judge_retries"`
	// Scope is last_user | conversation. P1 = last_user; conversation is P3.
	Scope string `toml:"scope"`
	// RetentionDays bounds the obs_admission_events audit table. 0 = keep.
	RetentionDays int `toml:"retention_days"`
	// Criterion is the admin's policy table (§4).
	Criterion []AdmissionCriterionConfig `toml:"criterion"`
	// Judge overrides the shared [observability.judge] for admission only.
	// Zero value = fall back to [observability.judge].
	Judge ObservabilityJudgeConfig `toml:"judge"`
	// Prefilter holds the deterministic allow/deny lists + size ceiling.
	Prefilter AdmissionPrefilterConfig `toml:"prefilter"`
	// SecretRemoteJudge is the local decision (allow|flag|ask|deny) applied
	// when the request carries a pattern-certain secret AND the judge is
	// REMOTE — the request is NOT egressed to the hosted judge; the configured
	// decision is returned locally instead (spec §3 layer 3). Empty/"allow" =
	// off (the request still goes to the — already secret-scrubbed, §item 8 —
	// remote judge). Inert for a local/off judge.
	SecretRemoteJudge string `toml:"secret_remote_judge"`
	// CacheTTLS is the verdict-cache TTL in seconds. 0 = the svc default.
	CacheTTLS int `toml:"cache_ttl_s"`
	// JudgeChunkBytes bounds a single judge call's content size: a request
	// longer than this is split into overlapping windows, each judged, and the
	// verdicts reduced strictest-wins (map-reduce, spec §4 — mirrors the demo's
	// app-layer chunking, now in-core). 0 = the engine default (3500).
	JudgeChunkBytes int `toml:"judge_chunk_bytes"`
	// JudgeChunkOverlapBytes is the overlap between adjacent judge windows so a
	// concern straddling a boundary is still seen whole by one chunk. 0 = the
	// engine default (200); clamped below JudgeChunkBytes.
	JudgeChunkOverlapBytes int `toml:"judge_chunk_overlap_bytes"`
	// IncludeReasoning asks the judge to explain (OpenAI's ~40% latency
	// finding — default false).
	IncludeReasoning bool `toml:"include_reasoning"`
	// Budget is the per-end-user spend guardrail evaluated at the admission
	// chokepoint (the org-hosted-app model: the budgeted subject is an
	// end-user of the hosted app, identified by the app-shared enduser.id /
	// the admission `user` field → obs_traces.user; spend is summed from
	// obs_spans.cost_usd). Off by default.
	Budget AdmissionBudgetConfig `toml:"budget"`
}

// AdmissionBudgetConfig is the per-end-user spend guardrail evaluated at the
// admission chokepoint (docs/guardrails.md; org-budget plan §1). A window
// breach yields a Deny verdict: in observe mode it is recorded as a shadow
// "would-deny"; enforce blocks (P2). It requires the app to share the end-user
// identity (enduser.id / the admission `user` field); an anonymous request is
// inert. A 0 cap disables that window; Enabled=false disables the gate.
//
// PLANE A budget (docs/deployment-models.md): caps a HOSTED-APP END-USER's
// spend at the admission chokepoint. Distinct from the two Plane-B budgets:
// [guard.budget] (GuardBudgetConfig — the DEVELOPER's own provider spend) and
// [routing.budget] (RoutingBudgetConfig — the routing spend-band downshift).
type AdmissionBudgetConfig struct {
	Enabled           bool    `toml:"enabled"`
	PerUser5hUSD      float64 `toml:"per_user_5h_usd"`
	PerUserWeeklyUSD  float64 `toml:"per_user_weekly_usd"`
	PerUserMonthlyUSD float64 `toml:"per_user_monthly_usd"`
	// UserHeader names the request header the proxy pre-forward backstop reads
	// the end-user identity from — the app shares it as an integration
	// requirement (the SDK path passes `user` directly and ignores this).
	// Empty → DefaultAdmissionUserHeader. Absent header ⇒ the per-end-user gate
	// is inert for that request (the app-wide policy still applies).
	UserHeader string `toml:"user_header"`
}

// DefaultAdmissionUserHeader is the request header the proxy admission backstop
// reads the end-user identity from when [observability.admission.budget]
// user_header is unset.
const DefaultAdmissionUserHeader = "X-Superbased-User"

// AdmissionCriterionConfig is one policy criterion (§4). type ∈
// valid_use_case | denied_topics | jailbreak | custom (the pure package
// resolves the vocabulary). Topics apply to denied_topics; Definition to the
// judged types.
type AdmissionCriterionConfig struct {
	ID         string   `toml:"id"`
	Type       string   `toml:"type"`
	Name       string   `toml:"name"`
	Definition string   `toml:"definition"`
	Topics     []string `toml:"topics"`
	Decision   string   `toml:"decision"`
	Severity   string   `toml:"severity"`
}

// AdmissionPrefilterConfig is the deterministic pre-filter layer (§3 layers
// 1-2). Allow/Deny are regex-or-prefix patterns; MaxMessageBytes caps length
// (0 = off).
type AdmissionPrefilterConfig struct {
	Allow           []string `toml:"allow"`
	Deny            []string `toml:"deny"`
	MaxMessageBytes int      `toml:"max_message_bytes"`
}

// ObservabilityEvalConfig configures the obs eval plane (plan §8). LOCAL-ONLY,
// never distributed. Online sampling is off by default (OnlineSampleRate 0).
type ObservabilityEvalConfig struct {
	// OnlineSampleRate, in (0,1], runs OnlineScorers over that fraction of
	// live LLM spans as they ingest (the Langfuse/Arize online-eval model).
	// 0 (default) disables online sampling entirely.
	OnlineSampleRate float64 `toml:"online_sample_rate"`
	// OnlineScorers are the scorer specs run during online sampling, each a
	// string "name" or "name:key=val,key2=val2". Only facts-based code
	// scorers make sense online (status_ok / latency_under / cost_under) —
	// content scorers need a stored body. Empty disables online sampling.
	OnlineScorers []string `toml:"online_scorers"`
	// JudgeModel names the model an llm_judge scorer uses by default (when a
	// scorer spec omits its own model=). Empty disables the LLM judge: the
	// host JudgeClient stays unbound, llm_judge errors clearly, and code
	// scorers run fully offline. The judge call is the ONLY outbound network
	// in the subsystem and runs ONLY for an explicitly-invoked `observer eval
	// run` (never the daemon/online-sampling path).
	JudgeModel string `toml:"judge_model"`
	// JudgeBaseURL is the OpenAI-compatible chat-completions base URL the
	// judge posts to. Empty defaults to OpenRouter (https://openrouter.ai/api/v1).
	JudgeBaseURL string `toml:"judge_base_url"`
	// JudgeAPIKeyEnv names the ENVIRONMENT VARIABLE holding the judge API key
	// — the key is never written to config or disk (the pi/hermes launcher
	// posture). Empty defaults to OPENROUTER_API_KEY.
	JudgeAPIKeyEnv string `toml:"judge_api_key_env"`
}

// GuardConfig is the full [guard] surface (guard spec §16). Same
// partial-merge invariant as CacheTrackConfig: an install with no
// [guard] section gets Enabled=true + Mode="observe" from Default()
// — never a zero-valued false/"" (operator decision D2: fresh
// installs observe and alert; nothing blocks until the operator
// flips enforce).
//
// Sub-sections gate later G-commits (proxy G9, mcp G10, budget G12,
// dialects G11, cloud G15); they are declared now so the config
// vocabulary is stable and a forward-written config file round-trips.
type GuardConfig struct {
	// Enabled gates all guard wiring (ingest seam, hook seam, CLI
	// surfaces). When false, no policy engine is constructed and no
	// guard_events are written.
	Enabled bool `toml:"enabled"`
	// Mode is the global posture: "off" | "observe" | "enforce"
	// (default "observe", D2). In observe, deny/ask-class verdicts
	// are recorded + alerted but the action proceeds.
	Mode string `toml:"mode"`
	// Strict inverts the Q2 fail-open default: a guard internal
	// error then blocks instead of approving. Enterprise posture;
	// default false.
	Strict bool `toml:"strict"`
	// RetentionDays is the guard_events / expired-approvals prune
	// horizon (spec §10.3). Default 365 — audit data wants ≥1y for
	// compliance buyers. ≤0 disables the guard prune.
	RetentionDays int `toml:"retention_days"`

	Rules    GuardRulesConfig    `toml:"rules"`
	Boundary GuardBoundaryConfig `toml:"boundary"`
	Taint    GuardTaintConfig    `toml:"taint"`
	Proxy    GuardProxyConfig    `toml:"proxy"`
	MCP      GuardMCPConfig      `toml:"mcp"`
	Budget   GuardBudgetConfig   `toml:"budget"`
	Alerts   GuardAlertsConfig   `toml:"alerts"`
	Export   GuardExportConfig   `toml:"export"`
	Dialects GuardDialectsConfig `toml:"dialects"`
	Cloud    GuardCloudConfig    `toml:"cloud"`
	Prompt   GuardPromptConfig   `toml:"prompt"`
}

// GuardRulesConfig is [guard.rules] (spec §16): rule disabling and
// the user/project policy-file locations.
type GuardRulesConfig struct {
	// Disable lists rule IDs turned off entirely.
	Disable []string `toml:"disable"`
	// UserPolicy is the user policy file location. Default
	// "~/.observer/guard-policy.toml".
	UserPolicy string `toml:"user_policy"`
	// ProjectPolicy is the project policy file location relative to
	// each project root. Default ".observer/guard-policy.toml".
	ProjectPolicy string `toml:"project_policy"`
	// OrgBundle is the local cache location of the verified org
	// policy bundle envelope (guard spec §14.2). Default
	// "~/.observer/org-policy-bundle.json". Written ONLY by the org
	// client after full signature + key-pin verification; read by
	// every guard construction (daemon and hook processes alike) as
	// the org policy layer, with the signature re-checked at load.
	// The file is absent on non-enrolled installs — absence simply
	// means no org layer.
	OrgBundle string `toml:"org_bundle"`
	// CEL is the Q1 v2 gate for CEL-expression user rules. Parsed
	// but rejected by the loader until the v2 arc lands (decided:
	// matchers v1, CEL deferred).
	CEL bool `toml:"cel"`
}

// GuardBoundaryConfig is [guard.boundary] (spec §16). Nil slices mean
// "use the policy-engine defaults" (policy.DefaultAllowPaths /
// DefaultProtectedBranches); explicitly empty lists mean "none".
type GuardBoundaryConfig struct {
	AllowPaths        []string `toml:"allow_paths"`
	ProtectedBranches []string `toml:"protected_branches"`
}

// GuardTaintConfig is [guard.taint] (spec §4.5, §16).
type GuardTaintConfig struct {
	// Enabled gates taint tracking + the T-5xx rules' input (with
	// tracking off the snapshot is always empty, so taint rules
	// never fire).
	Enabled bool `toml:"enabled"`
	// DecayTurns is the mark lifetime in session turns. Default 10.
	DecayTurns int `toml:"decay_turns"`
}

// GuardProxyConfig is [guard.proxy] (spec §8, lands G9).
type GuardProxyConfig struct {
	// EgressScan gates the §8.2 typed secret scan over the final
	// outbound request body.
	EgressScan bool `toml:"egress_scan"`
	// EgressAction is the enforce-class action when the R-172
	// api_request verdict blocks: "flag" (record only), "mask"
	// (rewrite detector-certain values to [REDACTED:type] and
	// forward; entropy hits never mask), "deny" (synthetic 403,
	// §8.5). Default "mask" per §8.2 ("mask mode default-on in
	// enforce for detector-certain types") — inert in observe mode,
	// where every egress verdict is a flag (D2).
	EgressAction string `toml:"egress_action"` // flag | mask | deny
	// EgressAllow are regex patterns over the MATCHED VALUE: a
	// finding whose value matches is ignored entirely (test
	// fixtures, known-fake keys). Compiled by the guard layer;
	// invalid patterns degrade to load issues. Global in G9 —
	// per-project egress_allow joins when the project policy
	// vocabulary grows a proxy section (deferred, documented).
	EgressAllow []string `toml:"egress_allow"`
	// ResponseScan gates the §8.3 response-side tool_use inspection
	// (flag/alert only in v1).
	ResponseScan bool `toml:"response_scan"`
	// InjectionHeuristics gates the §8.4 prompt-injection heuristics
	// on inbound tool-result/web content (flag + taint, never deny).
	InjectionHeuristics bool `toml:"injection_heuristics"`
}

// GuardMCPConfig is [guard.mcp] (spec §9, lands G10).
type GuardMCPConfig struct {
	Pinning             bool `toml:"pinning"`
	PoisoningHeuristics bool `toml:"poisoning_heuristics"`
}

// GuardBudgetConfig is [guard.budget] (spec §12.1, lands G12). 0
// means off.
//
// PLANE B budget (docs/deployment-models.md): caps the DEVELOPER's OWN
// provider spend on their coding-agent turns. Distinct from [routing.budget]
// (RoutingBudgetConfig — the routing spend-band downshift, also Plane B) and
// from the Plane-A [observability.admission.budget] (AdmissionBudgetConfig —
// a hosted-app END-USER's spend at the admission chokepoint).
type GuardBudgetConfig struct {
	SessionUSD float64 `toml:"session_usd"`
	DailyUSD   float64 `toml:"daily_usd"`
	// WeeklyUSD / MonthlyUSD are $ ceilings over a rolling 7-day
	// window and the calendar month (rules B-604 / B-603), enforced
	// with the same deny-on-proxy discipline as SessionUSD/DailyUSD.
	// 0 disables the window.
	WeeklyUSD  float64 `toml:"weekly_usd"`
	MonthlyUSD float64 `toml:"monthly_usd"`
	// SessionTokens / DailyTokens / WeeklyTokens / MonthlyTokens are the
	// TOKEN-denominated siblings of the four $ ceilings above, one for one
	// (org-budget plan §3.3c, rules B-621..B-624). 0 disables the window,
	// exactly like the $ fields — 0 is "unset", never a cap of zero.
	//
	// They exist because a token cap is the denomination an org budget is
	// authored in (the plan's R3): tokens are the unit the org can enforce
	// without a rate card, and `int` is the only numeric kind the governance
	// pin vocabulary carries, so a token cap is expressible end to end where a
	// float USD cap is not.
	SessionTokens int64 `toml:"session_tokens"`
	DailyTokens   int64 `toml:"daily_tokens"`
	WeeklyTokens  int64 `toml:"weekly_tokens"`
	MonthlyTokens int64 `toml:"monthly_tokens"`
	Hard          bool  `toml:"hard"`
	// FromOrg opts this node into applying the ORGANIZATION's budget, fetched
	// per caller from GET /api/agent/budget (org-budget plan §3.3c). Default
	// false: with it off the node behaves byte-identically to a build that
	// never had this feature.
	//
	// With it on, the composition is capability-branched, never
	// source-branched: on an INDIVIDUAL node the org's numbers may only LOWER
	// the four thresholds above (govern.LowerFloat / LowerInt — min with the
	// "0 means unset" rule); on a MANAGED node whose grant carries
	// govern.AuthorityEnforceBudget the org's numbers and enforcement mode are
	// authoritative. Both this key and Hard are pinnable through node
	// governance (internal/policyfam/nodegov.PinnableKeys) so an org can set
	// the fleet's POSTURE; the NUMBERS never ride the pin rail, because a pin
	// is one value for a whole fleet and a cap is per developer.
	//
	// The node-side fetch/compose/enforce half is wave W3b; this key exists in
	// W3a because the governance vocabulary row must resolve against a real
	// config key (TestEveryPinnableKeyResolvesInConfig).
	FromOrg bool `toml:"from_org"`
	// MaxDocumentAge is the freshness window a SIGNED org budget document
	// must fall inside to be applied: the node refuses a 200 whose issued_at
	// is older than this, or in the future beyond a small clock skew. A Go
	// duration string ("1h", "30m"); empty means the 1h default, and an
	// unparsable value also falls back to the default rather than disabling
	// the check.
	//
	// It closes the REPLAY window the signature alone cannot (fundamentals
	// finding M3). Version monotonicity refuses an OLDER document, but an
	// EQUAL-version one is legitimately re-served on every poll — so an
	// intermediary holding yesterday's correctly signed explicit-none can
	// replay it against a node whose cache is cold (a restart, a fresh
	// install) and that node would run uncapped, believing the org said so.
	// A timestamp INSIDE the signed body is the only thing that dates the
	// document, and the org is the only party that can mint a fresh one.
	//
	// Tighter is safer but not free: the value must exceed the poll interval
	// or a node that misses one cycle starts refusing documents it should
	// accept.
	MaxDocumentAge string `toml:"max_document_age"`
	// Window gates on the provider's own 5h / weekly usage windows
	// (utilization 0..1, read from limit_snapshots) — distinct from
	// the $ caps above; the "limit" guardrails B-610..B-613.
	Window GuardBudgetWindowConfig `toml:"window"`
}

// GuardBudgetWindowConfig is [guard.budget.window] (spec §12.1) —
// utilization thresholds (0..1) over the provider's unified 5h and
// weekly usage windows. warn flags, deny blocks (proxy). 0 disables
// the threshold. deny must be >= warn when both are set.
type GuardBudgetWindowConfig struct {
	Util5hWarn     float64 `toml:"util_5h_warn"`
	Util5hDeny     float64 `toml:"util_5h_deny"`
	UtilWeeklyWarn float64 `toml:"util_weekly_warn"`
	UtilWeeklyDeny float64 `toml:"util_weekly_deny"`
}

// GuardAlertsConfig is [guard.alerts] (spec §16, lands G5).
type GuardAlertsConfig struct {
	// Desktop enables exec-based desktop notifications (Q3).
	Desktop bool `toml:"desktop"`
	// MinSeverity is the alert threshold: "info" | "warn" | "high" |
	// "critical". Default "high".
	MinSeverity string `toml:"min_severity"`
}

// GuardExportConfig is [guard.export] (spec §11.4, lands G16).
type GuardExportConfig struct {
	OTel bool `toml:"otel"`
}

// GuardDialectsConfig is [guard.dialects] (spec §13.2, lands G11).
type GuardDialectsConfig struct {
	Compile bool     `toml:"compile"`
	Targets []string `toml:"targets"`
}

// GuardCloudConfig is [guard.cloud] (spec §15, lands G15). EVERYTHING
// here requires explicit opt-in (operator decision D1); the master
// Enabled plus per-feature switches all default false.
type GuardCloudConfig struct {
	Enabled         bool                  `toml:"enabled"`
	LLMJudge        GuardLLMJudgeConfig   `toml:"llm_judge"`
	Reputation      GuardReputationConfig `toml:"reputation"`
	Webhooks        []GuardWebhookConfig  `toml:"webhooks"`
	PayloadMaxBytes int                   `toml:"payload_max_bytes"`
}

// GuardLLMJudgeConfig configures the §15.2 LLM-judge reviewer.
// Endpoint is an OpenAI-chat-completions-compatible URL (bring-your-
// own: a local gateway, litellm, or the user's own proxied provider
// session). APIKeyEnv names an ENVIRONMENT VARIABLE holding the
// bearer key — never the key itself (the no-secrets-in-config rule);
// empty means the endpoint authenticates locally or not at all.
type GuardLLMJudgeConfig struct {
	Enabled   bool   `toml:"enabled"`
	Endpoint  string `toml:"endpoint"`
	Model     string `toml:"model"`
	APIKeyEnv string `toml:"api_key_env"`
}

// GuardReputationConfig configures the §15.3 reputation lookups.
type GuardReputationConfig struct {
	Enabled bool `toml:"enabled"`
}

// GuardWebhookConfig is one [[guard.cloud.webhooks]] entry (§15.4).
// RoutingKey is PagerDuty's Events-API v2 routing key (kind =
// "pagerduty" only; URL then stays the standard events endpoint).
type GuardWebhookConfig struct {
	URL         string `toml:"url"`
	Kind        string `toml:"kind"` // generic | slack | discord | pagerduty
	MinSeverity string `toml:"min_severity"`
	RoutingKey  string `toml:"routing_key"`
}

// AdvisorConfig gates the suggestions engine (docs/advisor.md; plan
// docs/plans/suggestions-engine-implementation-plan-2026-06-10.md).
// "§15.7" is the engine's long-standing informal handle used across
// docs/plans — the numbered spec itself only goes to §15.6, so this
// comment cites the operator doc instead of a section that doesn't exist.
// Default-ON: read-layer only, local, zero LLM cost. Same partial-merge
// invariant as CacheTrackConfig — an install with no [advisor] section
// must get Enabled=true from Default(), never a zero-valued false.
type AdvisorConfig struct {
	// Enabled gates the /api/suggestions endpoint, the dashboard tab's
	// data, and `observer advise`.
	Enabled bool `toml:"enabled"`
	// WindowDays is the default evidence window. Default 14.
	WindowDays int `toml:"window_days"`
	// MinConfidence hides suggestions below this floor. Default 0.5.
	MinConfidence float64 `toml:"min_confidence"`
	// MinSavingsUSD hides cost suggestions claiming less than this
	// (calibration T7). Default 1.0.
	MinSavingsUSD float64 `toml:"min_savings_usd"`
	// SessionDigest, when true, lets the Claude Code session-start hook
	// inject a ≤400-token advisory digest (top suggestions) as
	// additionalContext. Default OFF until proven quiet (plan Phase 3).
	// The hook only point-reads the advisor_digest snapshot — it never
	// computes (P1).
	SessionDigest bool `toml:"session_digest"`
	// DigestRefreshMinutes is the daemon's advisor_digest refresh
	// cadence. Default 30.
	DigestRefreshMinutes int `toml:"digest_refresh_minutes"`
}

// DefaultAggregateEndpoint is the published default collector endpoint for
// the opt-in aggregate rail (design §9.2). It is seeded by Default() so a
// partial-merge install inherits it; a change to a non-approved host requires
// [aggregate_share].allow_custom_endpoint AND invalidates the consent receipt.
const DefaultAggregateEndpoint = "https://aggregate.superbased.app/v1/submit"

// approvedAggregateHosts is the closed set of hosts the aggregate rail may
// submit to without the self-host/testing escape (design §9.2, finding #21).
var approvedAggregateHosts = map[string]bool{
	"aggregate.superbased.app": true,
}

// AggregateShareConfig is the [aggregate_share] surface — the opt-in aggregate
// rail (docs/plans/g25-optin-aggregate-rail-design-2026-07-11.md §9.2). It is
// OPT-IN and default OFF in EVERY path: the zero value has Enabled=false, and
// the loader's partial-merge default (Default()) also leaves Enabled=false —
// only Endpoint is seeded to the published constant. Unlike CacheTrack/Predict
// (default-ON), the whole rail stays inert until the operator consents via
// `observer aggregate enable`. Deliberately TOP-LEVEL (not under [org_client])
// because it is org-independent — it works for solo nodes and never touches
// the Teams wire.
type AggregateShareConfig struct {
	// Enabled gates the whole rail. Default FALSE (zero value AND partial-
	// merge). Even when true, the daemon submits only while a valid consent
	// receipt exists (design §9.1/§9.3) — enabling in config alone never
	// bypasses consent.
	Enabled bool `toml:"enabled"`
	// Endpoint is the collector URL the coarsened monthly aggregate would be
	// POSTed to. Validated at load: HTTPS-only, no credentials/query, host on
	// the approved list unless AllowCustomEndpoint. A change invalidates the
	// consent receipt (re-consent required). Default DefaultAggregateEndpoint.
	Endpoint string `toml:"endpoint"`
	// AllowCustomEndpoint is the explicit self-host / testing escape (design
	// §9.2): only with it true may Endpoint point at a non-approved host.
	// Default false.
	AllowCustomEndpoint bool `toml:"allow_custom_endpoint"`
}

// PredictConfig is the [predict] surface — the Next-Message Cost &
// Limit Predictor (docs/cost-predictor.md). Default-ON, same partial-
// merge invariant as CacheTrackConfig: an install with no [predict]
// section gets Enabled=true (NOT a zero-valued false) because Load()
// starts from Default() and unmarshals TOML on top. LOCAL-ONLY — never
// distributed to an org server.
type PredictConfig struct {
	// Enabled gates the predictor. The cost estimate is pure read-side
	// math (no cost when unused); when false the proxy also skips
	// limit-snapshot capture and the dashboard/CLI surfaces stay empty.
	Enabled bool `toml:"enabled"`
	// YoungSessionMessages is the §0 T-ladder threshold: at/above this
	// many observed user messages the session's own turns-per-message
	// distribution is trusted; below it the cross-session prior wins.
	// Default 3.
	YoungSessionMessages int `toml:"young_session_messages"`
	// DefaultTurnsPerMessage is the tier-3 fallback fan-out when neither
	// the session nor a prior yields turns-per-message. Default 12.
	DefaultTurnsPerMessage int `toml:"default_turns_per_message"`
	// PriorWindowDays bounds the recency of sessions feeding the
	// cross-session T prior. Default 30. 0 = no bound.
	PriorWindowDays int `toml:"prior_window_days"`
}

// GuidanceConfig is the [guidance] surface — the agent-guidance-file
// inventory (CLAUDE.md / AGENTS.md / .cursor/rules / skills / commands /
// subagent definitions and their per-tool equivalents). LOCAL-ONLY: the
// scan records file NAMES, sizes, hashes and frontmatter metadata, never
// file bodies (CLAUDE.md "no content in the DB" rule — a body is read on
// demand through the capped, symlink-safe fsview reader instead).
//
// Default-ON, with the CacheTrack partial-merge rule: an install whose
// config.toml has no [guidance] section MUST get Enabled=true from
// Default(), not a zero-valued false, and a section that sets only
// rescan_minutes must keep Enabled=true.
type GuidanceConfig struct {
	// Enabled gates the daemon-lifetime scan loop, the CLI's implicit
	// scan, and the dashboard/MCP read surfaces. When false nothing is
	// scanned and the surfaces report the disabled state honestly.
	Enabled bool `toml:"enabled"`
	// RescanMinutes is the interval between whole-estate rescans (every
	// known project root). Default 15. <= 0 disables the periodic tick —
	// the one-shot scan at daemon start still runs.
	RescanMinutes int `toml:"rescan_minutes"`
	// MaxFileBytes caps how much of a guidance file the scanner reads to
	// hash it and parse its frontmatter. Default 524288 (512KB). A larger
	// file is still inventoried; only its parse is bounded.
	MaxFileBytes int64 `toml:"max_file_bytes"`
	// MaxDepth bounds directory recursion below a guidance root (e.g.
	// `.claude/skills/<name>/SKILL.md`). Default 4.
	MaxDepth int `toml:"max_depth"`
	// IncludeUserScope also inventories the operator's HOME-scoped
	// guidance (`~/.claude/CLAUDE.md`, `~/.claude/skills/…`) alongside the
	// project-scoped files. Default true — a user-scope skill changes the
	// agent's behaviour in this project just as much as a project one.
	IncludeUserScope bool `toml:"include_user_scope"`
	// MaxRootsPerPass caps how many project roots one pass walks. Roots
	// are ordered most-recently-active first, so the cap drops the
	// dormant tail; the tail is not starved, because each pass rotates
	// its start offset. Default 50. <= 0 means the seeded default.
	//
	// It was 200 (a compile-time constant) until a live machine with 404
	// recorded roots — most of them slow DrvFs mounts — turned a start-up
	// pass into four CPU-minutes.
	MaxRootsPerPass int `toml:"max_roots_per_pass"`
	// RootTimeoutSeconds bounds ONE root's walk. A root that overruns is
	// reported incomplete and NOT persisted — a partial inventory would
	// tombstone guidance files that are still there — and is retried on
	// the next pass. Default 20. <= 0 means the seeded default; there is
	// deliberately no "unbounded" setting, because an unbounded root is
	// exactly the failure this bounds.
	RootTimeoutSeconds int `toml:"root_timeout_seconds"`
	// RootTimeoutMaxSeconds is the ADAPTIVE CEILING for a root's walk. A
	// root that overruns RootTimeoutSeconds is granted a larger budget on
	// its next pass (doubling per consecutive overrun) up to this ceiling,
	// so a legitimately slow-but-real root — e.g. a large repo on a slow
	// DrvFs mount — is given the time to finish and finally persist, rather
	// than overrunning the same fixed budget forever and never landing its
	// inventory. Default 180. <= 0 means the seeded default; a positive
	// value below RootTimeoutSeconds is refused by Validate (the ceiling can
	// never be below the base). 180s gives real headroom over the ~106s a
	// live DrvFs walk took while still bounding a runaway.
	RootTimeoutMaxSeconds int `toml:"root_timeout_max_seconds"`
	// PassTimeoutMinutes bounds a WHOLE pass. Roots not reached inside it
	// are simply picked up next tick. Default 10. <= 0 means the seeded
	// default.
	PassTimeoutMinutes int `toml:"pass_timeout_minutes"`
	// StartupDelaySeconds delays the first pass after the daemon starts,
	// so a restart is not immediately CPU-heavy while the proxy, watcher
	// and dashboard are coming up. Default 90. <= 0 runs the first pass
	// immediately.
	StartupDelaySeconds int `toml:"startup_delay_seconds"`
	// FirstScanPollSeconds is how often the daemon looks for project roots
	// that have NEVER been scanned and inventories just those, so a brand
	// new project does not wait up to RescanMinutes for its first (and
	// only informative) inventory. Default 60. 0 disables the poll
	// entirely; the periodic pass still covers the root eventually.
	//
	// It is deliberately NOT a per-session trigger: a scan is filesystem
	// work, and firing one every time a session starts in an
	// already-inventoried project would be the same unbounded cost the
	// per-root/per-pass budgets exist to prevent. Never-scanned is the one
	// state where waiting a quarter of an hour shows the operator nothing.
	FirstScanPollSeconds int `toml:"first_scan_poll_seconds"`
}

// DefaultPricingFeedURL is the public edge route serving the signed pricing
// feed (docs/plans/pricing-sync-tokenomics-to-platform-plan-2026-09-11.md §B.4).
// The body names no org and no subject, so it is cacheable and verified offline
// against the compiled-in PricingFeedPublicKeyV1.
const DefaultPricingFeedURL = "https://superbased.app/api/pricing/v1/observer-pricing"

// PricingSectionConfig is the [pricing] surface. It is a thin holder for the
// [pricing.feed] sub-block today (D7 chose a NEW top-level namespace over
// [intelligence.pricing.feed] so the feed reads as its own concern). LOCAL-ONLY.
type PricingSectionConfig struct {
	// Feed is the [pricing.feed] sub-block — the standalone-node pricing feed
	// client.
	Feed PricingFeedConfig `toml:"feed"`
}

// PricingFeedConfig is the [pricing.feed] surface — the OPT-IN pricing feed
// client for a STANDALONE (non-enrolled) node (plan §C.3). It is the ONLY case
// that needs a new node->internet path, and it is OFF by default in every path
// to preserve the zero-egress-by-default invariant (D3): with the zero value,
// and with this Default() seed, the node makes no feed call.
//
// An ENROLLED node (individual or managed) ignores this block entirely — it
// receives prices through the org rail, which is the one authority per enrolled
// node (§C.3/D8); the standalone-vs-enrolled resolution lives next to
// orgpricing.Mode (Wave N), not here.
//
// Same partial-merge invariant as CacheTrackConfig/PredictConfig: an install
// with no [pricing.feed] section gets the Default() seed (URL/interval set,
// Enabled=false), NOT a zero-valued struct, because Load() starts from
// Default() and unmarshals TOML on top. LOCAL-ONLY, never distributed.
type PricingFeedConfig struct {
	// Enabled gates the whole feed client. Default FALSE: the feed is inert
	// until the standalone operator opts in (with this, or with a manual
	// `observer pricing sync`). When false, no feed is fetched and no feed
	// source badge renders.
	Enabled bool `toml:"enabled"`
	// Auto turns on the BACKGROUND poller (in addition to the manual sync).
	// Default FALSE: even an Enabled node only fetches on an explicit
	// `observer pricing sync` until Auto is set, so the first outbound call is
	// always operator-initiated.
	Auto bool `toml:"auto"`
	// URL is the feed endpoint. Default DefaultPricingFeedURL (the public
	// edge); overridable for testing / a self-hosted mirror.
	URL string `toml:"url"`
	// PollIntervalHours is the Auto poller cadence. Default 24 (D2: the feed
	// moves daily at most and a 304 is cheap). Ignored when Auto is false.
	PollIntervalHours int `toml:"poll_interval_hours"`
}

// DefaultLocEditorTokenFile is where the daemon keeps the per-install
// editor-endpoint secret when [loc].editor_token_file is unset. It sits in
// the observer home beside observer.db and config.toml; Load() expands the
// leading "~/" the same way it does for observer.db_path.
const DefaultLocEditorTokenFile = "~/.observer/loc-editor-token" //nolint:gosec // G101: a PATH, not a credential

// LocConfig is the [loc] surface — lines-of-code tracking
// (docs/loc-tracking.md). LOCAL-ONLY, never distributed to an org server
// (same posture as [predict]/[routing]/[cachewarm]). Same partial-merge
// invariant as CacheTrackConfig: an install with no [loc] section gets
// the Default() seed, NOT the zero value, because Load() starts from
// Default() and unmarshals TOML on top.
//
// The block holds ONLY the editor-endpoint credential today. The
// classifier itself has no knobs: it runs over rows the store already
// holds and its behaviour is versioned by internal/loc.Version, not by
// config.
type LocConfig struct {
	// EditorTokenFile is where the daemon keeps the per-install shared
	// secret the VS Code extension sends as X-Observer-Token on
	// POST /api/loc/editor-change. The daemon GENERATES the file on
	// first start (32 random bytes, hex, mode 0600) and never logs its
	// contents; the extension reads the same path.
	//
	// Default "~/.observer/loc-editor-token" — beside observer.db and
	// config.toml, so an operator who relocates the observer home by
	// hand relocates this with it in one edit.
	//
	// A file the daemon cannot read is NOT fatal: the endpoint keeps its
	// loopback + Origin posture and a warning is logged. Blocking daemon
	// start on a credential that only hardens one reporting endpoint
	// would trade a whole install for a hardening measure.
	EditorTokenFile string `toml:"editor_token_file"`
	// EditorTokenRequired makes the token MANDATORY on
	// POST /api/loc/editor-change: a request with no token, or with the
	// wrong one, is refused 401.
	//
	// Default FALSE this release. An extension older than the token file
	// sends nothing, and flipping the default before installs have caught
	// up would silently stop human-line capture on every one of them.
	// A request that DOES carry a token is verified either way — a wrong
	// token is never silently accepted. The default flips to true in a
	// later release; set it now on an install whose extension is current.
	EditorTokenRequired bool `toml:"editor_token_required"`
}

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

// TasksConfig is the [tasks] surface — session-level task/todo/plan
// checklist tracking (docs/task-tracking.md,
// docs/audits/task-tracking-capture-audit-2026-09-07.md). Default-ON,
// same partial-merge invariant as CacheTrackConfig/PredictConfig: an
// install with no [tasks] section gets Enabled=true, because it is a
// pure re-decode of data already captured in actions.raw_tool_input/
// raw_tool_output (internal/taskflow + internal/store/taskflow.go) —
// no new capture surface, no adapter change, no proxy hook. LOCAL-ONLY
// — task_items/task_transitions (migration 109) never enter the org
// push wire (tests/invariant/privacy_test.go's forbiddenCacheTables).
type TasksConfig struct {
	// Enabled gates the ingest-time decode + the (out-of-scope-for-v1)
	// backfill default. false makes Store.Ingest's task-tracking pass a
	// pure no-op — the pre-feature baseline.
	Enabled bool `toml:"enabled"`
	// MatchMode selects how Snapshot-kind (whole-list-rewrite) items are
	// identified across consecutive calls when the tool carries no
	// vendor id. "exact" (the default, per §R2.3.4's measured guidance:
	// fuzzy matching trades a known, countable loss for an unknown,
	// silent mis-join) matches on the trimmed content string
	// (taskflow.ContentKey). "normalized" additionally lowercases and
	// collapses internal whitespace before hashing
	// (taskflow.NormalizedContentKey) — tolerates a vendor's own cosmetic
	// re-wording between two consecutive snapshot calls, at the cost of
	// silently merging two genuinely different items whose text happens
	// to normalize the same. CONSUMED: threaded into every taskflow.Decode
	// call as ActionInput.MatchMode (internal/store/taskflow.go), applied
	// post-decode by applyMatchMode — see that function's doc comment for
	// why it is a single recompute seam rather than a parameter threaded
	// through every one of decoderTable's ~10 decode functions.
	MatchMode string `toml:"match_mode"`
	// ConcurrentAttribution selects how a token/action row is bucketed
	// when two or more tasks are simultaneously in_progress (§R2.3.2).
	// "shared" (the recommended, measured default — 6.6% of tokens on
	// the grounding corpus) buckets the row into a per-session `shared`
	// total rather than splitting it evenly or picking a "dominant"
	// task, both of which would invent a precision the data does not
	// contain. "none" drops the row from every task's total instead
	// (still counted, just not attributed to a specific task) — for an
	// operator who would rather under-report than see a shared bucket.
	// There is deliberately no "split" option (see MatchMode's note).
	// CONSUMED: passed to taskflow.Attributor.SetConcurrentAttribution by
	// the Phase-2 cost/report layer (internal/store's
	// LoadSessionTaskReport) — "none" makes Attributor.At report
	// BucketBetweenTasks instead of BucketShared.
	ConcurrentAttribution string `toml:"concurrent_attribution"`
	// IncludeSidechains folds a spawned sub-agent's OWN token_usage rows
	// (is_sidechain=1, migration 087) into whichever task happened to be
	// open in the PARENT session at the same wall-clock time. Default
	// false: sub-agent usage is reported as a separate `sidechain` total
	// instead (§3.3's option (a) — option (b), resolving a
	// TaskUpdate.owner string to the actual spawned session, is not
	// implementable: owner is free text, not a session id, §R2.6 item 6).
	// CONSUMED: passed straight through as the includeSidechains argument
	// to Store.LoadTaskTokenRows/LoadTaskActionTimestamps, via an
	// explicit taskflow.Options each Phase-2 read surface (dashboard/
	// CLI/MCP) builds from this config directly — not read off a store
	// instance's TasksOptions(), which none of those per-request/
	// per-invocation store instances had SetTasksOptions called on.
	IncludeSidechains bool `toml:"include_sidechains"`
	// BackfillOnStart re-derives task_items/task_transitions from
	// historical actions rows once at daemon start (same work as
	// `observer backfill --tasks`, run automatically). Default false —
	// the explicit CLI flag is the v1 path; an operator upgrading onto
	// a build with [tasks] newly enabled runs it once by hand. CONSUMED:
	// cmd/observer/main.go calls Store.BackfillTaskItems(ctx, 0) once,
	// in a background goroutine, right after SetTasksEnabled, when this
	// is true.
	BackfillOnStart bool `toml:"backfill_on_start"`
	// RetentionDays bounds how long task_items/task_transitions are kept
	// before pruning. 0 = never prune (the CacheTrackConfig.RetentionDays
	// shape) — v1 ships no pruning sweep at all; the field exists so a
	// future one has a home without a config-shape change.
	RetentionDays int `toml:"retention_days"`
}

// BrowserConfig is the [browser] surface — the opt-in browser-chatbot
// capture rail (docs/plans/browser-extension-and-m365-copilot-proposal-
// 2026-07-10.md §5). LOCAL-ONLY, never distributed via the org policy
// registry (same posture as [predict]/[routing]/[cachewarm]). Same
// partial-merge invariant as CacheTrackConfig: an install with no [browser]
// section inherits the Default() seed (receiver AVAILABLE but the loopback
// LISTENER OFF — the native-messaging bridge is the default binding; the
// HTTP listener is the opt-in alternate). The daemon is the CEILING
// authority on what is stored (§5.1): GranularityCeiling clamps whatever
// the extension sends.
type BrowserConfig struct {
	// Enabled gates the whole browser rail on the daemon side. When false
	// the loopback listener never starts (the native-messaging hook path is
	// unaffected — it opens the DB directly like every CLI hook). Default
	// true so the rail is ready the moment the operator installs the
	// extension; the extension itself is opt-in regardless.
	Enabled bool `toml:"enabled"`
	// Listener configures the opt-in loopback HTTP receiver — the alternate
	// to the default native-messaging bridge.
	Listener BrowserListenerConfig `toml:"listener"`
	// Sites holds per-site enable toggles keyed by the *-web tool name
	// (chatgpt-web/claude-web/perplexity-web/gemini-web/copilot-web). A
	// missing key means "enabled" (fail-open — the extension's own per-site
	// toggle is the primary control; this is the daemon backstop). Set a key
	// false to make the daemon DROP that site's turns regardless of what the
	// extension sends.
	Sites map[string]bool `toml:"sites"`
	// GranularityCeiling is the daemon's maximum stored granularity
	// (§5.1: "usage_only" | "redacted" | "full"). The daemon is the final
	// authority on what is STORED, so the effective granularity of every
	// turn is min(what the extension sent, this ceiling). Default "full":
	// Observer is a local-first observability tool and browser capture
	// follows the same posture as every coding-agent adapter — full
	// prompt/response content stored NODE-LOCALLY (the scrub.Scrubber
	// secrets pass still applies; nothing leaves the node without the
	// [org_client.share] opt-in). The extension discovers this ceiling via
	// the native-messaging `config` event and sends at exactly this level;
	// an operator who wants less sets "redacted" or "usage_only" here (one
	// lever, dashboard-editable). An empty/unknown value is treated as
	// usage_only by the normalizer (fail-closed).
	GranularityCeiling string `toml:"granularity_ceiling"`
	// RetentionDays bounds how long browser rows are kept (rides the
	// existing retention machinery — 0 = keep forever / inherit the global
	// retention). Default 0.
	RetentionDays int `toml:"retention_days"`
	// IngestTimeoutMS bounds the browser-capture DB ingest path
	// (ingestBrowserTurn → store.Ingest). It is DELIBERATELY DECOUPLED from
	// the blocking-hook timeout ([observer.hooks].timeout_ms, ~500ms): by the
	// time this deadline applies the browser hook has ALREADY ACKed the
	// extension on stdout and runs as a detached child, so keeping it short
	// protects nothing — it only sheds captured turns whenever the daemon
	// briefly holds the SQLite write lock (a WAL checkpoint on a large DB, a
	// batch insert) even though the 30s busy_timeout would ride the
	// contention out. Default 35000 (35s); a zero / negative value resolves
	// to the default via IngestTimeout(). Same partial-merge rule as the
	// other [browser] keys — an install with no [browser] section inherits
	// the default.
	IngestTimeoutMS int `toml:"ingest_timeout_ms"`
}

// defaultBrowserIngestTimeoutMS is the fallback browser-capture ingest
// deadline used when [browser].ingest_timeout_ms is unset or non-positive.
// 35s: it must EXCEED the 30s SQLite busy_timeout (db.Open pragma) so a
// maximum-length write-lock wait is ridden out rather than cut off mid-wait
// (a 15s deadline still dropped turns whenever the daemon held the lock
// 15–30s). The pile-up trade-off — every captured turn is its own detached
// hook child, so a long deadline means more concurrent waiters — is accepted
// for this lane: browser-turn arrival is human-paced (single-digit per
// minute), and drops stay legible in browser-health.json telemetry.
const defaultBrowserIngestTimeoutMS = 35000

// maxBrowserIngestTimeoutMS caps [browser].ingest_timeout_ms. It exists so the
// daemon's end-to-end browser-ingest work is GUARANTEED to finish before the
// native-messaging host gives up on it: host.js
// (internal/browserhost/hostfiles/host.js) replies to Chrome after its
// HOST_INGEST_CAP_MS reply cap (40000ms) and then Chrome tears down the
// Windows→WSL bridge, killing a still-running ingest child. Because
// cmd/observer/browser.go now bounds db.Open + store.Ingest under IngestTimeout()
// (started BEFORE db.Open, whose SQLite busy_timeout can wait 30s), the real
// child runtime is <= IngestTimeout(); clamping that to 35000ms holds it ~5s
// below the 40000ms host cap. Keep the two constants in sync — host.js carries
// the matching cross-reference comment on HOST_INGEST_CAP_MS.
const maxBrowserIngestTimeoutMS = 35000

// IngestTimeout returns the browser-capture ingest deadline as a
// time.Duration. A zero or negative IngestTimeoutMS (unset, or an operator
// clamp) resolves to the generous default so the detached, post-ACK DB write
// is never starved by the short blocking-hook timeout; a value above
// maxBrowserIngestTimeoutMS is clamped DOWN so the end-to-end bound can never
// exceed the native host's reply cap even if Validate is bypassed (e.g. a
// programmatically-built config in a test).
func (b BrowserConfig) IngestTimeout() time.Duration {
	ms := b.IngestTimeoutMS
	if ms <= 0 {
		ms = defaultBrowserIngestTimeoutMS
	}
	if ms > maxBrowserIngestTimeoutMS {
		ms = maxBrowserIngestTimeoutMS
	}
	return time.Duration(ms) * time.Millisecond
}

// BrowserListenerConfig is the [browser.listener] sub-surface — the opt-in
// loopback HTTP receiver (internal/ingest/browser). The native-messaging
// bridge is the default binding; this is the alternate for deployments that
// prefer HTTP. Its own dedicated port, never :8820 / the dashboard mux.
type BrowserListenerConfig struct {
	// Enabled gates the loopback listener. Default FALSE — the
	// native-messaging bridge is the default receiver; turn this on only
	// when a deployment routes captured turns over HTTP instead.
	Enabled bool `toml:"enabled"`
	// ListenAddr is the host:port bind. Default 127.0.0.1:8821. A
	// non-loopback host is refused unless AllowNonLoopback is set.
	ListenAddr string `toml:"listen_addr"`
	// AllowNonLoopback permits a non-loopback bind (default false — the
	// network-posture guard).
	AllowNonLoopback bool `toml:"allow_non_loopback"`
	// Token is the shared secret the loopback receiver requires in the
	// X-SBO-Browser-Token header (defense-in-depth for the clientless,
	// default-off ingress — A4). Empty means the daemon auto-generates one at
	// start and persists it 0600 next to the observer DB
	// (browser-ingest-token), so an operator never has to set it by hand; set
	// it explicitly only to pin a known value.
	Token string `toml:"token"`
}

// HandoffConfig is the [handoff] surface — session handoff /
// continue-anywhere (docs/plans/session-handoff-plan-2026-07-03.md §12).
// LOCAL-ONLY, never distributed via the org policy registry. Read-side
// feature: default-ON with the same partial-merge rule as CacheTrack.
type HandoffConfig struct {
	// Enabled gates the handoff surfaces (CLI today; dashboard/MCP in P2).
	Enabled bool `toml:"enabled"`
	// TailMessages is the verbatim-tail length for the distilled_tail
	// carry mode. Default 6.
	TailMessages int `toml:"tail_messages"`
	// MaxDocTokens budgets the rendered HandoverDoc (file/MCP lanes);
	// sections degrade tail-first past it. Default 12000 (≈48KB).
	MaxDocTokens int `toml:"max_doc_tokens"`
	// DefaultCarry is the carry mode when the caller names none. Default
	// "distilled_tail".
	DefaultCarry string `toml:"default_carry"`
	// FileName templates the inject_file artifact; {shortid} expands.
	// Default "HANDOFF-{shortid}.md".
	FileName string `toml:"file_name"`
	// HookMaxBytes budgets the P3 hook lane (Phase 0 D-P0.2: SessionStart
	// additionalContext delivers intact only to ~8KB). Default 8192.
	HookMaxBytes int `toml:"hook_max_bytes"`
	// HookTTLMinutes bounds how long an armed inject_hook handoff waits for
	// the next target session before it expires (plan §10/§12). It is also
	// one-shot: the first delivery marks the row delivered. Default 240
	// (4h) — a stale armed handoff must never fire days later.
	HookTTLMinutes int `toml:"hook_ttl_minutes"`
	// RetentionDays is the horizon for the handoffs-table prune sweep
	// (plan §15 P4), swept by runRetention through
	// store.PruneHandoffRows. handoffs rows are tiny content-free
	// metadata (hashes/enums/paths), so the default is generous —
	// 180 days keeps ~6 months of handoff history for the target-session
	// linker while still bounding growth. 0 = keep forever.
	RetentionDays int `toml:"retention_days"`
	// AllowDashboardLaunch gates the dashboard's "Launch <tool> here"
	// embedded web terminal (docs/session-handoff.md launch section): the
	// daemon spawns `observer <tool> --continue-from <id>` in a PTY and
	// streams its TUI into the browser over a websocket. Default TRUE — it
	// lives entirely within the dashboard's loopback + browserGuard trust
	// boundary (opaque token minted only by an Origin-checked POST; the ws
	// upgrade rejects cross-origin by default). Set false to disable the
	// launch surface entirely (the endpoints 503 and the button hides).
	// LOCAL-ONLY, like the rest of [handoff].
	AllowDashboardLaunch bool `toml:"allow_dashboard_launch"`
	// ContextWarnTokens is the conservative context-window floor the handoff
	// estimate warns against: when the FULL carry exceeds it, the modal/CLI
	// flag that the target tool's (often unknown) default model may be too
	// small to rehydrate the whole context in one shot — the "350K in Opus
	// into a 200K free model" mismatch. Default 200000; 0 disables the
	// warning. LOCAL-ONLY.
	ContextWarnTokens int `toml:"context_warn_tokens"`
	// MaxCacheBytes is the safety cap on the `full_cache` carry doc — the
	// only mode that inlines the actual UN-EXCERPTED read bodies (the "full
	// incl cache" mode; docs/session-handoff.md). full_cache deliberately
	// bypasses the ~100KB inline-prompt bound so the warm context travels
	// from the first prompt, so this cap is the guard against a pathological
	// multi-hundred-MB session writing an unusable doc: past it the doc is
	// truncated with an honest note. Default 8388608 (8MB); 0 = uncapped.
	// LOCAL-ONLY.
	MaxCacheBytes int `toml:"max_cache_bytes"`
}

// TerminalConfig is the [terminal] surface — the embedded web-terminal
// cockpit (docs/plans/terminal-product-exploitation-plan-2026-07-12.md §8).
// LOCAL-ONLY: it never appears in [org_client.share] and is never distributed
// to an org. Terminal-wide knobs live at the top; fresh-agent launch is a
// SEPARATE, default-OFF opt-in under [terminal.launch] — it EXPANDS execution
// authority, so (unlike the code_graph→codeintel rename) it is never migrated
// on. [terminal].enabled gates the terminal-wide surface; it does NOT grant
// fresh-launch (that needs [terminal.launch].allow_fresh_agent too).
//
// Same partial-merge invariant as CacheTrackConfig: an install with no
// [terminal] section gets the Default() seed (Enabled=true, Status.Enabled=true,
// but Launch.AllowFreshAgent=false); a partial section keeps unset fields at
// their Default() values.
type TerminalConfig struct {
	// Enabled gates the terminal-wide surface (status API, sessions list).
	// Default TRUE. The existing handoff-continue launcher stays gated by
	// [handoff].allow_dashboard_launch — this does NOT absorb it.
	Enabled bool `toml:"enabled"`
	// MaxConcurrent caps live terminal sessions (default 9 — sized for the
	// Terminal Workspace grid; the termsession zero-value fallback stays 4).
	// 0 falls back to the termsession default.
	MaxConcurrent int `toml:"max_concurrent"`
	// IdleTimeout, when set to a positive Go duration (e.g. "30m"), reaps a
	// terminal whose PTY has seen no I/O for that long. "0" or empty — the
	// DEFAULT — disables idle reaping: a live session stays available (and on
	// the dashboard) until its child exits or it is explicitly closed. An
	// interactive agent idling at its prompt produces zero PTY I/O for hours;
	// reaping it kills the operator's session mid-thought ("the session ended
	// but its exit status could not be determined"), so continuity is the
	// default and reaping is the opt-in.
	IdleTimeout string `toml:"idle_timeout"`
	// RingBytes bounds each session's raw replay ring (default 262144). 0 uses
	// the termsession default.
	RingBytes int `toml:"ring_bytes"`
	// MaxSubscribers caps concurrent read-only viewers PER session (Phase 4
	// output fan-out, §4.α.1). Default 8. 0 uses the termsession default.
	MaxSubscribers int `toml:"max_subscribers"`
	// WSPingIntervalSeconds is how often the terminal websocket bridge pings its
	// peer to detect a dead / half-open transport. Default 30. 0 keeps the
	// built-in default.
	WSPingIntervalSeconds int `toml:"ws_ping_interval_seconds"`
	// WSPingTimeoutSeconds bounds the wait for one pong. Default 10. 0 keeps the
	// built-in default.
	WSPingTimeoutSeconds int `toml:"ws_ping_timeout_seconds"`
	// WSPingFailuresAllowed is how many CONSECUTIVE missed pongs the bridge
	// tolerates before declaring the peer dead. Default 5 — with the 30s/10s
	// defaults that is roughly 3.3 minutes of grace. It exists because a mobile
	// browser FREEZES a backgrounded tab: the user switching to their mail app
	// to copy a pairing code stops the tab answering pings, and a one-strike
	// liveness check tore the bridge down within ~40s, which is what surfaced as
	// "reconnect to the terminal" on return. 1 restores the old one-strike
	// behaviour. A genuinely dead peer is still reaped — just later.
	WSPingFailuresAllowed int `toml:"ws_ping_failures_allowed"`
	// Launch is the fresh-agent launch opt-in block (F1). ALL default-off.
	Launch TerminalLaunchConfig `toml:"launch"`
	// Status is the agent-status detection block (F4). Default-on.
	Status TerminalStatusConfig `toml:"status"`
	// Attach is the session-attach block (session-attach design Phase 1).
	// Default-on: the attach socket is AF_UNIX owner-only 0600.
	Attach TerminalAttachConfig `toml:"attach"`
	// Sandbox is the [terminal.sandbox] block — B9 filesystem-isolated
	// terminals (docs/plans/b9-sandboxed-terminals-implementation-plan-2026-08-08.md
	// §5). Default-off (Enabled=false): sandboxing is new machinery that
	// spawns a daemon-side bwrap process tree and (for clone sources)
	// daemon-side git, so it stays a conscious opt-in like
	// [terminal.launch].AllowFreshAgent, distinct from that block because
	// sandboxing only SHRINKS execution authority (fs isolation) rather
	// than expanding it.
	Sandbox TerminalSandboxConfig `toml:"sandbox"`
	// SSH is the [terminal.ssh] block — SSH remote-system terminals
	// (docs/plans/ssh-remote-profiles-plan-2026-08-27.md). Default-ON
	// (Enabled=true) as of the 2026-08-28 operator ruling: Enabled only
	// gates VISIBILITY of the surface, not authority to reach any machine —
	// launching a session still requires a named [[terminal.ssh.profiles]]
	// entry, profiles exist only via operator-authored config, and the zero
	// value (no profiles) can launch nothing regardless of Enabled. Enabled
	// stays available as an explicit kill switch (set `enabled = false` to
	// hide the surface entirely, e.g. on a shared/managed install).
	SSH TerminalSSHConfig `toml:"ssh"`
}

// TerminalSSHConfig is the [terminal.ssh] block — outbound SSH remote-system
// terminals (docs/plans/ssh-remote-profiles-plan-2026-08-27.md).
//
// DISTINCT FROM [remote] (plan §1). [remote] is INBOUND: it exposes this
// node's own dashboard over a tailnet and authenticates an external client TO
// Observer. This block is OUTBOUND: it lets the daemon spawn an `ssh` client
// that authenticates Observer TO a third-party host. They share no code, no
// config, and no tables, and neither should ever be implemented in terms of
// the other.
//
// CREDENTIAL DISCIPLINE (operator requirement, plan §0 answer 2): a profile
// carries a key-file PATH and nothing else. Observer never opens, reads, or
// stores key material, and there is deliberately no password/passphrase key in
// this schema — ssh-agent (or an interactive prompt inside the PTY) owns that.
//
// AUTHORIZATION SHAPE (plan §3.1): Profiles is an operator-authored ALLOW-LIST,
// exactly like [terminal.launch].allowed_project_roots. The dashboard SELECTS a
// profile by name; it can never CREATE one. That is why profiles live in config
// rather than in a DB table with a CRUD API — a table would make "which remote
// machines may this daemon shell into" editable by anything that can reach the
// dashboard.
//
// LOCAL-ONLY: like the whole [terminal] tree, it never appears in
// [org_client.share] and is never distributed by the org policy registry.
type TerminalSSHConfig struct {
	// Enabled is the surface visibility switch. Default TRUE — see the block
	// comment. It does not grant authority to reach any machine: reaching one
	// always requires a named entry in Profiles, which only an operator
	// editing config.toml can add. Set to false as an explicit kill switch to
	// hide the surface (e.g. on a shared/managed install) regardless of
	// Profiles.
	Enabled bool `toml:"enabled"`
	// ConnectTimeoutSeconds bounds the ssh connect (-o ConnectTimeout) so a
	// dead host cannot hold a PTY slot open forever. 0 uses the sshprofile
	// default (10).
	ConnectTimeoutSeconds int `toml:"connect_timeout_seconds"`
	// KeepaliveSeconds is the ssh -o ServerAliveInterval. 0 uses the sshprofile
	// default (30). With the fixed ServerAliveCountMax=3, a dead link ends the
	// PTY (and records the run's exit) instead of hanging forever.
	KeepaliveSeconds int `toml:"keepalive_seconds"`
	// Profiles is the operator-authored list of remote systems, written as
	// repeated [[terminal.ssh.profiles]] blocks. Empty (the default) means no
	// system can be reached even when Enabled is true.
	Profiles []SSHProfileConfig `toml:"profiles"`
}

// SSHProfileConfig is one [[terminal.ssh.profiles]] entry.
//
// NAMING NOTE (plan §3.2): internal/config ALREADY has a Profile type and a
// ProfileStore — those are COMPRESSION profiles served by
// /api/config/profiles, and are entirely unrelated. This type is deliberately
// spelled SSHProfileConfig, and its HTTP surface lives under /api/terminal/ssh,
// so the two can never be confused.
type SSHProfileConfig struct {
	// Name is the stable id the dashboard references. [a-z0-9][a-z0-9._-]*
	Name string `toml:"name"`
	// Label is an optional human-readable name for the picker.
	Label string `toml:"label"`
	// Host is a hostname, an IP literal, or a ~/.ssh/config Host alias.
	Host string `toml:"host"`
	// User is an optional login name (passed to ssh via -l).
	User string `toml:"user"`
	// Port is an optional TCP port; 0 or 22 omits the -p flag.
	Port int `toml:"port"`
	// KeyPath is an optional ABSOLUTE PATH to a private key file. It is handed
	// to `ssh -i` and is never opened by Observer. Passphrases are ssh-agent's
	// job; there is no passphrase key here, by design.
	KeyPath string `toml:"key_path"`
	// Jump is an optional [user@]host[:port] ProxyJump spec (ssh -J). Multi-hop
	// comma chains are rejected in v1.
	//
	// There is deliberately NO ProxyCommand key: it executes an arbitrary LOCAL
	// command, and exposing it as a config field reachable from a UI click
	// would create a local-RCE surface. An operator who needs one sets it in
	// their own ~/.ssh/config against a Host alias and points Host at that
	// alias — their own pre-existing authority, not a new one Observer grants.
	Jump string `toml:"jump"`
	// DashboardPort is the port THIS remote machine's own Observer dashboard
	// listens on. 0 (the default) means 8081, the daemon's own built-in bind.
	//
	// It exists solely for the dashboard instance switcher, which opens
	// `ssh -N -L 127.0.0.1:<free>:127.0.0.1:<dashboard_port>` so the operator
	// can view the REMOTE install's dashboard locally (docs/ssh-terminals.md,
	// "Instance switcher"). Set it only when the remote daemon was started on a
	// non-default port.
	//
	// This is the ONLY remote port the forward can ever reach, and it is read
	// from here rather than accepted from a request — which is what keeps the
	// switcher from being a general-purpose tunnel surface.
	DashboardPort int `toml:"dashboard_port"`
	// ReverseProxy opts THIS profile into an additional `-R` remote forward
	// on the instance-switcher connection, so the remote machine can reach
	// this machine's own Observer proxy (docs/ssh-terminals.md "Reverse
	// proxy forward"). Default false. It only helps once the remote AI
	// tool is itself pointed at the forwarded loopback address — Observer
	// does not configure the remote tool for you.
	ReverseProxy bool `toml:"reverse_proxy"`
	// ReverseProxyPort is the port the `-R` forward binds on the REMOTE
	// side. 0 (the default) means sshprofile.DefaultReverseProxyPort
	// (8820). The LOCAL side is always this machine's own Observer proxy
	// port and is not configurable here — see
	// sshprofile.DefaultObserverProxyPort.
	ReverseProxyPort int `toml:"reverse_proxy_port"`
}

// TerminalAttachConfig is the [terminal.attach] block — session attach
// (session-attach design 2026-07-19, Phase 1). Unlike [terminal.launch], this
// block is default-ON: the attach control channel is an AF_UNIX socket at mode
// 0600 (owner-only, never network-reachable), so serving it grants no authority
// beyond what the operator already has at their own shell — per-session attach
// stays opt-in via the `observer <tool> --attach` flag.
type TerminalAttachConfig struct {
	// Enabled gates the daemon's attach socket. Default TRUE. With it false the
	// daemon does not serve the socket and `--attach` has nothing to connect to.
	Enabled bool `toml:"enabled"`
	// RouteProxy makes attach-launched children inherit the launcher's
	// proxy-routing env (so an attach session captures tokens through :8820).
	// Default TRUE (design §6 decision #7: proxy-routed by default with an
	// escape hatch — the CLI `--no-proxy` flag and a future Settings toggle both
	// express opting out).
	RouteProxy bool `toml:"route_proxy"`
	// DefaultOn makes the `observer <tool>` launchers attach by default
	// (resilient-attach arc): a launch resumes/attaches to a live session
	// automatically unless the operator opts out per-launch with `--no-attach`.
	// Default TRUE. Read per-launch by the CLI, so a change takes effect on the
	// next launch with no daemon restart. The partial-merge default keeps this
	// TRUE for an existing [terminal.attach] block that predates the key: the
	// field is seeded true in Default() and BurntSushi's field-level decode
	// leaves an absent key untouched (same mechanism as RouteProxy above).
	DefaultOn bool `toml:"default_on"`
	// ReclaimOnInput lets a native `observer <tool> --attach` terminal RE-TAKE
	// the writer after a dashboard Jump-in stole it: when the wrapper's lease is
	// revoked and the operator types a real key (anything but a bare ESC), the
	// daemon re-acquires the local writer through the normal funnel, delivers the
	// keystroke, and tells the wrapper control is back. ESC-initiated chunks —
	// including a TUI's machine-generated cursor-position / Device-Attributes
	// replies — never reclaim, so the dashboard's control is never stolen with
	// nobody typing. Default TRUE. Off restores the fence-and-notify behavior
	// (one revoked notice, keystrokes dropped). The partial-merge default keeps
	// this TRUE for an existing [terminal.attach] block that predates the key
	// (seeded true in Default(); BurntSushi leaves an absent key untouched, same
	// mechanism as RouteProxy / DefaultOn above).
	ReclaimOnInput bool `toml:"reclaim_on_input"`
	// ForwardAuthEnv makes an attach launch forward the caller's own provider-
	// credential env vars (the tool's grounded integration.Capability.AuthEnv
	// NAMES — e.g. ANTHROPIC_API_KEY, OPENAI_API_KEY) across the attach socket
	// to the daemon-spawned child. Default TRUE: it RESTORES bare-launch
	// behavior — a bare launch inherits the caller's os.Environ() directly, so a
	// shell-exported-only key reaches the tool; a daemon-spawned attach child
	// inherits the DAEMON's env instead, so without this a key exported only in
	// the caller's shell would be invisible and the attach launch would fail to
	// authenticate where a bare launch succeeds. The forwarded values transit
	// the owner-only (0600 AF_UNIX) attach socket ONCE per launch and are never
	// logged or persisted. Set false to withhold them (the child then falls back
	// to the daemon's own env / the tool's config-file or OAuth auth). The
	// partial-merge default keeps this TRUE for an existing [terminal.attach]
	// block that predates the key (seeded true in Default(); BurntSushi leaves an
	// absent key untouched — the same mechanism as RouteProxy / DefaultOn /
	// ReclaimOnInput above). An explicit forward_auth_env = false sticks.
	ForwardAuthEnv bool `toml:"forward_auth_env"`
}

// TerminalLaunchConfig is the [terminal.launch] block — the fresh-agent
// launch opt-in (plan §8/F1). The fresh-launch fields default to the ZERO
// value (off / empty): a fresh (non-handoff) agent launch from the dashboard
// is refused until the operator consciously grants it, because those fields
// EXPAND execution authority. The exception is AllowInstall (added by the
// tool-binary-resolution arc, 2026-07-23): it is a KILL-SWITCH for the guided
// install endpoint and defaults TRUE — the consent there is the explicit
// dashboard click, not a config flip, so the switch's job is to let an
// operator turn the affordance OFF, not gate it on. It is seeded true in
// Default() with the same absent-key-preserves-default partial-merge treatment
// as [terminal.attach]'s booleans.
//
// `allow_shell` (AllowShell below) is a SEPARATE default-OFF opt-in for
// spawning a plain shell (not an AI agent) via a fresh terminal launch —
// added post-F1. It is independent of AllowFreshAgent: a bare shell can run
// ANY command, a strictly larger execution-authority expansion than a known,
// capability-registry-bounded AI-tool launcher, so it is gated by its own
// explicit toggle even when fresh-agent launch is already on.
type TerminalLaunchConfig struct {
	// AllowFreshAgent is the master opt-in for non-handoff AI-tool launches.
	// Default FALSE. With it false, POST /api/terminal/launch refuses every
	// non-shell request.
	AllowFreshAgent bool `toml:"allow_fresh_agent"`
	// AllowShell is the opt-in for a fresh PLAIN SHELL launch (the child's
	// $SHELL, or /bin/bash / /bin/sh as a fallback — never an AI tool).
	// Default FALSE, and deliberately independent of AllowFreshAgent: turning
	// on fresh AI-tool launches must not silently also grant an arbitrary
	// command shell. BurntSushi leaves an absent key untouched, so a
	// pre-existing [terminal.launch] block that predates this key still
	// loads with AllowShell=false.
	AllowShell bool `toml:"allow_shell"`
	// AllowInstall gates POST /api/terminal/install — the guided one-click
	// "Install in terminal" affordance (tool-binary-resolution arc). Default
	// TRUE: the consent is the explicit dashboard click that runs a grounded,
	// compile-time-constant install command in a visible PTY, so this key is
	// the operator KILL-SWITCH to disable that affordance entirely, not the
	// gate that turns it on. Independent of AllowFreshAgent — installing a tool
	// is not launching a fresh agent. Seeded true in Default(); BurntSushi
	// leaves an absent key untouched, so a pre-existing [terminal.launch] block
	// that predates this key still loads with AllowInstall=true (the same
	// partial-merge mechanism [terminal.attach].default_on relies on). An
	// explicit allow_install = false sticks.
	AllowInstall bool `toml:"allow_install"`
	// AllowedTools is the allow-list of launchable tool names a fresh launch
	// may start (e.g. ["claude-code","codex"]). Empty = none (deny-all). A
	// tool must ALSO be launchable in the capability registry.
	AllowedTools []string `toml:"allowed_tools"`
	// AllowedProjectRoots is the operator-configured allow-list of directories
	// a fresh launch may set as the child cwd. Each entry is canonicalized
	// (real filesystem identity, symlinks resolved) at validation time; a
	// requested project_root must canonicalize to (or under) an entry. Empty
	// = no project_root is accepted (the launcher's own default cwd is used).
	// This is NOT "a project Observer has seen" — observed roots are learned
	// from tool data and may be stale or attacker-influenced.
	AllowedProjectRoots []string `toml:"allowed_project_roots"`
}

// TerminalSandboxConfig is the [terminal.sandbox] block — B9 filesystem-
// isolated terminals (docs/plans/b9-sandboxed-terminals-implementation-plan-2026-08-08.md
// §5). Separate from [terminal.launch] (the consent-gated AUTHORIZATION
// block for who may launch what): this block is MECHANISM — bwrap
// namespace composition, workspace preparation, and the honesty knobs
// around them. It only ever SHRINKS execution authority (tmpfs-home +
// selective binds), except the two knobs called out below which EXPAND
// it and are their own default-off/empty gates, mirroring the
// AllowShell-shaped-gate discipline elsewhere in [terminal].
type TerminalSandboxConfig struct {
	// Enabled is the master opt-in for the whole sandbox feature. Default
	// FALSE: this is new daemon-spawned machinery (bwrap + git), so it
	// stays a conscious opt-in even though the mechanism itself only
	// shrinks authority.
	Enabled bool `toml:"enabled"`
	// Backend names the isolation mechanism. "bwrap" is the only value in
	// v1 (Linux + WSL2, bubblewrap >= 0.4.0).
	Backend string `toml:"backend"`
	// HomeMode selects how $HOME is treated inside the sandbox: "tmpfs"
	// (default — blinds the real home, then punches back exactly the
	// tool's SandboxSpec state) or "readonly" (an escape hatch that omits
	// the tmpfs, leaving the whole home readable read-only).
	HomeMode string `toml:"home_mode"`
	// DefaultOn pre-checks the dashboard "Run in sandbox" toggle. Default
	// FALSE.
	DefaultOn bool `toml:"default_on"`
	// AllowRemoteClone is the opt-in for the `clone-remote` workspace
	// source: the DAEMON runs `git clone <url>` with the operator's own
	// ambient auth before the sandbox starts. Default FALSE — an
	// authority-EXPANDING knob (daemon-initiated network git), gated like
	// [terminal.launch].AllowShell.
	AllowRemoteClone bool `toml:"allow_remote_clone"`
	// RemoteAllowedHosts restricts AllowRemoteClone to these hosts. Empty
	// (the default) means any host is allowed once AllowRemoteClone is
	// true.
	RemoteAllowedHosts []string `toml:"remote_allowed_hosts"`
	// AllowWorktreeSource is the opt-in for the `worktree` workspace
	// source (`git worktree add`), off by default per plan §4/D6: it
	// needs the main repo's .git bound rw and attributes the session to
	// the MAIN repo root, not the workspace (ledger G18).
	AllowWorktreeSource bool `toml:"allow_worktree_source"`
	// WorkspacesDir overrides where prepared workspaces are minted.
	// Empty (the default) uses `<observer dir>/workspaces`.
	WorkspacesDir string `toml:"workspaces_dir"`
	// WorkspaceRetentionDays is the sweep horizon for prepared workspaces
	// (full repo copies, not small). 0 (the default) keeps them forever —
	// B7 needs workspaces to persist past run exit.
	WorkspaceRetentionDays int `toml:"workspace_retention_days"`
	// MaskPaths lists extra paths to `--tmpfs`-mask inside the sandbox, on
	// top of the auto-detected foreign-OS mount roots (e.g. /mnt/c on
	// WSL). Empty by default.
	MaskPaths []string `toml:"mask_paths"`
	// ExtraROBinds is a config escape hatch of additional read-only binds.
	// Empty by default.
	ExtraROBinds []string `toml:"extra_ro_binds"`
	// ExtraRWBinds is a config escape hatch of additional read-write
	// binds — EXPANDS write authority inside the sandbox. Empty by
	// default.
	ExtraRWBinds []string `toml:"extra_rw_binds"`
	// PrepTimeoutSeconds bounds workspace-preparation subprocesses (git
	// clone/worktree). Default 300.
	PrepTimeoutSeconds int `toml:"prep_timeout_seconds"`
}

// TerminalStatusConfig is the [terminal.status] block — agent-status
// detection (plan §8/F4). Default-on. Per-tool prompt patterns are shipped
// data, not config.
type TerminalStatusConfig struct {
	// Enabled gates the status classifier + the status API/WS frame. Default
	// TRUE (seeded by Default()).
	Enabled bool `toml:"enabled"`
}

// LaunchConfig is the [launch] block — per-tool binary-resolution overrides
// for the `observer <tool>` launchers (tool-binary-resolution arc,
// 2026-07-23). LOCAL-ONLY: it is never distributed to an org (same posture as
// [routing]/[predict]) and never appears in [org_client.share]. The map is
// keyed by the registry tool name (e.g. "opencode", "claude-code"); an entry's
// Path pins the exact binary to launch, winning over the toolresolve
// resolution ladder (PATH → login PATH → probe dirs) and losing only to the
// per-launch `--<tool>-path` flag. It is a narrow escape hatch for an install
// the ladder cannot find or classifies wrong; a missing entry means "resolve
// normally". Zero value (nil map) = no overrides, the common case.
type LaunchConfig struct {
	// Tools maps a registry tool name to its per-tool launch override.
	Tools map[string]LaunchToolConfig `toml:"tools"`

	// AgentRuntimeDir relocates a launched agent's install/config/cache
	// tree onto a rename-safe local filesystem. Empty (default) = OFF: no
	// env is injected and launch behaviour is byte-for-byte unchanged.
	//
	// It exists for deployments where the developer's HOME is on a
	// filesystem that cannot complete the atomic renames npm/bun perform
	// during a provider-dependency install — most notably a containerized
	// node whose HOME is an Azure Files / SMB / NFS mount (the Plane-B
	// test-node). There, an agent like OpenCode installs its provider
	// module into ~/.config/<tool>/node_modules, the rename fails with
	// EACCES, and the agent can't load the provider (an opaque
	// UnknownError before any model call).
	//
	// When set, every `observer <tool>` launcher points the agent's
	// XDG_CONFIG_HOME/XDG_CACHE_HOME/XDG_STATE_HOME plus the npm/bun cache
	// dirs under this path (see cmd/observer agentRuntimeEnv). It is
	// deliberately adapter-agnostic — keyed on the capability "this agent
	// needs a rename-safe runtime dir", never on a tool name — and it does
	// NOT relocate XDG_DATA_HOME, so agents still write their session
	// storage under $HOME/.local/share where the watcher captures it.
	//
	// The OBSERVER_AGENT_RUNTIME_DIR environment variable overrides this
	// key, so a container can set it without editing config. LOCAL-ONLY;
	// never distributed to an org.
	AgentRuntimeDir string `toml:"agent_runtime_dir"`
}

// LaunchToolConfig is one [launch.tools.<tool>] entry.
type LaunchToolConfig struct {
	// Path is an absolute path to the tool's binary. When set (and it stat-
	// checks as a file), the launcher uses it verbatim, bypassing resolution.
	// It wins over the toolresolve ladder and loses to the `--<tool>-path`
	// flag. Empty = resolve normally.
	Path string `toml:"path"`
}

// BenchmarkConfig is the [benchmark] surface — the Benchmarks Harness
// (docs/plans/benchmarks-harness-plan-2026-07-11.md). LOCAL-ONLY, never
// distributed to an org (same posture as [routing]/[predict]). The harness
// itself is CLI-driven and operator-invoked; the only persistent config today
// is the retention horizon for the node-local benchmark_* tables.
type BenchmarkConfig struct {
	// RetentionDays is the horizon for the benchmark_* prune sweep (plan
	// §3.12), swept by runRetention through store.PruneBenchmarkRows. Benchmark
	// rows hold repo paths, prompts, final-answer excerpts, and judge
	// rationales, so the default is bounded — 180 days keeps ~6 months of run
	// history for baseline diffs. 0 = keep forever.
	RetentionDays int `toml:"retention_days"`
}

// CodeIntelConfig is the [codeintel] surface — the in-process code-
// intelligence module (docs/codeintel/). LOCAL-ONLY, never distributed
// to an org (same posture as [routing]/[predict]/[cachewarm]). Same
// partial-merge invariant as CacheTrackConfig: an install with no
// [codeintel] section gets Enabled=true (Default() seeds it); a partial
// section keeps unset fields at their Default() values.
//
// Defaults are conservative: indexing is read-only on the repo; the
// only model-visible change (compression.code_aggressive) is OFF and
// opt-in per project AND language.
type CodeIntelConfig struct {
	// Enabled gates the whole module. When false the indexer doesn't
	// run, the native provider reports unavailable, and the CLI/MCP
	// surfaces stay empty.
	Enabled bool `toml:"enabled"`
	// Languages, when non-empty, restricts indexing to this subset of
	// the embedded language set. Empty = all supported languages.
	Languages []string `toml:"languages"`
	// AutoIndexLimit consent-gates a NEW project whose file count
	// exceeds it (a huge monorepo waits for `observer index <path>`).
	// Default 25000.
	AutoIndexLimit int `toml:"auto_index_limit"`
	// MaxFileBytes skips files larger than this. Default 2_000_000.
	MaxFileBytes int64 `toml:"max_file_bytes"`
	// IgnorePaths lists project-root path prefixes the auto-indexer must
	// never index. A project at or under any of these is skipped on
	// `observer start` (an explicit `observer index <path>` still works,
	// with a warning). Use absolute paths. Local-only; never distributed
	// to an org server.
	IgnorePaths []string `toml:"ignore_paths"`
	// RetentionDays is the codeintel_* prune horizon: a project whose
	// most recent index pass (MAX(codeintel_files.indexed_at)) is older
	// than this is deleted wholesale — files, nodes, edges, sites,
	// minhash, embeddings, FTS — via the same per-project delete path
	// `observer index delete -r` uses. The index is rebuildable from
	// the repo, so age-pruning is safe; a project still being indexed
	// always has a fresh indexed_at and is never touched, and a project
	// with NO successful index pass yet (MAX(indexed_at)=0, e.g.
	// freshly registered pending files) is also never touched. Swept by
	// the retention pass (startup + the [observer.retention] periodic
	// tick + `observer prune`). Default 90 — conservative, so an
	// actively-used index is never nuked. ≤ 0 disables the codeintel
	// prune entirely.
	RetentionDays int `toml:"retention_days"`

	Index       CodeIntelIndexConfig       `toml:"index"`
	Compression CodeIntelCompressionConfig `toml:"compression"`
	Semantic    CodeIntelSemanticConfig    `toml:"semantic"`
}

// ArchiveConfig is the [archive] block — cold storage for data that is not
// garbage but is no longer part of the hot working set
// (docs/plans/observer-corpus-archival-lazyload-design-2026-08-26.md).
//
// The block is LOCAL-ONLY (like [routing] / [cachewarm] / [codeintel]) and
// entirely additive: an operator who never writes it sees byte-identical
// behaviour, because Enabled defaults to false.
type ArchiveConfig struct {
	// Enabled switches the retention pass's stale-project handling from
	// DELETE to ARCHIVE. Default false.
	//
	// What turning it on changes, precisely: a codeintel project past
	// [codeintel].retention_days is copied to the archive database, verified
	// there, and only then removed from the hot one — instead of being
	// deleted outright, which is what happens today. So enabling it is a
	// strict improvement on the destructiveness axis even before the
	// rehydrate surfaces land.
	//
	// RESTORING an archived project is `observer archive rehydrate <path>`,
	// which replays the verified cold copy back into the hot database and
	// rebuilds the derived search index (shipped in P2 — an earlier version of
	// this comment said restoring meant a full re-index, and that has been
	// false since). The replay is refused, honestly and by name, when the cold
	// copy is missing, incomplete, or was produced by a parser this build no
	// longer accepts; the command then points at `observer index <path>`, the
	// disaster-recovery floor that always works because the code index is
	// derived from the repository on disk.
	//
	// Archived PROCESS capture needs no rehydrate at all: the dashboard reads
	// it straight from cold storage, with nothing copied back.
	//
	// What enabling this does NOT do is shrink the database file. Archived rows
	// leave the hot tables, but SQLite keeps the freed pages on its freelist —
	// turning them back into free disk is `observer archive reclaim`, which is
	// operator-invoked and never automatic.
	Enabled bool `toml:"enabled"`
	// Path is the archive database file. Empty applies
	// ~/.observer/archive.db — a sibling of observer.db, matching the
	// internal/edge/wal precedent of one flat file per subsystem. `~` is
	// expanded at load.
	//
	// It is deliberately a SEPARATE FILE rather than more tables in
	// observer.db: the entire point is that archived data stops being
	// carried on every VACUUM, backup, quick_check and dbstat walk of the
	// hot database.
	Path string `toml:"path"`
	// MaxProjectsPerPass caps how many projects one retention pass moves.
	// Default 8; ≤ 0 applies the default.
	//
	// The cap is not a performance tuning knob so much as an incident guard:
	// an unbounded "drain the whole backlog now" sweep is exactly the
	// loop-until-done shape that made a single retention pass hang the
	// machine for minutes. A capped batch on the ordinary startup + periodic
	// tick converges just as surely.
	MaxProjectsPerPass int `toml:"max_projects_per_pass"`
	// BatchRows bounds one streamed copy batch. Default 512; ≤ 0 applies the
	// default. Keeps a single move's memory proportional to the batch, not to
	// the project.
	BatchRows int `toml:"batch_rows"`
}

// CodeIntelIndexConfig is the [codeintel.index] block — resource +
// scheduling controls for the offline indexer.
type CodeIntelIndexConfig struct {
	// OnStart indexes known projects when `observer start` boots.
	// Default true.
	OnStart bool `toml:"on_start"`
	// Watch incrementally re-indexes on save (reuses fsnotify
	// mechanics, distinct from the session-file watcher). Default true.
	Watch bool `toml:"watch"`
	// Mode is "auto" (index/watch automatically) or "manual" (only
	// `observer index`). Default "auto".
	Mode string `toml:"mode"`
	// Workers caps index parallelism (0 = auto). Default 0.
	Workers int `toml:"workers"`
	// IdleOnly pauses indexing while the machine is busy. Default false.
	IdleOnly bool `toml:"idle_only"`
	// NOTE: `disk_budget_mb` used to be declared here and was never read
	// by anything. It is REMOVED, not renamed — see
	// migrateRemovedCodeIntelKeys for the disposition and the warning an
	// existing config still gets.
	//
	// OnStartTimeoutMinutes bounds the AGGREGATE wall-clock time
	// runCodeIntelOnStart (cmd/observer/codeintel.go) spends indexing
	// every known project on one `observer start` boot (T2.4, 2026-08-26
	// disk/compute remediation plan, P2-H). Per-project consent-gating
	// (auto_index_limit) and the home/drive-root block
	// (index.isAutoIndexBlocked) are unaffected — this is an orthogonal
	// outer bound for a large PROJECT SET (historically a 384K-file
	// Windows home directory's worth of discovered project roots), not a
	// per-project limit. When the deadline passes, indexing of any
	// remaining projects is skipped for this boot; they're picked up
	// again next start or by `observer index`. Default 10. ≤ 0 disables
	// the bound (unbounded, matching pre-2026-08-26 behavior).
	OnStartTimeoutMinutes int `toml:"on_start_timeout_minutes"`
}

// CodeIntelCompressionConfig is the [codeintel.compression] block — the
// ONLY model-visible behaviour, all OFF by default.
type CodeIntelCompressionConfig struct {
	// CodeAggressive enables opt-in body-collapse. DEFAULT OFF.
	CodeAggressive bool `toml:"code_aggressive"`
	// AggressiveLanguages opts in body-collapse per language; empty =
	// none even when CodeAggressive is true.
	AggressiveLanguages []string `toml:"aggressive_languages"`
	// PreviewOnly logs what WOULD collapse and changes nothing.
	PreviewOnly bool `toml:"preview_only"`
}

// CodeIntelSemanticConfig is the [codeintel.semantic] block.
type CodeIntelSemanticConfig struct {
	// Embedder selects the embedding backend: "tfidf" (default) or
	// (future) "neural".
	Embedder string `toml:"embedder"`
	// SimilarTo enables MinHash/LSH near-clone edges. Default true.
	SimilarTo bool `toml:"similar_to"`
}

// CacheWarmConfig is the [cachewarm] surface — the cache-expiry warning
// system + the opt-in smart keep-warm
// (docs/plans/cache-expiry-warning-and-keepwarm-plan-2026-06-25.md).
// LOCAL-ONLY, never distributed (same posture as [predict]/[routing]).
//
// The WARNING half (Part A) is default-ON: it is a pure read over the
// cache_entries the engine already writes, with zero LLM cost and no
// outward network call. The KEEP-WARM half (Part B, the nested Keepwarm
// block) is OFF by default — it is an outward-facing, money-spending
// action and is treated like routing enforce: explicit operator opt-in.
//
// Same partial-merge invariant as CacheTrackConfig: an install with no
// [cachewarm] section MUST get Enabled=true (Default() seeds it); a
// partial section keeps the unset fields at their Default() values.
type CacheWarmConfig struct {
	// Enabled gates the warning system. When false the dashboard/CLI/MCP
	// cache-expiry surfaces stay empty and no keep-warm runs.
	Enabled bool `toml:"enabled"`
	// WarnAtSeconds is the time-to-expiry threshold for the 'soon'
	// severity. Default 90.
	WarnAtSeconds int `toml:"warn_at_seconds"`
	// CriticalAtSeconds is the time-to-expiry threshold for the
	// 'critical' severity. Default 30. Clamped to ≤ WarnAtSeconds.
	CriticalAtSeconds int `toml:"critical_at_seconds"`
	// MinValueUSD suppresses warnings for caches whose value-at-risk is
	// below this floor (not worth keeping warm). Default 0.05.
	MinValueUSD float64 `toml:"min_value_usd"`
	// Implicit (OpenAI/Codex) caches expose NO fixed TTL — survival is a
	// best-effort retention policy, not a lease (see
	// docs/general_info/openai_cache_expiry.md). We model it as a GRADED
	// idle-risk progression keyed on time since last activity, surfaced as
	// an ESTIMATE (the card hedges with "~"):
	//   idle < ImplicitWarnSeconds          → ok    (high-confidence reuse)
	//   ImplicitWarnSeconds ≤ idle < Crit    → soon  ("at risk of expiry")
	//   ImplicitCriticalSeconds ≤ idle < Max → critical ("significantly
	//                                           increased risk of expiry")
	//   idle ≥ ImplicitMaxSeconds            → expired (hard max)
	// Defaults follow the extended-cache reality for gpt-5.5/gpt-5/gpt-4.1:
	// 1h / 2h / 24h. Anthropic explicit caches ignore these — they carry a
	// real TTL and use WarnAtSeconds/CriticalAtSeconds.
	ImplicitWarnSeconds int `toml:"implicit_warn_seconds"`
	// ImplicitCriticalSeconds — idle age at which an implicit cache is at
	// significantly increased risk of eviction. Default 7200 (2h).
	ImplicitCriticalSeconds int `toml:"implicit_critical_seconds"`
	// ImplicitMaxSeconds — idle age at which an implicit cache is treated as
	// expired (OpenAI's hard 24h retention ceiling). Default 86400 (24h).
	ImplicitMaxSeconds int `toml:"implicit_max_seconds"`
	// Keepwarm is the Part B keep-warm sub-surface (advise/enforce).
	Keepwarm KeepWarmConfig `toml:"keepwarm"`
}

// KeepWarmConfig is the [cachewarm.keepwarm] sub-surface — the Part B
// economics + action mode. Default OFF: it is the only outward-facing,
// money-spending action in this feature.
type KeepWarmConfig struct {
	// Mode is "off" | "advise" | "enforce". Default "off". advise
	// surfaces a recommendation (e.g. switch to the 1h tier) but sends
	// nothing; enforce additionally permits the proxy in-memory replay
	// path (Anthropic proxied sessions only) — built in a later phase.
	Mode string `toml:"mode"`
	// MinValueUSD is the value-at-risk floor below which keep-warm is
	// never recommended. Default 0.20 (higher than the warning floor —
	// it is not worth acting on small caches).
	MinValueUSD float64 `toml:"min_value_usd"`
	// MinResumeConfidence gates a keep-warm bet on the likelihood the
	// session actually resumes (a warm cache nobody returns to is wasted
	// spend). 0..1. Default 0.5.
	MinResumeConfidence float64 `toml:"min_resume_confidence"`
}

// CacheTrackConfig gates the proxy-side cache observation engine
// (docs/plans/cache-tracking-implementation-spec-2026-06-08.md §11).
// Default-ON per spec §11: the feature is local, passive, network-
// free, and writes only hashes/counts/enums (no content). An
// install with no [cachetrack] section MUST get Enabled=true via
// the loader's partial-merge against Default() (NOT zero-valued
// false) — the live-daemon-captures-nothing bug traced to this.
type CacheTrackConfig struct {
	// Enabled gates the engine. When false, the proxy still
	// parses request bodies for cache_control markers (cheap;
	// already in the requestShape single pass) but the engine
	// is not constructed and no cache_* rows are written.
	Enabled bool `toml:"enabled"`
	// MaxTrackedSessions is the LRU bound on the engine's
	// per-session CacheModel map. Default 64. ≤ 0 disables the
	// cap (unbounded; not recommended).
	MaxTrackedSessions int `toml:"max_tracked_sessions"`
	// CalibrateLogPath enables the per-block diagnostic sidecar
	// when non-empty: every block fed to Engine.ObserveTurn is
	// written as one JSON line carrying (api_turn_id, seq, level,
	// kind, len_raw, sha_raw, len_canon, sha_canon) — plus a
	// bounded canonical-bytes prefix for tools+system levels
	// (message-level stays hash-only per CLAUDE.md "no content"
	// rule).
	//
	// Off by default (""). When set, auto-stops after ~200 blocks
	// so the file stays small and the daemon's hot path is
	// untouched for the rest of the soak. Used to localize chain-
	// hash drift to the lowest-seq differing block (the 39326aa9
	// soak post Fix B left seq=29 tools boundary still drifting
	// — this sidecar is the next-step diagnostic).
	CalibrateLogPath string `toml:"calibrate_log_path"`
	// RetentionDays is the per-table horizon for the cache_* row
	// sweep (spec §9). cache_segments + cache_events past this
	// horizon are deleted; cache_entries in terminal states
	// (expired / invalidated / unverified) past a tighter 14-day
	// horizon are also deleted (live entries are never pruned
	// regardless of age — they may still be in the provider).
	// Default 90. ≤ 0 disables the cache prune entirely.
	//
	// The sweep runs from the retention pass (startup + the
	// [observer.retention].interval_hours periodic tick) — the
	// same pass that handles actions / observer_log /
	// file_state. See cmd/observer/prune.go::runRetention. Each
	// call is idempotent: a second run within the same horizon
	// is a no-op (TestPruneCacheRows_SecondRunNoop).
	//
	// NOT pushed to the org server: cache_* tables are NODE-LOCAL
	// per `tests/invariant/privacy_test.go::TestSelectUnpushedSinceExcludesCacheTables`.
	// The sweep stays node-local; no org-push coupling.
	RetentionDays int `toml:"retention_days"`
	// ---
	// DELIBERATE OMISSION — R7 cache_scope salt.
	//
	// Spec §11 + §24.4 R7 names `sha256(upstream_host + ":" +
	// auth_identity + scope_salt)[:16]` as the eventual cache_scope
	// derivation. Today both seam call sites
	// (`internal/proxy/proxy.go::966` Tier-1 +
	// `internal/store/store.go::1376` Tier-2) use the literal
	// "default" — workspace-blind, single-scope. The R7 derivation
	// landing means wiring an auth_identity source (header parse?
	// operator email? machine ID?) at BOTH seams, then composing
	// with this salt. That's a cross-cutting change touching
	// proxy + store + per-adapter Tier-2 emit. Out of scope for
	// the v1 cachetrack closure; tracked as backlog item 9 in
	// `docs/plans/cachetrack-p3-backlog-2026-06-09.md` (R7
	// cache_scope derivation). DO NOT add ScopeSalt as an empty
	// field — the absence of the field IS the documentation that
	// this is deferred. If/when R7 lands, the field shape is
	// likely `string` plus a non-empty default per install.
}

// ExporterConfig groups second-rail telemetry exporters (Teams & Org
// Visibility, spec §2.4.3). Currently only the OTel exporter. Like the org
// client it is OFF by default: a solo-local install has no [exporter] section
// (or Enabled=false on each sub-exporter), so the daemon makes zero exporter
// network calls and the behaviour is byte-identical to a non-org build.
type ExporterConfig struct {
	OTel OTelExporterConfig `toml:"otel"`
}

// IngestConfig groups the agent-side native-telemetry receivers
// (native-console integration). Today only the OTLP logs receiver exists.
type IngestConfig struct {
	OTel IngestOTelConfig `toml:"otel"`
}

// IngestOTelConfig configures the embedded OTLP logs receiver that ingests a
// coding assistant's native telemetry (e.g. Claude Code with
// CLAUDE_CODE_ENABLE_TELEMETRY=1) directly — no OpenTelemetry Collector needed.
// Disabled by default: a solo-local install opens no listener and the
// solo-local UX stays byte-identical.
type IngestOTelConfig struct {
	// Enabled gates the receiver. When false (default), start.go opens no
	// listener and the process accepts no OTLP traffic.
	Enabled bool `toml:"enabled"`
	// GRPCAddr / HTTPAddr are the loopback binds for OTLP/gRPC and OTLP/HTTP.
	// Empty disables that transport. Defaults 127.0.0.1:4317 / 127.0.0.1:4318.
	GRPCAddr string `toml:"grpc_addr"`
	HTTPAddr string `toml:"http_addr"`
	// AllowNonLoopback permits binding a non-loopback address. Default false —
	// opening the receiver to a network is an explicit operator decision with
	// a documented threat model (native-console template §2.2 / L3).
	AllowNonLoopback bool `toml:"allow_non_loopback"`
	// ContentCapture sets how much of the OTel stream's CONTENT the receiver
	// stores: "full" (prompts + tool I/O bodies, when the admin enabled the
	// OTEL_LOG_* flags at Claude Code), "metadata" (turns/tokens only — content
	// events skipped), or "none" (alias of metadata). Default "full" — in an
	// admin-driven deployment the admin already chose to emit this content at
	// the source. Stored content is scrubbed for secrets and obeys the same
	// node-side push gate as locally-captured content.
	ContentCapture string `toml:"content_capture"`
	// ContentMaxBytes caps a single otel_content row's stored Content, after
	// scrubbing. Mirrors the org gateway's classify.Policy.BodyMaxBytes bound
	// (32 KiB) — an OTel content event is one prompt/tool-I/O body, the same
	// shape that bound already governs on the server-side capture ladder, and
	// unlike raw_tool_input/RawJSON's 1 MiB ceiling this stream has no
	// dashboard full-text-fetch use case pushing for a larger cap. 0 or
	// negative falls back to the default (partial TOML merge leaves it unset).
	ContentMaxBytes int `toml:"content_max_bytes"`
}

// OTelExporterConfig configures the agent-side OpenTelemetry exporter that
// emits one gen_ai.client span per api_turns row to any OTLP/HTTP endpoint
// (spec §2.4.3). It requires only M0 (it works identically on a solo-local
// install and never couples to the org server). All fields default to the
// safe, privacy-preserving option; OTEL_* environment variables override the
// file values at construction time per the OTel configuration spec.
type OTelExporterConfig struct {
	// Enabled gates the exporter. When false (the default), start.go starts
	// no exporter goroutine and the process makes zero OTLP network calls.
	Enabled bool `toml:"enabled"`
	// Endpoint is the OTLP/HTTP collector endpoint as host:port (no scheme,
	// no path — the SDK appends /v1/traces). Default "localhost:4318".
	// Overridden by OTEL_EXPORTER_OTLP_ENDPOINT / _TRACES_ENDPOINT.
	Endpoint string `toml:"endpoint"`
	// Insecure sends over plain HTTP instead of HTTPS. Default false.
	Insecure bool `toml:"insecure"`
	// PollIntervalSeconds is the row-tail poll cadence against api_turns.id.
	// Default 1.
	PollIntervalSeconds int `toml:"poll_interval_seconds"`
	// EmitPromptContent attaches prompt/completion bodies as the
	// gen_ai.client.inference.operation.details event. Default false — the
	// data-volume and privacy implications are documented in the exporter's
	// doc.go; the operator who turns it on has read that doc.
	EmitPromptContent bool `toml:"emit_prompt_content"`
	// EmitUserEmail attaches sbo.user.email when the agent is enrolled.
	// Default false — opt-in for the customer who wants per-developer slicing
	// in their own backend.
	EmitUserEmail bool `toml:"emit_user_email"`
	// SemconvStability is the value the exporter advertises for
	// OTEL_SEMCONV_STABILITY_OPT_IN. Default "gen_ai_latest_experimental" so
	// the exporter emits the v1.41.0 gen_ai.* attribute names. Overridden by
	// the OTEL_SEMCONV_STABILITY_OPT_IN environment variable.
	SemconvStability string `toml:"semconv_stability"`
}

// OrgClientConfig configures the Teams & Org Visibility agent-side push
// client (spec §2.6). It is OFF by default: a solo-local install has no
// [org_client] section (or Enabled=false), and that absence is the trigger
// for the no-op path — the daemon starts no push loop and writes no org
// data. Only an enrolled agent with Enabled=true pushes anything.
type OrgClientConfig struct {
	// Enabled gates the entire push loop. When false (the default), the
	// agent behaves byte-identically to a non-org build.
	Enabled bool `toml:"enabled"`
	// OrgServerURL is the base URL of the customer's org server, e.g.
	// "https://observer-org.acme.example". Required when Enabled.
	OrgServerURL string `toml:"org_server_url"`
	// PushIntervalSeconds is the cadence of the push loop. Default 120 (2m).
	PushIntervalSeconds int `toml:"push_interval_seconds"`
	// SnapshotIntervalSeconds bounds how often the SNAPSHOT wire families
	// (the teams-tier aggregates and the enterprise per-developer/per-session
	// wires) recompute, even when their source data changed. The CURSOR wires
	// — sessions, actions, api_turns, token_usage, guard_events, otel_content
	// — are unaffected and keep every push tick, so new activity still reaches
	// the org dashboard at push_interval_seconds.
	//
	// This is Lever 2 of the steady-state CPU remediation (plan Track R2): the
	// change-detection gate already skips a snapshot family whose source data
	// is untouched, and this knob additionally bounds worst-case CPU on a
	// CONSTANTLY-changing node, where that gate never gets to skip.
	//
	// 0 (the default) means 4× the effective push interval — computed at use,
	// so a node that tightens or loosens push_interval_seconds keeps the same
	// 4:1 relationship rather than inheriting a stale absolute. At the shipped
	// defaults that is 8 minutes. A NEGATIVE value disables the throttle: every
	// changed family recomputes on every tick (the pre-Track-R2 cadence).
	//
	// The staleness this buys is explicit and bounded: a snapshot wire can lag
	// its source by up to this interval. See docs/teams-operations.md.
	SnapshotIntervalSeconds int `toml:"snapshot_interval_seconds"`
	// PolicyPollIntervalSeconds is the cadence of the org policy-bundle
	// poll (guard spec §14.2). Default 3600 (1h). The poll also fires
	// once at `observer start`. Only meaningful on an enrolled agent
	// with the guard enabled — the daemon starts no poll loop
	// otherwise.
	PolicyPollIntervalSeconds int `toml:"policy_poll_interval_seconds"`
	// PolicyStateHeartbeatSeconds is the cadence of the P0-6 effective-
	// policy-state reporter's heartbeat POST (docs/plans/
	// plane-a-p0-6-effective-policy-state-plan.md §4.3). Default 300 (5m).
	// Content-free: only meaningful when [org_client.share].policy_state is
	// set — the reporter goroutine is not launched otherwise.
	PolicyStateHeartbeatSeconds int `toml:"policy_state_heartbeat_seconds"`
	// MaxPushBytes caps the uncompressed JSON size of a single batch.
	// Default 1 MiB; the client clamps to MaxPushBytesCeiling (16 MiB).
	MaxPushBytes int64 `toml:"max_push_bytes"`
	// KeychainID is the OS-keychain service/account handle under which the
	// bearer (and the agent's Ed25519 signing key) are stored.
	KeychainID string `toml:"keychain_id"`
	// Share gates the v1.8.0 content-bearing columns on the push payload.
	// Default zero value = metadata-only (hashes + counts only; raw paths
	// and commands withheld). A node operator can opt into full-content
	// sharing by setting [org_client.share].full_content = true. The org
	// admin cannot force this remotely — it lives solely in the node's
	// local config file.
	Share OrgClientShareConfig `toml:"share"`
	// Scope restricts which projects (by root path) push at all. Default
	// zero value = all projects. Combine with Share to narrow what
	// crosses the wire from both axes.
	Scope OrgClientScopeConfig `toml:"scope"`
	// Policy is [org_client.policy] — the Plane-A P0-5 unified policy
	// resource acceptance configuration (plan §6.4). See
	// OrgClientPolicyConfig.
	Policy OrgClientPolicyConfig `toml:"policy"`
}

// ConfiguredServerURL reports whether org_server_url carries a non-blank
// value IN CONFIG. It deliberately does NOT fold in Enabled, and it
// CANNOT fold in whether a persisted org_enrolment DB row exists — this
// package is pure TOML loading with no database access (CLAUDE.md
// "Module Boundaries" #1), so it has no way to see that row.
//
// This used to be a method named Enrolled() that returned `Enabled &&
// ConfiguredServerURL()` and was treated as "is this node's org rail
// running." That was a lie for a real, live shape: `ensureOrgClientBlock`
// (cmd/observer/org.go) is header-idempotent — an existing [org_client]
// table header means org_server_url is never (re)written — so a node
// enrolled before that field existed, or re-enrolled without a full
// `observer unenroll` first, can carry `enabled = true` with a genuinely
// blank org_server_url while its org_enrolment DB row (and the org
// server's own record of the enrolment) is perfectly real. The push,
// announcement, and routing-policy loops all dial the URL in THAT
// persisted row (internal/orgclient.Client.PushOnce), not this config
// field, so the old Enrolled() gate silently killed every org loop on a
// node that was, in fact, still enrolled.
//
// The real construction gate now lives in cmd/observer/start.go
// (orgClientShouldStart), which combines this method with a
// hasPersistedEnrolment DB lookup the config package cannot perform
// itself — see its doc comment for the four-state truth table. Use
// ConfiguredServerURL only where you genuinely mean "does config alone
// carry a server URL" (e.g. internal/diag and cmd/observer/privacy.go's
// best-effort, DB-free disclosure report, which say so explicitly).
func (c OrgClientConfig) ConfiguredServerURL() bool {
	return strings.TrimSpace(c.OrgServerURL) != ""
}

// OrgClientPolicyConfig is [org_client.policy] — the Plane-A P0-5 unified
// policy resource acceptance configuration
// (docs/plans/plane-a-p0-5-unified-policy-resource-v1-plan.md §6.4).
//
// RESTART REQUIRED: both lists are read once when the daemon constructs its
// policy-resource fetch options at start (Phase W wires the read site —
// internal/orgclient.PolicyResourceOptions.AcceptFamilies/
// PreauthorizeEnforce); changing this section takes effect on the next
// `observer start`, not on a running daemon.
//
// The v1 closed family enum is "admission.input" | "egress.routing_guardrail"
// | "gateway.providers" | "node.governance"
// (internal/policyfam.SupportedFamilies is the source of truth; duplicated
// here as literal strings rather than importing policyfam, matching this
// codebase's convention of each boundary owning its own copy of a small
// closed enum — see internal/policystate/collector.go and
// internal/policyfam/families.go, which do the same).
type OrgClientPolicyConfig struct {
	// AcceptFamilies is the closed set of families this node installs into
	// its durable cache. Default empty = accept nothing: every family is
	// still polled and reported (plan §6.6 — polling is independent of
	// this list), but nothing is durably cached/installed until an
	// operator opts a family in here.
	AcceptFamilies []string `toml:"accept_families"`
	// PreauthorizeEnforce MUST be a subset of AcceptFamilies — config.Validate
	// rejects a config where it is not. A family listed here whose
	// delivered body requests the family's "enforce" posture installs
	// live-enforceable; a family in AcceptFamilies but NOT here installs
	// inert (EnforceAllowed=false, InertReason=not_preauthorized) whenever
	// its body requests enforce — the signed body and its BodyHash are
	// never rewritten to reflect this, only the local enforcement gate is.
	PreauthorizeEnforce []string `toml:"preauthorize_enforce"`

	// NodeWorkspace / NodeEnvironment / NodeService are this node's
	// targeting attributes over the closed selector vocabulary
	// (internal/orgcontract.Selectors), used by the P0-10 Phase B
	// policy-targeting rail
	// (docs/plans/policy-targeting-rollback-design-2026-08-13.md §2).
	//
	// CORROBORATION ONLY — NOT AUTHORIZATION. The org server resolves the
	// AUTHORITATIVE attributes from the verified bearer's identity and
	// decides which resource a node is served; these values are never
	// presented to the server as a claim, and setting them can only make
	// this node install LESS (a delivered envelope whose signed selectors
	// contradict a value configured here is rejected selector_mismatch,
	// keeping the prior last-known-good policy). Setting them cannot
	// acquire a policy the server did not already choose to serve.
	//
	// Each key is independently optional. An attribute left empty is
	// "unknown to this node": a signed selector naming it is accepted and
	// logged as uncorroborated rather than blocking, so a fleet that has
	// not configured attributes yet keeps working across the upgrade.
	//
	// RESTART REQUIRED, like the two lists above.
	NodeWorkspace   string `toml:"node_workspace"`
	NodeEnvironment string `toml:"node_environment"`
	NodeService     string `toml:"node_service"`
}

// OrgClientScopeConfig restricts which projects (by root path) feed
// into the push payload. Both lists are exact-string match against
// `projects.root_path`. When ProjectRootAllowlist is non-empty, ONLY
// rows whose project_root is in the list are eligible. When
// ProjectRootDenylist is non-empty, rows whose project_root is in the
// list are skipped. Allowlist + denylist can be combined; denylist is
// applied to the allowlist result.
//
// Both lists are per-node config (TOML); the org admin cannot set them
// remotely. They sit alongside OrgClientShareConfig as the operator's
// other major scope-narrowing knob (alongside the share-mode opt-in).
type OrgClientScopeConfig struct {
	ProjectRootAllowlist []string `toml:"project_root_allowlist"`
	ProjectRootDenylist  []string `toml:"project_root_denylist"`
}

// OrgClientShareConfig is the per-node opt-in for full-content org
// sharing (v1.8.0 privacy posture, addressing Issues 1 + 2 of the
// 2026-06-02 teams test findings).
//
// FullContent, when true, causes the push seam to ship raw command
// bodies (actions.target for run_command), raw assistant prose
// (actions.target for task_complete), raw filesystem paths
// (actions.source_file, sessions.project_root, sessions.git_remote,
// api_turns.project_root, token_usage.project_root +
// token_usage.source_file) in addition to the always-present sha256
// hashes. When false (the default), only the hashes ship; raw
// content/path columns are stripped at the SQL seam.
//
// TargetActionAllowlist is a per-action opt-in for the raw target
// column specifically, useful when the operator wants the org dashboard
// to display human-readable file paths for safe action types
// (read_file, edit_file, write_file) but withhold commands
// (run_command) and prose (task_complete). Values must be exact
// action_type strings from models.ActionXxx. Empty list means: no
// per-action exception — when FullContent is false, NO action ships a
// raw target.
//
// These knobs are intentionally redundant with FullContent (a node that
// turns FullContent on doesn't need the allowlist) so a cautious
// operator can ship a *targeted* subset without buying into the full
// content posture. The contract is the same in either case: this lives
// on the node, the server cannot flip it remotely.
//
// PLANE BOUNDARY (docs/deployment-models.md; audit finding M1). This
// one struct carries flags for BOTH deployment planes. Grouped below:
//   - Plane B (this node's OWN coding-agent usage → org admin):
//     FullContent, TargetActionAllowlist, AdminManaged, RoutingSummary,
//     PolicyState.
//   - Plane A (general observability of an admin/org-hosted LLM app whose
//     END-USERS route through Observer): ObsSummary, ObsTraces, ObsContent,
//     ObsEvalSummary.
//
// The wire paths are already separate (obs tiers compose via the
// store.ObsOrgProviders func seam; the privacy sentinel forbids obs_*
// table names in orgpush.go). This grouping is legibility only — every
// flag is node-side opt-in, default false, never server-forced.
type OrgClientShareConfig struct {
	// --- Plane B: this node's own coding-agent usage ---
	FullContent           bool     `toml:"full_content"`
	TargetActionAllowlist []string `toml:"target_action_allowlist"`
	// AdminManaged flips the content-sharing default for an admin-driven
	// (native-console) deployment: when true, all content-bearing columns ship
	// raw by default. The premise differs from FullContent's node-opt-in — here
	// the org admin provisions the node via managed-settings/MDM and configured
	// the telemetry collection at the source, so sharing-by-default is the
	// intended posture. It remains a NODE-SIDE config the admin authors through
	// provisioning; there is no server-side force override (the no-remote-force
	// invariant holds). Default false — the zero value stays metadata-only.
	AdminManaged bool `toml:"admin_managed"`
	// FullToolBodies ships the four `actions` body columns — raw_tool_input,
	// raw_tool_output, preceding_reasoning, error_message — that the local
	// dashboard renders inline and that the org-push seam NEVER ships in any
	// other mode. It is its OWN tier, distinct from FullContent/AdminManaged
	// (which ship paths/targets but never these bodies), so extraction is
	// granular per the enterprise-managed control model. Node-side opt-in,
	// default false; on a MANAGED node the org may RAISE it remotely
	// (extract.managed authority) — the sanctioned enterprise lift — but on an
	// individual node it is node-only and can never be server-raised.
	FullToolBodies bool `toml:"full_tool_bodies"`
	// RoutingSummary opts the §R19.4 routing aggregate (counts +
	// dollars by tier/reason ONLY — never decision rows) onto the
	// push. Its own consent toggle, default false, node-side only —
	// the org admin cannot force it (model-routing spec §R26.4 +
	// the share-mode posture).
	RoutingSummary bool `toml:"routing_summary"`
	// CacheDetail opts the Arc 4 P5c cache-detail aggregate (day × model ×
	// kind counts + tokens + cost delta from the node-local cache_events log)
	// onto the wire. CONTENT-FREE — no prompt prefix, no raw scope, no path.
	// Its own consent toggle, default false, node-side only on an individual
	// node; on a managed node the org may RAISE it (extract.managed).
	CacheDetail bool `toml:"cache_detail"`
	// RoutingDetail opts the Arc 4 P5d routing-detail aggregate (day ×
	// original_model × selected_model × turn_kind × mode counts + savings from
	// the node-local router_decisions log) onto the wire. CONTENT-FREE but
	// MODEL-ID-BEARING (unlike routing_summary). Its own consent toggle,
	// default false, node-side only on an individual node; on a managed node
	// the org may RAISE it (extract.managed).
	RoutingDetail bool `toml:"routing_detail"`
	// LimitGauge opts the Arc 4 P5e predictions aggregate (per day × provider
	// rate-limit utilization from the node-local limit_snapshots log) onto the
	// wire. CONTENT-FREE (utilization stats only). Its own consent toggle,
	// default false, node-side only on an individual node; on a managed node
	// the org may RAISE it (extract.managed).
	LimitGauge bool `toml:"limit_gauge"`
	// CodeintelDetail opts the Arc 4 P5f codeintel-detail aggregate (per
	// project-hash × language file/symbol/edge counts from the node-local
	// code-intelligence index) onto the wire. CONTENT-FREE STRUCTURE counts —
	// no symbol name, fqn, signature, or raw path; the project path is one-way
	// hashed. Its own consent toggle, default false, node-side only on an
	// individual node; on a managed node the org may RAISE it via the DISTINCT
	// extract.codeintel authority (NOT the umbrella extract.managed — this is
	// the highest-sensitivity tier and gets its own explicit consent).
	CodeintelDetail bool `toml:"codeintel_detail"`
	// ProcessDetail opts the Arc 4 P5g process-detail aggregate (per day ×
	// tool run/exit/duration counts from the node-local process-observability
	// log) onto the wire. CONTENT-FREE counts — no exe path, argv, cwd,
	// network body, or hash. Its own consent toggle, default false, node-side
	// only on an individual node; on a managed node the org may RAISE it via
	// the DISTINCT extract.process authority (NOT the umbrella extract.managed
	// — the process/eBPF trees are a highest-sensitivity tier).
	ProcessDetail bool `toml:"process_detail"`
	// TerminalDetail opts the Arc 4 P5h terminal-detail aggregates (per
	// day×tool×kind terminal run/command counts + per day×kind×decision×principal
	// remote-audit event counts from the node-local terminal_* / remote_audit
	// logs) onto the wire. CONTENT-FREE counts — no command, hash, session id,
	// peer address, or route. Its own consent toggle, default false, node-side
	// only on an individual node; on a managed node the org may RAISE it via the
	// DISTINCT extract.terminal authority. The raw terminal_* / remote_audit
	// tables stay pinned out of the wire otherwise.
	TerminalDetail bool `toml:"terminal_detail"`
	// TaskDetail opts the session task/todo checklist (the node-local
	// task_items / task_transitions tables, agent migration 109) onto the
	// wire — docs/plans/node-session-detail-trickle-up-to-org-plan-2026-09-10.md
	// §2 "W2". It is a TWO-LEVEL tier, deliberately unlike its siblings: this
	// key alone ships the STATUS vocabulary, the vendor `raw_status` spelling,
	// the ordering/counters and the status transitions, so the org can render
	// "5 of 9 done, 1 vanished" for a session; the item PROSE (content /
	// active_form / owner — agent-authored plan text) additionally requires
	// full_content or admin_managed, exactly as obs.content's raw body does.
	// Its own consent toggle, default false, node-side only on an individual
	// node; on a managed node the org may RAISE it via the DISTINCT
	// extract.tasks authority (NOT the umbrella extract.managed — a work plan
	// is a high-sensitivity surface and gets its own explicit consent).
	TaskDetail bool `toml:"task_detail"`
	// ToolAccountDetail opts the vendor login / account observations (the
	// node-local tool_account_observations table, agent migration 111) onto
	// the wire — same plan, §2 "W3". Also a TWO-LEVEL tier: this key alone
	// ships the binding enums (binding_kind / role / source / scope / stage),
	// the opaque `account_key` and the observation time, which is everything
	// the org needs to render "account changed / conflict / unknown" and count
	// DISTINCT accounts; the raw identity (email / name / account_id — the one
	// genuine developer-PII field set in the arc) additionally requires
	// full_content or admin_managed (operator decision D2). Default false,
	// node-side only on an individual node; org-raisable on a managed node via
	// the DISTINCT extract.tool_accounts authority.
	ToolAccountDetail bool `toml:"tool_account_detail"`
	// PolicyState opts the P0-6 effective-policy-state reverse channel
	// (docs/plans/plane-a-p0-6-effective-policy-state-plan.md §2.3) onto a
	// dedicated POST /api/agent/policy-ack. CONTENT-FREE — the report carries
	// only hash/version/enum/timestamp rows (attribution empty-on-wire,
	// server-stamped). Its own consent toggle, default false, node-side only
	// — the org admin cannot force it (the share-mode posture).
	PolicyState bool `toml:"policy_state"`
	// --- Plane A: general observability of an admin/org-hosted LLM app ---
	// Org-tier observability opt-ins now live under the nested
	// [org_client.share.obs] sub-table (Obs below) so the config namespace
	// reflects the plane split (plane-separation audit M1). The four flat
	// keys after it (obs_summary/obs_traces/obs_content/obs_eval_summary)
	// are DEPRECATED but still parsed for one release: migrateLegacyOrgShareObs
	// maps them onto Obs.* at load (deprecation-warning once per key), and
	// `observer config migrate` (step 2) physically rewrites them.
	Obs OrgClientShareObsConfig `toml:"obs"`

	// Deprecated flat obs share keys — kept parseable for one release for
	// config-compat. Prefer [org_client.share.obs] (Obs above). Consumers
	// read Obs.*; the load-time shim copies these onto it when Obs.* is unset.
	ObsSummary     bool `toml:"obs_summary"`
	ObsTraces      bool `toml:"obs_traces"`
	ObsContent     bool `toml:"obs_content"`
	ObsEvalSummary bool `toml:"obs_eval_summary"`
}

// OrgClientShareObsConfig is [org_client.share.obs] — the Plane-A org-tier
// observability opt-ins (obs-org-tier plan §1, the T1–T4 ladder). Each
// default false, each independent, each node-side only (no server force).
// Summary = T1 aggregate rollup (content-free); Traces = T2 trace/span
// structure (hashes only); Content = T3 raw span bodies (additionally
// requires full_content/admin_managed for the raw body — the content_hash
// ships regardless); EvalSummary = T4 eval-run health. The underlying obs_*
// tables stay node-local; only these aggregates/structure cross the wire,
// via the obs provider seam.
type OrgClientShareObsConfig struct {
	Summary     bool `toml:"summary"`
	Traces      bool `toml:"traces"`
	Content     bool `toml:"content"`
	EvalSummary bool `toml:"eval_summary"`
	// Admission = T6 input-admission verdicts + policy snapshots (Plane-A
	// admission org tier, gap-audit 2026-07-10 §2.1 / #1a). Default false,
	// node-side opt-in only — there is NO remote toggle, the org admin cannot
	// force it (same posture as the other obs_* opt-ins). Verdict metadata is
	// content-free; the PII/prose columns additionally require
	// full_content/admin_managed, while the admin-authored policy body ships
	// regardless. The underlying obs_admission_* tables stay node-local; only
	// this tier's rows cross the wire, via the obs provider seam.
	Admission bool `toml:"admission"`
	// EvalItems = T7 per-item eval scores (Plane-A eval-run detail org tier,
	// gap-audit 2026-07-10 §1 / §2.2 / §6). Default false, node-side opt-in
	// only — there is NO remote toggle (same posture as the other obs_*
	// opt-ins). Distinct from EvalSummary (T4, run/scorer aggregates): this
	// ships the per-item scores that let the org Evals page drill into one run
	// and diff two runs. The score metadata + content_hash are content-free;
	// the item content excerpts additionally require full_content/admin_managed.
	// The underlying obs_eval_* tables stay node-local; only this tier's rows
	// cross the wire, via the obs provider seam.
	EvalItems bool `toml:"eval_items"`
	// Egress gates the T8 egress-routing decision feed (W5.3): what the
	// node's own compiled routing policy decided for outbound model/provider
	// calls. Default false, node-side only, never server-forced.
	Egress bool `toml:"egress"`
}

// Org-client push-size bounds (spec §2.4.2).
const (
	// DefaultMaxPushBytes is the default uncompressed batch ceiling (1 MiB).
	DefaultMaxPushBytes int64 = 1 << 20
	// MaxPushBytesCeiling is the hard upper bound the client clamps to (16 MiB).
	MaxPushBytesCeiling int64 = 16 << 20
	// DefaultPushIntervalSeconds is the default push cadence (2 minutes). Kept
	// deliberately short so a freshly-enrolled node's activity reaches the org
	// dashboard promptly — the 15-minute default it replaced was the dominant
	// cause of the "org dashboard is slow to update" complaint (the push loop is
	// async best-effort telemetry, never in a request path, so a tighter cadence
	// costs only a small, bounded delta upload). Existing nodes keep whatever
	// they already wrote to config; this only changes new enrollments.
	DefaultPushIntervalSeconds = 120
	// DefaultSnapshotIntervalMultiple is how many push intervals the snapshot
	// wire families coalesce into when [org_client] snapshot_interval_seconds
	// is unset (plan Track R2, Lever 2). Deliberately expressed as a MULTIPLE
	// rather than an absolute default so the ratio survives a node retuning
	// push_interval_seconds; internal/orgclient resolves it at use.
	DefaultSnapshotIntervalMultiple = 4
	// DefaultPolicyPollIntervalSeconds is the default org policy-bundle
	// poll cadence (1 hour — guard spec §14.2).
	DefaultPolicyPollIntervalSeconds = 3600
	// DefaultPolicyStateHeartbeatSeconds is the default P0-6 effective-
	// policy-state reporter heartbeat cadence (5 minutes).
	DefaultPolicyStateHeartbeatSeconds = 300
	// DefaultKeychainID is the default keychain service handle.
	DefaultKeychainID = "sbo-org-bearer-v1"
)

// OTel exporter defaults (spec §2.4.3 / §2.7).
const (
	// DefaultOTelEndpoint is the default OTLP/HTTP collector endpoint
	// (host:port). The SDK appends the /v1/traces path.
	DefaultOTelEndpoint = "localhost:4318"
	// DefaultOTelPollIntervalSeconds is the default api_turns row-tail
	// poll cadence.
	DefaultOTelPollIntervalSeconds = 1
	// DefaultOTelSemconvStability emits the v1.41.0 GenAI attribute names
	// per the OTel semconv transition plan.
	DefaultOTelSemconvStability = "gen_ai_latest_experimental"
	// DefaultIngestOTelGRPCAddr / DefaultIngestOTelHTTPAddr are the loopback
	// binds for the embedded OTLP logs receiver — the standard OTLP ports on
	// 127.0.0.1 so managed-settings can point Claude Code straight at them.
	DefaultIngestOTelGRPCAddr = "127.0.0.1:4317"
	DefaultIngestOTelHTTPAddr = "127.0.0.1:4318"

	// Content-capture levels for [ingest.otel].content_capture.
	ContentCaptureFull     = "full"     // store prompts + tool I/O content
	ContentCaptureMetadata = "metadata" // turns/tokens only; skip content events
	ContentCaptureNone     = "none"     // alias of metadata

	// DefaultIngestOTelContentMaxBytes is the default per-row cap for
	// [ingest.otel].content_max_bytes — see the field doc comment.
	DefaultIngestOTelContentMaxBytes = 32 << 10 // 32 KiB
)

// CapturesContent reports whether the configured content-capture level stores
// OTel content events. Unknown/empty values are treated as "full" (the default).
func (c IngestOTelConfig) CapturesContent() bool {
	switch c.ContentCapture {
	case ContentCaptureMetadata, ContentCaptureNone:
		return false
	default: // ContentCaptureFull and any unrecognized value
		return true
	}
}

// MaxContentBytes resolves the effective per-row content cap: the configured
// ContentMaxBytes when positive, else DefaultIngestOTelContentMaxBytes.
func (c IngestOTelConfig) MaxContentBytes() int {
	if c.ContentMaxBytes > 0 {
		return c.ContentMaxBytes
	}
	return DefaultIngestOTelContentMaxBytes
}

// ObserverConfig groups settings for the capture side of the system.
type ObserverConfig struct {
	DBPath      string            `toml:"db_path"`
	LogLevel    string            `toml:"log_level"`
	Watch       WatchConfig       `toml:"watch"`
	Freshness   FreshnessConfig   `toml:"freshness"`
	Secrets     SecretsConfig     `toml:"secrets"`
	Retention   RetentionConfig   `toml:"retention"`
	Hooks       HooksConfig       `toml:"hooks"`
	Antigravity AntigravityConfig `toml:"antigravity"`
	Process     ProcessConfig     `toml:"process"`
	DB          DBConfig          `toml:"db"`

	// ConfigVersion is the schema-migration stamp written by the config
	// auto-migration rail (internal/config/migrate). It records the
	// highest migration step applied to this file so the migrator can
	// skip an already-current config cheaply. Absent/0 on legacy files.
	// The migration DECISION reads the version from the raw file text;
	// this field only keeps the key out of the decoder's Undecoded set
	// and available to any in-process consumer. See MigrateFile.
	ConfigVersion int `toml:"config_version"`
}

// DBConfig controls the SQLite connection/pragma layer that
// internal/db.Open drives for the main observer.db (docs/plans/observer-
// disk-compute-remediation-plan-2026-08-26.md Phase 1, P0-B). It exists so
// an operator can tune the memory/disk tradeoff without a rebuild; the
// zero-value defaults below match internal/db.Options' own built-in
// defaults, so an unconfigured [observer.db] block is safe.
type DBConfig struct {
	// HardHeapLimitMB sets SQLite's process-global PRAGMA hard_heap_limit in
	// megabytes — the memory backstop that makes TempStore == "memory" safe:
	// a runaway unindexed sort or VACUUM fails fast with SQLITE_NOMEM
	// instead of exhausting host RAM. Zero (unset) applies the built-in
	// 1024 MB (1 GiB) default. A negative value explicitly disables the
	// pragma (omitted from the DSN entirely) — use with caution, and only
	// alongside TempStore == "file".
	HardHeapLimitMB int `toml:"hard_heap_limit_mb"`
	// TempStore selects SQLite's PRAGMA temp_store: "file" (spill temp
	// b-trees / VACUUM scratch to disk — the default), "memory" (hold temp
	// in RAM, bounded by HardHeapLimitMB), or "default" (inherit whatever
	// the driver/SQLite build ships with). Empty (unset) applies "file".
	// FILE is the default so the operator's `observer prune --vacuum` still
	// works on a multi-GB DB (MEMORY would fail SQLITE_NOMEM building the
	// whole-file temp copy in RAM) and nothing can OOM; see
	// internal/db.Options.TempStore for the full rationale.
	TempStore string `toml:"temp_store"`
	// MaxOpenConns bounds the connection pool (see
	// database/sql.DB.SetMaxOpenConns). Zero (unset) applies the built-in
	// default of 16.
	MaxOpenConns int `toml:"max_open_conns"`
	// ConnMaxIdleSeconds bounds how long an idle pooled connection is kept
	// before being closed (see database/sql.DB.SetConnMaxIdleTime). Zero
	// (unset) applies a 300s (5-minute) default.
	ConnMaxIdleSeconds int `toml:"conn_max_idle_seconds"`
	// IntegrityCheckMaxGB caps the AUTOMATIC `PRAGMA quick_check` the
	// daemon runs once per process, off its readiness path, via
	// db.RunStartupMaintenance (cmd/observer/diag.go::
	// runStartupDBMaintenance). quick_check checksums every page of the
	// file, so its cost scales with the database, not with the work the
	// daemon came to do — on a 41.8 GB install it was measured as the
	// dominant startup CPU cost (P1-D, docs/audits/observer-disk-compute-
	// exhaustion-audit-2026-08-26.md). Above this many GB the automatic
	// pass is skipped with one calm log line; the schema-034 path-hash
	// backfill still runs regardless (idempotent, cheap after its
	// done-marker). This gates ONLY the automatic startup pass —
	// `observer doctor` always runs its own quick_check unconditionally,
	// on demand, regardless of size. Default 8 (GB). ≤ 0 disables the
	// gate (quick_check always runs, matching pre-2026-08-26 behavior).
	IntegrityCheckMaxGB int `toml:"integrity_check_max_gb"`
}

// AntigravityConfig controls the Antigravity adapter's behavior.
//
// NetworkRecovery selects the fallback strategy when local .pb file
// decryption fails (which is currently the case on Windows hosts —
// the documented AES-128-CTR scheme doesn't match the Windows-side
// cipher). Values:
//
//   - "" / "off" (default): no fallback. Decrypt failure → warning,
//     skip the file. Pure-local, no network calls, no process tree
//     introspection.
//   - "local": try the running language_server's gRPC API on
//     localhost, falling back through the article-described
//     ConvertTrajectoryToMarkdown path. Requires Antigravity to be
//     running. The language_server has the in-memory key and decrypts
//     locally; we just consume the Markdown response and parse it
//     into events. Lossy compared to direct decryption (no per-tool
//     args, no token counts) but recovers the conversation flow.
//
// The "local" mode is opt-in because:
//   - It introspects running processes (visible cmdline args, CSRF
//     tokens) — strictly local, but a behavior change worth surfacing.
//   - On WSL2-with-Windows-Antigravity, the call requires a Windows-
//     side bridge (PowerShell shell-out) which adds per-call latency.
//   - The Markdown parser produces approximate events, not the
//     full-fidelity ToolEvent stream a real .pb decrypt would yield.
type AntigravityConfig struct {
	NetworkRecovery string `toml:"network_recovery"`

	// DumpShapeMismatchesDir, when non-empty, enables an opt-in
	// debug mode that writes the raw GetCascadeTrajectory gRPC
	// response bytes to disk whenever the adapter's
	// ParseStructuredTrajectory yields zero tokens AND empty model
	// on a non-trivial payload (≥ 10 KiB). Each dump goes to
	// <dir>/<conversation_id>.bin so the operator can compare wire
	// shapes between known-working and known-broken sessions when
	// investigating the v1.6.10 audit residual: some sessions
	// return 100s of KB of structured data but the proto-path
	// mapping at structured.go:122-185 doesn't extract anything
	// (e.g. maintainer session e371fdb1-… returned 430,202 bytes,
	// 0 tokens, model="").
	//
	// Default empty = no dumping. Set to an absolute path like
	// "/tmp/antigravity-shape-dumps/" to enable. The directory is
	// created on first dump (mkdir -p semantics). Files are owned
	// by the observer process; rotate or delete manually. (Issue
	// #5 follow-up — first pass only added the tracef warning.)
	DumpShapeMismatchesDir string `toml:"dump_shape_mismatches_dir"`
}

// ProcessConfig is the [observer.process] surface — the optional
// OS-level process-capture layer (docs/process-observability.md §11).
//
// UNLIKE CacheTrack/Guard/Advisor, this feature is OPT-IN: Enabled
// defaults to FALSE (D1). It may require elevated privileges and captures
// sensitive process metadata, so an install with no [observer.process]
// section makes zero process-backend calls and behaves byte-identically to
// a build without the feature (MVP acceptance criterion 1).
//
// The non-zero defaults below (Backend, RetentionDays, QueueSize,
// BatchSize, and the sub-section fields) only take effect once the operator
// flips Enabled. They are set in Default() so a partial [observer.process]
// section (e.g. just `enabled = true`) inherits sane values rather than
// zero — the same partial-merge discipline CacheTrackConfig documents.
type ProcessConfig struct {
	// Enabled gates the whole backend lifecycle. False = no backend is
	// constructed, no process_runs/process_events rows are written.
	// Restart-gated: flipping this in a running daemon takes effect on the
	// next start (the dashboard setup flow says so — §11).
	Enabled bool `toml:"enabled"`
	// Backend selects the capture source: "auto" (pick the best available
	// for the host OS), "linux_ebpf", "etw", "endpointsecurity", "poll"
	// (low-fidelity dev/test fallback), or "off". Default "auto".
	Backend string `toml:"backend"`
	// CaptureUnattributed stores process rows that could not be joined to a
	// session (D5/§9.2.7). Default false: unattributed processes are counted
	// for health only, never persisted, to bound the privacy blast radius.
	CaptureUnattributed bool `toml:"capture_unattributed"`
	// RetentionDays is the process_runs/process_events prune horizon, swept
	// by the retention pass — startup + the [observer.retention].
	// interval_hours periodic tick (cmd/observer/prune.go::runRetention).
	// Default 30. ≤ 0 disables the process prune.
	//
	// WHAT IT MEANS CHANGES WITH [archive].enabled, and the change is a
	// strict improvement. With archival OFF it is what it has always been:
	// the point at which process capture is DELETED, unrecoverably. With
	// archival ON it becomes the ARCHIVE FILE's own delete horizon, and
	// ArchiveDays below becomes the (earlier) point at which capture leaves
	// the hot database. So the same 30 means "hot for 14 days, recoverable
	// from cold storage for 30" rather than "hot for 30, then gone".
	RetentionDays int `toml:"retention_days"`
	// ArchiveDays is the horizon past which process capture is MOVED to
	// ~/.observer/archive.db instead of staying in the hot database. Default
	// 14. ≤ 0 disables the archive sweep (capture then stays hot until
	// RetentionDays deletes it, i.e. today's behaviour).
	//
	// Read only when [archive].enabled is true; with archival off this knob
	// does nothing and the process prune behaves exactly as before.
	//
	// The default sits WELL INSIDE RetentionDays deliberately. Process
	// capture is the arc's ONLY-COPY bucket (design §2.2) — live eBPF/ETW
	// records of processes that have since exited, with no artifact on disk
	// to re-derive them from — so the two horizons must not race: capture has
	// to reach cold storage with room to spare before anything deletes it.
	// 14 days also keeps the hot working set aligned with the window in which
	// an operator actually opens a process trail, which is the whole point of
	// separating hot from cold (design §1.3).
	ArchiveDays int `toml:"archive_days"`
	// QueueSize bounds the userspace enrichment queue between the backend
	// and the store batch writer. Overflow drops newest low-value events
	// after a health counter (§15). Default 10000.
	QueueSize int `toml:"queue_size"`
	// BatchSize is the store insert batch size (§15 targets 100–500 rows
	// per transaction). Default 250.
	BatchSize int `toml:"batch_size"`

	// WindowsBinaryPath is the Windows observer.exe the cross-OS bridge
	// (§5.5) execs over WSL interop — a /mnt/<drive>/... path (a C:\… path is
	// accepted and translated). Empty = auto-resolve. Used only by the
	// "bridge" backend (and "auto" on WSL). LOCAL-ONLY, never distributed.
	WindowsBinaryPath string `toml:"windows_binary_path"`
	// PollIntervalMS is the unified process-table snapshot cadence (the
	// "process poll rate" the dashboard Settings page exposes). It drives BOTH
	// the Linux /proc poll backend AND the Windows cross-OS bridge capturer, so
	// a single knob controls how often every process source is sampled. Default
	// 2000 (2s). Lower = fresher capture + more CPU; higher = cheaper but more
	// likely to miss short-lived commands (the poll backend can't see a process
	// that starts and exits inside one interval). LOCAL-ONLY, never distributed.
	PollIntervalMS int `toml:"poll_interval_ms"`
	// BridgePollIntervalMS optionally overrides PollIntervalMS for the bridge
	// capturer only (back-compat / asymmetric-cadence escape hatch). Zero =
	// inherit PollIntervalMS. Default 0. LOCAL-ONLY, never distributed.
	BridgePollIntervalMS int `toml:"bridge_poll_interval_ms"`
	// CorrelateIntervalMS is the cadence of the daemon's periodic background
	// cross-OS correlation sweep (docs/process-observability.md §9.2.5). The
	// deferred CorrelateCrossOS pass — the join that makes an unattributed
	// process row VISIBLE to a session — otherwise runs only lazily (a human
	// opening the dashboard Processes drawer, or `observer process tree`), so
	// captured rows stay invisible until someone looks. The sweep re-runs that
	// same idempotent, confidence-guarded store pass over the recent-active
	// session set every interval, so attribution converges without a viewer.
	// Default 90000 (90s); <= 0 inherits that default. RESTART-BOUND: the sweep
	// goroutine reads this once at daemon start (like Enabled / the poll loop),
	// so a change takes effect on the next start. LOCAL-ONLY, never distributed.
	CorrelateIntervalMS int `toml:"correlate_interval_ms"`

	Argv       ProcessArgvConfig       `toml:"argv"`
	Executable ProcessExecutableConfig `toml:"executable"`
	Env        ProcessEnvConfig        `toml:"env"`
	Network    ProcessNetworkConfig    `toml:"network"`
	Filesystem ProcessFilesystemConfig `toml:"filesystem"`
	Metrics    ProcessMetricsConfig    `toml:"metrics"`
	ETW        ProcessETWConfig        `toml:"etw"`
}

// ProcessETWConfig is the [observer.process.etw] surface: the daemon-side
// ACCEPT listener for the elevated Windows ETW capturer
// (docs/process-observability.md §5.5,
// docs/plans/process-obs-etw-windows-parity-plan-2026-07-26.md §W3).
//
// It is its OWN sub-block on purpose. [observer.process.network] is already
// taken by capture of the TARGET process's own connections (§7.2), and
// overloading that name would make two unrelated features share a namespace.
//
// WHY THE DAEMON LISTENS AND THE CAPTURER DIALS (measured 2026-07-26, not a
// preference): WSL cannot reach a Windows-bound listener — 127.0.0.1 is WSL's
// own loopback and the default gateway is dropped by Defender on the WSL vNIC
// — while Windows→WSL loopback works via localhostForwarding. So the elevated
// capturer dials out to this listener; the daemon never dials Windows. That
// needs no firewall rule and no host-IP discovery.
//
// SECURITY: localhostForwarding also means a WSL-side loopback listener is
// reachable from ANY process on the Windows host, including other users'. The
// shared token is therefore load-bearing, not decorative, and the listener has
// NO unauthenticated mode.
//
// This is an ADDITIVE feed, never a replacement: with it enabled the
// zero-privilege poll/bridge baseline runs exactly as before, and an install
// where no elevated capturer ever connects behaves identically to one without
// the block. LOCAL-ONLY, never distributed.
type ProcessETWConfig struct {
	// Enabled starts the daemon-side accept listener. Default FALSE: it opens
	// a port and the feed behind it needs an elevated Windows Scheduled Task,
	// so it follows the opt-in posture of the rest of [observer.process].
	Enabled bool `toml:"enabled"`
	// ListenAddr is the loopback bind. Default "127.0.0.1:8823" — its own
	// port, like every other loopback rail (proxy :8820, browser ingest
	// :8821). Kept in lock-step with processobs/bridge.DefaultListenAddr.
	ListenAddr string `toml:"listen_addr"`
	// AllowNonLoopback permits a non-loopback bind. Default false; the
	// listener refuses one otherwise (ErrNonLoopback). An explicit operator
	// decision, never a fallback.
	AllowNonLoopback bool `toml:"allow_non_loopback"`
	// Token is the shared secret the capturer must present as its first act.
	// Empty (the default) means the daemon GENERATES one and persists it 0600
	// at TokenPath, so the capturer can read it with --token-file. A token set
	// here is never written to disk — the operator who set it owns its
	// distribution.
	Token string `toml:"token"`
	// TokenPath overrides where a generated token is persisted. Empty =
	// "process-bridge-token" next to the observer DB.
	TokenPath string `toml:"token_path"`
	// HandshakeTimeoutMS bounds the authentication exchange only; an
	// authenticated stream is legitimately idle for long stretches and is not
	// deadlined. Default 10000 (10s). 0 inherits the default.
	HandshakeTimeoutMS int `toml:"handshake_timeout_ms"`
}

// ProcessMetricsConfig is the [observer.process.metrics] surface: the live
// CPU / memory / disk / network chart's ring buffer.
//
// THE WRITE-AMPLIFICATION TRAP this section exists to solve. The ring is
// persisted inside ONE column (process_runs.metric_samples_json), so every
// persist rewrites the whole row. Before this section the two cadences were
// welded together: the poll backend emitted a metrics event every
// poll_interval_ms (2s) and EVERY one of them rewrote the row, while the ring
// itself only accepted a new point every 15s — the worst of both worlds
// (30 row-rewrites/minute/process for a 4-point/minute chart). Sampling
// faster without splitting them would have multiplied those writes on a DB
// already in the multi-GB range.
//
// So SampleIntervalMS (how fresh the chart is) and PersistIntervalMS (how
// often we touch the DB) are independent, and PersistMaxSamples downsamples
// the stored copy so the column size does not grow with the sample rate. At
// the defaults: samples every 2s (7.5× finer than before), rows rewritten
// every 15s (7.5× fewer writes than before), ≤60 points stored (the same
// column size as before).
//
// LOCAL-ONLY, never distributed. Restart-bound (read once at daemon start).
type ProcessMetricsConfig struct {
	// SampleIntervalMS is the in-memory ring append cadence. Default 2000,
	// matching PollIntervalMS.
	//
	// CEILING: a sample can never be fresher than the poll that produced it.
	// Setting this BELOW [observer.process].poll_interval_ms does not make the
	// chart finer — it just makes every poll append a point instead of
	// refreshing one in place. To genuinely get 1s resolution you must ALSO
	// set poll_interval_ms = 1000, which doubles the /proc scan cost. The
	// daemon logs a WARN at start when this is below the poll interval rather
	// than silently promising resolution it cannot deliver.
	SampleIntervalMS int `toml:"sample_interval_ms"`
	// WindowSeconds is the retained live window: points older than
	// newest-window are evicted on append, so memory is bounded by TIME
	// regardless of how long a process lives. Default 300 (5 min).
	WindowSeconds int `toml:"window_seconds"`
	// MaxSamples hard-caps the in-memory ring whatever window/interval imply.
	// Default 300 (≈24 KB per tracked process, worst case).
	MaxSamples int `toml:"max_samples"`
	// PersistIntervalMS throttles DB row rewrites for metrics-only refreshes.
	// Lifecycle events (exec/exit) always persist, so a finished process
	// always lands with its final ring; at most this much of the tail is lost
	// if the daemon is killed. Default 15000. <= 0 persists every refresh (the
	// pre-decoupling behaviour — NOT recommended).
	PersistIntervalMS int `toml:"persist_interval_ms"`
	// PersistMaxSamples downsamples the persisted ring (evenly, always keeping
	// the oldest AND newest points). Default 60. <= 0 stores the whole ring.
	//
	// The stored ring still spans the whole window, but at
	// window_seconds/persist_max_samples resolution (5s at the defaults). To
	// store the full in-memory resolution set this to
	// window_seconds / (sample_interval_ms/1000) — 150 at the defaults — which
	// grows the bytes per rewrite but NOT the number of rewrites.
	PersistMaxSamples int `toml:"persist_max_samples"`
}

// ProcessArgvConfig controls argv capture (§8 Command group, §12.1).
type ProcessArgvConfig struct {
	// Mode: "preview" (scrubbed + capped preview plus full-argv hash),
	// "hash_only" (hash only, no preview — the enterprise posture), or
	// "off". Default "preview" (§19 Q1: on by default, capped, scrubbed).
	Mode string `toml:"mode"`
	// MaxPreviewBytes caps the stored argv preview. Default 512.
	MaxPreviewBytes int `toml:"max_preview_bytes"`
	// StoreArgCount keeps the integer argc even when the preview is off.
	// Default true.
	StoreArgCount bool `toml:"store_arg_count"`
}

// ProcessExecutableConfig controls executable hashing (§8 Executable group).
type ProcessExecutableConfig struct {
	// HashEnabled turns on content hashing of the resolved exe. Default
	// false (§19 Q6: useful but adds I/O cost).
	HashEnabled bool `toml:"hash_enabled"`
	// MaxHashFileSizeMB caps the file size eligible for hashing. Default 25.
	MaxHashFileSizeMB int `toml:"max_hash_file_size_mb"`
}

// ProcessEnvConfig controls environment posture capture (§8.1). Values
// always flow through the scrubber and a max-byte cap; this is posture
// (presence/hash), never full env.
type ProcessEnvConfig struct {
	// Enabled captures env posture (proxy-var presence, PATH hash,
	// virtualenv/node/CI hints). Default true.
	Enabled bool `toml:"enabled"`
	// Allowlist names additional env keys whose (scrubbed, capped) values
	// may be stored. Default empty.
	Allowlist []string `toml:"allowlist"`
	// StorePathHash stores a hash of PATH rather than its value. Default
	// true.
	StorePathHash bool `toml:"store_path_hash"`
}

// ProcessNetworkConfig controls network_connect capture (§7.2). Off until
// the privacy UX lands (§19 Q3).
type ProcessNetworkConfig struct {
	// Enabled turns on outbound-connect capture for attributed processes.
	// Default false.
	Enabled bool `toml:"enabled"`
	// CaptureRemoteHost stores the resolved remote host (scrubbed). Default
	// true (only meaningful when Enabled).
	CaptureRemoteHost bool `toml:"capture_remote_host"`
	// RedactPrivateIPs drops RFC1918/loopback destinations. Default false.
	RedactPrivateIPs bool `toml:"redact_private_ips"`
	// CaptureBodies stores capped/scrubbed request + response excerpts when a
	// capture source can see plaintext. Supported values:
	// "off" (metadata only), "proxied" (Observer proxy flows only), "available"
	// (any future plaintext/instrumented backend). Default "off".
	CaptureBodies string `toml:"capture_bodies"`
	// MaxRequestBytes caps the stored request-body excerpt. Default 65536.
	MaxRequestBytes int `toml:"max_request_bytes"`
	// MaxResponseBytes caps the stored response-body excerpt. Default 65536.
	MaxResponseBytes int `toml:"max_response_bytes"`
	// CaptureHeaders stores a scrubbed, compact allowlist of request/response
	// headers with body captures. Default true.
	CaptureHeaders bool `toml:"capture_headers"`
	// ScrubBodies applies the secret scrubber before body excerpts are stored.
	// Default true.
	ScrubBodies bool `toml:"scrub_bodies"`
	// StoreBinary allows non-text/binary response bodies to be stored as text
	// excerpts after best-effort UTF-8 conversion. Default false: binary bodies
	// get hashes/byte counts only.
	StoreBinary bool `toml:"store_binary"`
	// ProcessBytes turns on per-process CUMULATIVE socket byte counters, which
	// feed the live network series of the process metric samples. Default
	// FALSE: it attaches extra privileged eBPF programs (fentry/fexit on
	// tcp_sendmsg / tcp_cleanup_rbuf), so it follows the same opt-in posture as
	// the rest of [observer.process].
	//
	// LINUX ONLY, TCP ONLY. It needs CAP_BPF+CAP_PERFMON (or root), a
	// BTF-carrying kernel with BPF trampolines (≥5.5, x86-64/arm64), and it
	// counts TCP payload bytes only — no UDP/QUIC, no unix sockets, no
	// headers. Windows-side processes (the WSL cross-OS bridge) are NEVER
	// counted; that needs ETW and is not implemented. When the probes cannot
	// attach, capture degrades to lifecycle-only and samples are marked
	// UNMEASURED (never a fabricated zero).
	//
	// It yields BYTE COUNTS on sockets — never plaintext. TLS payloads stay
	// invisible to this path; body capture remains the proxy's job
	// (CaptureBodies).
	ProcessBytes bool `toml:"process_bytes"`
}

// ProcessFilesystemConfig controls file_write/file_open_sensitive capture
// (§7.2). Off outside high-signal paths.
type ProcessFilesystemConfig struct {
	// Enabled turns on filesystem side-effect capture. Default false.
	Enabled bool `toml:"enabled"`
	// Mode: "sensitive" (credential/config/SSH/token-like paths only),
	// "writes" (writes outside the project root), or
	// "all_attributed_writes". Default "sensitive".
	Mode string `toml:"mode"`
}

// WatchConfig controls the file watcher daemon.
type WatchConfig struct {
	PollIntervalSeconds int      `toml:"poll_interval_seconds"`
	MaxFileSizeMB       int      `toml:"max_file_size_mb"`
	EnabledAdapters     []string `toml:"enabled_adapters"`
}

// FreshnessConfig controls content hashing and classification.
type FreshnessConfig struct {
	EnableContentHashing bool     `toml:"enable_content_hashing"`
	MaxHashFileSizeMB    int      `toml:"max_hash_file_size_mb"`
	FastPathStatOnly     bool     `toml:"fast_path_stat_only"`
	IgnorePatterns       []string `toml:"ignore_patterns"`
}

// SecretsConfig controls the scrubbing pipeline.
type SecretsConfig struct {
	EnableScrubbing bool     `toml:"enable_scrubbing"`
	ExtraPatterns   []string `toml:"extra_patterns"`
}

// RetentionConfig controls DB pruning.
type RetentionConfig struct {
	MaxAgeDays            int  `toml:"max_age_days"`
	MaxDBSizeMB           int  `toml:"max_db_size_mb"`
	PruneOnStartup        bool `toml:"prune_on_startup"`
	ObserverLogMaxAgeDays int  `toml:"observer_log_max_age_days"`
	// IntervalHours is the cadence of the daemon's periodic maintenance
	// tick: `observer start` re-runs the full retention pass (the same
	// cmd/observer/prune.go::runRetention that prune_on_startup and
	// `observer prune` invoke) every IntervalHours while the daemon is
	// up, so a daemon that stays up for weeks still prunes. Default 24
	// (daily). ≤ 0 disables the tick (startup + manual prune only —
	// the pre-v1.20 behavior).
	IntervalHours int `toml:"interval_hours"`
	// WALAlertMB is the §1e follow-through (2026-08-22 write-stall arc):
	// the daemon's WAL watchdog WARNs and attempts a TRUNCATE checkpoint
	// once observer.db-wal exceeds this size. The 2026-08-21 stall left
	// the WAL pinned at 15.5 GB for hours because frames were long
	// checkpointed but the file was never released — bounded visibility
	// plus a reclaim attempt turns that from silent into actionable.
	// Default 1024 (1 GiB). ≤ 0 disables the watchdog.
	WALAlertMB int `toml:"wal_alert_mb"`
	// WALWatchMinutes is the watchdog cadence. Default 10. ≤ 0 disables.
	WALWatchMinutes int `toml:"wal_watch_minutes"`
	// CompactionEventsDays drops compaction_events rows whose timestamp is
	// older than this. Default 30. 0 keeps them forever.
	//
	// Each row carries a whole point-in-time file-state blob
	// (file_state_snapshot plus ghost_files_after), which averaged ~1.1 MB
	// per row on the operator's live node — 1.4 GiB in 1,333 rows, with no
	// horizon of any kind until 2026-09-16. The snapshot exists to
	// reconstruct what a session knew across a context compaction, which
	// stops being actionable long before the session's own actions age out,
	// so its horizon is deliberately much shorter than max_age_days.
	CompactionEventsDays int `toml:"compaction_events_days"`
	// CompressionEventsDays drops compression_events rows whose timestamp is
	// older than this. Default 90. 0 keeps them forever.
	//
	// One row per compression decision per proxied turn: small rows, but
	// 3.59M of them / 915 MB on the live node. The savings figures the
	// dashboard and `observer compression` report are rolled up from
	// api_turns, so this table is the per-decision debugging tail behind
	// them and can age out on its own, longer horizon.
	CompressionEventsDays int `toml:"compression_events_days"`
}

// HooksConfig controls hook runtime.
type HooksConfig struct {
	TimeoutMS int `toml:"timeout_ms"`
	// AutoRegister, when true, has `observer start` install hooks for
	// every detected tool on every launch (idempotent). New tools
	// installed after the daemon was first started are picked up on
	// the next restart without a manual `observer init`. Safe by
	// default: never overwrites user-authored hook entries — conflicts
	// log a warning and skip. Default: true.
	AutoRegister bool `toml:"auto_register"`
}

// ProxyConfig controls the API reverse proxy.
type ProxyConfig struct {
	Enabled           bool   `toml:"enabled"`
	Port              int    `toml:"port"`
	AnthropicUpstream string `toml:"anthropic_upstream"`
	OpenAIUpstream    string `toml:"openai_upstream"`
	ChatGPTUpstream   string `toml:"chatgpt_upstream"`
	GeminiUpstream    string `toml:"gemini_upstream"`
	ForceChatGPTHTTP  bool   `toml:"force_chatgpt_http"`
	// PrewarmTargets are URLs the proxy fires HEAD against at startup
	// to populate the http.Transport connection pool with warm TLS
	// sessions (V6-3 mitigation). The first real proxy request reuses
	// a pooled connection, saving the TLS handshake cost that pushed
	// codex's inner-pipe TTFB past its ~15s timeout. Defaults set in
	// Default(); empty slice disables pre-warm entirely.
	PrewarmTargets []string `toml:"prewarm_targets"`
	// Upstreams maps a routing id to an upstream base URL, selected
	// per-request via a `/up/<id>/` path prefix (Phase C per-provider
	// upstream selection). A routed tool whose traffic must reach a
	// non-default host — e.g. hermes → OpenRouter — points its base URL at
	// http://127.0.0.1:<port>/up/<id>/v1 and the proxy strips the prefix
	// and forwards to the mapped host. The value is the host root WITHOUT
	// the version suffix (the client's base URL keeps `/v1`), exactly like
	// the fixed upstreams: e.g. openrouter = "https://openrouter.ai/api".
	// Empty/unset → only the fixed three upstreams exist (current
	// behavior; fail-open). Locally authored here; an org may ALSO
	// distribute lane entries via the signed `gateway.providers` policy
	// family (installed through SetLaneTable, never written back into
	// this file) — the two sources merge at the live lane table, and
	// this TOML block remains the node-local layer.
	Upstreams map[string]string `toml:"upstreams"`
	// AutoDefaultLane names the Upstreams lane id the virtual `/up/auto/`
	// lane falls back to (gateway config plane spec Phase 2) when the
	// request's top-level model has no `<lane>/` prefix matching a
	// configured lane. Must name a key present in Upstreams when set
	// (validated below); "" means no default — an unresolvable auto
	// request falls through exactly like an unknown /up/<id> today
	// (fixed upstream, warn-once). Like Upstreams, this is the
	// node-local layer; the signed `gateway.providers` policy family can
	// also set the live auto-default via SetLaneTable.
	AutoDefaultLane string `toml:"auto_default_lane"`
	// OrgRoute is the node-local bootstrap for the org-wide AI Gateway
	// route (Phase P5a, docs/plans/plane-b-dual-mode-gateway-rbac-ia-
	// design-2026-08-29.md §2, Sol S7/S8). It mirrors the Upstreams/
	// AutoDefaultLane relationship above: this TOML block seeds
	// Proxy.SetOrgGatewayRoute at startup, and — once wired at the
	// cmd/observer layer — a signed org policy can supersede it hot with
	// no restart, the same two-source-one-live-table pattern already
	// used for [proxy.upstreams]. The zero value (no [proxy.org_route]
	// section) is fully inert: no SetOrgGatewayRoute call is ever made
	// for it, so an existing config gets byte-identical proxy behavior.
	OrgRoute ProxyOrgRouteConfig `toml:"org_route"`
}

// ProxyOrgRouteConfig is the node-local bootstrap shape for
// Proxy.SetOrgGatewayRoute(mode, primary, fallbacks) — see ProxyConfig.OrgRoute.
type ProxyOrgRouteConfig struct {
	// Mode is fed to SetOrgGatewayRoute verbatim — it must be exactly ""
	// (node mode, the default: org-route stays inert) or "gateway" (all
	// default-lane traffic, per Sol S8's fall-through guard, redirects to
	// Primary). There is deliberately no "node" synonym for the empty
	// string: this field carries the same wire vocabulary
	// SetOrgGatewayRoute already validates, not a separate translation
	// layer that could drift from it.
	Mode string `toml:"mode"`
	// Primary is the AI Gateway base URL. Required when Mode == "gateway";
	// ignored (and must be empty) when Mode == "".
	Primary string `toml:"primary"`
	// Fallbacks lists additional gateway/provider URLs for the fallback
	// ladder (Sol S10). The runtime executor (Luna L16,
	// internal/proxy/gatewayfallback.go) walks primary → each fallback →
	// TerminalPolicy on exhaustion.
	Fallbacks []string `toml:"fallbacks"`
	// TerminalPolicy is the fallback-ladder terminal rung reached after
	// primary + every fallback endpoint is exhausted: "" or "hold" (the
	// fail-closed default), "break_glass" (permission only — the lease rides
	// the enrolment rail), or "direct" (auto-fallback to the developer's
	// direct provider, which requires DirectFallbackCustodyAck). Fed verbatim
	// to Proxy.SetOrgGatewayRouteWithFallback, which validates it.
	TerminalPolicy string `toml:"terminal_policy"`
	// DirectFallbackCustodyAck acknowledges the custody downgrade that
	// TerminalPolicy == "direct" entails. Ignored for other terminals; the
	// proxy setter refuses to honor a "direct" terminal without it.
	DirectFallbackCustodyAck bool `toml:"direct_fallback_custody_ack"`
}

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
}

// CompressionConfig groups all four compression layers' toggles.
type CompressionConfig struct {
	CodeGraph    CodeGraphConfig    `toml:"code_graph"`
	Shell        ShellConfig        `toml:"shell"`
	Indexing     IndexingConfig     `toml:"indexing"`
	Conversation ConversationConfig `toml:"conversation"`
}

// CodeGraphConfig is the DEPRECATED [compression.code_graph] block.
//
// Deprecated: the external code-graph companion was
// decommissioned in Phase 4 in favour of the in-process [codeintel]
// module. The block is parsed for one release window only so existing
// configs don't break: on load, migrateLegacyCodeGraph maps `enabled`
// onto [codeintel].enabled and `auto_index` onto
// [codeintel.index].on_start, emits a per-key deprecation warning, then
// the values are otherwise unused. `auto_install` and `path` have no
// in-process analog (no binary is downloaded, no graph.db is read) and
// are reported as removed. See docs/codeintel/migration-from-codegraph.md.
type CodeGraphConfig struct {
	Enabled     bool   `toml:"enabled"`
	AutoInstall bool   `toml:"auto_install"`
	AutoIndex   bool   `toml:"auto_index"`
	Path        string `toml:"path"`
}

// ShellConfig controls shell output filtering.
type ShellConfig struct {
	Enabled         bool     `toml:"enabled"`
	ExcludeCommands []string `toml:"exclude_commands"`
}

// IndexingConfig controls FTS5 tool output indexing.
type IndexingConfig struct {
	Enabled         bool `toml:"enabled"`
	MaxExcerptBytes int  `toml:"max_excerpt_bytes"`
	Embeddings      bool `toml:"embeddings"`
}

// ConversationConfig controls conversation-level compression.
//
// Mode selects the strategy:
//   - "token": legacy default. Per-type compression then drop the
//     lowest-scored non-preserved messages until target_ratio is met.
//   - "cache": restricts drops to the tail half of the conversation
//     and injects a cache_control marker at the prefix boundary.
//   - "cache_aware": designed for Anthropic Pro/Max where the SDK
//     already places cache_control markers. Skips drops entirely
//     (drop ranking is budget-relative and shifts across turns,
//     invalidating Anthropic's prefix cache), narrows per-type
//     compression eligibility to RoleTool only, and skips cache_control
//     injection. The cross-turn determinism this preserves is what
//     makes cache_creation tokens fall on subsequent turns. No-ops
//     gracefully (effectively ModeToken without drops) when no SDK
//     marker is present.
type ConversationConfig struct {
	Enabled       bool     `toml:"enabled"`
	Mode          string   `toml:"mode"`
	TargetRatio   float64  `toml:"target_ratio"`
	PreserveLastN int      `toml:"preserve_last_n"`
	CompressTypes []string `toml:"compress_types"`
	// DisableDrops turns off the budget enforcer's lossy Pass-2
	// eviction (dropping the lowest-importance messages and replacing
	// runs with a `[N messages compressed — use search_past_outputs]`
	// marker). When true, the budget target becomes best-effort: only
	// the content-preserving per-type compressors run, and the body
	// ships with whatever compression they achieved — even 0% — never
	// truncated, never dropped.
	//
	// Default false = drops allowed = the historical behaviour for every
	// existing config and profile. Set true on a profile (see the
	// codex-safe recipe) whose per-type compressors frequently no-op, so
	// the enforcer can't degenerate into a drop-only pass. This is a
	// PROVIDER-NEUTRAL capability, distinct from the Anthropic-shaped
	// `mode = "cache_aware"` (which ALSO skips drops but additionally
	// narrows per-type eligibility to tool_result messages for prefix-
	// cache determinism). Added 2026-07-16.
	DisableDrops bool             `toml:"disable_drops"`
	Logs         LogsConfig       `toml:"logs"`
	Stash        StashConfig      `toml:"stash"`
	Compaction   CompactionConfig `toml:"compaction"`
	Rolling      RollingConfig    `toml:"rolling"`
}

// LogsConfig tunes LogsCompressor's final head+tail truncation pass
// (step 8 in the LogsCompressor pipeline; see
// internal/compression/conversation/logs.go). The earlier
// content-preserving steps (ANSI strip, CR collapse, dedup, blank-run
// cap) are not configurable — they have no destructive failure mode.
//
// The truncation pass is the only step that can elide content the
// agent may want to re-read. For codex-variant models (gpt-5.3-codex
// family) the post-truncation elision marker is treated as missing
// data and triggers re-derivation — see V7-11 in
// docs/v4-codex-compression-recipe-and-issues.md. Operators tuning
// for codex-variant workloads can disable truncation entirely by
// setting `max_lines = 0`, or raise the head/tail budgets so typical
// source-file reads (200-500 lines) survive verbatim.
type LogsConfig struct {
	// MaxLines is the ceiling on the post-dedup line count; zero
	// disables the truncation pass entirely. Default 200.
	MaxLines int `toml:"max_lines"`
	// Head is the line count preserved at the head of an over-budget
	// body; zero falls back to MaxLines/2. Default 100.
	Head int `toml:"head"`
	// Tail is the line count preserved at the tail of an over-budget
	// body; zero falls back to MaxLines/2. Default 100.
	Tail int `toml:"tail"`
}

// RollingConfig controls the v1.4.43+ / Tier 2 / D20 rolling-
// summarisation feature: when a session's conversation crosses
// ThresholdTokens, the proxy calls Anthropic with the user's captured
// auth to get a one-paragraph summary of older messages, then
// replaces them inline with a `[<N> earlier messages summarized: ...]`
// marker. Cross-turn invariance is preserved via a per-session
// sticky boundary — see internal/compression/conversation/rolling.go.
//
// Disabled by default. Opt-in via
// `compression.conversation.rolling.enabled = true`. Once dogfood on
// long sessions shows the cost/benefit (Haiku call cost vs. the
// avoided context blow-up + cache_creation premium) lands net-
// positive, the default may flip.
type RollingConfig struct {
	Enabled         bool `toml:"enabled"`
	ThresholdTokens int  `toml:"threshold_tokens"`
	// SummaryModel is the Anthropic-side rolling-summary model.
	// Default: "claude-haiku-4-5".
	SummaryModel string `toml:"summary_model"`
	// OpenAISummaryModel is the OpenAI-side rolling-summary model used
	// when the proxy is forwarding codex (or any other OpenAI-flavoured)
	// traffic. Default: "gpt-5-nano" (free per OpenAI's 2026-04-29
	// catalog). The two summary models are independent — Anthropic and
	// OpenAI traffic each pick their own.
	OpenAISummaryModel string `toml:"openai_summary_model"`
	AuthCacheSize      int    `toml:"auth_cache_size"`
}

// CompactionConfig controls the v1.4.43+ / Tier 3 / D23 compaction-
// survival feature: when enabled, the proxy detects Anthropic requests
// whose session_id has a recent compaction event in the observer DB
// and prepends a synthetic system block carrying recovery context
// (last reads, last edits, recent failures, learned rules) so the
// model can re-orient without re-Reading every file.
//
// Disabled by default. Opt-in via
// `compression.conversation.compaction.inject_post_compact = true`.
// Once dogfood shows recovery-context utility (model uses the data
// rather than ignoring it) and cross-turn invariance holds in
// practice, this may flip default-on.
type CompactionConfig struct {
	InjectPostCompact bool `toml:"inject_post_compact"`
}

// StashConfig controls the v1.4.41 / Tier 1 / G31 (CCR — Compressed
// Content Retrieval) feature: tool_result bodies whose post-per-type-
// compression size still exceeds ThresholdBytes are written to a
// content-addressed on-disk stash and replaced inline with a marker
// referencing the SHA. The model retrieves originals via the
// `retrieve_stashed` MCP tool.
//
// Disabled by default for the first release; opt-in via
// `compression.conversation.stash.enabled = true`. Once dogfood data
// shows the retrieve-rate is healthy and threshold tuning lands, this
// will flip to default-on.
type StashConfig struct {
	Enabled        bool   `toml:"enabled"`
	Dir            string `toml:"dir"`             // default: ~/.observer/stash
	ThresholdBytes int    `toml:"threshold_bytes"` // default: 8192
	MaxTotalMB     int    `toml:"max_total_mb"`    // default: 1024
}

// IntelligenceConfig groups intelligence-layer settings.
//
// MonthlyBudgetUSD is the user's self-set spend cap for the calendar
// month — surfaced on the Analysis dashboard as a progress tile. Zero
// disables budget tracking. Stored in `intelligence.monthly_budget_usd`.
// The Settings page (PR 2 of the dashboard refresh) writes this from the
// UI; until then users can edit `config.toml` directly.
//
// ProjectBudgetsUSD maps a project root path (exactly as the projects
// table records it) to a monthly advisory budget for that project.
// Absent / zero = no per-project budget. ADVISORY ONLY — budget state
// renders banners and tiles; nothing ever gates proxy traffic (P1).
// Stored in `[intelligence.project_budgets_usd]`; edited from the Cost
// page's Budget card or `observer config set
// intelligence.project_budgets_usd.<root> <usd>`.
type IntelligenceConfig struct {
	CodeGraph         IntelligenceCodeGraphConfig `toml:"code_graph"`
	Pricing           PricingConfig               `toml:"pricing"`
	APIKeyEnv         string                      `toml:"api_key_env"`
	SummaryModel      string                      `toml:"summary_model"`
	MonthlyBudgetUSD  float64                     `toml:"monthly_budget_usd"`
	ProjectBudgetsUSD map[string]float64          `toml:"project_budgets_usd"`
	MCP               IntelligenceMCPConfig       `toml:"mcp"`
	// OrgEnrichment opts this node into pulling Cloud Intelligence enrichment
	// from the ORG server it is enrolled with, instead of the hosted personal
	// plane (org-served-cloud-intelligence plan §2.1, W3). Read-only here; the
	// managed-node RAISE of this key is a govern authority (W5) under the
	// enterprise posture (an extract.intel grant on a managed enrolment), so
	// this is the node-authored default and, on an individual node, the
	// "never server-forced" floor. Default false:
	// a node that never sets it makes no org-intelligence request at all.
	OrgEnrichment bool `toml:"org_enrichment"`
}

// IntelligenceMCPConfig groups settings for the V7-12 retrieval-surface
// MCP tools and their shared audit log. Top-level switch is per-tool
// (each subtype carries its own Enabled flag) — there is no global
// `[intelligence.mcp].enabled` knob because operators should be able
// to disable individual tools without losing audit visibility.
//
// Features is the V7-16 allow-list for the four V7-12 retrieval tools
// (`get_file`, `get_symbols`, `get_relations`, `retrieve_stashed`).
// Scope is deliberately V7-12-only — the 13 built-in observability
// tools (check_*, get_action_details, get_cost_summary,
// get_failure_context, get_file_history, get_last_test_result,
// get_project_patterns, get_redundancy_report,
// get_session_recovery_context, get_session_summary,
// list_actions_around, search_past_outputs) are NOT filtered. See
// D-3 in docs/plans/v1.7.11-stash-retrieval-correctness-plan-2026-05-31.md
// for the trade-off discussion.
//
// Precedence: per-tool `enabled = false` ALWAYS wins. Features filter
// cannot re-enable a per-tool-disabled tool. Empty Features (the
// default) = no filter, per-tool flags decide alone.
type IntelligenceMCPConfig struct {
	Features        []string                             `toml:"features"`
	GetFile         IntelligenceMCPGetFileConfig         `toml:"get_file"`
	GetSymbols      IntelligenceMCPGetSymbolsConfig      `toml:"get_symbols"`
	GetRelations    IntelligenceMCPGetRelationsConfig    `toml:"get_relations"`
	RetrieveStashed IntelligenceMCPRetrieveStashedConfig `toml:"retrieve_stashed"`
	Audit           IntelligenceMCPAuditConfig           `toml:"audit"`
}

// IntelligenceMCPGetFileConfig tunes the v1.7.8 get_file MCP tool.
//
// AllowExtensions empty disables the allow-list (operator escape
// hatch for binary-mostly workloads); see V7-13 Gap 4 in
// docs/v4-codex-compression-recipe-and-issues.md.
//
// DenyPaths supports a small glob syntax: `*`, `?`, `<dir>/**`.
// Patterns using unsupported syntax (`[abc]`, `{a,b}`, escapes) are
// silently dead; [Load] emits a warning per unsupported pattern at
// startup so operators notice.
//
// MaxResponseKB caps individual response bytes. Truncated responses
// carry `truncated: true` so the agent knows to retry tighter.
type IntelligenceMCPGetFileConfig struct {
	Enabled         bool     `toml:"enabled"`
	AllowExtensions []string `toml:"allow_extensions"`
	DenyPaths       []string `toml:"deny_paths"`
	MaxResponseKB   int      `toml:"max_response_kb"`
}

// IntelligenceMCPGetSymbolsConfig tunes the v1.7.9 get_symbols MCP
// tool (V7-12 retrieval surface, second of four).
//
// Path-safety knobs (allow/deny lists, max response size) live on
// [IntelligenceMCPGetFileConfig] and are SHARED — one place to keep
// in sync; both tools resolve files the same way and operators
// shouldn't have to author two extension allow-lists. If a future
// release surfaces a divergence (e.g. get_symbols wants binary file
// extensions get_file shouldn't allow), this struct grows its own
// AllowExtensions/DenyPaths fields and the resolver prefers them
// over GetFile's.
//
// MaxCallers and MaxCallees cap the per-symbol callers/callees list
// returned by `include_relations: true`. The accompanying
// `callers_count` / `callees_count` fields report the unlimited
// totals so the agent sees `callers_count: 47, callers: [...top 20...]`
// without being misled.
type IntelligenceMCPGetSymbolsConfig struct {
	Enabled    bool `toml:"enabled"`
	MaxCallers int  `toml:"max_callers"`
	MaxCallees int  `toml:"max_callees"`
}

// IntelligenceMCPGetRelationsConfig tunes the v1.7.10 get_relations
// MCP tool (V7-12 retrieval surface, third of four).
//
// Path-safety knobs (allow/deny lists, max response KB) live on
// [IntelligenceMCPGetFileConfig] and are SHARED across all three
// retrieval tools — one place for operators to keep in sync.
//
// MaxDepth caps BFS recursion depth; MaxResults caps the per-call
// reachable-node count. Lower these on very large codebases where
// a worst-case BFS could otherwise visit thousands of nodes per call.
// Larger values are bounded only by SQLite recursive-CTE cost; the
// MCP layer truncates at MaxResults regardless.
type IntelligenceMCPGetRelationsConfig struct {
	Enabled    bool `toml:"enabled"`
	MaxDepth   int  `toml:"max_depth"`
	MaxResults int  `toml:"max_results"`
}

// IntelligenceMCPRetrieveStashedConfig tunes the v1.7.11
// retrieve_stashed MCP tool extension (V7-12 retrieval surface,
// fourth of four).
//
// Enabled gates registration. When the stash itself is enabled
// (`[compression.conversation.stash].enabled = true`) AND this flag is
// true, the tool is registered. Setting this to false lets operators
// keep proxy-side stash compression active while denying the agent
// the retrieval surface (e.g., security/audit scenarios where the
// proxy and the MCP server have asymmetric trust).
//
// MaxShasPerCall caps the array-form sha input per request. Defaults
// to 25 (matches get_symbols's per-call batch cap). Set higher only
// if your agent reliably emits larger batches AND your audit budget
// can absorb the per-sha row volume.
type IntelligenceMCPRetrieveStashedConfig struct {
	Enabled        bool `toml:"enabled"`
	MaxShasPerCall int  `toml:"max_shas_per_call"`
}

// IntelligenceMCPAuditConfig controls the V7-14 audit log. When
// Enabled, every V7-12 MCP call (success or denial) writes one row
// into mcp_audit. Operators can `SELECT ... FROM mcp_audit` for
// "what was denied?" / "what is the agent reading?" forensics until
// the operator CLI lands (deferred to v1.8.x).
//
// Default true: the table is local-only, the volume budget is small,
// and the forensic value is high. Privacy-conscious operators opt
// out with one TOML line.
type IntelligenceMCPAuditConfig struct {
	Enabled bool `toml:"enabled"`
}

// UnsupportedDenyPatterns returns the subset of [DenyPaths] that use
// glob syntax outside the supported `*`, `?`, `<dir>/**` subset
// (e.g. character classes `[a-z]`, brace alternation `{a,b}`, or
// escape sequences `\x`). The patterns are NOT removed from the
// config — they're inert at match time. Callers (notably
// `observer serve`) emit one warning line per returned pattern at
// startup so operators notice silently-dead deny rules.
func (g IntelligenceMCPGetFileConfig) UnsupportedDenyPatterns() []string {
	var bad []string
	for _, p := range g.DenyPaths {
		if hasUnsupportedDenyGlob(p) {
			bad = append(bad, p)
		}
	}
	return bad
}

// hasUnsupportedDenyGlob mirrors internal/mcp/pathsafety.go's
// hasUnsupportedGlobSyntax. Duplicated here (5 lines) so config
// doesn't import mcp — config sits beneath mcp in the dependency
// graph. Keep both in sync; the test
// [TestIntelligenceMCPGetFileConfig_UnsupportedDenyPatterns] pins
// the contract.
func hasUnsupportedDenyGlob(pattern string) bool {
	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '[', ']', '{', '}', '\\':
			return true
		}
	}
	return false
}

// IntelligenceCodeGraphConfig is the DEPRECATED [intelligence.code_graph]
// block.
//
// Deprecated: superseded by the in-process [codeintel] module (Phase 4).
// Parsed for one release window; on load `enabled` maps onto
// [codeintel].enabled with a deprecation warning. See
// docs/codeintel/migration-from-codegraph.md.
type IntelligenceCodeGraphConfig struct {
	Enabled bool `toml:"enabled"`
}

// PricingConfig carries per-model input/output/cache pricing.
//
// Models holds CURRENT rates — one entry per model id, replacing the
// baked-in row wholesale. Dated optionally holds a HISTORICAL rate
// timeline per model id, so a provider's mid-life price change doesn't
// silently reprice everything that came before it. Zero Dated entries =
// zero behaviour change.
type PricingConfig struct {
	Models map[string]ModelPricing `toml:"models"`
	// Dated maps a model id to its rate timeline, newest-last (order in
	// file doesn't matter; the cost engine sorts by effective_from).
	// The rate for usage at time T is the LAST entry whose
	// effective_from is <= T; if T precedes every entry, or the model
	// has no timeline, Models / the baked-in table applies.
	//
	// Because the flat table always represents CURRENT rates, a price
	// CUT needs BOTH periods spelled out — the historical one AND the
	// new one:
	//
	//	[[intelligence.pricing.dated."gpt-5.6-terra"]]
	//	effective_from = ""            # empty = since forever
	//	input = 2.50
	//	output = 15
	//	cache_read = 0.25
	//
	//	[[intelligence.pricing.dated."gpt-5.6-terra"]]
	//	effective_from = "2026-08-01"  # bare date = midnight UTC
	//	input = 1.75
	//	output = 10
	//	cache_read = 0.175
	//
	// effective_from accepts a bare date or an RFC3339 stamp. A row with
	// an unparseable date is SKIPPED (never fails closed) and reported
	// through cost.Engine.PricingWarnings.
	Dated map[string][]DatedModelPricing `toml:"dated"`
}

// DatedModelPricing is one period of a model's rate timeline: the rates
// that took effect at EffectiveFrom. Every ModelPricing field is
// available (including the long-context and fast-multiplier tiers) —
// a provider can change any of them.
//
// EffectiveFrom is inclusive: usage at exactly this instant bills at
// THIS entry's rates. Empty means "since forever", the idiomatic way to
// spell a timeline's oldest period.
type DatedModelPricing struct {
	EffectiveFrom string `toml:"effective_from"`
	ModelPricing
}

// ModelPricing is per-million-token pricing for a single model. CacheCreation
// is optional — when zero, the cost engine defaults it to 1.25 × Input
// (Anthropic's published cache-write premium). CacheCreation1h is the
// 1-hour ephemeral tier rate; defaults to 2 × CacheCreation when zero.
//
// LongContextThreshold + LongContext* model providers that reprice an
// entire request when the prompt exceeds a token threshold (Anthropic
// Sonnet 4 / 4.5 at 200K, OpenAI gpt-5.4 / gpt-5.5 at 272K, Gemini
// 2.5 Pro / 3.1 Pro at 200K). Threshold zero disables the tier; each
// LongContext* rate falls back to its standard counterpart when zero.
type ModelPricing struct {
	Input           float64 `toml:"input"`
	Output          float64 `toml:"output"`
	CacheRead       float64 `toml:"cache_read"`
	CacheCreation   float64 `toml:"cache_creation"`
	CacheCreation1h float64 `toml:"cache_creation_1h"`

	LongContextThreshold       int64   `toml:"long_context_threshold"`
	LongContextInput           float64 `toml:"long_context_input"`
	LongContextOutput          float64 `toml:"long_context_output"`
	LongContextCacheRead       float64 `toml:"long_context_cache_read"`
	LongContextCacheCreation   float64 `toml:"long_context_cache_creation"`
	LongContextCacheCreation1h float64 `toml:"long_context_cache_creation_1h"`

	// FastMultiplier scales every per-token rate when the turn was
	// served in the provider's low-latency "fast" tier (Anthropic Opus
	// 4.8 speed:"fast" → 2× across all dimensions). Zero means no fast
	// tier. Operators can pin per-model overrides for future SKUs that
	// adopt fast mode.
	FastMultiplier float64 `toml:"fast_multiplier"`
}

// Default returns the baked-in defaults (spec §16.1).
func Default() Config {
	return Config{
		Observer: ObserverConfig{
			DBPath:   "~/.observer/observer.db",
			LogLevel: "info",
			Watch: WatchConfig{
				PollIntervalSeconds: 2,
				MaxFileSizeMB:       50,
				EnabledAdapters: []string{
					"claude-code", "codex", "cline", "cline-cli", "roo-code", "zoo-code", "cursor", "copilot", "copilot-cli", "cowork", "opencode", "openclaw", "pi", "gemini-cli", "antigravity", "antigravity-cli", "hermes", "kilo-code", "kilo-code-cli", "qwen-code", "kiro-cli", "crush", "kimi-code", "grok", "devin", "qoder", "aider", "goose", "chatgpt-web", "claude-web", "perplexity-web", "gemini-web", "copilot-web", "droid", "open-interpreter", "command-code", "muse", "prime-agent", "deepseek", "junie", "zcode", "mistral-code", "freebuff", "grokbot", "kiro-crew", "poolside", "zed",
				},
			},
			Freshness: FreshnessConfig{
				EnableContentHashing: true,
				MaxHashFileSizeMB:    10,
				FastPathStatOnly:     true,
				IgnorePatterns: []string{
					"node_modules/", ".git/", "vendor/", "dist/", "build/",
					"target/", "__pycache__/",
					"*.exe", "*.bin", "*.wasm",
				},
			},
			Secrets: SecretsConfig{
				EnableScrubbing: true,
			},
			Retention: RetentionConfig{
				MaxAgeDays:            180,
				MaxDBSizeMB:           2048,
				PruneOnStartup:        true,
				ObserverLogMaxAgeDays: 30,
				IntervalHours:         24,
				WALAlertMB:            1024,
				WALWatchMinutes:       10,
				CompactionEventsDays:  30,
				CompressionEventsDays: 90,
			},
			Hooks: HooksConfig{
				TimeoutMS:    500,
				AutoRegister: true,
			},
			// Process observability (docs/process-observability.md §11) is
			// OPT-IN: Enabled defaults false (D1). The non-zero defaults
			// below only matter once the operator flips it; they're set
			// here so a partial [observer.process] section inherits sane
			// values rather than zeros (the CacheTrack partial-merge rule).
			Process: ProcessConfig{
				Enabled:              false,
				Backend:              "auto",
				CaptureUnattributed:  false,
				RetentionDays:        30,
				ArchiveDays:          14,
				QueueSize:            10000,
				BatchSize:            250,
				PollIntervalMS:       2000,
				BridgePollIntervalMS: 0,     // 0 = inherit PollIntervalMS (see resolveProcessPollIntervals)
				CorrelateIntervalMS:  90000, // background cross-OS correlation sweep cadence (90s); 0 = inherit
				Argv: ProcessArgvConfig{
					Mode:            "preview",
					MaxPreviewBytes: 512,
					StoreArgCount:   true,
				},
				Executable: ProcessExecutableConfig{
					HashEnabled:       false,
					MaxHashFileSizeMB: 25,
				},
				Env: ProcessEnvConfig{
					Enabled:       true,
					StorePathHash: true,
				},
				Network: ProcessNetworkConfig{
					Enabled:           false,
					CaptureRemoteHost: true,
					RedactPrivateIPs:  false,
					CaptureBodies:     "off",
					MaxRequestBytes:   64 * 1024,
					MaxResponseBytes:  64 * 1024,
					CaptureHeaders:    true,
					ScrubBodies:       true,
					StoreBinary:       false,
					ProcessBytes:      false, // privileged eBPF attach — opt-in
				},
				// Live-chart ring. Sample at the poll cadence, retain 5 min,
				// persist every 15s with at most 60 stored points — see
				// ProcessMetricsConfig for the write-amplification arithmetic.
				Metrics: ProcessMetricsConfig{
					SampleIntervalMS:  2000,
					WindowSeconds:     300,
					MaxSamples:        300,
					PersistIntervalMS: 15000,
					PersistMaxSamples: 60,
				},
				Filesystem: ProcessFilesystemConfig{
					Enabled: false,
					Mode:    "sensitive",
				},
				// Daemon-side accept listener for the elevated Windows ETW
				// capturer. OFF by default; the values below are seeded so a
				// bare `[observer.process.etw] enabled = true` inherits sane
				// ones rather than zeros (the partial-merge rule).
				ETW: ProcessETWConfig{
					Enabled:            false,
					ListenAddr:         "127.0.0.1:8823", // == processobs/bridge.DefaultListenAddr
					AllowNonLoopback:   false,
					HandshakeTimeoutMS: 10000,
				},
			},
			// SQLite connection/pragma tuning (docs/plans/observer-disk-
			// compute-remediation-plan-2026-08-26.md Phase 1, P0-B). These
			// mirror internal/db.Options' own built-in defaults; spelled out
			// here so a partial [observer.db] section inherits sane values
			// rather than zeros (the CacheTrack partial-merge rule).
			DB: DBConfig{
				HardHeapLimitMB:     1024,
				TempStore:           "file",
				MaxOpenConns:        16,
				ConnMaxIdleSeconds:  300,
				IntegrityCheckMaxGB: 8,
			},
		},
		// Cloud seeds only the compiled-in public WorkOS client id — every
		// other [cloud] key defaults to its zero value (manual-only until an
		// operator opts in; see CloudConfig).
		Cloud: CloudConfig{
			WorkOSClientID: DefaultCloudWorkOSClientID,
		},
		// Org client is OFF by default (solo-local invariant). The defaults
		// below only take effect once a user sets [org_client] enabled = true.
		OrgClient: OrgClientConfig{
			Enabled:                     false,
			PushIntervalSeconds:         DefaultPushIntervalSeconds,
			PolicyPollIntervalSeconds:   DefaultPolicyPollIntervalSeconds,
			PolicyStateHeartbeatSeconds: DefaultPolicyStateHeartbeatSeconds,
			MaxPushBytes:                DefaultMaxPushBytes,
			KeychainID:                  DefaultKeychainID,
		},
		// OTel exporter is OFF by default (solo-local invariant). The
		// defaults below only take effect once a user sets
		// [exporter.otel] enabled = true.
		Exporter: ExporterConfig{
			OTel: OTelExporterConfig{
				Enabled:             false,
				Endpoint:            DefaultOTelEndpoint,
				Insecure:            false,
				PollIntervalSeconds: DefaultOTelPollIntervalSeconds,
				EmitPromptContent:   false,
				EmitUserEmail:       false,
				SemconvStability:    DefaultOTelSemconvStability,
			},
		},
		Ingest: IngestConfig{
			OTel: IngestOTelConfig{
				Enabled:          false,
				GRPCAddr:         DefaultIngestOTelGRPCAddr,
				HTTPAddr:         DefaultIngestOTelHTTPAddr,
				AllowNonLoopback: false,
				ContentCapture:   ContentCaptureFull,
				ContentMaxBytes:  DefaultIngestOTelContentMaxBytes,
			},
		},
		// Dashboard: the org-announcements rail (announcements plan §4)
		// is default-ON. Seeded here so the partial-merge rule holds —
		// an existing config with only [dashboard].addr set must keep
		// the rail on, not inherit a zero-value false. Addr stays empty
		// (the built-in 127.0.0.1:8081 default resolves in cmd).
		Dashboard: DashboardConfig{
			OrgAnnouncements: true,
		},
		// CacheTrack is default-ON per spec §11: local, passive,
		// network-free, hashes/counts/enums only. An install with
		// no [cachetrack] section gets Enabled=true here; partial-
		// merge against an empty section leaves it true so the
		// loader doesn't silently downgrade to false.
		CacheTrack: CacheTrackConfig{
			Enabled:            true,
			MaxTrackedSessions: 64,
			RetentionDays:      90,
		},
		// CacheWarm (cache-expiry warning + smart keep-warm) — the
		// WARNING half is default-ON (pure read over cache_entries, zero
		// LLM cost); the KEEP-WARM half (Keepwarm.Mode) is OFF by default
		// (outward-facing spend, opt-in like routing enforce). Same
		// partial-merge rule as CacheTrack — an install with no
		// [cachewarm] section keeps Enabled=true and Keepwarm.Mode="off".
		CacheWarm: CacheWarmConfig{
			Enabled:                 true,
			WarnAtSeconds:           90,
			CriticalAtSeconds:       30,
			MinValueUSD:             0.05,
			ImplicitWarnSeconds:     3600,
			ImplicitCriticalSeconds: 7200,
			ImplicitMaxSeconds:      86400,
			Keepwarm: KeepWarmConfig{
				Mode:                "off",
				MinValueUSD:         0.20,
				MinResumeConfidence: 0.5,
			},
		},
		// Predict (Next-Message Cost & Limit Predictor) is default-ON:
		// the cost estimate is pure read-side math, the limit capture is
		// a cheap header parse on the proxy path. Same partial-merge rule
		// as CacheTrack — an install with no [predict] section keeps
		// Enabled=true.
		Predict: PredictConfig{
			Enabled:                true,
			YoungSessionMessages:   3,
			DefaultTurnsPerMessage: 12,
			PriorWindowDays:        30,
		},
		// Guidance (the agent-guidance-file inventory) is default-ON for
		// the same reasons CacheTrack is: local, passive, network-free,
		// and it records names/sizes/hashes — never file bodies. Same
		// partial-merge rule — an install with no [guidance] section gets
		// Enabled=true here, and a section that sets only rescan_minutes
		// must not silently downgrade Enabled to a zero-valued false.
		Guidance: GuidanceConfig{
			Enabled:               true,
			RescanMinutes:         15,
			MaxFileBytes:          512 * 1024,
			MaxDepth:              4,
			IncludeUserScope:      true,
			MaxRootsPerPass:       50,
			RootTimeoutSeconds:    20,
			RootTimeoutMaxSeconds: 180,
			PassTimeoutMinutes:    10,
			StartupDelaySeconds:   90,
			FirstScanPollSeconds:  60,
		},
		// Pricing feed (standalone-node pricing sync) is OPT-IN and OFF by
		// default — the zero-egress-by-default invariant (D3). The seed sets
		// only the endpoint and cadence so an operator who flips enabled=true
		// needs no further lines. Same partial-merge rule as Predict — an
		// install with no [pricing.feed] section gets this seed (Enabled=false),
		// not a zero-valued struct with an empty URL.
		Pricing: PricingSectionConfig{
			Feed: PricingFeedConfig{
				Enabled:           false,
				Auto:              false,
				URL:               DefaultPricingFeedURL,
				PollIntervalHours: 24,
			},
		},
		// Loc (lines-of-code tracking) carries only the editor-endpoint
		// credential. Same partial-merge rule as CacheTrack/Predict — an
		// install with no [loc] section gets this seed, so the daemon
		// generates and reads the token file at the standard path without
		// the operator writing a config line. Required=false this release
		// (see the field comment); LOCAL-ONLY.
		Loc: LocConfig{
			EditorTokenFile:     DefaultLocEditorTokenFile,
			EditorTokenRequired: false,
		},
		// Update (enterprise update management) is DEFAULT-ON for the
		// notify half and DEFAULT-OFF for the apply half, which is the
		// §2.4 failure-mode direction expressed as a seed: learning that
		// you are behind is fail-open and costs no new egress class,
		// applying an update is fail-closed. AutoApply is left nil — not
		// false — so the managed-fleet carve-out (§3.9) can supply the
		// default without overriding a node that answered for itself.
		// LOCAL-ONLY, never distributed.
		Update: UpdateConfig{
			Enabled:          true,
			AutoApply:        nil,
			KeepPreviousDays: 14,
			MaxDownloadBytes: 268435456,
			StateDir:         DefaultUpdateStateDir,
			DrainTimeout:     "90s",
			HandshakeTimeout: "60s",
		},
		// Tasks (session-level task/todo/plan checklist tracking) is
		// default-ON: it is a pure re-decode of data already captured in
		// actions.raw_tool_input/raw_tool_output, no new capture surface.
		// Same partial-merge rule as CacheTrack/Predict — an install with
		// no [tasks] section keeps Enabled=true.
		Tasks: TasksConfig{
			Enabled:               true,
			MatchMode:             "exact",
			ConcurrentAttribution: "shared",
			IncludeSidechains:     false,
			BackfillOnStart:       false,
			RetentionDays:         0,
		},
		// AggregateShare (opt-in aggregate rail) is OFF by default in every
		// path. Unlike CacheTrack/Predict, the partial-merge default keeps
		// Enabled=false — only Endpoint is seeded so a consenting operator
		// inherits the published collector without hand-typing it. The zero
		// value (no [aggregate_share] section) is also OFF. LOCAL-ONLY,
		// org-independent, never on the Teams wire.
		AggregateShare: AggregateShareConfig{
			Enabled:             false,
			Endpoint:            DefaultAggregateEndpoint,
			AllowCustomEndpoint: false,
		},
		// Remote (remote dashboard access) is OFF by default in every path:
		// exposure is the first network-facing node surface, so the zero value
		// (no [remote] section) AND the partial-merge default keep it inert —
		// loopback-only, today's behaviour. The non-zero seeds are the SECURE
		// defaults a consenting operator inherits (TLS required, terminal off,
		// argon2-class rate limit, bounded device sessions). LOCAL-ONLY,
		// org-independent, never on the Teams wire.
		Remote: RemoteConfig{
			Enabled:                      false,
			Mode:                         "off",
			RequireTLS:                   true,
			AllowTerminal:                false,
			AllowRemoteTerminalTakeover:  true,
			AllowTerminalView:            true,
			AllowStandingTerminalControl: false,
			WriterLeaseIdleMinutes:       5,
			WriterLeaseMaxMinutes:        30,
			RateLimitPerMin:              6,
			CapabilityTTLMinutes:         10,
			// Device sessions: 24h idle inside a 48-hour absolute cap
			// (2026-07-25 mobile terminal-continuity arc; 48h is the
			// operator's decision over the 7d first implemented). An EXISTING
			// config.toml that already spells session_ttl_minutes = 720 /
			// session_idle_minutes = 60 keeps those values — BurntSushi's
			// field-level decode leaves only ABSENT keys at the seed — so an
			// upgrading operator who wants the new window must clear or edit
			// those two keys. Kept in lock-step with
			// remoteauth.DefaultSessionTTL / DefaultSessionIdle (pinned by
			// internal/config/continuity_defaults_test.go).
			SessionTTLMinutes:  DefaultRemoteSessionTTLMinutes,
			SessionIdleMinutes: DefaultRemoteSessionIdleMinutes,
			MaxSessions:        5,
			Notify: RemoteNotifyConfig{
				Enabled: false,
				Kind:    "webhook",
				Events:  []string{"session_blocked", "session_finished"},
			},
		},
		// Browser (opt-in browser-chatbot capture rail) — the RAIL is
		// default-ON (Enabled=true) so it is ready the moment the operator
		// installs the extension, but the HTTP LISTENER is default-OFF
		// (the native-messaging bridge is the default receiver) and the
		// GranularityCeiling defaults to "full" — local-first posture,
		// same as coding-agent capture (see the BrowserConfig field
		// comment for the rationale + the fail-closed extension side).
		// Same partial-merge rule as CacheTrack — an install with no
		// [browser] section keeps these values. LOCAL-ONLY.
		Browser: BrowserConfig{
			Enabled: true,
			Listener: BrowserListenerConfig{
				Enabled:    false,
				ListenAddr: "127.0.0.1:8821",
			},
			GranularityCeiling: "full",
			RetentionDays:      0,
			IngestTimeoutMS:    defaultBrowserIngestTimeoutMS,
		},
		// Handoff (session handoff / continue-anywhere) is default-ON:
		// pure read-side until the operator runs `observer handoff`.
		// Same partial-merge rule as CacheTrack. LOCAL-ONLY.
		Handoff: HandoffConfig{
			Enabled:              true,
			TailMessages:         6,
			MaxDocTokens:         12000,
			DefaultCarry:         "distilled_tail",
			FileName:             "HANDOFF-{shortid}.md",
			HookMaxBytes:         8192,
			HookTTLMinutes:       240,
			RetentionDays:        180,
			AllowDashboardLaunch: true,
			ContextWarnTokens:    200_000,
			MaxCacheBytes:        8 * 1024 * 1024,
		},
		// Terminal (the embedded web-terminal cockpit) is default-ON for the
		// terminal-wide surface + status detection, but fresh-agent launch is
		// a SEPARATE default-OFF opt-in ([terminal.launch].allow_fresh_agent).
		// Same partial-merge rule as CacheTrack — an install with no [terminal]
		// section inherits these values. LOCAL-ONLY.
		Terminal: TerminalConfig{
			Enabled:        true,
			MaxConcurrent:  9,
			IdleTimeout:    "0", // never idle-reap live sessions (continuity default)
			RingBytes:      262144,
			MaxSubscribers: 8,
			// WS liveness: ping every 30s, 10s per pong, tolerate 5 consecutive
			// misses (~3.3 min) so a frozen backgrounded mobile tab survives a
			// trip to the mail app. A dead peer is still reaped.
			WSPingIntervalSeconds: 30,
			WSPingTimeoutSeconds:  10,
			WSPingFailuresAllowed: 5,
			Status:                TerminalStatusConfig{Enabled: true},
			// Attach is default-ON (owner-only AF_UNIX 0600 socket), children
			// proxy-routed by default; DefaultOn makes the launchers attach by
			// default (opt-out per-launch with --no-attach).
			Attach: TerminalAttachConfig{Enabled: true, RouteProxy: true, DefaultOn: true, ReclaimOnInput: true, ForwardAuthEnv: true},
			// Launch: fresh-launch fields stay zero-valued (opt-in), but the
			// guided-install kill-switch defaults ON — the consent is the
			// dashboard click, so this only lets an operator turn it OFF.
			Launch: TerminalLaunchConfig{AllowInstall: true},
			// Sandbox (B9): the master switch stays off, but the mechanism
			// defaults are seeded so an operator flipping just `enabled =
			// true` gets the documented v1 shape (bwrap, tmpfs home, 300s
			// prep timeout) rather than an unusable all-zero block.
			Sandbox: TerminalSandboxConfig{
				Enabled:                false,
				Backend:                "bwrap",
				HomeMode:               "tmpfs",
				DefaultOn:              false,
				AllowRemoteClone:       false,
				AllowWorktreeSource:    false,
				WorkspaceRetentionDays: 0,
				PrepTimeoutSeconds:     300,
			},
			// [terminal.ssh] — default ON for VISIBILITY (2026-08-28 operator
			// ruling); the surface still launches nothing without an
			// operator-authored [[terminal.ssh.profiles]] entry, so a fresh
			// install with no profiles remains inert. The two timeouts are
			// seeded to the sshprofile defaults so `observer config` prints
			// the real values; a 0 in a hand-written config still resolves to
			// the same numbers at argv-composition time.
			SSH: TerminalSSHConfig{
				Enabled:               true,
				ConnectTimeoutSeconds: 10,
				KeepaliveSeconds:      30,
			},
		},
		// Benchmark (the Benchmarks Harness) is CLI-driven; the only default
		// is the retention horizon for the node-local benchmark_* tables.
		Benchmark: BenchmarkConfig{
			RetentionDays: 180,
		},
		// CodeIntel (the in-process code-intelligence module) is
		// default-ON for indexing (read-only on the repo, zero LLM cost),
		// but the only model-visible change (compression.code_aggressive)
		// stays OFF. Same partial-merge rule as CacheTrack.
		CodeIntel: CodeIntelConfig{
			Enabled:        true,
			AutoIndexLimit: 25000,
			MaxFileBytes:   2_000_000,
			RetentionDays:  90,
			Index: CodeIntelIndexConfig{
				OnStart:               true,
				Watch:                 true,
				Mode:                  "auto",
				OnStartTimeoutMinutes: 10,
			},
			Compression: CodeIntelCompressionConfig{},
			Semantic: CodeIntelSemanticConfig{
				Embedder:  "tfidf",
				SimilarTo: true,
			},
		},
		// Archive (cold storage, corpus archival arc) is OPT-IN: disabled
		// means the retention pass behaves exactly as it did before the arc.
		// The non-zero defaults below only decide HOW it behaves once an
		// operator turns it on.
		Archive: ArchiveConfig{
			Enabled:            false,
			Path:               "~/.observer/archive.db",
			MaxProjectsPerPass: 8,
			BatchRows:          512,
		},
		// Advisor (the suggestions engine, docs/advisor.md) is default-ON:
		// read-layer only, local, zero LLM cost. Same partial-merge
		// rule as CacheTrack — an install with no [advisor] section
		// gets Enabled=true. Detector thresholds default in the
		// advisor package (Phase-0 calibrated); config overrides land
		// in a later phase.
		Advisor: AdvisorConfig{
			Enabled:              true,
			WindowDays:           14,
			MinConfidence:        0.5,
			MinSavingsUSD:        1.0,
			SessionDigest:        false,
			DigestRefreshMinutes: 30,
		},
		// Routing (docs/model-routing-spec.md §R21) is OFF by default —
		// an opt-in feature, unlike cachetrack. The sub-defaults matter
		// for the partial-merge invariant: `[routing] enabled = true`
		// alone must yield advise mode on the value template, never
		// zero-valued strings.
		Routing: defaultRouting(),
		SelfObs: SelfObsConfig{
			Enabled:        false,
			RoutingSampleN: 32,
		},
		// Observability itself defaults OFF (Enabled: false, the zero
		// value — unlike CacheTrack this subsystem has real setup cost:
		// the obs_* schema + OTLP receiver). ProxyTurnTraces is seeded
		// true so that once an operator DOES flip Enabled on, an
		// [observability] section that only sets `enabled = true`
		// still gets the gateway rail (the CacheTrack partial-merge
		// rule) rather than silently landing on a zero-valued false.
		Observability: ObservabilityConfig{
			ProxyTurnTraces: true,
		},
		// Guard (security & control layer, guard spec §16) is
		// default-ON in OBSERVE mode (D2): local, deterministic,
		// flags + alerts but never blocks until the operator flips
		// enforce. Same partial-merge rule as CacheTrack — an
		// install with no [guard] section gets Enabled=true +
		// Mode="observe", never zero values. Boundary slices stay
		// nil so the policy-engine defaults apply. Cloud features
		// are all-off (D1: explicit opt-in only).
		Guard: GuardConfig{
			Enabled:       true,
			Mode:          "observe",
			Strict:        false,
			RetentionDays: 365,
			Rules: GuardRulesConfig{
				UserPolicy:    "~/.observer/guard-policy.toml",
				ProjectPolicy: ".observer/guard-policy.toml",
				OrgBundle:     "~/.observer/org-policy-bundle.json",
			},
			Taint: GuardTaintConfig{
				Enabled:    true,
				DecayTurns: 10,
			},
			Proxy: GuardProxyConfig{
				EgressScan: true,
				// "mask" per §8.2: default-on in enforce for
				// detector-certain types; inert in observe mode (D2 —
				// observe never mutates, every verdict is a flag).
				EgressAction:        "mask",
				ResponseScan:        true,
				InjectionHeuristics: true,
			},
			MCP: GuardMCPConfig{
				Pinning:             true,
				PoisoningHeuristics: true,
			},
			Alerts: GuardAlertsConfig{
				Desktop:     true,
				MinSeverity: "high",
			},
			Dialects: GuardDialectsConfig{
				Compile: true,
			},
			Cloud: GuardCloudConfig{
				PayloadMaxBytes: 4096,
			},
			// Prompt (prompt-submit intervention, §8.1) is default-ON
			// with the reconsider-once posture: certain PII and
			// certain secrets interrupt the developer once, everything
			// else is off/warn. Same partial-merge rule as the rest of
			// [guard] — an install with a bare `[guard.prompt]` (or no
			// section at all) gets these seeded values, never zero
			// values.
			Prompt: GuardPromptConfig{
				Enabled:            true,
				Mode:               "ask-once",
				HookLane:           true,
				ProxyLane:          true,
				EnforceIndependent: true,
				ReconsiderTTL:      "30m",
				ReconsiderMinDelay: "3s",
				SuppressInCode:     true,
				MaxFindings:        64,
				Detectors: map[string]string{
					"credit_card": "ask-once",
					"iban":        "ask-once",
					"us_ssn":      "ask-once",
					"uk_nino":     "ask-once",
					"in_aadhaar":  "ask-once",
					"in_pan":      "ask-once",
					"email":       "off",
					"phone_e164":  "off",
					"phone_nanp":  "off",
					"github_pat":  "block",
				},
			},
		},
		Profiles: defaultProfiles(),
		Proxy: ProxyConfig{
			Enabled:           true,
			Port:              8820,
			AnthropicUpstream: "https://api.anthropic.com",
			OpenAIUpstream:    "https://api.openai.com",
			ChatGPTUpstream:   "https://chatgpt.com",
			GeminiUpstream:    "https://generativelanguage.googleapis.com",
			// V6-3 pre-warm: HEAD against these URLs at proxy
			// startup so the first real codex request reuses a
			// warm TLS connection. Empty slice (set explicitly in
			// config.toml) disables pre-warm.
			PrewarmTargets: []string{
				"https://chatgpt.com/",
				"https://api.openai.com/",
			},
		},
		Compression: CompressionConfig{
			CodeGraph: CodeGraphConfig{
				Enabled:     true,
				AutoInstall: true,
				AutoIndex:   true,
			},
			Shell: ShellConfig{
				Enabled:         true,
				ExcludeCommands: []string{"curl", "playwright"},
			},
			Indexing: IndexingConfig{
				Enabled:         true,
				MaxExcerptBytes: 2048,
			},
			Conversation: ConversationConfig{
				Enabled:       false,
				Mode:          "cache_aware",
				TargetRatio:   0.85,
				PreserveLastN: 5,
				// Default excludes "text": its head-tail truncation
				// strategy elides mid-content from tool_result bodies the
				// agent may re-reference, forcing re-reads (one fewer
				// answer, two more turns).
				//
				// "code" entered the allow-list in v1.4.40 once
				// CodeCompressor was rewritten content-preserving (no
				// body elision, no signature-only skeleton). JSON schema
				// replacement, logs dedup, and code skeleton are all
				// content-preserving; text head-tail is not. Users who
				// want text can opt in explicitly.
				//
				// V7-22 (v1.7.22, 2026-06-01): the default was temporarily
				// flipped to []{} based on an n=4 measurement that showed
				// +60% cost regression on the V7-21 binary. V7-24 (v1.7.23,
				// 2026-06-01) re-measured on the V7-22 binary at n=8 and
				// found the cascade had stopped — V7-22's preceding fixes
				// (V7-19 nil-trap + V7-21 tools-defs gate) closed enough of
				// the re-marshal pathway that per-type compression no longer
				// breaks Anthropic's prefix cache.
				//
				// Restored to ["json","logs","code"] as the empirical
				// winner: -6.9% cost vs no-proxy (n=8), CV 7.6% (tighter
				// than OFF's 7.5%), zero tail outliers. Operators MUST
				// also set ENABLE_TOOL_SEARCH=true in the launching shell
				// to recover Claude Code's deferred MCP loading (otherwise
				// the SDK eager-inlines all MCP schemas under
				// ANTHROPIC_BASE_URL, costing ~+21K tokens per turn).
				//
				// "text" is omitted by choice — TextCompressor head-tail
				// eliding middle content is the v1.4.38 regression class.
				// "tools" is opt-in (V7-21). Stash is opt-in but cache-
				// breaking on Anthropic — see StashConfig.
				//
				// See docs/v1.7.23-compression-savings-empirical-2026-06-01.md.
				CompressTypes: []string{"json", "logs", "code"},
				Logs: LogsConfig{
					MaxLines: 200,
					Head:     100,
					Tail:     100,
				},
				Stash: StashConfig{
					Enabled:        false,
					Dir:            "~/.observer/stash",
					ThresholdBytes: 8192,
					MaxTotalMB:     1024,
				},
				Compaction: CompactionConfig{
					InjectPostCompact: false,
				},
				Rolling: RollingConfig{
					Enabled:            false,
					ThresholdTokens:    80000,
					SummaryModel:       "claude-haiku-4-5",
					OpenAISummaryModel: "gpt-5-nano",
					AuthCacheSize:      1024,
				},
			},
		},
		Intelligence: IntelligenceConfig{
			CodeGraph: IntelligenceCodeGraphConfig{Enabled: true},
			Pricing:   PricingConfig{Models: map[string]ModelPricing{}},
			MCP: IntelligenceMCPConfig{
				GetFile: IntelligenceMCPGetFileConfig{
					Enabled: true,
					AllowExtensions: []string{
						"ts", "tsx", "js", "jsx", "mjs", "cjs",
						"py", "rs", "go", "java", "kt", "rb", "php", "swift",
						"c", "cc", "cpp", "h", "hpp", "cs",
						"md", "txt", "json", "toml", "yaml", "yml",
						"html", "css", "scss", "sass",
						"sh", "bash", "ps1", "sql",
					},
					DenyPaths: []string{
						".env*", "*.key", "*.pem", "*.pfx", "*.p12",
						".git/**", ".hg/**", ".svn/**",
						"node_modules/**", "vendor/**",
						".ssh/**", ".aws/**", ".gnupg/**",
						".npmrc", ".pypirc", ".netrc",
					},
					MaxResponseKB: 100,
				},
				GetSymbols: IntelligenceMCPGetSymbolsConfig{
					Enabled:    true,
					MaxCallers: 20,
					MaxCallees: 20,
				},
				GetRelations: IntelligenceMCPGetRelationsConfig{
					Enabled:    true,
					MaxDepth:   5,
					MaxResults: 100,
				},
				RetrieveStashed: IntelligenceMCPRetrieveStashedConfig{
					Enabled:        true,
					MaxShasPerCall: 25,
				},
				// Features empty = no filter applied (per-tool flags
				// alone decide registration). See doc-comment on
				// IntelligenceMCPConfig.Features for V7-16 precedence.
				Features: []string{},
				Audit:    IntelligenceMCPAuditConfig{Enabled: true},
			},
		},
	}
}

// LoadOptions parameterizes Load.
type LoadOptions struct {
	// GlobalPath overrides the location of the user-global config. Defaults to
	// ~/.observer/config.toml.
	GlobalPath string
	// ProjectPath, when set, is a per-project .observer/config.toml that
	// overrides the global file.
	ProjectPath string
	// Env is the environment lookup function. Defaults to os.Getenv.
	Env func(string) string
	// GovernanceSidecar overrides the governance sidecar path (admin-
	// controlled Plane B, Phase 1b §1.3). Empty means "resolve the default
	// beside the DB". Set to config.NoGovernanceSidecar to disable the read
	// entirely — used by the solo-parity invariant test and by
	// `observer config show --local`.
	GovernanceSidecar string
	// GovernanceNow overrides the clock the sidecar's expiry rule is
	// evaluated against. Nil means time.Now. Injected so the offboarding
	// rule is testable without sleeping.
	GovernanceNow func() time.Time
}

// Load merges defaults ← global TOML ← project TOML ← environment overrides.
// Missing TOML files are not errors (defaults apply). Env variable form:
// OBSERVER_<SECTION>_<KEY> (uppercased, underscores). Nested sections are
// joined with additional underscores, e.g. OBSERVER_COMPRESSION_CONVERSATION_ENABLED.
// ResolveGlobalPath returns the global config file path Load would
// use given the same override. Lets callers (notably the Settings
// page's PUT /api/config/pricing handler) locate the file for
// save-back operations without reimplementing the resolution rule.
func ResolveGlobalPath(override string) (string, error) {
	if override != "" {
		return override, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".observer", "config.toml"), nil
}

// Load merges defaults ← global TOML ← project TOML ← env ← GOVERNANCE.
//
// Governance is LAST for one honest reason: last-writer-wins is the only
// merge order in which a pinned value is the value the process actually
// uses. It is NOT an anti-escape control — the sidecar's own location is
// derived from Observer.DBPath, which is settable from the global TOML, a
// project TOML and the env, so pointing db_path elsewhere yields no sidecar
// in one line. §1.8 concedes that class honestly.
//
// Load NEVER fails because of governance (review B4): if the merged config
// fails Validate WITH the overlay, the whole overlay is discarded and the
// ungoverned config is returned. A governance-caused Load error would turn
// every hook invocation on every node into an early return with a stderr
// line, losing fleet-wide ingest for a policy typo.
func Load(opts LoadOptions) (Config, error) {
	cfg, _, err := LoadGovernance(opts)
	return cfg, err
}

// LoadGovernance is Load plus the record of what the governance sidecar did.
// The disclosure surfaces (`observer org grant show`, `observer doctor
// governance`) and the daemon's startup identity (§1.6, pending_restart) use
// the outcome; every other caller uses Load and ignores it.
func LoadGovernance(opts LoadOptions) (Config, GovernanceOutcome, error) {
	if opts.Env == nil {
		opts.Env = os.Getenv
	}
	cfg := Default()

	// NOTE (Track R, P2.2): the v1.7.6 recipe overlay that used to sit
	// here is gone. Recipes are now compression PROFILES resolved per
	// traffic class at the proxy boundary (profiles.go) — never merged
	// into the global Config, so a dashboard save can no longer bake
	// recipe values into config.toml. `observer start --recipe` survives
	// as a deprecated alias mapped onto [profiles] for the run, in
	// cmd/observer.

	globalPath := opts.GlobalPath
	if globalPath == "" {
		home, err := os.UserHomeDir()
		if err == nil {
			globalPath = filepath.Join(home, ".observer", "config.toml")
		}
	}
	globalMeta, err := mergeTOMLFile(&cfg, globalPath)
	if err != nil {
		return Config{}, GovernanceOutcome{}, err
	}
	metas := []toml.MetaData{globalMeta}
	if opts.ProjectPath != "" {
		projMeta, err := mergeTOMLFile(&cfg, opts.ProjectPath)
		if err != nil {
			return Config{}, GovernanceOutcome{}, err
		}
		metas = append(metas, projMeta)
	}
	// Capture the config-file dashboard addr BEFORE env overrides so a
	// MALFORMED OBSERVER_DASHBOARD_ADDR can be dropped without failing Load —
	// matching the silent-drop precedent of the int/float/bool env overrides
	// in setEnvValue (a bad env value is ignored, never fatal). Because
	// resolveDashboardAddr (cmd/observer) reads the same env var directly and
	// ranks a valid --dashboard-addr flag ABOVE it, a hard Load failure here
	// would let a garbage env value shadow a perfectly good flag. Demote to a
	// one-time warning and restore the file value so validation proceeds.
	dashAddrFromFile := cfg.Dashboard.Addr
	applyEnvOverrides(&cfg, opts.Env)
	if envAddr := strings.TrimSpace(opts.Env("OBSERVER_DASHBOARD_ADDR")); envAddr != "" {
		if err := ValidateDashboardAddr(cfg.Dashboard.Addr); err != nil {
			emitConfigWarnOnce(fmt.Sprintf("OBSERVER_DASHBOARD_ADDR=%q ignored (%v); falling back to --dashboard-addr flag / [dashboard].addr / default", envAddr, err))
			cfg.Dashboard.Addr = dashAddrFromFile
		}
	}

	// Phase 4 decommission: map the deprecated [compression.code_graph]
	// and [intelligence.code_graph] blocks onto [codeintel] and warn once
	// per legacy key. Honored for one release window, then removed.
	for _, w := range migrateLegacyCodeGraph(&cfg, metas) {
		emitDeprecationOnce(w)
	}

	// Corpus-archival P4: [codeintel] keys that were removed outright rather
	// than renamed. Nothing to map — the warning IS the migration.
	for _, w := range migrateRemovedCodeIntelKeys(&cfg, metas) {
		emitDeprecationOnce(w)
	}

	// M1 plane-separation: map the deprecated flat [org_client.share]
	// obs_* keys onto the nested [org_client.share.obs] sub-table and warn
	// once per legacy key. Honored for one release window, then removed.
	for _, w := range migrateLegacyOrgShareObs(&cfg, metas) {
		emitDeprecationOnce(w)
	}

	cfg.Observer.DBPath = expandHome(cfg.Observer.DBPath)
	cfg.Archive.Path = expandHome(cfg.Archive.Path)
	cfg.Compression.Conversation.Stash.Dir = expandHome(cfg.Compression.Conversation.Stash.Dir)
	cfg.Loc.EditorTokenFile = expandHome(cfg.Loc.EditorTokenFile)
	cfg.Update.StateDir = expandHome(cfg.Update.StateDir)

	// Governance overlay — the LAST merge step (§1.3). Everything above is
	// the ungoverned config; the overlay is applied to a COPY so a
	// Validate failure can fall back to it without re-parsing.
	now := time.Now
	if opts.GovernanceNow != nil {
		now = opts.GovernanceNow
	}
	file, gout := readGovernanceSidecar(cfg, opts.GovernanceSidecar, now())
	if file == nil {
		if err := Validate(cfg); err != nil {
			return Config{}, gout, err
		}
		return cfg, gout, nil
	}
	governed := cfg
	applyGovernancePins(&governed, file.Pinned, &gout)
	if err := Validate(governed); err != nil {
		// Review B4: a well-formed, correctly-typed pinned value that
		// Validate rejects must NEVER make Load fail. Six of the nine
		// hook.go config.Load sites return before db.Open, so the fleet
		// would lose ingest and the developer would see a stderr line on
		// every tool call. Discard the WHOLE overlay, record why, and
		// return the ungoverned config.
		gout.Discarded, gout.DiscardErr = true, err.Error()
		gout.Applied = nil
		if verr := Validate(cfg); verr != nil {
			return Config{}, gout, verr
		}
		return cfg, gout, nil
	}
	return governed, gout, nil
}

// deprecationEmit guards one-per-process printing of config deprecation
// lines. config.Load runs in ~20 short- and long-lived call sites during a
// single `observer start` (proxy, watcher, dashboard, every feature
// goroutine, hooks auto-register) — each re-parses the same file and,
// pre-dedup, re-printed the identical block of deprecation lines, drowning
// the `dashboard → http://…` readiness banner. The dedup suppresses only
// the repeated PRINTING; the key MAPPING in migrateLegacyCodeGraph /
// migrateLegacyOrgShareObs still runs on every Load, and the FIRST
// occurrence of each distinct message is always shown.
var deprecationEmit struct {
	mu       sync.Mutex
	seen     map[string]struct{}
	hintDone bool
}

// emitDeprecationOnce prints "config: deprecation: <msg>" to stderr at most
// once per process, keyed on msg, and prints a single follow-up remediation
// hint the first time any deprecation is emitted. Concurrency-safe: several
// components may Load config in parallel goroutines.
func emitDeprecationOnce(msg string) {
	deprecationEmit.mu.Lock()
	defer deprecationEmit.mu.Unlock()
	if deprecationEmit.seen == nil {
		deprecationEmit.seen = make(map[string]struct{})
	}
	if _, ok := deprecationEmit.seen[msg]; ok {
		return
	}
	deprecationEmit.seen[msg] = struct{}{}
	fmt.Fprintln(os.Stderr, "config: deprecation: "+msg)
	if !deprecationEmit.hintDone {
		deprecationEmit.hintDone = true
		fmt.Fprintln(os.Stderr, "config: deprecation: the keys above are deprecated aliases still honored this run — "+
			"edit ~/.observer/config.toml to adopt the new keys (or run `observer config migrate`); this notice prints once per process.")
	}
}

// emitConfigWarnOnce prints "config: warning: <msg>" to stderr at most once
// per process, keyed on msg. Shares the emit-once dedup state with
// emitDeprecationOnce because config.Load runs in ~20 call sites per process
// and each would otherwise re-print the identical line. Unlike a deprecation
// this carries no remediation-hint follow-up.
func emitConfigWarnOnce(msg string) {
	deprecationEmit.mu.Lock()
	defer deprecationEmit.mu.Unlock()
	if deprecationEmit.seen == nil {
		deprecationEmit.seen = make(map[string]struct{})
	}
	if _, ok := deprecationEmit.seen[msg]; ok {
		return
	}
	deprecationEmit.seen[msg] = struct{}{}
	fmt.Fprintln(os.Stderr, "config: warning: "+msg)
}

// resetDeprecationEmitForTest clears the one-per-process dedup state so a
// test can assert the emit-once behavior across multiple Load calls.
func resetDeprecationEmitForTest() {
	deprecationEmit.mu.Lock()
	defer deprecationEmit.mu.Unlock()
	deprecationEmit.seen = nil
	deprecationEmit.hintDone = false
}

func mergeTOMLFile(cfg *Config, path string) (toml.MetaData, error) {
	if path == "" {
		return toml.MetaData{}, nil
	}
	body, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return toml.MetaData{}, nil
	}
	if err != nil {
		return toml.MetaData{}, fmt.Errorf("config.Load: read %s: %w", path, err)
	}
	meta, err := toml.Decode(string(body), cfg)
	if err != nil {
		return toml.MetaData{}, fmt.Errorf("config.Load: parse %s: %w", path, err)
	}
	return meta, nil
}

// migrateLegacyCodeGraph maps the deprecated codegraph config blocks onto
// the [codeintel] family and returns one deprecation message per legacy
// key actually present across the loaded files (Phase 4 decommission, plan
// §11.5). The mapping is honored only when the corresponding [codeintel]
// key was NOT explicitly set, so a config carrying both keeps [codeintel]
// authoritative. Keys with no in-process analog (the external binary
// download + graph.db path) are reported as removed, not remapped — the
// concerns disappear with the third-party binary.
//
// metas carries the BurntSushi decode metadata for each loaded file so we
// can distinguish "key present" from "default value"; toml.MetaData's zero
// value answers IsDefined==false, so an absent file contributes nothing.
func migrateLegacyCodeGraph(cfg *Config, metas []toml.MetaData) []string {
	defined := func(keys ...string) bool {
		for _, m := range metas {
			if m.IsDefined(keys...) {
				return true
			}
		}
		return false
	}
	codeintelEnabledSet := defined("codeintel", "enabled")
	codeintelOnStartSet := defined("codeintel", "index", "on_start")
	compressionEnabledSet := defined("compression", "code_graph", "enabled")

	var warnings []string
	// [compression.code_graph]
	if compressionEnabledSet {
		warnings = append(warnings,
			"compression.code_graph.enabled is deprecated; use codeintel.enabled (see docs/codeintel/configuration.md)")
		if !codeintelEnabledSet {
			cfg.CodeIntel.Enabled = cfg.Compression.CodeGraph.Enabled
		}
	}
	if defined("compression", "code_graph", "auto_index") {
		warnings = append(warnings,
			"compression.code_graph.auto_index is deprecated; use codeintel.index.on_start")
		if !codeintelOnStartSet {
			cfg.CodeIntel.Index.OnStart = cfg.Compression.CodeGraph.AutoIndex
		}
	}
	if defined("compression", "code_graph", "auto_install") {
		warnings = append(warnings,
			"compression.code_graph.auto_install is removed; the code index is in-process (no third-party binary is downloaded)")
	}
	if defined("compression", "code_graph", "path") {
		warnings = append(warnings,
			"compression.code_graph.path is removed; the in-process code index has no external graph.db")
	}
	// [intelligence.code_graph]
	if defined("intelligence", "code_graph", "enabled") {
		warnings = append(warnings,
			"intelligence.code_graph.enabled is deprecated; use codeintel.enabled (see docs/codeintel/configuration.md)")
		if !codeintelEnabledSet && !compressionEnabledSet {
			cfg.CodeIntel.Enabled = cfg.Intelligence.CodeGraph.Enabled
		}
	}
	return warnings
}

// migrateRemovedCodeIntelKeys reports [codeintel] keys that have been REMOVED
// outright — no replacement key to map onto, so there is nothing to migrate,
// only something to say. It mirrors the "removed, not remapped" arm of
// migrateLegacyCodeGraph (`auto_install` / `path`), including its contract that
// a config still carrying the key LOADS FINE: BurntSushi ignores keys with no
// struct field, so the only consequence is the warning below.
//
// Today that is exactly one key.
//
// codeintel.index.disk_budget_mb — declared since the codeintel module landed,
// documented as "caps the index size; cold projects LRU-evict past this",
// defaulted to 500, and read by NOTHING outside config.go. No LRU eviction ever
// existed. The corpus-archival design (§2.1 / open question 3,
// docs/plans/observer-corpus-archival-lazyload-design-2026-08-26.md) ruled out
// leaving it defined-but-inert and offered two dispositions: implement it as a
// size-based archive trigger, or retire it. It is RETIRED, because a size
// trigger has no honest input:
//
//   - A truthful per-project byte figure means summing row payloads across
//     codeintel_nodes/edges/embeddings — a full scan of the largest tables in
//     the database, on the automatic retention path. That is precisely the
//     O(corpus)-work-on-a-hot-path class that caused the 2026-08-26 disk/compute
//     exhaustion incident (docs/audits/observer-disk-compute-exhaustion-audit-2026-08-26.md).
//     dbstat cannot help: it reports per-b-tree pages, never per-project.
//   - The cheap alternative — row counts times a bytes-per-row constant — is a
//     fabricated number dressed as a measurement, and it would drive an
//     IRREVERSIBLE-looking decision about which projects leave the hot database.
//
// The age-based horizons the operator already sets do the same job on inputs
// that are cheap AND real: [codeintel].retention_days selects stale projects
// through an indexed O(distinct projects) query, and [archive].enabled turns
// that selection from a delete into a reversible move to cold storage.
func migrateRemovedCodeIntelKeys(_ *Config, metas []toml.MetaData) []string {
	defined := func(keys ...string) bool {
		for _, m := range metas {
			if m.IsDefined(keys...) {
				return true
			}
		}
		return false
	}
	var warnings []string
	if defined("codeintel", "index", "disk_budget_mb") {
		warnings = append(warnings,
			"codeintel.index.disk_budget_mb is removed; it was never implemented (no size-based eviction ever ran). "+
				"Bound the code index with codeintel.retention_days, and set [archive].enabled = true to archive stale "+
				"projects to cold storage instead of deleting them (docs/codeintel/configuration.md)")
	}
	return warnings
}

// migrateLegacyOrgShareObs maps the deprecated flat [org_client.share] obs_*
// keys onto the nested [org_client.share.obs] sub-table and returns one
// deprecation message per legacy key actually present across the loaded
// files (plane-separation audit M1). The mapping is honored only when the
// corresponding nested key was NOT explicitly set, so a config carrying both
// keeps the nested [org_client.share.obs] value authoritative — mirroring
// migrateLegacyCodeGraph. metas distinguishes "key present" from "default
// value" (see that function's note on toml.MetaData).
func migrateLegacyOrgShareObs(cfg *Config, metas []toml.MetaData) []string {
	defined := func(keys ...string) bool {
		for _, m := range metas {
			if m.IsDefined(keys...) {
				return true
			}
		}
		return false
	}
	sh := &cfg.OrgClient.Share
	var warnings []string
	type mapping struct {
		flatKey   string
		flatVal   bool
		nestedKey string
		nestedSet bool
		dst       *bool
	}
	mappings := []mapping{
		{"obs_summary", sh.ObsSummary, "summary", defined("org_client", "share", "obs", "summary"), &sh.Obs.Summary},
		{"obs_traces", sh.ObsTraces, "traces", defined("org_client", "share", "obs", "traces"), &sh.Obs.Traces},
		{"obs_content", sh.ObsContent, "content", defined("org_client", "share", "obs", "content"), &sh.Obs.Content},
		{"obs_eval_summary", sh.ObsEvalSummary, "eval_summary", defined("org_client", "share", "obs", "eval_summary"), &sh.Obs.EvalSummary},
	}
	for _, mp := range mappings {
		if !defined("org_client", "share", mp.flatKey) {
			continue
		}
		warnings = append(warnings,
			"org_client.share."+mp.flatKey+" is deprecated; use org_client.share.obs."+mp.nestedKey)
		if !mp.nestedSet {
			*mp.dst = mp.flatVal
		}
	}
	return warnings
}

// Validate checks semantic constraints on cfg.
// validateObservabilityJudges checks the admission budget floors and both
// [observability.judge] blocks (shared + admission override): tuning fields
// non-negative, and the C1 relay's ambiguous-transport rule — use_org_relay
// combined with base_url/api_key_env on the SAME raw block is an error, since
// the relay ignores both (docs/plans/c1-judge-relay-spec-2026-08-15.md §3).
func validateObservabilityJudges(cfg Config) error {
	if b := cfg.Observability.Admission.Budget; b.PerUser5hUSD < 0 || b.PerUserWeeklyUSD < 0 || b.PerUserMonthlyUSD < 0 {
		return errors.New("config: observability.admission.budget.per_user_*_usd must be >= 0")
	}
	for _, jc := range []ObservabilityJudgeConfig{cfg.Observability.Judge, cfg.Observability.Admission.Judge} {
		if jc.TimeoutMS < 0 || jc.MaxTokens < 0 || jc.NumCtx < 0 {
			return errors.New("config: observability judge timeout_ms/max_tokens/num_ctx must be >= 0")
		}
		if jc.UseOrgRelay && (jc.BaseURL != "" || jc.APIKeyEnv != "") {
			return errors.New("config: observability judge use_org_relay=true is ambiguous with base_url/api_key_env set on the same block — the relay ignores both")
		}
	}
	switch strings.TrimSpace(cfg.Observability.Admission.OnJudgeError) {
	case "", "fail_open", "fail_closed":
	default:
		return fmt.Errorf("config: observability.admission.on_judge_error %q not in {fail_open, fail_closed}", cfg.Observability.Admission.OnJudgeError)
	}
	if cfg.Observability.Admission.JudgeRetries < 0 {
		return errors.New("config: observability.admission.judge_retries must be >= 0")
	}
	return nil
}

func Validate(cfg Config) error {
	if cfg.Observer.DBPath == "" {
		return errors.New("config: observer.db_path is required")
	}
	switch cfg.Observer.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("config: observer.log_level %q not in {debug, info, warn, error}", cfg.Observer.LogLevel)
	}
	if cfg.Observer.Watch.PollIntervalSeconds < 0 {
		return errors.New("config: observer.watch.poll_interval_seconds must be >= 0")
	}
	if cfg.Observer.Hooks.TimeoutMS <= 0 {
		return errors.New("config: observer.hooks.timeout_ms must be > 0")
	}
	if cfg.Proxy.Enabled && (cfg.Proxy.Port <= 0 || cfg.Proxy.Port > 65535) {
		return fmt.Errorf("config: proxy.port %d out of range", cfg.Proxy.Port)
	}
	if err := validateProxyUpstreams(cfg.Proxy); err != nil {
		return err
	}
	if err := validateProxyOrgRoute(cfg.Proxy.OrgRoute); err != nil {
		return err
	}
	if err := validateDashboard(cfg.Dashboard); err != nil {
		return err
	}
	if err := validateUpdate(cfg.Update); err != nil {
		return err
	}
	if err := validateCompression(cfg.Compression); err != nil {
		return err
	}
	if err := validateRouting(cfg.Routing); err != nil {
		return err
	}
	if err := validateRemote(cfg.Remote); err != nil {
		return err
	}
	if err := validateCacheWarmAndBrowser(cfg); err != nil {
		return err
	}
	if err := validatePricingFeed(cfg.Pricing.Feed); err != nil {
		return err
	}
	if err := validateGuard(cfg.Guard); err != nil {
		return err
	}
	if err := validateTasks(cfg.Tasks); err != nil {
		return err
	}
	if err := validateGuidance(cfg.Guidance); err != nil {
		return err
	}
	if err := validateObservabilityJudges(cfg); err != nil {
		return err
	}
	if err := validateObservabilityAlerts(cfg.Observability.Alerts); err != nil {
		return err
	}
	if err := cfg.Email.Validate(); err != nil {
		return fmt.Errorf("config: %w", err)
	}
	if err := cfg.Digest.Validate(); err != nil {
		return fmt.Errorf("config: %w", err)
	}
	if err := validateProcessObs(cfg.Observer.Process); err != nil {
		return err
	}
	if err := validateAggregateShare(cfg.AggregateShare); err != nil {
		return err
	}
	if err := validateTerminal(cfg.Terminal); err != nil {
		return err
	}
	if err := validateOrgClientPolicy(cfg.OrgClient.Policy); err != nil {
		return err
	}
	if err := validateCloud(cfg.Cloud); err != nil {
		return err
	}
	return nil
}

// validateCloud checks the [cloud] block (D15). Both fields are optional —
// an absent/empty [cloud] section always passes (LoginPort's zero value
// means "unset", not "port 0"). When set, BaseURL must parse as an absolute
// http(s) URL and LoginPort must be a valid TCP port.
func validateCloud(c CloudConfig) error {
	if c.LoginPort < 0 || c.LoginPort > 65535 {
		return fmt.Errorf("config: cloud.login_port %d out of range (0-65535; 0 means unset — use the command's built-in default)", c.LoginPort)
	}
	if c.AutoSyncIntervalMinutes < 0 || (c.AutoSyncIntervalMinutes > 0 && c.AutoSyncIntervalMinutes < CloudAutoSyncMinMinutes) {
		return fmt.Errorf("config: cloud.auto_sync_interval_minutes %d out of range (0 means the built-in default; otherwise >= %d)", c.AutoSyncIntervalMinutes, CloudAutoSyncMinMinutes)
	}
	if c.AutoEnrichIntervalMinutes < 0 || (c.AutoEnrichIntervalMinutes > 0 && c.AutoEnrichIntervalMinutes < CloudAutoEnrichMinMinutes) {
		return fmt.Errorf("config: cloud.auto_enrich_interval_minutes %d out of range (0 means the built-in default; otherwise >= %d)", c.AutoEnrichIntervalMinutes, CloudAutoEnrichMinMinutes)
	}
	if c.AutoEnrichQuietMinutes < 0 || (c.AutoEnrichQuietMinutes > 0 && c.AutoEnrichQuietMinutes < CloudAutoEnrichMinMinutes) {
		return fmt.Errorf("config: cloud.auto_enrich_quiet_minutes %d out of range (0 means the built-in default; otherwise >= %d)", c.AutoEnrichQuietMinutes, CloudAutoEnrichMinMinutes)
	}
	if s := strings.TrimSpace(c.BaseURL); s != "" {
		u, err := url.Parse(s)
		if err != nil {
			return fmt.Errorf("config: cloud.base_url %q is not a valid URL: %w", c.BaseURL, err)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return fmt.Errorf("config: cloud.base_url %q must be http or https (got %q)", c.BaseURL, u.Scheme)
		}
		if u.Host == "" {
			return fmt.Errorf("config: cloud.base_url %q has no host", c.BaseURL)
		}
	}
	return nil
}

// validateCacheWarmAndBrowser checks [cachewarm] keepwarm mode and the
// [browser] ceiling/timeout bounds. Extracted from Validate to keep that
// function under the gocyclo threshold after [org_client.policy] landed.
func validateCacheWarmAndBrowser(cfg Config) error {
	if cfg.CacheWarm.Enabled {
		switch cfg.CacheWarm.Keepwarm.Mode {
		case "", "off", "advise", "enforce":
		default:
			return fmt.Errorf("config: cachewarm.keepwarm.mode %q not in {off, advise, enforce}", cfg.CacheWarm.Keepwarm.Mode)
		}
	}
	switch cfg.Browser.GranularityCeiling {
	case "", "usage_only", "redacted", "full":
	default:
		return fmt.Errorf("config: browser.granularity_ceiling %q not in {usage_only, redacted, full}", cfg.Browser.GranularityCeiling)
	}
	if cfg.Browser.IngestTimeoutMS > maxBrowserIngestTimeoutMS {
		// The end-to-end browser ingest (db.Open + store.Ingest, bounded by
		// BrowserConfig.IngestTimeout()) must finish before the native host's
		// 40s reply cap tears down the WSL bridge and kills the child
		// mid-write. Reject a value that would break that guarantee rather
		// than silently clamp, so the operator learns their setting is unsafe.
		return fmt.Errorf("config: browser.ingest_timeout_ms %d exceeds the maximum %d (it must stay below the native-messaging host's 40000ms reply cap so a slow ingest is never killed mid-write)", cfg.Browser.IngestTimeoutMS, maxBrowserIngestTimeoutMS)
	}
	return nil
}

// validatePricingFeed checks the [pricing.feed] block (plan §C.4): a
// non-negative poll interval and, when the feed is enabled, a well-formed
// http/https URL. The URL is only required/checked when enabled so a node that
// has never touched the block (the default seed carries the public URL anyway)
// is never failed for it.
func validatePricingFeed(c PricingFeedConfig) error {
	if c.PollIntervalHours < 0 {
		return fmt.Errorf("config: pricing.feed.poll_interval_hours %d must be >= 0", c.PollIntervalHours)
	}
	if !c.Enabled {
		return nil
	}
	s := strings.TrimSpace(c.URL)
	if s == "" {
		return errors.New("config: pricing.feed.url is required when pricing.feed.enabled = true")
	}
	u, err := url.Parse(s)
	if err != nil {
		return fmt.Errorf("config: pricing.feed.url %q is not a valid URL: %w", c.URL, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("config: pricing.feed.url %q must be http or https (got %q)", c.URL, u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("config: pricing.feed.url %q has no host", c.URL)
	}
	return nil
}

// policyResourceSupportedFamilies is the v1 closed family enum — see
// OrgClientPolicyConfig's doc comment for why this is a local copy rather
// than an internal/policyfam import.
var policyResourceSupportedFamilies = map[string]bool{
	"admission.input":          true,
	"egress.routing_guardrail": true,
	// Config plane Phase 3 (gateway-config-plane spec): the signed provider
	// lane-table family. Missing from this local copy until 2026-08-15, which
	// made accept_families reject the family and every gateway resource land
	// delivered_unaccepted — the sync test in policyfam_sync_test.go now pins
	// this map to policyfam.SupportedFamilies so the next family can't repeat
	// the drift.
	"gateway.providers": true,
	// Admin-controlled Plane B (docs/plans/admin-controlled-plane-b-spec-2026-08-15.md
	// Phase 1a): the node-governance family. Added here in the SAME change
	// as policyfam.FamilyNodeGovernance — policyfam_sync_test.go fails the
	// build otherwise, which is the drift gate gateway.providers taught us
	// to want.
	"node.governance": true,
	// Org-parity W5.1 (docs/plans/org-parity-full-depth-plan-2026-08-24.md
	// §4): the per-feature enable/disable + limits family. Added here in the
	// SAME change as policyfam.FamilyNodeFeatures for the same drift-gate
	// reason as node.governance above.
	"node.features": true,
	// planeb.admission (2026-09-02, G1-JUDGED-ADM): the Plane-B judged-
	// admission body — gateway request-path judged admission + the default-OFF
	// node-lane flip (design §4.6).
	"planeb.admission": true,
}

// validateOrgClientPolicy checks [org_client.policy]: every listed family
// must be one of the v1 closed set, and preauthorize_enforce must be a
// subset of accept_families (plan §6.4 — preauthorizing enforcement for a
// family the node doesn't even accept is a config mistake, not a valid
// "half-opted-in" state).
func validateOrgClientPolicy(p OrgClientPolicyConfig) error {
	accepted := make(map[string]bool, len(p.AcceptFamilies))
	for _, f := range p.AcceptFamilies {
		if !policyResourceSupportedFamilies[f] {
			return fmt.Errorf("config: org_client.policy.accept_families contains unsupported family %q (want one of admission.input, egress.routing_guardrail, gateway.providers, node.governance, node.features, planeb.admission)", f)
		}
		accepted[f] = true
	}
	for _, f := range p.PreauthorizeEnforce {
		if !policyResourceSupportedFamilies[f] {
			return fmt.Errorf("config: org_client.policy.preauthorize_enforce contains unsupported family %q (want one of admission.input, egress.routing_guardrail, gateway.providers, node.governance, node.features, planeb.admission)", f)
		}
		if !accepted[f] {
			return fmt.Errorf("config: org_client.policy.preauthorize_enforce contains %q, which is not in accept_families (preauthorize_enforce must be a subset of accept_families)", f)
		}
	}
	attrs := []struct {
		key   string
		value string
	}{
		{"node_workspace", p.NodeWorkspace},
		{"node_environment", p.NodeEnvironment},
		{"node_service", p.NodeService},
	}
	for _, a := range attrs {
		if err := validatePolicyNodeAttr(a.key, a.value); err != nil {
			return err
		}
	}
	return nil
}

// maxPolicyNodeAttrBytes bounds one [org_client.policy] node attribute. The
// value must match an org-side attribute exactly to corroborate anything, so
// a long value is a config mistake, not a use case.
const maxPolicyNodeAttrBytes = 128

// validatePolicyNodeAttr checks one node targeting attribute: optional, but
// when set it must be a bounded, single-line, non-padded string. The
// comparison against a signed selector is byte-exact after the server's own
// trim, so a value with surrounding whitespace or an embedded control
// character could never corroborate — rejecting it loudly at load beats
// silently never matching.
func validatePolicyNodeAttr(key, value string) error {
	if value == "" {
		return nil
	}
	if len(value) > maxPolicyNodeAttrBytes {
		return fmt.Errorf("config: org_client.policy.%s is %d bytes, over the %d-byte maximum", key, len(value), maxPolicyNodeAttrBytes)
	}
	if strings.TrimSpace(value) != value {
		return fmt.Errorf("config: org_client.policy.%s %q has leading or trailing whitespace (it must match the org-side attribute exactly)", key, value)
	}
	if !utf8.ValidString(value) {
		return fmt.Errorf("config: org_client.policy.%s is not valid UTF-8", key)
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return fmt.Errorf("config: org_client.policy.%s %q contains a control character", key, value)
		}
	}
	return nil
}

// validateTerminal checks the [terminal] block: bounds must be non-negative
// and IdleTimeout (when set) must parse as a Go duration. The launch
// allow-lists are validated at spawn time (canonicalization needs the real
// filesystem), not here.
func validateTerminal(c TerminalConfig) error {
	if c.MaxConcurrent < 0 {
		return errors.New("config: terminal.max_concurrent must be >= 0")
	}
	if c.RingBytes < 0 {
		return errors.New("config: terminal.ring_bytes must be >= 0")
	}
	if c.WSPingIntervalSeconds < 0 {
		return errors.New("config: terminal.ws_ping_interval_seconds must be >= 0")
	}
	if c.WSPingTimeoutSeconds < 0 {
		return errors.New("config: terminal.ws_ping_timeout_seconds must be >= 0")
	}
	if c.WSPingFailuresAllowed < 0 {
		return errors.New("config: terminal.ws_ping_failures_allowed must be >= 0")
	}
	if strings.TrimSpace(c.IdleTimeout) != "" {
		d, err := time.ParseDuration(c.IdleTimeout)
		if err != nil {
			return fmt.Errorf("config: terminal.idle_timeout %q is not a valid duration: %w", c.IdleTimeout, err)
		}
		// A negative duration would silently mean "disabled" everywhere it is
		// consumed; require the honest spelling ("0") instead of persisting a
		// value that reads like a timeout but never fires.
		if d < 0 {
			return fmt.Errorf("config: terminal.idle_timeout %q must not be negative (use \"0\" to disable idle reaping)", c.IdleTimeout)
		}
	}
	if err := validateTerminalSandbox(c.Sandbox); err != nil {
		return err
	}
	if err := validateTerminalSSH(c.SSH); err != nil {
		return err
	}
	return nil
}

// validateTerminalSSH checks the [terminal.ssh] block. Like
// validateTerminalSandbox it runs UNCONDITIONALLY (not gated on Enabled), so a
// typo'd host or a relative key_path is caught loudly at load time rather than
// silently at the operator's first click.
//
// It delegates every field rule to internal/sshprofile — the single owner of
// the closed-vocabulary validators — so config and the launch path can never
// disagree about what a valid profile is. The launch path re-validates anyway
// (with the filesystem check), mirroring the ValidateProjectRoot-at-spawn
// discipline.
func validateTerminalSSH(c TerminalSSHConfig) error {
	if c.ConnectTimeoutSeconds < 0 {
		return errors.New("config: terminal.ssh.connect_timeout_seconds must be >= 0")
	}
	if c.KeepaliveSeconds < 0 {
		return errors.New("config: terminal.ssh.keepalive_seconds must be >= 0")
	}
	seen := make(map[string]bool, len(c.Profiles))
	for i, p := range c.Profiles {
		if err := SSHProfile(p).Validate(); err != nil {
			return fmt.Errorf("config: terminal.ssh.profiles[%d]: %w", i, err)
		}
		if seen[p.Name] {
			return fmt.Errorf("config: terminal.ssh.profiles[%d]: duplicate name %q", i, p.Name)
		}
		seen[p.Name] = true
	}
	return nil
}

// SSHProfile converts one config entry into the pure-package Profile the
// validator and argv composer operate on. It is the ONE translation point
// between the TOML shape and internal/sshprofile (module-boundary rule #2), so
// a field added to the config block has exactly one place to be threaded.
func SSHProfile(p SSHProfileConfig) sshprofile.Profile {
	return sshprofile.Profile{
		Name:             p.Name,
		Label:            p.Label,
		Host:             p.Host,
		User:             p.User,
		Port:             p.Port,
		KeyPath:          p.KeyPath,
		Jump:             p.Jump,
		DashboardPort:    p.DashboardPort,
		ReverseProxy:     p.ReverseProxy,
		ReverseProxyPort: p.ReverseProxyPort,
	}
}

// SSHProfiles converts the whole configured list. Callers wiring the terminal
// service use this so the daemon holds pure Profiles, never TOML structs.
func SSHProfiles(c TerminalSSHConfig) []sshprofile.Profile {
	if len(c.Profiles) == 0 {
		return nil
	}
	out := make([]sshprofile.Profile, 0, len(c.Profiles))
	for _, p := range c.Profiles {
		out = append(out, SSHProfile(p))
	}
	return out
}

// SSHOptions maps the block's connection-tuning knobs onto the pure package's
// Options. A zero value resolves to the sshprofile defaults.
func SSHOptions(c TerminalSSHConfig) sshprofile.Options {
	return sshprofile.Options{
		ConnectTimeoutSeconds: c.ConnectTimeoutSeconds,
		KeepaliveSeconds:      c.KeepaliveSeconds,
	}
}

// validateTerminalSandbox checks semantic constraints on the [terminal.sandbox]
// block (B9). Runs unconditionally (not gated on Enabled) so a typo'd
// backend/home_mode is caught at load time even before an operator flips the
// master switch on.
func validateTerminalSandbox(c TerminalSandboxConfig) error {
	switch c.Backend {
	case "", "bwrap":
	default:
		return fmt.Errorf("config: terminal.sandbox.backend %q not in {bwrap}", c.Backend)
	}
	switch c.HomeMode {
	case "", "tmpfs", "readonly":
	default:
		return fmt.Errorf("config: terminal.sandbox.home_mode %q not in {tmpfs, readonly}", c.HomeMode)
	}
	if c.WorkspaceRetentionDays < 0 {
		return errors.New("config: terminal.sandbox.workspace_retention_days must be >= 0")
	}
	if c.PrepTimeoutSeconds < 0 {
		return errors.New("config: terminal.sandbox.prep_timeout_seconds must be >= 0")
	}
	return nil
}

// validateAggregateShare enforces the endpoint binding (design §9.2, finding
// #21): the collector endpoint must be HTTPS, carry no credentials or query
// string, and resolve to an approved host unless the explicit self-host /
// testing escape (AllowCustomEndpoint) is set. Validation runs only when the
// rail is enabled — a default-off install with an empty/custom endpoint never
// fails to load. A change of endpoint invalidates the consent receipt
// (enforced at the CheckConsent seam, not here).
func validateAggregateShare(c AggregateShareConfig) error {
	if !c.Enabled {
		return nil
	}
	if strings.TrimSpace(c.Endpoint) == "" {
		return errors.New("config: aggregate_share.endpoint is required when aggregate_share.enabled is true")
	}
	u, err := url.Parse(strings.TrimSpace(c.Endpoint))
	if err != nil {
		return fmt.Errorf("config: aggregate_share.endpoint %q is not a valid URL: %w", c.Endpoint, err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("config: aggregate_share.endpoint must be https (got %q)", u.Scheme)
	}
	if u.User != nil {
		return errors.New("config: aggregate_share.endpoint must not carry credentials")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return errors.New("config: aggregate_share.endpoint must not carry a query string or fragment")
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return fmt.Errorf("config: aggregate_share.endpoint %q has no host", c.Endpoint)
	}
	if !approvedAggregateHosts[host] && !c.AllowCustomEndpoint {
		return fmt.Errorf("config: aggregate_share.endpoint host %q is not approved; set aggregate_share.allow_custom_endpoint=true only for a self-host/testing collector", host)
	}
	return nil
}

// validateRemote checks the [remote] block (remote-dashboard-access plan §5).
// Validation runs only when the rail is enabled — a default-off install never
// fails to load. Mode is a closed enum; Phase 1 accepts only "off" (tailscale
// and lan land in Phases 2/3). The notify sub-block is validated whenever it is
// enabled, independent of the master switch, since the outbound rail can run
// with the exposure listener off.
func validateRemote(c RemoteConfig) error {
	if c.Enabled {
		switch strings.ToLower(strings.TrimSpace(c.Mode)) {
		case "", "off":
		case "tailscale":
			// Phase 2 (plan §4.4): the tailnet-serve backend binds a dedicated
			// LOOPBACK address distinct from the owner-trusted direct listener.
			// A non-loopback backend would defeat the whole point (the backend
			// must be reachable ONLY via `tailscale serve`).
			if err := validateTailscaleBackendAddr(c.TailscaleBackendAddr); err != nil {
				return err
			}
		case "lan":
			return fmt.Errorf("config: remote.mode %q is deferred (Phase 3, operator decision 2026-07-12 — tailnet-HTTPS-only for v1); use \"tailscale\"", c.Mode)
		default:
			return fmt.Errorf("config: remote.mode %q not in {off, tailscale, lan}", c.Mode)
		}
		if c.RateLimitPerMin < 0 {
			return fmt.Errorf("config: remote.rate_limit_per_min %d must be >= 0", c.RateLimitPerMin)
		}
		if c.MaxSessions < 0 {
			return fmt.Errorf("config: remote.max_sessions %d must be >= 0", c.MaxSessions)
		}
		if c.CapabilityTTLMinutes < 0 {
			return fmt.Errorf("config: remote.capability_ttl_minutes %d must be >= 0", c.CapabilityTTLMinutes)
		}
		// The two device-session bounds. Both follow capability_ttl_minutes'
		// convention: 0 means "use the package default" (remoteauth's
		// NewSessionStore clamps <= 0 to DefaultSessionTTL / DefaultSessionIdle),
		// and a NEGATIVE value is a config error rather than a silent
		// promotion to the maximum. Unvalidated, `session_ttl_minutes = -720`
		// loaded cleanly and yielded the LONGEST window the build offers —
		// the exact inverse of the operator's intent, and a blast radius that
		// grew when these bounds were widened (2026-07-25 review B2).
		if c.SessionTTLMinutes < 0 {
			return fmt.Errorf("config: remote.session_ttl_minutes %d must be >= 0 (0 = default %d)", c.SessionTTLMinutes, DefaultRemoteSessionTTLMinutes)
		}
		if c.SessionIdleMinutes < 0 {
			return fmt.Errorf("config: remote.session_idle_minutes %d must be >= 0 (0 = default %d)", c.SessionIdleMinutes, DefaultRemoteSessionIdleMinutes)
		}
		// Coherence: the idle window must fit INSIDE the absolute cap. The
		// tighter of the two already wins at runtime, so an idle > absolute
		// config is safe — but it is also silently inoperative (the idle rule
		// can never fire), and that exact interaction is why the absolute cap
		// was widened at all. Refusing it makes the mistake loud instead of
		// invisible. Compared on EFFECTIVE values so a 0 (= default) on either
		// key is checked against the default it will actually resolve to.
		ttl, idle := c.SessionTTLMinutes, c.SessionIdleMinutes
		if ttl == 0 {
			ttl = DefaultRemoteSessionTTLMinutes
		}
		if idle == 0 {
			idle = DefaultRemoteSessionIdleMinutes
		}
		if idle > ttl {
			return fmt.Errorf("config: remote.session_idle_minutes %d exceeds remote.session_ttl_minutes %d — the absolute cap would expire the session first, making the idle window unreachable", idle, ttl)
		}
		if c.Enabled && len(c.TrustedHosts) == 0 && strings.EqualFold(strings.TrimSpace(c.Mode), "tailscale") {
			return errors.New("config: remote.trusted_hosts must name the tailnet host (the Host the browser sends) when remote.mode = \"tailscale\" — `observer remote enable --tailscale` populates it")
		}
	}
	if c.Notify.Enabled {
		switch strings.ToLower(strings.TrimSpace(c.Notify.Kind)) {
		case "", "webhook", "ntfy":
		default:
			return fmt.Errorf("config: remote.notify.kind %q not in {webhook, ntfy}", c.Notify.Kind)
		}
		if strings.TrimSpace(c.Notify.URL) == "" {
			return errors.New("config: remote.notify.url is required when remote.notify.enabled is true")
		}
		u, err := url.Parse(strings.TrimSpace(c.Notify.URL))
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			return fmt.Errorf("config: remote.notify.url %q must be a valid http(s) URL", c.Notify.URL)
		}
	}
	return nil
}

// validateDashboard enforces that [dashboard].addr, when set, parses as a
// host:port pair with a NUMERIC port in 1–65535. Empty is valid (the built-in
// default applies). Delegates to ValidateDashboardAddr so the same shape check
// backs both the config-load path and cmd/observer's env-value guard.
func validateDashboard(d DashboardConfig) error {
	return ValidateDashboardAddr(d.Addr)
}

// validateUpdate enforces the [update] surface.
//
// It refuses rather than clamps, and it does so at LOAD time, because every
// one of these values is consulted at the worst possible moment — while the
// daemon is quiesced with its binary half-swapped. A drain timeout that
// silently became zero there would abort every apply with error_class=drain
// and nobody would know why.
//
// The window's grammar is validated through update.ParseWindow rather than
// re-implemented here: one owner for "what is a maintenance window", so the
// config check and the apply gate can never disagree about a string like
// "22:00-02:00".
func validateUpdate(u UpdateConfig) error {
	if _, err := update.ParseWindow(u.Window); err != nil {
		return fmt.Errorf("config: update.window: %w", err)
	}
	if u.Channel != "" && !update.KnownChannel(update.Channel(u.Channel)) {
		return fmt.Errorf("config: update.channel %q not in {stable, lts, edge} (empty = whatever the org assigns)", u.Channel)
	}
	if u.KeepPreviousDays < 0 {
		return errors.New("config: update.keep_previous_days must be >= 0 (0 disables retention pruning)")
	}
	if u.MaxDownloadBytes < 0 {
		return errors.New("config: update.max_download_bytes must be >= 0")
	}
	for _, d := range []struct {
		key, val string
	}{
		{"update.drain_timeout", u.DrainTimeout},
		{"update.handshake_timeout", u.HandshakeTimeout},
	} {
		if strings.TrimSpace(d.val) == "" {
			continue
		}
		parsed, err := time.ParseDuration(d.val)
		if err != nil {
			return fmt.Errorf("config: %s %q is not a duration (e.g. \"90s\"): %w", d.key, d.val, err)
		}
		if parsed <= 0 {
			return fmt.Errorf("config: %s must be > 0", d.key)
		}
	}
	return nil
}

// ValidateDashboardAddr validates a dashboard listen address string. It is a
// pure SHAPE check — host:port must parse and the port must be a base-10
// integer in 1–65535. Empty is valid (the built-in default applies). It
// intentionally does NOT judge the host: an EMPTY host (":8082", meaning
// bind-all-interfaces / 0.0.0.0) and any non-loopback host are accepted here
// and gated instead by dashboard.CheckRemoteBind, which fails closed unless
// the [remote] security substrate is armed. Keeping the security policy in one
// owner (CheckRemoteBind) and the shape check here mirrors the proxy split
// (proxy.port is a numeric range check; the bind host is a separate flag).
// Mirrors the proxy.port range check's loud-error style.
func ValidateDashboardAddr(addr string) error {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return nil
	}
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("config: dashboard.addr %q must be host:port (e.g. 127.0.0.1:8082): %w", addr, err)
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		return fmt.Errorf("config: dashboard.addr %q needs a numeric port (got %q)", addr, port)
	}
	if n < 1 || n > 65535 {
		return fmt.Errorf("config: dashboard.addr %q port %d out of range (1–65535)", addr, n)
	}
	return nil
}

// validateTailscaleBackendAddr enforces plan §4.4: the tailnet-serve backend
// address must be an explicit LOOPBACK host:port (never 0.0.0.0, never a
// non-loopback IP, never an interface name). `tailscale serve` forwards
// plaintext to this address, so it must be reachable ONLY on loopback.
func validateTailscaleBackendAddr(addr string) error {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return errors.New("config: remote.tailscale_backend_addr is required when remote.mode = \"tailscale\" (a loopback IP:port for `tailscale serve` to forward to) — `observer remote enable --tailscale` pins one")
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("config: remote.tailscale_backend_addr %q must be host:port: %w", addr, err)
	}
	if port == "" || port == "0" {
		return fmt.Errorf("config: remote.tailscale_backend_addr %q needs an explicit non-zero port", addr)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("config: remote.tailscale_backend_addr host %q must be an explicit loopback IP (127.0.0.1 / ::1) — the tailnet-serve backend is loopback-only (plan §4.4)", host)
	}
	return nil
}

// validateCompression checks the [compression] block's conversation mode / ratio
// enums and the log head/tail bounds. Extracted from Validate to keep that
// function's cyclomatic complexity in check.
func validateCompression(c CompressionConfig) error {
	if c.Conversation.Enabled {
		switch c.Conversation.Mode {
		case "token", "cache", "cache_aware":
		default:
			return fmt.Errorf("config: compression.conversation.mode %q not in {token, cache, cache_aware}", c.Conversation.Mode)
		}
		if r := c.Conversation.TargetRatio; r <= 0 || r >= 1 {
			return fmt.Errorf("config: compression.conversation.target_ratio %.2f must be in (0, 1)", r)
		}
	}
	logs := c.Conversation.Logs
	if logs.MaxLines < 0 {
		return fmt.Errorf("config: compression.conversation.logs.max_lines %d must be >= 0", logs.MaxLines)
	}
	if logs.Head < 0 || logs.Tail < 0 {
		return fmt.Errorf("config: compression.conversation.logs.head/tail must be >= 0 (head=%d, tail=%d)", logs.Head, logs.Tail)
	}
	return nil
}

// validateProcessObs checks the [observer.process] block's enums + numeric
// bounds, but only when process observability is enabled — a stale disabled
// section never fails the daemon (the feature is opt-in). Extracted from
// Validate to keep that function's cyclomatic complexity in check.
func validateProcessObs(p ProcessConfig) error {
	if !p.Enabled {
		return nil
	}
	switch p.Backend {
	case "auto", "bridge", "both", "linux_ebpf", "etw", "endpointsecurity", "poll", "off":
	default:
		return fmt.Errorf("config: observer.process.backend %q not in {auto, bridge, both, linux_ebpf, etw, endpointsecurity, poll, off}", p.Backend)
	}
	if p.PollIntervalMS < 0 {
		return fmt.Errorf("config: observer.process.poll_interval_ms must be >= 0 (0 inherits the default), got %d", p.PollIntervalMS)
	}
	if p.BridgePollIntervalMS < 0 {
		return fmt.Errorf("config: observer.process.bridge_poll_interval_ms must be >= 0 (0 inherits poll_interval_ms), got %d", p.BridgePollIntervalMS)
	}
	if p.CorrelateIntervalMS < 0 {
		return fmt.Errorf("config: observer.process.correlate_interval_ms must be >= 0 (0 inherits the default), got %d", p.CorrelateIntervalMS)
	}
	switch p.Argv.Mode {
	case "preview", "hash_only", "off":
	default:
		return fmt.Errorf("config: observer.process.argv.mode %q not in {preview, hash_only, off}", p.Argv.Mode)
	}
	switch p.Filesystem.Mode {
	case "sensitive", "writes", "all_attributed_writes":
	default:
		return fmt.Errorf("config: observer.process.filesystem.mode %q not in {sensitive, writes, all_attributed_writes}", p.Filesystem.Mode)
	}
	switch p.Network.CaptureBodies {
	case "", "off", "proxied", "available":
	default:
		return fmt.Errorf("config: observer.process.network.capture_bodies %q not in {off, proxied, available}", p.Network.CaptureBodies)
	}
	if p.Network.MaxRequestBytes < 0 {
		return fmt.Errorf("config: observer.process.network.max_request_bytes must be >= 0, got %d", p.Network.MaxRequestBytes)
	}
	if p.Network.MaxResponseBytes < 0 {
		return fmt.Errorf("config: observer.process.network.max_response_bytes must be >= 0, got %d", p.Network.MaxResponseBytes)
	}
	// [observer.process.etw] is validated whenever process observability is
	// enabled, NOT only when the ETW block itself is — the same choice the
	// Network/Filesystem enums above make. Rationale: a bad listen_addr or a
	// negative timeout in a block the operator is about to flip on should
	// fail NOW, at the edit, rather than at flip time when they have already
	// moved on. The parent `p.Enabled` gate (the early return at the top of
	// this function) still applies, so an install with process capture off
	// never fails the daemon over a stale ETW section.
	if p.ETW.HandshakeTimeoutMS < 0 {
		return fmt.Errorf("config: observer.process.etw.handshake_timeout_ms must be >= 0 (0 inherits the default), got %d", p.ETW.HandshakeTimeoutMS)
	}
	if p.ETW.ListenAddr != "" {
		if _, _, err := net.SplitHostPort(p.ETW.ListenAddr); err != nil {
			return fmt.Errorf("config: observer.process.etw.listen_addr %q must be host:port: %w", p.ETW.ListenAddr, err)
		}
	}
	if p.QueueSize <= 0 {
		return fmt.Errorf("config: observer.process.queue_size %d must be > 0 when enabled", p.QueueSize)
	}
	if p.BatchSize <= 0 {
		return fmt.Errorf("config: observer.process.batch_size %d must be > 0 when enabled", p.BatchSize)
	}
	return nil
}

// validateGuard checks the [guard] block's enums + budget/limit bounds (only
// when the guard is enabled — a stale disabled section never fails the daemon).
// Extracted from Validate to keep that function's cyclomatic complexity in
// check as the guard surface grew.
// validateObservabilityAlerts checks the [observability.alerts] block — the
// metric vocabulary + comparator enums + non-negative numeric bounds — only
// when alerting is enabled, so a stale disabled section never fails the daemon
// (the feature is opt-in). The metric set is kept in lock-step with
// internal/obs/alert.Metrics (config is a lower layer and cannot import obs).
func validateObservabilityAlerts(a ObservabilityAlertsConfig) error {
	if !a.Enabled {
		return nil
	}
	if a.EvalIntervalMinutes < 0 {
		return errors.New("config: observability.alerts.eval_interval_minutes must be >= 0")
	}
	for i, r := range a.Rules {
		switch r.Metric {
		case "error_rate", "cost_usd", "latency_p95_ms":
		default:
			return fmt.Errorf("config: observability.alerts.rules[%d].metric %q not in {error_rate, cost_usd, latency_p95_ms}", i, r.Metric)
		}
		switch r.Comparator {
		case "", "gt", "gte":
		default:
			return fmt.Errorf("config: observability.alerts.rules[%d].comparator %q not in {gt, gte}", i, r.Comparator)
		}
		if r.Threshold < 0 {
			return fmt.Errorf("config: observability.alerts.rules[%d].threshold must be >= 0", i)
		}
		if r.WindowMinutes < 0 || r.CooldownMinutes < 0 {
			return fmt.Errorf("config: observability.alerts.rules[%d] window_minutes/cooldown_minutes must be >= 0", i)
		}
	}
	return nil
}

// validateProxyUpstreams enforces the gateway config plane spec's two
// [proxy.upstreams]/auto_default_lane invariants: "auto" is a reserved
// virtual lane id (Phase 2 — it can never be a real configured lane,
// since Proxy.SetUpstreams routes it through resolveAutoLane, not the
// upstream map), and a configured auto_default_lane must name a lane
// that actually exists in upstreams (an unresolvable default is a config
// mistake, not a runtime fail-open case).
func validateProxyUpstreams(p ProxyConfig) error {
	if _, reserved := p.Upstreams["auto"]; reserved {
		return errors.New(`config: proxy.upstreams "auto" is a reserved lane id (the virtual auto lane) and cannot be configured directly`)
	}
	if p.AutoDefaultLane != "" {
		if _, ok := p.Upstreams[p.AutoDefaultLane]; !ok {
			return fmt.Errorf("config: proxy.auto_default_lane %q must name a lane configured in proxy.upstreams", p.AutoDefaultLane)
		}
	}
	return nil
}

// validateProxyOrgRoute enforces [proxy.org_route]'s shape before it ever
// reaches Proxy.SetOrgGatewayRoute, so a malformed node-local bootstrap
// fails at config load (a clear, early error) rather than being silently
// skipped at startup wiring time. Mirrors validateProxyUpstreams' style:
// the zero value (Mode == "") is always valid and inert.
func validateProxyOrgRoute(r ProxyOrgRouteConfig) error {
	switch r.Mode {
	case "":
		if r.Primary != "" || len(r.Fallbacks) > 0 {
			return errors.New(`config: proxy.org_route.primary/fallbacks require mode = "gateway"`)
		}
		return nil
	case "gateway":
		if r.Primary == "" {
			return errors.New(`config: proxy.org_route.primary is required when proxy.org_route.mode = "gateway"`)
		}
	default:
		return fmt.Errorf(`config: proxy.org_route.mode %q not in {"", "gateway"}`, r.Mode)
	}
	if _, err := url.Parse(r.Primary); err != nil {
		return fmt.Errorf("config: proxy.org_route.primary %q: %w", r.Primary, err)
	}
	for i, fb := range r.Fallbacks {
		if _, err := url.Parse(fb); err != nil {
			return fmt.Errorf("config: proxy.org_route.fallbacks[%d] %q: %w", i, fb, err)
		}
	}
	return nil
}

func validateTasks(t TasksConfig) error {
	switch t.MatchMode {
	case "", "exact", "normalized":
	default:
		return fmt.Errorf("config: tasks.match_mode %q not in {exact, normalized}", t.MatchMode)
	}
	switch t.ConcurrentAttribution {
	case "", "shared", "none":
	default:
		return fmt.Errorf("config: tasks.concurrent_attribution %q not in {shared, none}", t.ConcurrentAttribution)
	}
	return nil
}

// validateGuidance rejects the one [guidance] value that has no sensible
// meaning. Every other key in the block resolves a <= 0 value to its seeded
// budget (an unbounded pass is the failure those budgets exist to prevent),
// but first_scan_poll_seconds is a CADENCE, so 0 legitimately means "never
// poll" and only a negative value is nonsense.
func validateGuidance(g GuidanceConfig) error {
	if g.FirstScanPollSeconds < 0 {
		return fmt.Errorf("config: guidance.first_scan_poll_seconds %d must be >= 0 (0 disables the poll)",
			g.FirstScanPollSeconds)
	}
	// The adaptive ceiling can never sit below the base budget: a max below
	// the base would mean the very first grant already exceeds the cap. <= 0
	// stays "use the seeded default" (resolved in guidanceBudgets), exactly
	// like root_timeout_seconds itself, so only a positive-but-too-small
	// value is a mistake worth refusing.
	if g.RootTimeoutMaxSeconds > 0 && g.RootTimeoutSeconds > 0 && g.RootTimeoutMaxSeconds < g.RootTimeoutSeconds {
		return fmt.Errorf("config: guidance.root_timeout_max_seconds %d must be >= root_timeout_seconds %d (the adaptive ceiling cannot be below the base budget)",
			g.RootTimeoutMaxSeconds, g.RootTimeoutSeconds)
	}
	return nil
}

func validateGuard(g GuardConfig) error {
	if !g.Enabled {
		return nil
	}
	switch g.Mode {
	case "off", "observe", "enforce":
	default:
		return fmt.Errorf("config: guard.mode %q not in {off, observe, enforce}", g.Mode)
	}
	switch g.Alerts.MinSeverity {
	case "", "info", "warn", "high", "critical":
	default:
		return fmt.Errorf("config: guard.alerts.min_severity %q not in {info, warn, high, critical}", g.Alerts.MinSeverity)
	}
	switch g.Proxy.EgressAction {
	case "", "flag", "mask", "deny":
	default:
		return fmt.Errorf("config: guard.proxy.egress_action %q not in {flag, mask, deny}", g.Proxy.EgressAction)
	}
	if g.Rules.CEL {
		return errors.New("config: guard.rules.cel is not yet supported (CEL user rules are deferred — matchers v1)")
	}
	b := g.Budget
	for _, usd := range []float64{b.SessionUSD, b.DailyUSD, b.WeeklyUSD, b.MonthlyUSD} {
		if math.IsNaN(usd) || math.IsInf(usd, 0) || usd < 0 {
			return errors.New("config: guard.budget.*_usd must be finite and >= 0")
		}
	}
	// The token ceilings follow the same rule as the $ ones: 0 disables the
	// window and a negative value is a mistake, never "everything is over
	// budget". Refusing it here is what keeps govern.LowerInt's own
	// negative-is-unset guard a defence against a REMOTE body rather than a
	// second owner of local validation.
	if b.SessionTokens < 0 || b.DailyTokens < 0 || b.WeeklyTokens < 0 || b.MonthlyTokens < 0 {
		return errors.New("config: guard.budget.*_tokens must be >= 0")
	}
	w := b.Window
	for _, u := range []float64{w.Util5hWarn, w.Util5hDeny, w.UtilWeeklyWarn, w.UtilWeeklyDeny} {
		if math.IsNaN(u) || math.IsInf(u, 0) || u < 0 || u > 1 {
			return fmt.Errorf("config: guard.budget.window utilization %.2f must be in [0, 1]", u)
		}
	}
	if w.Util5hDeny > 0 && w.Util5hWarn > 0 && w.Util5hDeny < w.Util5hWarn {
		return errors.New("config: guard.budget.window.util_5h_deny must be >= util_5h_warn")
	}
	if w.UtilWeeklyDeny > 0 && w.UtilWeeklyWarn > 0 && w.UtilWeeklyDeny < w.UtilWeeklyWarn {
		return errors.New("config: guard.budget.window.util_weekly_deny must be >= util_weekly_warn")
	}
	if err := validateGuardPrompt(g.Prompt); err != nil {
		return err
	}
	return nil
}

// validateGuardPrompt validates [guard.prompt] (§8.1). Unlike
// GuardProxyConfig/GuardMCPConfig — which have no Enabled field of their
// own and are therefore validated unconditionally whenever the outer
// [guard].enabled is true — GuardPromptConfig does carry its own Enabled
// flag. Following the same precedent (no sub-config in validateGuard
// conditions its checks on a sub-Enabled flag; only the top-level
// g.Enabled gates the whole function), this still validates
// unconditionally: a malformed [guard.prompt] should fail loudly even
// while prompt.enabled=false, the same way a malformed
// [guard.proxy]/[guard.mcp] would.
func validateGuardPrompt(p GuardPromptConfig) error {
	if !guardPromptModes[p.Mode] {
		return fmt.Errorf("config: guard.prompt.mode %q not in {off, warn, ask-once, block, redact}", p.Mode)
	}
	for id, mode := range p.Detectors {
		if !knownPromptDetectors[id] {
			return fmt.Errorf("config: guard.prompt.detectors names unknown detector %q", id)
		}
		if !guardPromptModes[mode] {
			return fmt.Errorf("config: guard.prompt.detectors[%q] %q not in {off, warn, ask-once, block, redact}", id, mode)
		}
	}
	if err := scrub.ValidatePatterns(p.Allow); err != nil {
		return fmt.Errorf("config: guard.prompt.allow: %w", err)
	}
	ttl, err := p.ReconsiderTTLDuration()
	if err != nil {
		return fmt.Errorf("config: guard.prompt.reconsider_ttl %q: %w", p.ReconsiderTTL, err)
	}
	if ttl <= 0 {
		return fmt.Errorf("config: guard.prompt.reconsider_ttl %q must be > 0", p.ReconsiderTTL)
	}
	if p.ReconsiderMinDelay != "" {
		d, err := time.ParseDuration(p.ReconsiderMinDelay)
		if err != nil {
			return fmt.Errorf("config: guard.prompt.reconsider_min_delay %q: %w", p.ReconsiderMinDelay, err)
		}
		if d < 0 {
			return fmt.Errorf("config: guard.prompt.reconsider_min_delay %q must be >= 0", p.ReconsiderMinDelay)
		}
		// A floor at/over reconsider_ttl is NOT a load error: the default
		// is on and an operator may have set a sub-3s TTL before this key
		// existed — a hard refusal to start over a key they never set is
		// worse than the engine ignoring the floor (which it does; see
		// EvaluatePrompt's ask-once ladder).
	}
	if p.MaxFindings < 0 {
		return errors.New("config: guard.prompt.max_findings must be >= 0")
	}
	return nil
}

// HookTimeout returns the hook timeout as a time.Duration.
func (c HooksConfig) HookTimeout() time.Duration {
	return time.Duration(c.TimeoutMS) * time.Millisecond
}

func expandHome(p string) string {
	if !strings.HasPrefix(p, "~/") {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return p
	}
	return filepath.Join(home, p[2:])
}

// applyEnvOverrides walks cfg via reflection and applies any matching
// OBSERVER_<...> environment variables. Supports string, int, float64,
// bool, and []string (comma-separated).
func applyEnvOverrides(cfg *Config, env func(string) string) {
	v := reflect.ValueOf(cfg).Elem()
	applyEnvToStruct(v, []string{"OBSERVER"}, env)
}

func applyEnvToStruct(v reflect.Value, prefix []string, env func(string) string) {
	t := v.Type()
	for i := 0; i < v.NumField(); i++ {
		field := t.Field(i)
		tag := field.Tag.Get("toml")
		if tag == "" {
			tag = field.Name
		}
		// Split embedded options like "name,omitempty".
		tag = strings.SplitN(tag, ",", 2)[0]
		if tag == "-" {
			continue
		}
		envSegment := strings.ToUpper(strings.ReplaceAll(tag, ".", "_"))
		newPrefix := append(append([]string{}, prefix...), envSegment)
		fv := v.Field(i)

		if fv.Kind() == reflect.Struct {
			applyEnvToStruct(fv, newPrefix, env)
			continue
		}
		key := strings.Join(newPrefix, "_")
		raw := env(key)
		if raw == "" {
			continue
		}
		setEnvValue(fv, raw)
	}
}

func setEnvValue(fv reflect.Value, raw string) {
	switch fv.Kind() {
	case reflect.String:
		fv.SetString(raw)
	case reflect.Int, reflect.Int32, reflect.Int64:
		if n, err := strconv.ParseInt(raw, 10, 64); err == nil {
			fv.SetInt(n)
		}
	case reflect.Float32, reflect.Float64:
		if f, err := strconv.ParseFloat(raw, 64); err == nil {
			fv.SetFloat(f)
		}
	case reflect.Bool:
		if b, err := strconv.ParseBool(raw); err == nil {
			fv.SetBool(b)
		}
	case reflect.Slice:
		if fv.Type().Elem().Kind() == reflect.String {
			parts := strings.Split(raw, ",")
			for i := range parts {
				parts[i] = strings.TrimSpace(parts[i])
			}
			fv.Set(reflect.ValueOf(parts))
		}
	default:
		// Unsupported types are ignored — add cases as needed.
	}
}
