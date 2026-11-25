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
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/BurntSushi/toml"

	"github.com/marmutapp/superbased-observer/internal/alertspec"
	"github.com/marmutapp/superbased-observer/internal/notifycfg"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/sandboxcidr"
	"github.com/marmutapp/superbased-observer/internal/sandboxenv"
	"github.com/marmutapp/superbased-observer/internal/sandboxvocab"
	"github.com/marmutapp/superbased-observer/internal/scrub"
	"github.com/marmutapp/superbased-observer/internal/updatespec"
)

// Config is the root configuration for the observer. Field defaults are set
// by Default(). Partial TOML files (including missing sections) are supported
// — unspecified fields retain their defaults.
type Config struct {
	// Deferred lists the settings Load switched off because this build
	// cannot honour them yet (D-514), one reason each. Never read from or
	// written to the file; `observer start` prints them once.
	Deferred []string `toml:"-" json:"-"`
	// Inert lists the config sections Load set aside because the optional
	// component that owns them is not active and the section would not
	// validate (component_sections.go), one line each. The loaded copy holds
	// the section's defaults; the file keeps the operator's value. Never read
	// from or written to the file; `observer start` prints them once.
	Inert []string `toml:"-" json:"-"`
	// TerminalLaunchSet records which agent keys of [terminal.launch] were
	// actually set (a file, an env override or a verified pin), not
	// defaulted (terminal_launch_set.go; Agent Arena, ruling P-203).
	TerminalLaunchSet TerminalLaunchKeys `toml:"-" json:"-"`

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
	Projects     ProjectsConfig     `toml:"projects"`
	Delivery     DeliveryConfig     `toml:"delivery"`
	Update       UpdateConfig       `toml:"update"`
	Tasks        TasksConfig        `toml:"tasks"`
	Browser      BrowserConfig      `toml:"browser"`
	Handoff      HandoffConfig      `toml:"handoff"`
	Terminal     TerminalConfig     `toml:"terminal"`
	Launch       LaunchConfig       `toml:"launch"`
	CodeIntel    CodeIntelConfig    `toml:"codeintel"`
	// ShellWrap is the opt-in [shell_wrap] "wrapped command" shell
	// integration (backlog item 7); see ShellWrapConfig. Zero value = off.
	ShellWrap ShellWrapConfig `toml:"shell_wrap"`
	// Workspace is the [workspace] block: Observer's default workspace
	// folder (see WorkspaceConfig). Zero value = the built-in
	// <home>/observer-workspace.
	Workspace WorkspaceConfig `toml:"workspace"`
	// Security is the security pillar's [security] block (component
	// `security`); see SecurityConfig. Validated only while the module is
	// active (component_sections.go).
	Security SecurityConfig `toml:"security"`
	// Messages is the developer's own [messages] surface choice for admin
	// and developer messaging (T-854); see MessagesConfig. LOCAL-ONLY: the
	// org has no remote toggle for it.
	Messages MessagesConfig `toml:"messages"`
	// Archive is the [archive] surface — cold storage for the corpus
	// archival arc (docs/plans/observer-corpus-archival-lazyload-design-
	// 2026-08-26.md). LOCAL-ONLY, never distributed to an org server, and
	// OPT-IN: with the zero value the retention pass behaves exactly as it
	// did before the arc existed.
	Archive ArchiveConfig `toml:"archive"`
	// MCPRelay is the [mcp_relay] surface — the node MCP relay (Agent Access
	// P4, doc3 §8.2/§12). LOCAL-ONLY, never distributed, and OPT-IN: the zero
	// value is byte-identical to a build without the relay (no client config
	// rewrite, no listener, no table cache).
	MCPRelay MCPRelayConfig `toml:"mcp_relay"`
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
	Email notifycfg.EmailConfig `toml:"email"`
	// Digest is the [digest] surface — the scheduled personal cost digest
	// (gap-register G13): a weekly/monthly per-tool/per-model spend rollup
	// emailed through the shared [email] channel. LOCAL-ONLY. OPT-IN: default
	// off, and additionally requires [email].enabled. See internal/notify/digest.
	Digest notifycfg.DigestConfig `toml:"digest"`
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
	// Pricing is the [pricing] surface: today only the [pricing.feed]
	// sub-block, the standalone-node pricing feed client (docs/plans/
	// pricing-sync-tokenomics-to-platform-plan-2026-09-11.md §C.4 / D7: a NEW
	// top-level block, kept distinct from [intelligence.pricing] which is the
	// node's OWN authored price table). LOCAL-ONLY and never distributed. The
	// feed is ON by default (operator decisions 2026-09-20 and D-374: a stale
	// feed breaks budgets, and only the superbased.app Tokenomics database
	// keeps it fresh); a standalone node that wants zero egress opts OUT with
	// `[pricing.feed] enabled = false`. An enrolled node receives prices
	// through its org rail and never consults the public feed (§C.3/D8). See
	// PricingFeedConfig.
	Pricing PricingSectionConfig `toml:"pricing"`
	// Experiments is the [[experiments]] list — productized profile
	// A/B runs (usability arc P6.4). See experiments.go.
	Experiments []ExperimentConfig `toml:"experiments"`
	// Components is the [components] block: the node operator's component
	// selection (modular packaging P1). LOCAL-ONLY. The zero value keeps
	// every compiled component active, exactly as before the block existed.
	// See ComponentsConfig.
	Components ComponentsConfig `toml:"components,omitempty"`
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
	// VendorForcedNative decides a launch whose agent sandbox a vendor
	// managed policy forces on and which cannot nest in the chosen stack
	// (sandbox plan v2 section 4.4, D-746 Q17, lane SBX-P3D):
	// "nest_or_refuse" (default) chooses a stack where both run (an hw_vm
	// row, N13) and refuses tool_conflict when none is available, which is
	// every host until P4; "refuse" refuses at once. Running without
	// Observer's layer is deliberately not a value. An org may pin either.
	VendorForcedNative string `toml:"vendor_forced_native"`
	// WorkspacesDir overrides where prepared workspaces are minted.
	// Empty (the default) uses `<observer dir>/workspaces`.
	WorkspacesDir string `toml:"workspaces_dir"`
	// WorkspaceRetentionDays is the sweep horizon for prepared workspaces
	// (full repo copies, not small). 0 (the default) keeps them forever —
	// B7 needs workspaces to persist past run exit.
	WorkspaceRetentionDays int `toml:"workspace_retention_days"`
	// ReturnedCopyRetentionDays (decision SBXD-2) is how many days a
	// sandboxed run's managed copy is kept once its work came home: past
	// it, the daemon removes the copy only when the removal table would
	// remove it on a click (its commits came back, nothing in it is
	// uncommitted, the run is not live, the copy could be compared), one
	// capped batch per pass. Default 30; 0 never removes a copy
	// automatically; at most 3650. workspace_retention_days is unchanged.
	ReturnedCopyRetentionDays int `toml:"returned_copy_retention_days"`
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
	// LiveRunUpdatePolicy says how soon an update apply that is waiting for
	// live sandboxed runs asks its owner (sandbox plan v2 sections 5.5 and
	// 10.1, SBX-UPD-1): "defer" (the default; the question waits in the
	// dashboard banner) or "ask_immediately" (the dialog opens at once).
	// Neither value ever ends a run silently.
	LiveRunUpdatePolicy string `toml:"live_run_update_policy"`
	// Egress selects the sandbox network tier (security ledger SR27-SBX-1):
	// "internet" (the default, also what an empty value means) gives the
	// sandbox its own network namespace with the observer model proxy
	// forwarded in and other traffic sent through a host-side egress gateway
	// that refuses every host-local address, so the sandboxed agent cannot
	// reach the dashboard's loopback control plane; "proxy_only" forwards
	// only the model proxy; "none" forwards nothing; "host" shares the host
	// network (the v1 behaviour, which leaves the dashboard reachable from
	// inside the sandbox). A tier this host cannot build fails the launch;
	// it never falls back to "host".
	Egress string `toml:"egress"`
	// EgressAllowCIDRs is an authority-EXPANDING allow-list for the
	// "internet" tier's egress gateway. The gateway refuses every private
	// destination by default (RFC 1918, 100.64.0.0/10 carrier-grade NAT and
	// tailnets, IPv6 unique-local and site-local): that is where the WSL2
	// NAT gateway (the Windows host), Docker bridge containers and LAN
	// services live. List a CIDR here (for example "10.20.0.0/16") to let a
	// sandboxed agent reach a corporate registry or git server on a private
	// address. Each entry must be a canonical CIDR inside one of those
	// private ranges; loopback, link-local and the host's own addresses can
	// never be listed. Empty by default.
	EgressAllowCIDRs []string `toml:"egress_allow_cidrs"`
	// EgressAllowHosts is a restrictive host allow-list for a sandboxed
	// agent run under the "internet" tier (lane LEFT-SBX): when set, the
	// egress gateway lets the box reach only these hosts (exact names, or
	// "*.example.com" for every name below it; ports 443 and 80, the TLS
	// server name equal to the host), beside the model proxy, and no literal
	// IP. Empty (the default) keeps the tier's own behaviour. It never
	// widens anything: the private-range rules and egress_allow_cidrs still
	// apply. A tier with no gateway (host) cannot honour it, so a launch
	// with it set there is refused. An org may pin it (the intersection: an
	// org list narrows yours, and an empty yours takes the org's).
	EgressAllowHosts []string `toml:"egress_allow_hosts"`
	// PinnedNoEgressHost is set only by the governance overlay when an org
	// pin of egress_allow_hosts left no host in common: the gateway then
	// allows no host at all (the model proxy still works). Never read from
	// the file.
	PinnedNoEgressHost string `toml:"-" json:"-"`
	// ProviderDirect is the organization's direct model-provider egress
	// posture for sandboxed internet runs (operator ruling DEC-9, gap review
	// OBS-8a, node.governance key terminal.sandbox.provider_direct):
	// "refuse_all" (the egress gateway refuses the provider hosts in every
	// sandboxed internet run it enforces), "capture_rule" (capture rule C6
	// alone decides, the default, also what "" means) or "allow" (no
	// refusal; a run whose full capture rested on the refusal reads
	// proxy_and_transcripts). It exists so the pin resolves in this build's
	// config. A launch reads only ProviderDirectInForce, never this local
	// value: an individual node keeps capture_rule whatever it says, and a
	// managed node takes only its organization's pin (the
	// proxy.maintain_routes precedent).
	ProviderDirect string `toml:"provider_direct"`
	// ProviderDirectInForce is the resolved posture a launch applies: the
	// organization's pinned ProviderDirect on a managed node (a valid org
	// lock recording managed tenancy), capture_rule ("") everywhere else.
	// Set only by Load; never read from the file.
	ProviderDirectInForce string `toml:"-" json:"-"`
	// AllowToolConfigWrites is an authority-EXPANDING opt-in. Default FALSE:
	// files a later UNSANDBOXED session executes (the daemon config, the
	// user guard policy, shell-wrap shims, each tool's hook/MCP/plugin
	// config, and the workspace's repository config + hooks dir) are
	// re-bound read-only inside the sandbox. Set true only if a sandboxed
	// tool must change its own user-level settings.
	AllowToolConfigWrites bool `toml:"allow_tool_config_writes"`
	// PassEnv lists the NAMES of extra environment variables a sandboxed
	// agent may receive from the environment that launched it. Every
	// backend builds the box's environment from an allow-list (the OS's own
	// variables, the tool's provider variables from its integration row and
	// Observer's own run variables; internal/sandboxenv), so a GITHUB_TOKEN,
	// a cloud key or another session's variables never reach the box unless
	// they are named here. Authority-expanding and local-only: an org has no
	// fleet-wide value for it and cannot pin it. Each entry is a variable
	// name (letters, digits and underscores, not starting with a digit, not
	// OBSERVER_). The names a run passes are shown in its posture. Empty by
	// default.
	PassEnv []string `toml:"pass_env"`
	// SignInSeedTools lists the tools whose sign-in a sandboxed run may
	// copy into its box without asking each time (lane BOXSIGNIN, ruling
	// P-180 (6)): the user's remembered consent, given at a launch (the CLI
	// prompt's "always", the dashboard's inline step) or written here.
	// Empty (the default) copies nothing unless the user consents at that
	// launch. Only the files the tool's registry row names are copied,
	// only into a box whose tool state is projected (a local container
	// row), never to a hosted row; the copy is removed when the run ends.
	// Local-only: an org has no value for it and cannot turn it on (it may
	// forbid seeding through the sandbox managed policy).
	SignInSeedTools []string `toml:"sign_in_seed_tools"`
	// SignInSeedForbidden is set only by the sandbox managed policy's
	// sign_in_seed_forbidden (an org forbid, lowering only). Never read
	// from the file.
	SignInSeedForbidden bool `toml:"-" json:"-"`
	// AllowOSC52Clipboard lets a sandboxed tool's OSC 52 escape sequences
	// (the terminal's clipboard set and query) reach the terminal that
	// shows the run. Default FALSE: Observer removes them from a sandboxed
	// run's output on the dashboard terminal and on the CLI host console,
	// so a box refused the clipboard (the Windows box's job carries
	// READCLIPBOARD and WRITECLIPBOARD) cannot write it through the
	// terminal (WINFIX4 audit finding 2, ruling P-175). Unsandboxed runs are
	// never filtered. Authority-expanding and local-only: an org has no
	// fleet-wide value for it and cannot pin it. A run that allows it says
	// so in its posture.
	AllowOSC52Clipboard bool `toml:"allow_osc52_clipboard"`
	// Seccomp turns on Observer's syscall filter (internal/sandboxseccomp,
	// the "observer_default" deny list answered with EPERM) for the bwrap
	// and process_lite rows (gap G16, lane N2). Default FALSE (D7): opt-in
	// until a clean live register across the tool matrix. When true, a
	// launch on either row is refused if the filter cannot be built,
	// applied or read back from /proc; it never runs unfiltered. Rows
	// whose engine applies its own default filter (the OCI rows) are not
	// affected. An absent key changes nothing.
	Seccomp bool `toml:"seccomp"`
	// SeccompAllowSeize lifts PTRACE_SEIZE from that filter, and nothing
	// else, so `strace <cmd>` works inside a sandboxed terminal with strace
	// 6.14 and later (lane ptrace, PT-96, operator ruling 2026-11-10).
	// Default FALSE. Authority-expanding and set only from the dashboard
	// (Terminals > Settings, the sandbox card's strace switch, POST
	// /api/terminal/sandbox/ptrace-seize): `observer config set`, the
	// generic keys route and the sandbox settings save never write it, and
	// an organization can neither pin nor raise it. It takes effect only on
	// a launch whose seize cannot reach a process outside the sandbox (the
	// sandbox's own pid namespace, or Yama ptrace_scope 1 or more, read at
	// launch); otherwise the launch keeps observer_default and says why.
	// PTRACE_ATTACH stays denied either way. Read on the next launch.
	SeccompAllowSeize bool `toml:"seccomp_allow_seize"`
	// Backends is the backend preference order (sandbox plan v2 section 10),
	// for example ["bwrap"]. When set it wins over Backend; empty means
	// Backend as a one-element list. Each entry is a registry backend id; an
	// id this build has no driver for is listed by `observer sandbox status`
	// with its reason and never selected.
	Backends []string `toml:"backends"`
	// MinIsolation is the local isolation floor: "" (none), "process",
	// "container", "userspace_kernel" or "hw_vm". A sandboxed launch on a
	// backend that builds a weaker class is refused, never run weaker.
	MinIsolation string `toml:"min_isolation"`
	// PinnedNoBackend is set only by the governance overlay and never read
	// from or written to TOML: when the organization's
	// terminal.sandbox.backends pin (an ordered filter) leaves none of the
	// node's own backends, no backend is enabled, and this names the pin a
	// sandboxed launch's refusal quotes. Empty otherwise.
	PinnedNoBackend string `toml:"-" json:"-"`
	// OCI is [terminal.sandbox.oci], the oci-runc driver (Docker Engine or
	// Podman through the Engine API on a local unix socket; sandbox plan v2
	// section 10.1, lane SBX-P3A). Read only while the terminals.sandbox.oci
	// component is active AND "oci-runc" is in Backends.
	OCI TerminalSandboxOCIConfig `toml:"oci"`
	// MXC is [terminal.sandbox.mxc], the mxc-process driver (Microsoft
	// Execution Containers' ProcessContainer on native Windows 11; sandbox
	// plan v2 section 13 P6, lane SBX-P6). Read only while the
	// terminals.sandbox.mxc component is active AND "mxc-process" is in
	// Backends.
	MXC TerminalSandboxMXCConfig `toml:"mxc"`
	// Seatbelt is [terminal.sandbox.seatbelt], the macOS Seatbelt driver
	// (sandbox plan v2 section 13 P5, lane SBX-P5; beta). Read only while
	// the terminals.sandbox.seatbelt component is active AND "seatbelt" is
	// in Backends.
	Seatbelt TerminalSandboxSeatbeltConfig `toml:"seatbelt"`
	// AppleContainer is [terminal.sandbox.apple_container], the Apple
	// container driver (macOS 26 on Apple silicon; lane SBX-P5; beta). Read
	// only while the terminals.sandbox.apple-container component is active
	// AND "apple-container" is in Backends.
	AppleContainer TerminalSandboxAppleContainerConfig `toml:"apple_container"`
	// Landlock is [terminal.sandbox.landlock], the Landlock-only
	// process_lite row (sandbox plan v2 section 4.1, lane SBX-P3B; beta).
	// Read only while the terminals.sandbox.landlock component is active
	// AND "process_lite" is in Backends.
	Landlock TerminalSandboxLandlockConfig `toml:"landlock"`
	// Hosted is [terminal.sandbox.hosted], the hosted sandbox rows (E2B,
	// Modal, Vercel Sandbox; sandbox plan v2 section 10, lane SBX-P7; beta).
	// Read only while a hosted driver's component is active AND its row is
	// in Backends. No credential is ever a key here: credentials live in
	// the OS keychain (or the vendor's environment variables).
	Hosted TerminalSandboxHostedConfig `toml:"hosted"`
	// Readopt, WSLC and HCS are lane GATES-SBX's blocks
	// (internal/config/sandbox_gates.go), each read only while its own
	// component is selected.
	Readopt TerminalSandboxReadoptConfig `toml:"readopt"`
	WSLC    TerminalSandboxWSLCConfig    `toml:"wslc"`
	HCS     TerminalSandboxHCSConfig     `toml:"hcs"`
	// Windows is [terminal.sandbox.windows]: the MXC tier floor (R-034).
	Windows TerminalSandboxWindowsConfig `toml:"windows"`

	// OpenShell is [terminal.sandbox.openshell], the OpenShell row
	// (internal/config/sandbox_openshell.go; lane O1A; beta). Read only
	// while the terminals.sandbox.openshell component is active AND
	// "openshell" is in Backends.
	OpenShell TerminalSandboxOpenShellConfig `toml:"openshell"`

	// VM is [terminal.sandbox.vm], the Cloud Hypervisor microVM driver
	// (sandbox plan v2 sections 10 and 10.1, lane SBX-P4; beta). Read only
	// while the terminals.sandbox.vm component is active AND
	// "cloud-hypervisor" is in Backends.
	VM TerminalSandboxVMConfig `toml:"vm"`

	// Setup is [terminal.sandbox.setup], the sandbox installation lifecycle
	// (plan docs/plans/sandbox-installation-lifecycle-plan-2026-11-06.md):
	// how far the setup steps of the New Terminal dialog, Settings and
	// `observer sandbox setup` may go on this machine.
	Setup TerminalSandboxSetupConfig `toml:"setup"`
}

// TerminalSandboxHostedConfig is the [terminal.sandbox.hosted] block.
type TerminalSandboxHostedConfig struct {
	// MinSessionMinutes drops a hosted row whose provider caps a box below
	// it (selection rule S13). Default 30, 5 to 1440, at most
	// MaxRunMinutes (so a short max_run_minutes needs it lowered too).
	MinSessionMinutes int `toml:"min_session_minutes"`
	// KeyCustody is where the model credential sits: auto (the default,
	// decision SBXD-1: per launch and per tool, the key stays on this
	// machine when credential injection or the org AI gateway adds it for
	// that tool, otherwise the tool's API key is put in the box; disclosed
	// on the consent screen and in the New Terminal dialog), home_relay
	// (the key always stays on this machine; a tool nothing here serves is
	// refused), in_box_api_key, in_box_oauth_seed (not built), or
	// provider_injected (no hosted row offers it yet).
	KeyCustody string `toml:"key_custody"`
	// KeyCustodyByTool sets the custody per tool (tool id -> auto,
	// home_relay or in_box_api_key), taking precedence over KeyCustody for
	// that tool's hosted launches. Default empty.
	KeyCustodyByTool map[string]string `toml:"key_custody_by_tool"`
	// ToolKeys opts a tool in (tool id -> true) to a third in-box key
	// source (decision SBXD-4 (b)): under in-box custody, the keys the tool
	// saved in its own key file (a grounded registry row; OpenCode's
	// auth.json), read only when the run starts, after the daemon's
	// environment and the stored keys. Default empty (off); disclosed on the
	// consent screen by tool.
	ToolKeys map[string]bool `toml:"tool_keys"`
	// LoginSeed opts a tool in (tool id -> true) to copying its login into
	// the box under in-box custody (decision SBXD-4 (c)): only the
	// short-lived access token, never the refresh token, and only while it
	// has not expired (a grounded registry row; Claude Code's
	// .credentials.json). Default empty (off); disclosed on the consent
	// screen by tool.
	LoginSeed map[string]bool `toml:"login_seed"`
	// MemoryImages is avoid (the default: a provider pause image is switched
	// off where the vendor allows, disclosed and deleted at teardown) or
	// refuse (a row whose provider could take one is dropped).
	MemoryImages string `toml:"memory_images"`
	// CheckpointMinutes is how often the run's transcripts are pulled home
	// while it runs (and always at teardown). Default 5, 1 to 60.
	CheckpointMinutes int `toml:"checkpoint_minutes"`
	// MaxRunMinutes is the vendor timeout every box is created with (never
	// none). Default 60, 5 to 1440.
	MaxRunMinutes int `toml:"max_run_minutes"`
	// DailyBoxMinutes caps the box-minutes per provider per UTC day; a
	// launch over it refuses. Default 240, 5 to 10080.
	DailyBoxMinutes int `toml:"daily_box_minutes"`
	// DBExport turns on the in-box database export at teardown (lane
	// LEFT-SBX, opt-in by orchestrator ruling P-141): consistent copies of
	// the tool's SQLite stores (conversation content, up to 1 GiB a run)
	// are pulled home under <observer dir>/sandbox-hosted/dbcopies/<run>
	// before the box is deleted, and swept after
	// [terminal.sandbox].workspace_retention_days. Default false.
	DBExport bool `toml:"db_export"`
	// DiffAgainst (the smaller item "diff against the box's baseline" of
	// the sandbox decisions) is what an upload run's saved diff is taken
	// against: "baseline" (the default; also what "" means) diffs against
	// the observer-baseline commit the upload made in the box, so commits
	// the agent made are in the diff and a run from a clean, committed
	// folder opens as a branch; "head" keeps the earlier capture (the box's
	// HEAD, so the agent's own commits are left out and such a diff is
	// offered as a file only). A row whose in-box guest keeps its own
	// baseline (the organization's row) always uses the guest's capture.
	DiffAgainst string `toml:"diff_against"`
	// AllowPrivateRanges (decision SBXD-7): false (the default) has a hosted
	// row's internet-tier create ask the vendor to refuse the cloud metadata
	// address, link-local and private ranges (169.254.0.0/16, 10.0.0.0/8,
	// 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, fc00::/7, fe80::/10), on
	// every vendor whose API takes deny rules; true asks for no deny, for a
	// box that must reach a private network. A vendor that takes no deny rule
	// is unaffected either way (disclosed). A provider table's own
	// allow_private_ranges overrides it for that vendor. An organization may
	// only pin it to false.
	AllowPrivateRanges bool `toml:"allow_private_ranges"`
	// GuardHooks is whether a hosted box gets guard's hook registration for
	// the agent tool (lane HOOKS, decision SBXD-6): auto (the default; ""
	// reads as auto) seeds it whenever guard enforcement is in force on this
	// machine, on always, off never. Seeding writes the tool's user-scope
	// settings file in the BOX home only, for a tool whose hook mechanism a
	// box can be seeded for (internal/hook.BoxHooksCover); the in-box hooks
	// ride the run's relay home, where guard decides, and a dropped relay
	// blocks a gate hook.
	GuardHooks string `toml:"guard_hooks"`
	// CloneWhere is where a hosted row's "Clone a remote URL" source
	// clones (decision SBXD-5): auto (the default) clones a repository
	// that answers an anonymous listing in the box and any other on this
	// machine; box always clones in the box (public repositories only,
	// the internet tier only); home always clones on this machine with
	// its own git login and uploads the clone's tracked files (any tier,
	// private repositories included, no credential leaves). Only auto
	// lets the New Terminal dialog choose per launch. A row whose box
	// clone is its organization's own always clones in the box.
	CloneWhere string `toml:"clone_where"`
	// UploadNonGit (decision SBXD-8, audit item H8) uploads a folder that is
	// not a git repository: its files are listed with git's own ignore
	// machinery through a temporary git directory outside the folder (the
	// folder is never written, never `git init`ed), honouring its
	// .gitignore files, Observer's default ignore set (dependency, build
	// and virtual-environment folders, version-control folders, .env files,
	// operating-system clutter) and UploadIgnore, then the upload's usual
	// credential-shaped exclusions and caps; the consent screen lists the
	// files and the changes come back as a diff file only. Default true;
	// false refuses such a folder before Start, as before. A folder inside
	// a repository, the home folder and / stay refused either way. An org
	// may only keep it off.
	UploadNonGit bool `toml:"upload_non_git"`
	// UploadIgnore are extra ignore patterns (gitignore syntax) for that
	// listing, written after the default set, so a negated pattern
	// ("!dist/") takes a default back out. At most 200, each at most 256
	// characters on one line. An org may only add patterns.
	UploadIgnore []string `toml:"upload_ignore"`
	// E2B, Modal and Vercel are the per-provider tables.
	E2B    TerminalSandboxHostedProviderConfig `toml:"e2b"`
	Modal  TerminalSandboxHostedProviderConfig `toml:"modal"`
	Vercel TerminalSandboxHostedProviderConfig `toml:"vercel"`
	// Docker is the Docker Sandboxes table (lane SBX-DOCKER).
	Docker TerminalSandboxHostedProviderConfig `toml:"docker"`
	// OpenShellOrg is the org-hosted OpenShell row's block (lane G4).
	OpenShellOrg TerminalSandboxHostedOrgShellConfig `toml:"openshell-org"`
	// InstaBox is the InstaBox row's provider table (region, template and
	// box_binary; InstaBox takes no region, so only the empty one resolves).
	InstaBox TerminalSandboxHostedProviderConfig `toml:"instabox"`
	// Daytona is the Daytona row's provider table (a hosted vendor;
	// its template is a Daytona snapshot name).
	Daytona TerminalSandboxHostedProviderConfig `toml:"daytona"`
}

// TerminalSandboxHostedProviderConfig is one provider's table.
type TerminalSandboxHostedProviderConfig struct {
	// Region is the region to run in ("" is the provider's default; E2B's
	// region is the API endpoint its key belongs to).
	Region string `toml:"region"`
	// Template is the vendor template, image or runtime that holds the
	// agent tool ("" is the vendor's default, which holds none: the tool
	// then installs from its vendor at first start on the internet tier
	// only).
	Template string `toml:"template"`
	// BoxBinary is an absolute path to a Linux observer binary of this
	// version for the box ("" uses the running binary when it is a Linux
	// binary of the box's architecture).
	BoxBinary string `toml:"box_binary"`
	// Endpoint is the provider's API origin, E2B only (lane SBX-UPD, plan
	// section 10.1's hosted.e2b.api_base): "" is the region's own endpoint.
	// A local value must be on the vendor's own domain; an origin elsewhere
	// (a self-hosted E2B) reaches a node only as an org-published endpoint
	// on a managed node (SBX-GOV-2), and a credential is sent there only
	// when it was connected for that origin (SBX-GOV-4).
	Endpoint string `toml:"endpoint"`
	// EndpointSPKISHA256 pins the endpoint server's public key (the SHA-256
	// of its SubjectPublicKeyInfo, 64 lowercase hex), E2B only; "" pins
	// nothing beyond the usual certificate checks.
	EndpointSPKISHA256 string `toml:"endpoint_spki_sha256"`
	// OrgPublished marks an Endpoint the org's managed pull set (never read
	// from a file): only such an endpoint may leave the vendor's domain.
	OrgPublished bool `toml:"-" json:"-"`
	// BoxBinaryInImage marks a row whose box image already carries the in-box
	// observer at the vendor's binary path, so nothing is uploaded and only
	// its version is checked in the box (never read from a file: the
	// organization's published box_binary = "image" sets it; FX3 item 2,
	// live finding F-L3P4-6).
	BoxBinaryInImage bool `toml:"-" json:"-"`
	// AllowPrivateRanges overrides [terminal.sandbox.hosted]
	// .allow_private_ranges for this vendor (nil follows it). Only a vendor
	// whose API takes deny rules accepts it (HostedPrivateRangeDenyProviders);
	// an organization pin of the shared key clears it.
	AllowPrivateRanges *bool `toml:"allow_private_ranges"`
}

// HostedPrivateRangeDenyProviders are the provider tables whose vendor's
// create request can deny address ranges (internal/sandboxremote's
// DenyRanges rows; config stays a leaf, so this mirror is pinned equal to
// that table by a test in cmd/observer).
var HostedPrivateRangeDenyProviders = []string{"docker", "e2b", "vercel"}

// ProviderTable returns the provider table named name (e2b, modal, vercel,
// docker, instabox, daytona), or nil for any other name.
func (c *TerminalSandboxHostedConfig) ProviderTable(name string) *TerminalSandboxHostedProviderConfig {
	if get, ok := hostedProviderTables[name]; ok {
		return get(c)
	}
	return nil
}

// hostedProviderTables maps a provider table name to its field.
var hostedProviderTables = map[string]func(*TerminalSandboxHostedConfig) *TerminalSandboxHostedProviderConfig{
	"e2b":      func(c *TerminalSandboxHostedConfig) *TerminalSandboxHostedProviderConfig { return &c.E2B },
	"modal":    func(c *TerminalSandboxHostedConfig) *TerminalSandboxHostedProviderConfig { return &c.Modal },
	"vercel":   func(c *TerminalSandboxHostedConfig) *TerminalSandboxHostedProviderConfig { return &c.Vercel },
	"docker":   func(c *TerminalSandboxHostedConfig) *TerminalSandboxHostedProviderConfig { return &c.Docker },
	"instabox": func(c *TerminalSandboxHostedConfig) *TerminalSandboxHostedProviderConfig { return &c.InstaBox },
	"daytona":  func(c *TerminalSandboxHostedConfig) *TerminalSandboxHostedProviderConfig { return &c.Daytona },
}

// PrivateRangesAllowed is the effective allow_private_ranges for one
// provider table: its own override when set, else the shared value.
func (c TerminalSandboxHostedConfig) PrivateRangesAllowed(p TerminalSandboxHostedProviderConfig) bool {
	if p.AllowPrivateRanges != nil {
		return *p.AllowPrivateRanges
	}
	return c.AllowPrivateRanges
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
	// Content-free: only meaningful while the channel is enabled (the local
	// [org_client.share].policy_state opt-in, or an org raise of it on a
	// managed node) — the reporter goroutine always runs but stays dormant
	// otherwise.
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
	// AcceptModuleFamilies and PreauthorizeModuleEnforce are the additive
	// twins of the two keys above for the families a released binary does
	// not know (the module floor families security.scanning and
	// terminals.isolation, and every later one; policyfamilies.go). They are
	// read TOGETHER with the old keys (AcceptedFamilies,
	// PreauthorizedFamilies) and obey the same rules; the managed
	// accept-list writers put a newly linked module family here, never in
	// the old keys, because an older binary refuses a config whose old keys
	// name a family it does not know but ignores a key it does not know.
	AcceptModuleFamilies      []string `toml:"accept_module_families"`
	PreauthorizeModuleEnforce []string `toml:"preauthorize_module_enforce"`

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
//     END-USERS route through Observer): the nested Obs sub-table
//     ([org_client.share.obs]: summary, traces, content, eval_summary,
//     admission, eval_items, egress).
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
	// HookActivity opts the per-session hook liveness counts (the node-local
	// hook_activity table, agent migration 198) onto the wire: surface-gap
	// review 2026-10-25, OBS-7, decision DEC-5. A metadata tier: this key
	// alone ships, per (session, tool, event), the invocation count, the
	// first and last time and the coarse route env classes, so the org Guard
	// tab can show a hook capability that was not observed on a surface. The
	// CLAUDE_CONFIG_DIR path hash additionally requires full_content or
	// admin_managed. Default false, node-side only on an individual node;
	// org-raisable on a managed node via extract.hook_activity (or the
	// umbrella extract.managed).
	HookActivity bool `toml:"hook_activity"`
	// MCPActivity opts an INDIVIDUAL (non-org-enrolled) node's HMAC-only daily
	// MCP relay aggregate (day x virtual server x keyed tool HMAC x decision x
	// client attestation counts, orgcontract.MCPRelayActivityRow) onto the
	// wire — Agent Access ruling R8.30.b, docs/plans/agent-access-
	// implementation-plan-2026-09-23.md §9.5 / §11.7 W4e. No plain server or
	// tool name, no arguments, no result, no per-call row. Default false,
	// node-side only, and it applies ONLY to an individual node: an ENROLLED
	// teams/enterprise node ships the aggregate AND the per-record L2 events
	// by capture posture (full_content / admin_managed, or the org-signed
	// EnterpriseGranted raise on an already-enrolled node — R9.5 / R11.10),
	// where this key neither adds nor removes anything. It is deliberately
	// NOT an org-raisable share tier (absent from the node-governance share
	// vocabulary): there is nothing for an org to raise on a node it does not
	// manage.
	MCPActivity bool `toml:"mcp_activity"`
	// Security is the security pillar's share level on an INDIVIDUAL node
	// (security plan 6.5 and 7.4, ruling Q7): "off" (also what an unknown
	// value means), "posture" (the enum-and-count daily posture row; the
	// default when the key is unset, ruling R1 of lane CODESEC-ORG,
	// 2026-11-03) or "findings" (posture plus finding rows; their paths and
	// redacted evidence still need full_content). Rows ship only while the
	// security module is active. Node-side only, never raised remotely: a
	// MANAGED node ignores it and follows the finding_share of its in-force
	// enforce.security pull (posture by default).
	Security string `toml:"security"`
	// PolicyState opts the P0-6 effective-policy-state reverse channel
	// (docs/plans/plane-a-p0-6-effective-policy-state-plan.md §2.3) onto a
	// dedicated POST /api/agent/policy-ack. CONTENT-FREE — the report carries
	// only hash/version/enum/timestamp rows (attribution empty-on-wire,
	// server-stamped). Its own consent toggle, default false, and it gates
	// an INDIVIDUAL node only (the org cannot raise it there). A MANAGED node
	// reports whatever this says (2026-11-12 ruling, govern
	// managedpolicytiers.go).
	PolicyState bool `toml:"policy_state"`
	// --- Plane A: general observability of an admin/org-hosted LLM app ---
	// Org-tier observability opt-ins live under the nested
	// [org_client.share.obs] sub-table so the config namespace reflects the
	// plane split (plane-separation audit M1). The four flat keys that
	// preceded it (org_client.share.obs_summary / obs_traces / obs_content /
	// obs_eval_summary) are REMOVED from the struct (post-Agent-Access
	// backlog item 12): while they were declared, every full re-marshal
	// (WriteToml: dashboard save, `observer config set`) wrote them back and
	// the deprecation warnings never stopped. A file still carrying them
	// loads (the decoder ignores keys with no field); the config-migrate
	// registry (internal/config/migrate, steps 2 and 5) is the one owner of
	// the removed keys and moves or strips them on disk.
	Obs OrgClientShareObsConfig `toml:"obs"`
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

// Default returns the baked-in defaults (spec §16.1).
func Default() Config {
	return Config{
		Observer: ObserverConfig{
			DBPath:   "~/.observer/observer.db",
			LogLevel: "info",
			Watch: WatchConfig{
				PollIntervalSeconds: 2,
				MaxFileSizeMB:       50,
				HomeWalk:            true,
				EnabledAdapters: []string{
					"claude-code", "codex", "cline", "cline-cli", "roo-code", "zoo-code", "cursor", "copilot", "copilot-cli", "cowork", "opencode", "openclaw", "pi", "gemini-cli", "antigravity", "antigravity-cli", "hermes", "kilo-code", "kilo-code-cli", "qwen-code", "kiro-cli", "crush", "kimi-code", "grok", "devin", "qoder", "aider", "goose", "chatgpt-web", "claude-web", "perplexity-web", "gemini-web", "copilot-web", "droid", "open-interpreter", "command-code", "muse", "prime-agent", "deepseek", "junie", "zcode", "mistral-code", "freebuff", "grokbot", "kiro-crew", "poolside", "zed", "autohand", "ibm-bob", "cortex-code", "codebuddy", "deepagents-code", "dimcode", "dirac", "kimchi", "stakpak", "vtcode", "custom-agent",
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
				HeldMaxMB:             2048,
			},
			Hooks: HooksConfig{
				TimeoutMS:        500,
				AutoRegister:     true,
				PeriodicRegister: HooksPeriodicRegisterManaged,
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
				// Process capture budget (plan §9.1 defaults). Seeded in
				// full so a partial [observer.process.capture] block
				// inherits the rest (the partial-merge rule).
				Capture: ProcessCaptureConfig{
					Enabled: true,
					Budget: ProcessCaptureBudgetConfig{
						PerToolCall: 200,
						PerSession:  5000,
						PerMinute:   300,
					},
					Services: ProcessCaptureServicesConfig{
						Track:               true,
						DetachAfterMinutes:  10,
						ExemplarsPerService: 20,
						TailMinutes:         30,
					},
					Fold:         ProcessCaptureFoldConfig{Enabled: true},
					Metrics:      ProcessCaptureMetricsConfig{RingMinLifetimeSeconds: 30},
					Rollups:      ProcessCaptureRollupsConfig{BucketSeconds: 60},
					Unattributed: ProcessCaptureUnattributedConfig{PendingHours: 24, Mode: "rollup"},
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
			LiveRibbon:       true,
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
		// Projects (the read-only git-commit-history scanner behind the
		// Projects-page ROI/commit-alignment arc) is default-ON for the
		// same reasons Guidance is: local, passive, network-free. Same
		// partial-merge rule — an install with no [projects] section gets
		// CommitScan=true here, not a zero-valued false.
		Projects: ProjectsConfig{
			CommitScan:                true,
			CommitScanIntervalSeconds: 120,
			CommitLinkWindowDays:      14,
			ActiveProjectDays:         30,
			// AlignmentJudge default OFF (W5a): unlike CommitScan, calling
			// a configured judge is a per-turn LLM cost (and, for a
			// remote judge, egress) the operator opts into explicitly —
			// not a passive local capture.
			AlignmentJudge:          "off",
			SkillHistory:            true,
			SkillHistorySkewSeconds: 120,
			QualityMetrics:          false,
		},
		// Delivery (commit to PR to merge, D-689): local landing detection
		// is default-ON for the same reasons as the commit scan (local,
		// read-only, network-free). Provider egress is not a config switch.
		Delivery: DeliveryConfig{
			Local:             true,
			PollMinutes:       10,
			MirrorCapMB:       2048,
			AbandonAfterDays:  30,
			CountLikely:       false,
			ContentOverlapMin: 0.8,
		},
		// Pricing feed (standalone-node pricing sync) is ON by default,
		// including its background poller (Auto). This is a deliberate
		// reversal (operator decision 2026-09-20) of the former
		// zero-egress-by-default invariant (D3): prices should track the
		// Tokenomics source without a per-node opt-in. A standalone node
		// that wants zero egress opts OUT with `[pricing.feed] enabled =
		// false`. Same partial-merge rule as Predict — an install with no
		// [pricing.feed] section gets this seed (Enabled=true), not a
		// zero-valued struct with an empty URL.
		Pricing: PricingSectionConfig{
			Feed: PricingFeedConfig{
				Enabled:           true,
				Auto:              true,
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
		// Messages: the developer's surfaces for org messages (T-854, D-688
		// ruling 1). Every in-editor surface defaults ON; the OS desktop
		// notification stays OFF until the developer turns it on. Partial
		// merge keeps these for an install with no [messages] section.
		Messages: DefaultMessagesConfig(),
		Security: DefaultSecurityConfig(),
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
		// Launch: a launcher that finds the daemon down starts it (L-169).
		Launch: LaunchConfig{StartDaemon: true, StartDaemonWaitSeconds: DefaultStartDaemonWaitSeconds},
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
				VendorForcedNative:     "nest_or_refuse",
				WorkspaceRetentionDays: 0,
				PrepTimeoutSeconds:     300,
				LiveRunUpdatePolicy:    "defer",
				Egress:                 "internet",
				OCI:                    TerminalSandboxOCIConfig{PodmanUserns: "keep-id", StopGraceSeconds: 10},
				MXC:                    TerminalSandboxMXCConfig{StopGraceSeconds: 5, ProbeTimeoutSeconds: 30},
				AppleContainer:         TerminalSandboxAppleContainerConfig{MemoryMiB: 4096, CPUs: 4},
				Landlock:               TerminalSandboxLandlockConfig{MinABI: 9},
				VM:                     TerminalSandboxVMConfig{VMM: "cloud-hypervisor", VCPUs: 2, MemoryMB: 4096, WorkspaceDelivery: "virtiofs"},
				// [terminal.sandbox.setup]: elevated setup steps stay guide
				// steps until the person turns the key on (P-250).
				Setup: TerminalSandboxSetupConfig{AllowElevated: false},
				Hosted: TerminalSandboxHostedConfig{
					MinSessionMinutes: 30, KeyCustody: "auto", MemoryImages: "avoid",
					CheckpointMinutes: 5, MaxRunMinutes: 60, DailyBoxMinutes: 240,
					DiffAgainst: HostedDiffAgainstBaseline,
					GuardHooks:  "auto",
					// SBXD-5: the clone location is decided per launch.
					CloneWhere: "auto",
					// SBXD-8: a folder that is not a repository uploads.
					UploadNonGit: true,
				},

				// SBXD-2: a returned, clean copy goes after 30 days.
				ReturnedCopyRetentionDays: 30,
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
		// CodeIntel (the in-process code-intelligence module) is OPT-IN
		// (D-307): indexing is read-only on the repo and costs no LLM
		// tokens, but it is CPU and disk heavy, so it runs only once the
		// user turns it on. The non-zero defaults below only decide HOW it
		// behaves after that. The only model-visible change
		// (compression.code_aggressive) stays OFF even then. Same
		// partial-merge rule as CacheTrack.
		CodeIntel: CodeIntelConfig{
			Enabled:        false,
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
		// MCPRelay is default OFF (byte-identical); the non-zero defaults
		// only decide HOW it behaves once a node opts in.
		MCPRelay: MCPRelayConfig{
			Enabled:             false,
			Mode:                MCPRelayModeStdioWrapper,
			AuditMode:           MCPRelayAuditAsync,
			PollIntervalSeconds: DefaultMCPRelayPollIntervalSeconds,
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
			// Node-local Plane A content storage is on by default
			// (D8/D17): node-local data never leaves the machine.
			StoreContent: true,
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
			// Budget.FromOrg is ON by default (operator decision
			// 2026-09-20) so an enrolled node applies its org's
			// pricing/budget by default — the node-side companion to
			// the default-on pricing feed. The composition stays
			// lowering-only on an individual node (see the FromOrg
			// field comment); the numeric caps stay zero (unset). A
			// node opts OUT with `[guard.budget] from_org = false`.
			Budget: GuardBudgetConfig{FromOrg: true},
			Rules: GuardRulesConfig{
				UserPolicy:        "~/.observer/guard-policy.toml",
				ProjectPolicy:     ".observer/guard-policy.toml",
				TrustedProjectDir: "~/.observer/guard-project-policies",
				OrgBundle:         "~/.observer/org-policy-bundle.json",
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
				// The shipped per-detector set (certain PII asks once,
				// a GitHub token blocks, email and phone numbers off) is
				// owned by orgcontract so the org server judges a
				// managed node's detector modes against the SAME
				// defaults (T-864 gap 3).
				Detectors: orgcontract.LocalGuardDefaultDetectorModes(),
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
			// OpenCodeZenLane: OpenCode's built-in "opencode" provider
			// (OpenCode Zen, e.g. the free big-pickle model) talks to
			// opencode.ai/zen, not to OPENAI_BASE_URL, so before this lane
			// existed a Zen session bypassed the proxy entirely: no
			// accurate tokens and no prompt-lane intervention (demo node 1,
			// 2026-10-02). `observer opencode` points that provider here.
			AgentUpstreams:  map[string]string{OpenCodeZenLane: "https://opencode.ai/zen"},
			ClientTokenFile: DefaultProxyClientTokenFile,
			AppLanes:        ProxyAppLanesConfig{Budget: AppLaneBudgetEnforce, IncludeUsage: true},
		},
		Compression: CompressionConfig{
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
			Pricing: PricingConfig{Models: map[string]ModelPricing{}},
			Scoring: IntelligenceScoringConfig{
				Auto:            true,
				IntervalMinutes: 5,
				IdleMinutes:     30,
				MaxPerPass:      200,
			},
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
	// NoGlobal reads no global file at all (GlobalPath is ignored): the
	// defaults, the project file and the environment, exactly what Load
	// gives for a global file that does not exist. A hook whose explicit
	// --config cannot be read runs on this outside enforcement (FU-185).
	NoGlobal bool
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
	if globalPath == "" && !opts.NoGlobal {
		home, err := os.UserHomeDir()
		if err == nil {
			globalPath = filepath.Join(home, ".observer", "config.toml")
		}
	}
	if opts.NoGlobal {
		globalPath = ""
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

	// Corpus-archival P4: [codeintel] keys that were removed outright rather
	// than renamed. Nothing to map — the warning IS the migration.
	for _, w := range migrateRemovedCodeIntelKeys(&cfg, metas) {
		emitDeprecationOnce(w)
	}

	// R-183: a "~" path expands from the real home or the load is refused
	// (home_unresolved), never used as a relative "~" folder.
	if err := expandHomePaths(&cfg); err != nil {
		return Config{}, GovernanceOutcome{}, err
	}

	// D-514: a setting this build cannot honour yet is switched off here,
	// with one reason, instead of failing Validate (deferred.go).
	cfg.Deferred = deferUnsupported(&cfg)

	// A section an inactive (or compiled-out) optional component owns is not
	// validated: a bad value there is set aside with one line instead of
	// failing Load (component_sections.go).
	cfg.Inert = setAsideInactiveSections(&cfg)

	// T-875: the [guard] switches the developer set, before a governance pin
	// replaces any of them. Reporting only (the guard floor's Local
	// snapshot); nothing that enforces reads it.
	ownGuard := ownGuardSwitchesOf(cfg.Guard, metas, opts.Env)
	cfg.TerminalLaunchSet = terminalLaunchKeysOf(metas, opts.Env)

	// Governance overlay — the LAST merge step (§1.3). Everything above is
	// the ungoverned config; the overlay is applied to a COPY so a
	// Validate failure can fall back to it without re-parsing.
	now := time.Now
	if opts.GovernanceNow != nil {
		now = opts.GovernanceNow
	}
	at := now()
	// T-839 / T-844 / T-845: the daemon's MAC'd org lock, read once here and
	// shared by the governance read (its verified sidecar copy) and the
	// managed-node guard floor (finishGuardFloor, the last step on every
	// return path below).
	lock := loadOrgLockFor(globalPath, opts.GovernanceSidecar)
	file, gout, exceptionsRaw := readGovernanceSidecar(cfg, opts.GovernanceSidecar, at, lock)
	if file == nil {
		if err := Validate(cfg); err != nil {
			return Config{}, gout, err
		}
		finishGuardFloor(&cfg, lock, gout.Path, globalPath, ownGuard)
		return cfg, gout, nil
	}
	governed := cfg
	// Request-grants G8: a feature-access exception lifts its pin (the
	// node's own value stands) until its own instant. Exceptions live in
	// their OWN file beside the sidecar, bound to this posture's hash, so
	// the sidecar body stays readable by released builds.
	pinned, excepted := governancePinsInForce(file, gout.Path, at, exceptionsRaw)
	gout.Excepted = excepted
	gout.PinsInForce = pinned
	applyGovernancePins(&governed, pinned, &gout)
	governed.TerminalLaunchSet = governed.TerminalLaunchSet.withPinned(gout.Applied)
	governed.Deferred = append(append([]string(nil), governed.Deferred...), deferUnsupported(&governed)...)
	governed.Inert = append(append([]string(nil), governed.Inert...), setAsideInactiveSections(&governed)...)
	if err := Validate(governed); err != nil {
		// Review B4: a well-formed, correctly-typed pinned value that
		// Validate rejects must NEVER make Load fail. Six of the nine
		// hook.go config.Load sites return before db.Open, so the fleet
		// would lose ingest and the developer would see a stderr line on
		// every tool call. Discard the WHOLE overlay, record why, and
		// return the ungoverned config.
		gout.Discarded, gout.DiscardErr = true, err.Error()
		gout.Applied = nil
		gout.PinsInForce = nil
		if verr := Validate(cfg); verr != nil {
			return Config{}, gout, verr
		}
		finishGuardFloor(&cfg, lock, gout.Path, globalPath, ownGuard)
		return cfg, gout, nil
	}
	finishGuardFloor(&governed, lock, gout.Path, globalPath, ownGuard)
	governed.Terminal.Sandbox.ProviderDirectInForce = sandboxProviderDirectInForce(governed, gout)
	return governed, gout, nil
}

// deprecationEmit guards one-per-process printing of config deprecation
// lines. config.Load runs in ~20 short- and long-lived call sites during a
// single `observer start` (proxy, watcher, dashboard, every feature
// goroutine, hooks auto-register) — each re-parses the same file and,
// pre-dedup, re-printed the identical block of deprecation lines, drowning
// the `dashboard → http://…` readiness banner. The dedup suppresses only
// the repeated PRINTING; the key checks (migrateRemovedCodeIntelKeys)
// still run on every Load, and the FIRST occurrence of each distinct
// message is always shown.
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
		fmt.Fprintln(os.Stderr, "config: deprecation: the keys above are deprecated aliases still honored this run - "+
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

// ReadError is a config file that exists but could not be read (permission
// denied, an I/O error). It carries the path, so a launcher whose own errors
// are silenced can still say which file it could not read (Linux live check
// 2026-10-23, LIN-1 F3: a sandboxed launcher denied its config.toml exited 1
// with no message). Its message is the loader's usual one.
type ReadError struct {
	Path string
	Err  error
}

// Error is the loader's message for the failed read.
func (e *ReadError) Error() string { return fmt.Sprintf("config.Load: read %s: %v", e.Path, e.Err) }

// Unwrap returns the underlying error.
func (e *ReadError) Unwrap() error { return e.Err }

func mergeTOMLFile(cfg *Config, path string) (toml.MetaData, error) {
	if path == "" {
		return toml.MetaData{}, nil
	}
	body, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return toml.MetaData{}, nil
	}
	if err != nil {
		return toml.MetaData{}, &ReadError{Path: path, Err: err}
	}
	// An older plan-branch string form of index_download still loads
	// (security_indexdownload_legacy.go).
	meta, err := toml.Decode(string(normalizeLegacyIndexDownload(body)), cfg)
	if err != nil {
		return toml.MetaData{}, fmt.Errorf("config.Load: parse %s: %w", path, err)
	}
	return meta, nil
}

// migrateRemovedCodeIntelKeys reports [codeintel] keys that have been REMOVED
// outright — no replacement key to map onto, so there is nothing to migrate,
// only something to say. Its contract: a config still carrying the key LOADS
// FINE (BurntSushi ignores keys with no struct field), so the only
// consequence is the warning below.
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
				"projects to cold storage instead of deleting them")
	}
	return warnings
}

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
		switch strings.ToLower(strings.TrimSpace(jc.RequestProfile)) {
		case "", "auto", "chat", "reasoning":
		default:
			return fmt.Errorf("config: observability judge request_profile %q not in {auto, chat, reasoning}", jc.RequestProfile)
		}
		if jc.UseOrgRelay && (jc.BaseURL != "" || jc.APIKeyEnv != "") {
			return errors.New("config: observability judge use_org_relay=true is ambiguous with base_url/api_key_env set on the same block - the relay ignores both")
		}
	}
	// The cross-block rule (hosted AI gateway plan, lane L6): the admission
	// judge is [observability.admission.judge] laid over [observability.judge]
	// (judgeclient.ResolveConfig), and use_org_relay is OR'ed across the two,
	// with the relay checked first. A relay set on the shared block therefore
	// reaches admission too and silently overrides a base_url / api_key_env
	// the admission block names for itself: an error. The reverse (the relay
	// on the admission block, an endpoint on the shared block for evals) is
	// coherent, admission to the org and evals to the endpoint, and validates.
	if shared, adm := cfg.Observability.Judge, cfg.Observability.Admission.Judge; shared.UseOrgRelay && (adm.BaseURL != "" || adm.APIKeyEnv != "") {
		return errors.New("config: observability.judge.use_org_relay=true also sends the admission judge through the org relay, so observability.admission.judge base_url/api_key_env would be ignored - set use_org_relay only on the block that should use the org's judge")
	}
	switch strings.TrimSpace(cfg.Observability.Admission.OnJudgeError) {
	case "", "fail_open", "fail_closed":
	default:
		return fmt.Errorf("config: observability.admission.on_judge_error %q not in {fail_open, fail_closed}", cfg.Observability.Admission.OnJudgeError)
	}
	if cfg.Observability.Admission.JudgeRetries < 0 {
		return errors.New("config: observability.admission.judge_retries must be >= 0")
	}
	// [observability.sdk] (D18) is validated here so Validate's own ladder
	// stays the same length.
	return validateObservabilitySDK(cfg.Observability.SDK)
}

// Validate checks semantic constraints on cfg.
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
	if err := validateMCPRelay(cfg.MCPRelay); err != nil {
		return err
	}
	// Sections an optional component owns (component_sections.go). Validate
	// is strict: it checks every one, whatever the component state, so a
	// save path never writes a bad value. Load is the component-aware side:
	// it sets aside a bad section of an inactive component before this runs.
	return validateComponentSections(&cfg)
}

// validateMCPRelay checks the [mcp_relay] block: closed mode / audit_mode
// vocabularies, an https gateway URL, a LOOPBACK-only listen address and a
// bounded reconcile cadence. Every check runs regardless of Enabled so a
// typo is caught before the node opts in, never at the moment it does.
func validateMCPRelay(m MCPRelayConfig) error {
	switch m.Mode {
	case "", MCPRelayModeStdioWrapper, MCPRelayModeIPC, MCPRelayModeLoopback:
	default:
		return fmt.Errorf("config: mcp_relay.mode %q must be one of stdio_wrapper, ipc, loopback", m.Mode)
	}
	switch m.AuditMode {
	case "", MCPRelayAuditAsync, MCPRelayAuditStrict:
	default:
		return fmt.Errorf("config: mcp_relay.audit_mode %q must be async or strict", m.AuditMode)
	}
	if u := strings.TrimSpace(m.GatewayURL); u != "" && !strings.HasPrefix(u, "https://") {
		return fmt.Errorf("config: mcp_relay.gateway_url %q must be an https:// URL", m.GatewayURL)
	}
	if addr := strings.TrimSpace(m.Listen); addr != "" {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return fmt.Errorf("config: mcp_relay.listen %q must be host:port: %w", addr, err)
		}
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return fmt.Errorf("config: mcp_relay.listen %q needs a port in 1-65535 (got %q)", addr, port)
		}
		if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return fmt.Errorf("config: mcp_relay.listen %q must be a loopback address (127.0.0.1, localhost or ::1) - the relay is never exposed beyond this machine", addr)
		}
	}
	if m.PollIntervalSeconds != 0 && (m.PollIntervalSeconds < 10 || m.PollIntervalSeconds > 3600) {
		return fmt.Errorf("config: mcp_relay.poll_interval_seconds %d out of range (10-3600)", m.PollIntervalSeconds)
	}
	return nil
}

// validateCloud checks the [cloud] block (D15). Both fields are optional —
// an absent/empty [cloud] section always passes (LoginPort's zero value
// means "unset", not "port 0"). When set, BaseURL must parse as an absolute
// http(s) URL and LoginPort must be a valid TCP port.
func validateCloud(c CloudConfig) error {
	if c.LoginPort < 0 || c.LoginPort > 65535 {
		return fmt.Errorf("config: cloud.login_port %d out of range (0-65535; 0 means unset - use the command's built-in default)", c.LoginPort)
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
	// tools.mcp_access (Agent Access P4, doc3 §6.2/§12.4): the signed MCP
	// grant family the node relay's local PDP compiles. Added in the same
	// spirit as the rows above — policyfam.FamilyMCPAccess shipped in P1/P2
	// and this copy lagged, which the sync test caught (the same drift class
	// gateway.providers taught us to gate).
	"tools.mcp_access": true,
	// node.components (modular packaging P4, lane MP-GOV): the managed
	// component-set family. Added in the SAME change as
	// policyfam.FamilyNodeComponents (policyfam_sync_test.go pins the two).
	"node.components": true,
	// security.scanning and terminals.isolation (roadmap F0-9/F0-10, lane
	// SHR-KIT): the security and sandbox modules' raise-only floor families.
	// Without them here the managed accept-list backfill's verified reload
	// would roll its write back (JSP-1 R4).
	"security.scanning":   true,
	"terminals.isolation": true,
}

// policyResourceFamilyList renders policyResourceSupportedFamilies, sorted,
// for the unsupported-family errors. Built from the map so a family can no
// longer be missing from the message (it omitted node.components until
// roadmap F0-10).
func policyResourceFamilyList() string {
	out := make([]string, 0, len(policyResourceSupportedFamilies))
	for f := range policyResourceSupportedFamilies {
		out = append(out, f)
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}

// validateOrgClientPolicy checks [org_client.policy]: every listed family
// must be one of the v1 closed set, and preauthorize_enforce must be a
// subset of accept_families (plan §6.4 — preauthorizing enforcement for a
// family the node doesn't even accept is a config mistake, not a valid
// "half-opted-in" state).
func validateOrgClientPolicy(p OrgClientPolicyConfig) error {
	accepted := make(map[string]bool, len(p.AcceptFamilies))
	for _, f := range p.AcceptedFamilies() {
		if !policyResourceSupportedFamilies[f] {
			return fmt.Errorf("config: org_client.policy.accept_families contains unsupported family %q (want one of %s)", f, policyResourceFamilyList())
		}
		accepted[f] = true
	}
	for _, f := range p.PreauthorizedFamilies() {
		if !policyResourceSupportedFamilies[f] {
			return fmt.Errorf("config: org_client.policy.preauthorize_enforce contains unsupported family %q (want one of %s)", f, policyResourceFamilyList())
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
	// [terminal.sandbox] belongs to the terminals.sandbox component and is
	// validated from the component section table (component_sections.go),
	// not here.
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
// It delegates every field rule to internal/sshspec - the single owner of
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

// maxReturnedCopyRetentionDays bounds returned_copy_retention_days (ten
// years, the bound an organization's pin of workspace_retention_days has).
const maxReturnedCopyRetentionDays = 3650

// validateTerminalSandbox checks semantic constraints on the [terminal.sandbox]
// block (B9). Not gated on Enabled, so a typo'd backend/home_mode is caught at
// load time even before an operator flips the master switch on. It is gated
// on the terminals.sandbox COMPONENT instead: it runs from the component
// section table (component_sections.go), so while that component is inactive
// or compiled out a bad block is set aside by Load, never a load failure.
func validateTerminalSandbox(c TerminalSandboxConfig) error {
	switch c.Backend {
	case "", "bwrap":
	default:
		// The key names the bwrap profile only; every other row is chosen
		// through backends, so the refusal names that key (LIN-1 F1).
		if sandboxvocab.ValidBackendID(c.Backend) {
			return fmt.Errorf("config: terminal.sandbox.backend %q not in {bwrap}: that key names the bwrap profile only; list %q in terminal.sandbox.backends instead (backends = [%q]) and name it per launch", c.Backend, c.Backend, c.Backend)
		}
		return fmt.Errorf("config: terminal.sandbox.backend %q not in {bwrap}: that key names the bwrap profile only; other backends are listed in terminal.sandbox.backends", c.Backend)
	}
	switch c.HomeMode {
	case "", "tmpfs", "readonly":
	default:
		return fmt.Errorf("config: terminal.sandbox.home_mode %q not in {tmpfs, readonly}", c.HomeMode)
	}
	if c.WorkspaceRetentionDays < 0 {
		return errors.New("config: terminal.sandbox.workspace_retention_days must be >= 0")
	}
	if c.ReturnedCopyRetentionDays < 0 || c.ReturnedCopyRetentionDays > maxReturnedCopyRetentionDays {
		return fmt.Errorf("config: terminal.sandbox.returned_copy_retention_days must be 0 (never remove a copy automatically) to %d", maxReturnedCopyRetentionDays)
	}
	if c.PrepTimeoutSeconds < 0 {
		return errors.New("config: terminal.sandbox.prep_timeout_seconds must be >= 0")
	}
	if err := validateSandboxChoices(c); err != nil {
		return err
	}
	switch c.Egress {
	case "", "host", "internet", "proxy_only", "none":
	default:
		return fmt.Errorf("config: terminal.sandbox.egress %q not in {host, internet, proxy_only, none}", c.Egress)
	}
	if _, err := sandboxcidr.ParseAllowCIDRs(c.EgressAllowCIDRs); err != nil {
		return fmt.Errorf("config: terminal.sandbox.egress_allow_cidrs: %w", err)
	}
	for _, h := range c.EgressAllowHosts {
		if !sandboxHostRuleRE.MatchString(h) || strings.HasPrefix(strings.TrimPrefix(h, "*."), "xn--") {
			return fmt.Errorf("config: terminal.sandbox.egress_allow_hosts entry %q is not a lowercase host name (or *.name) with at least two labels", h)
		}
	}
	if err := validateSandboxNameLists(c); err != nil {
		return err
	}
	if len(c.EgressAllowHosts) > 0 && c.Egress == "host" {
		return errors.New("config: terminal.sandbox.egress_allow_hosts needs a tier with the egress gateway; the host tier shares the host's network and cannot honour it")
	}
	seen := map[string]bool{}
	for _, b := range c.Backends {
		if !sandboxvocab.ValidBackendID(b) {
			return fmt.Errorf("config: terminal.sandbox.backends entry %q is not a backend id (lower-case letters, digits, dashes and underscores)", b)
		}
		if seen[b] {
			return fmt.Errorf("config: terminal.sandbox.backends lists %q twice", b)
		}
		seen[b] = true
	}
	if c.MinIsolation != "" {
		ok := false
		for _, v := range sandboxIsolationClasses {
			ok = ok || v == c.MinIsolation
		}
		if !ok {
			return fmt.Errorf("config: terminal.sandbox.min_isolation %q not in {process, container, userspace_kernel, hw_vm}", c.MinIsolation)
		}
	}
	if b := c.Readopt.BoundMinutes; b < 0 || b > 1440 {
		return fmt.Errorf("config: terminal.sandbox.readopt.bound_minutes %d must be 0 (the default) to 1440", b)
	}
	if m := c.Readopt.CheckpointCapMiB; m < 0 || m > 1<<20 {
		return fmt.Errorf("config: terminal.sandbox.readopt.checkpoint_cap_mib %d must be 0 (the default) to %d", m, 1<<20)
	}
	return nil
}

// sandboxChoice is one closed-choice [terminal.sandbox] key: its name under
// terminal.sandbox, the value set, and the allowed values ("" is always
// allowed: the default).
type sandboxChoice struct {
	key     string
	value   string
	allowed []string
}

// sandboxChoices is the table validateSandboxChoices walks, one row per
// closed-choice key.
func sandboxChoices(c TerminalSandboxConfig) []sandboxChoice {
	return []sandboxChoice{
		{"vendor_forced_native", c.VendorForcedNative, []string{"nest_or_refuse", "refuse"}},
		{"live_run_update_policy", c.LiveRunUpdatePolicy, []string{"defer", "ask_immediately"}},
		{"provider_direct", c.ProviderDirect, []string{string(sandboxvocab.ProviderDirectRefuseAll), string(sandboxvocab.ProviderDirectCaptureRule), string(sandboxvocab.ProviderDirectAllow)}},
		{"seatbelt.driver", c.Seatbelt.Driver, []string{"sandbox-exec", "mxc-exec-mac"}},
		{"windows.mxc_tier", c.Windows.MXCTier, []string{"process_container", "appcontainer"}},
	}
}

// validateSandboxChoices refuses a closed-choice key set to a value outside
// its set.
func validateSandboxChoices(c TerminalSandboxConfig) error {
	for _, ch := range sandboxChoices(c) {
		if ch.value == "" || slices.Contains(ch.allowed, ch.value) {
			continue
		}
		return fmt.Errorf("config: terminal.sandbox.%s %q not in {%s}", ch.key, ch.value, strings.Join(ch.allowed, ", "))
	}
	return nil
}

// validateTerminalSandboxOCI checks the [terminal.sandbox.oci] block. It
// runs from the component section table under terminals.sandbox.oci, so a
// bad block of an inactive driver is set aside, never a load failure.
func validateTerminalSandboxOCI(c TerminalSandboxOCIConfig) error {
	switch c.PodmanUserns {
	case "", "keep-id", "default":
	default:
		return fmt.Errorf("config: terminal.sandbox.oci.podman_userns %q not in {keep-id, default}", c.PodmanUserns)
	}
	if c.StopGraceSeconds < 0 || c.StopGraceSeconds > 600 {
		return errors.New("config: terminal.sandbox.oci.stop_grace_seconds must be 0 to 600")
	}
	if s := strings.TrimSpace(c.Socket); s != "" {
		p := strings.TrimPrefix(s, "unix://")
		if !strings.HasPrefix(p, "/") || filepath.Clean(p) != p {
			return fmt.Errorf("config: terminal.sandbox.oci.socket %q must be an absolute unix socket path (a TCP or SSH endpoint is never used)", c.Socket)
		}
	}
	if img := strings.TrimSpace(c.Image); img != "" && !sandboxImageDigestRE.MatchString(img) {
		return fmt.Errorf("config: terminal.sandbox.oci.image %q must be pinned by digest (name@sha256:<64 hex>)", c.Image)
	}
	switch c.InstallScripts {
	case "", "none", "pinned":
	default:
		return fmt.Errorf("config: terminal.sandbox.oci.install_scripts %q not in {none, pinned}", c.InstallScripts)
	}
	for _, t := range c.InstallScriptsTools {
		if !sandboxToolIDRE.MatchString(t) {
			return fmt.Errorf("config: terminal.sandbox.oci.install_scripts_tools entry %q is not a tool id", t)
		}
	}
	for i, p := range c.InstallScriptPins {
		switch {
		case !sandboxToolIDRE.MatchString(p.Tool):
			return fmt.Errorf("config: terminal.sandbox.oci.install_script_pins[%d].tool %q is not a tool id", i, p.Tool)
		case !sandboxInstallVersionRE.MatchString(p.Version):
			return fmt.Errorf("config: terminal.sandbox.oci.install_script_pins[%d].version %q is not a plain package version", i, p.Version)
		case !sandboxSHA256RE.MatchString(p.SHA256):
			return fmt.Errorf("config: terminal.sandbox.oci.install_script_pins[%d].sha256 must be 64 lowercase hex characters", i)
		case p.Added != "" && !sandboxDateRE.MatchString(p.Added):
			return fmt.Errorf("config: terminal.sandbox.oci.install_script_pins[%d].added %q is not YYYY-MM-DD", i, p.Added)
		case len(p.Packages) > sandboxPinMaxPackages:
			return fmt.Errorf("config: terminal.sandbox.oci.install_script_pins[%d].packages holds more than %d packages", i, sandboxPinMaxPackages)
		}
		for j, pk := range p.Packages {
			switch {
			case !sandboxPackageNameRE.MatchString(pk.Name):
				return fmt.Errorf("config: terminal.sandbox.oci.install_script_pins[%d].packages[%d].name %q is not a package name", i, j, pk.Name)
			case !sandboxInstallVersionRE.MatchString(pk.Version):
				return fmt.Errorf("config: terminal.sandbox.oci.install_script_pins[%d].packages[%d].version %q is not a plain package version", i, j, pk.Version)
			case !sandboxIntegrityRE.MatchString(pk.Integrity):
				return fmt.Errorf("config: terminal.sandbox.oci.install_script_pins[%d].packages[%d].integrity is not a registry sha512 value (sha512-<base64>)", i, j)
			}
		}
	}
	for t, v := range c.InstallVersions {
		if !sandboxToolIDRE.MatchString(t) || !sandboxInstallVersionRE.MatchString(v) {
			return fmt.Errorf("config: terminal.sandbox.oci.install_versions %q = %q: a tool id and a plain package version", t, v)
		}
	}
	return nil
}

// sandboxPinMaxPackages bounds one pin's package list (a main package and
// its platform packages; opencode and kilo ship 12 platform packages).
const sandboxPinMaxPackages = 64

// The shapes of the first-start install keys (lane LEFT-SBX): a registry
// tool id, a plain package version (the sandboxoci install pin rule), a
// sha256 and a date. config stays a leaf, so they are restated here; a
// cmd/observer test pins them to sandboxoci's.
var (
	sandboxToolIDRE         = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	sandboxInstallVersionRE = regexp.MustCompile(`^[0-9]{1,9}\.[0-9]{1,9}\.[0-9]{1,9}([-+][0-9A-Za-z][0-9A-Za-z.-]{0,40})?$`)
	sandboxSHA256RE         = regexp.MustCompile(`^[a-f0-9]{64}$`)
	sandboxDateRE           = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)
	// sandboxPackageNameRE and sandboxIntegrityRE restate sandboxoci's npm
	// package name and registry sha512 integrity rules (R-014).
	sandboxPackageNameRE = regexp.MustCompile(`^(@[a-z0-9][a-z0-9._-]{0,100}/)?[a-z0-9][a-z0-9._-]{0,100}$`)
	sandboxIntegrityRE   = regexp.MustCompile(`^sha512-[A-Za-z0-9+/]{86}==$`)
	// sandboxHostRuleRE is an egress host rule's shape (sandboxnet's
	// ParseHostRules is the full check, at launch).
	sandboxHostRuleRE = regexp.MustCompile(`^(\*\.)?[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)
	// sandboxSignInToolRE is a sign_in_seed_tools entry's shape (a registry
	// tool id; an unknown id is simply never matched at launch).
	sandboxSignInToolRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
)

// validateSandboxNameLists checks [terminal.sandbox]'s name lists:
// pass_env's variable names and sign_in_seed_tools' tool ids (lane
// BOXSIGNIN).
func validateSandboxNameLists(c TerminalSandboxConfig) error {
	for _, n := range c.PassEnv {
		if err := sandboxenv.ValidName(n); err != nil {
			return fmt.Errorf("config: terminal.sandbox.pass_env: %w", err)
		}
	}
	for _, tool := range c.SignInSeedTools {
		if !sandboxSignInToolRE.MatchString(tool) {
			return fmt.Errorf("config: terminal.sandbox.sign_in_seed_tools entry %q is not a tool id (lower-case letters, digits and dashes)", tool)
		}
	}
	return nil
}

// validateTerminalSandboxMXC checks the [terminal.sandbox.mxc] block. It
// runs from the component section table under terminals.sandbox.mxc, so a
// bad block of an inactive driver is set aside, never a load failure.
func validateTerminalSandboxMXC(c TerminalSandboxMXCConfig) error {
	if c.StopGraceSeconds < 0 || c.StopGraceSeconds > 600 {
		return errors.New("config: terminal.sandbox.mxc.stop_grace_seconds must be 0 to 600")
	}
	if c.ProbeTimeoutSeconds != 0 && (c.ProbeTimeoutSeconds < 5 || c.ProbeTimeoutSeconds > 300) {
		return errors.New("config: terminal.sandbox.mxc.probe_timeout_seconds must be 5 to 300")
	}
	return nil
}

// validateTerminalSandboxAppleContainer checks the
// [terminal.sandbox.apple_container] block. It runs from the component
// section table under terminals.sandbox.apple-container.
func validateTerminalSandboxAppleContainer(c TerminalSandboxAppleContainerConfig) error {
	if img := strings.TrimSpace(c.Image); img != "" && !sandboxImageDigestRE.MatchString(img) {
		return fmt.Errorf("config: terminal.sandbox.apple_container.image %q must be pinned by digest (name@sha256:<64 hex>)", c.Image)
	}
	if c.MemoryMiB != 0 && (c.MemoryMiB < 512 || c.MemoryMiB > 262144) {
		return errors.New("config: terminal.sandbox.apple_container.memory_mib must be 512 to 262144")
	}
	if c.CPUs != 0 && (c.CPUs < 1 || c.CPUs > 64) {
		return errors.New("config: terminal.sandbox.apple_container.cpus must be 1 to 64")
	}
	return nil
}

// vmImageSetRE is a guest image set id: its descriptor's version.
var vmImageSetRE = regexp.MustCompile(`^[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}$`)

// validateTerminalSandboxVM checks the [terminal.sandbox.vm] block (lane
// SBX-P4). It runs from the component section table under
// terminals.sandbox.vm, so a bad block of an inactive driver is set aside,
// never a load failure.
func validateTerminalSandboxVM(c TerminalSandboxVMConfig) error {
	if v := strings.TrimSpace(c.VMM); v != "" && v != "cloud-hypervisor" {
		return fmt.Errorf("config: terminal.sandbox.vm.vmm %q: only \"cloud-hypervisor\" is supported", c.VMM)
	}
	if c.ImageSet != "" && !vmImageSetRE.MatchString(c.ImageSet) {
		return fmt.Errorf("config: terminal.sandbox.vm.image_set %q must be a verified set's version (MAJOR.MINOR.PATCH) or empty for the newest, never a path", c.ImageSet)
	}
	if c.VCPUs != 0 && (c.VCPUs < 1 || c.VCPUs > 64) {
		return errors.New("config: terminal.sandbox.vm.vcpus must be 1 to 64")
	}
	if c.MemoryMB != 0 && (c.MemoryMB < 512 || c.MemoryMB > 262144) {
		return errors.New("config: terminal.sandbox.vm.memory_mb must be 512 to 262144")
	}
	switch c.WorkspaceDelivery {
	case "", "virtiofs", "disk_image":
	default:
		return fmt.Errorf("config: terminal.sandbox.vm.workspace_delivery %q must be virtiofs or disk_image", c.WorkspaceDelivery)
	}
	for _, kv := range []struct{ key, val string }{{"cloud_hypervisor_path", c.CloudHypervisorPath}, {"virtiofsd_path", c.VirtiofsdPath}} {
		if kv.val == "" {
			continue
		}
		if !filepath.IsAbs(kv.val) || filepath.Clean(kv.val) != kv.val {
			return fmt.Errorf("config: terminal.sandbox.vm.%s %q must be a clean absolute path", kv.key, kv.val)
		}
	}
	return nil
}

// landlockMinABIFloor mirrors internal/sandboxlandlock.MinABI (config stays
// a leaf; the mirror is pinned by a test in cmd/observer).
const landlockMinABIFloor = 9

// validateTerminalSandboxLandlock checks the [terminal.sandbox.landlock]
// block. It runs from the component section table under
// terminals.sandbox.landlock, so a bad block of an inactive driver is set
// aside, never a load failure.
func validateTerminalSandboxLandlock(c TerminalSandboxLandlockConfig) error {
	if c.MinABI != 0 && (c.MinABI < landlockMinABIFloor || c.MinABI > 64) {
		return fmt.Errorf("config: terminal.sandbox.landlock.min_abi must be %d to 64 (below ABI %d the daemon's sockets would be reachable from the box)", landlockMinABIFloor, landlockMinABIFloor)
	}
	return nil
}

// validateTerminalSandboxHosted checks the [terminal.sandbox.hosted]
// block (lane SBX-P7). It runs from the component section table under
// terminals.sandbox, so a bad block of an inactive module is set aside,
// never a load failure.
func validateTerminalSandboxHosted(c TerminalSandboxHostedConfig) error {
	// The floor is the shortest box a launch makes (sandboxremote
	// MinRunMinutes, 5), so max_run_minutes can go down to 5 (live run
	// 2026-10-23, finding F10: a floor of 15 kept it there).
	if c.MinSessionMinutes < 5 || c.MinSessionMinutes > 1440 {
		return errors.New("config: terminal.sandbox.hosted.min_session_minutes must be 5 to 1440")
	}
	if c.MaxRunMinutes < 5 || c.MaxRunMinutes > 1440 {
		return errors.New("config: terminal.sandbox.hosted.max_run_minutes must be 5 to 1440")
	}
	if c.MinSessionMinutes > c.MaxRunMinutes {
		return fmt.Errorf("config: terminal.sandbox.hosted.min_session_minutes (%d) must not exceed max_run_minutes (%d); lower min_session_minutes too", c.MinSessionMinutes, c.MaxRunMinutes)
	}
	if c.DailyBoxMinutes < 5 || c.DailyBoxMinutes > 10080 {
		return errors.New("config: terminal.sandbox.hosted.daily_box_minutes must be 5 to 10080")
	}
	if c.CheckpointMinutes < 1 || c.CheckpointMinutes > 60 {
		return errors.New("config: terminal.sandbox.hosted.checkpoint_minutes must be 1 to 60")
	}
	if err := validateHostedKeySources(c); err != nil {
		return err
	}
	if err := validateHostedEnums(c); err != nil {
		return err
	}
	if err := validateHostedUploadIgnore(c.UploadIgnore); err != nil {
		return err
	}
	for name, p := range map[string]TerminalSandboxHostedProviderConfig{"e2b": c.E2B, "modal": c.Modal, "vercel": c.Vercel, "docker": c.Docker, "instabox": c.InstaBox, "daytona": c.Daytona} {
		if r := p.Region; r != "" && !hostedRegionRE.MatchString(r) {
			return fmt.Errorf("config: terminal.sandbox.hosted.%s.region %q must be a region name (letters, digits and dashes)", name, r)
		}
		if tpl := p.Template; tpl != "" && !hostedTemplateRE.MatchString(tpl) {
			return fmt.Errorf("config: terminal.sandbox.hosted.%s.template %q must be a template, image or runtime name", name, tpl)
		}
		if b := strings.TrimSpace(p.BoxBinary); b != "" && (!filepath.IsAbs(b) || filepath.Clean(b) != b) {
			return fmt.Errorf("config: terminal.sandbox.hosted.%s.box_binary %q must be an absolute, clean path", name, p.BoxBinary)
		}
		if (p.Endpoint != "" || p.EndpointSPKISHA256 != "") && name != "e2b" {
			return fmt.Errorf("config: terminal.sandbox.hosted.%s.endpoint is E2B only", name)
		}
		if e := p.Endpoint; e != "" && !hostedEndpointRE.MatchString(e) {
			return fmt.Errorf("config: terminal.sandbox.hosted.%s.endpoint %q must be an https origin (scheme, host and an optional port)", name, e)
		}
		if k := p.EndpointSPKISHA256; k != "" && !hostedSPKIRE.MatchString(k) {
			return fmt.Errorf("config: terminal.sandbox.hosted.%s.endpoint_spki_sha256 must be 64 lowercase hex characters", name)
		}
		if p.AllowPrivateRanges != nil && !slices.Contains(HostedPrivateRangeDenyProviders, name) {
			return fmt.Errorf("config: terminal.sandbox.hosted.%s.allow_private_ranges has no effect: this vendor's API takes no rule that would refuse private ranges, so its box can reach them whatever the setting says; remove the key", name)
		}
	}
	return nil
}

// The values of [terminal.sandbox.hosted].diff_against ("" means baseline).
const (
	// HostedDiffAgainstBaseline diffs an upload run against the box's
	// observer-baseline commit (the default).
	HostedDiffAgainstBaseline = "baseline"
	// HostedDiffAgainstHead diffs it against the box's HEAD (the earlier
	// capture).
	HostedDiffAgainstHead = "head"
)

// hostedEnumKeys are the closed-vocabulary keys of [terminal.sandbox.hosted],
// one row each: the key, its value,
// and the values it takes ("" where the empty value means the default).
func hostedEnumKeys(c TerminalSandboxHostedConfig) []struct {
	key, value string
	allowed    []string
} {
	return []struct {
		key, value string
		allowed    []string
	}{
		{"key_custody", c.KeyCustody, []string{"auto", "home_relay", "in_box_api_key", "in_box_oauth_seed", "provider_injected"}},
		{"memory_images", c.MemoryImages, []string{"avoid", "refuse"}},
		{"diff_against", c.DiffAgainst, []string{"", HostedDiffAgainstBaseline, HostedDiffAgainstHead}},
		{"guard_hooks", c.GuardHooks, []string{"", "auto", "on", "off"}},
		// SBXD-5: the clone location (internal/workspace CloneWhere's
		// vocabulary); an older file that names none gets the default, auto.
		{"clone_where", c.CloneWhere, []string{"auto", "box", "home"}},
	}
}

// validateHostedEnums walks hostedEnumKeys.
func validateHostedEnums(c TerminalSandboxHostedConfig) error {
	for _, k := range hostedEnumKeys(c) {
		if !slices.Contains(k.allowed, k.value) {
			named := make([]string, 0, len(k.allowed))
			for _, a := range k.allowed {
				if a != "" {
					named = append(named, a)
				}
			}
			return fmt.Errorf("config: terminal.sandbox.hosted.%s %q not in {%s}", k.key, k.value, strings.Join(named, ", "))
		}
	}
	return nil
}

// hostedUploadIgnoreMax and hostedUploadIgnoreLen bound
// [terminal.sandbox.hosted].upload_ignore.
const (
	hostedUploadIgnoreMax = 200
	hostedUploadIgnoreLen = 256
)

// validateHostedUploadIgnore checks the extra ignore patterns of a hosted
// upload of a folder that is not a repository (SBXD-8): each a non-empty,
// one-line gitignore pattern that is not a comment and not a bare "!" or
// "/" (which would mean nothing or the whole folder).
func validateHostedUploadIgnore(list []string) error {
	if len(list) > hostedUploadIgnoreMax {
		return fmt.Errorf("config: terminal.sandbox.hosted.upload_ignore holds %d patterns; at most %d", len(list), hostedUploadIgnoreMax)
	}
	for _, p := range list {
		t := strings.TrimSpace(p)
		switch {
		case t == "":
			return errors.New("config: terminal.sandbox.hosted.upload_ignore holds an empty pattern")
		case len(t) > hostedUploadIgnoreLen:
			return fmt.Errorf("config: terminal.sandbox.hosted.upload_ignore pattern %.40q... is over %d characters", t, hostedUploadIgnoreLen)
		case strings.ContainsFunc(t, func(r rune) bool { return r < 0x20 || r == 0x7f }):
			return fmt.Errorf("config: terminal.sandbox.hosted.upload_ignore pattern %q holds a line break or control character", t)
		case strings.HasPrefix(t, "#"):
			return fmt.Errorf("config: terminal.sandbox.hosted.upload_ignore pattern %q is a comment; write \\# for a name that starts with #", t)
		case t == "!" || t == "/" || t == "!/":
			return fmt.Errorf("config: terminal.sandbox.hosted.upload_ignore pattern %q names nothing", t)
		}
	}
	return nil
}

// hostedRegionRE and hostedTemplateRE bound the per-provider values.
var (
	hostedRegionRE   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	hostedTemplateRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/:@-]{0,255}$`)
	// hostedEndpointRE is an https origin: a lower-case host and an
	// optional port, nothing after it but an optional "/".
	hostedEndpointRE = regexp.MustCompile(`^https://[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?(:[0-9]{1,5})?/?$`)
	hostedSPKIRE     = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

// sandboxImageDigestRE mirrors internal/sandboxoci's digest rule (config
// stays a leaf; the mirror is pinned by a test in cmd/observer).
var sandboxImageDigestRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._/:-]*@sha256:[a-f0-9]{64}$`)

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
			return fmt.Errorf("config: remote.mode %q is deferred (Phase 3, operator decision 2026-07-12 - tailnet-HTTPS-only for v1); use \"tailscale\"", c.Mode)
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
			return fmt.Errorf("config: remote.session_idle_minutes %d exceeds remote.session_ttl_minutes %d - the absolute cap would expire the session first, making the idle window unreachable", idle, ttl)
		}
		if c.Enabled && len(c.TrustedHosts) == 0 && strings.EqualFold(strings.TrimSpace(c.Mode), "tailscale") {
			return errors.New("config: remote.trusted_hosts must name the tailnet host (the Host the browser sends) when remote.mode = \"tailscale\" - `observer remote enable --tailscale` populates it")
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
	if _, err := updatespec.ParseWindow(u.Window); err != nil {
		return fmt.Errorf("config: update.window: %w", err)
	}
	if u.Channel != "" && !updatespec.KnownChannel(updatespec.Channel(u.Channel)) {
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
		return fmt.Errorf("config: dashboard.addr %q port %d out of range (1-65535)", addr, n)
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
		return errors.New("config: remote.tailscale_backend_addr is required when remote.mode = \"tailscale\" (a loopback IP:port for `tailscale serve` to forward to) - `observer remote enable --tailscale` pins one")
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
		return fmt.Errorf("config: remote.tailscale_backend_addr host %q must be an explicit loopback IP (127.0.0.1 / ::1) - the tailnet-serve backend is loopback-only (plan §4.4)", host)
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
	if err := alertspec.ValidSlackWebhookURL(a.SlackWebhookURL); err != nil {
		return fmt.Errorf("config: observability.alerts.slack_webhook_url: %w", err)
	}
	if err := alertspec.ValidPagerDutyRoutingKey(a.PagerDutyRoutingKey); err != nil {
		return fmt.Errorf("config: observability.alerts.pagerduty_routing_key: %w", err)
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
		if err := (alertspec.Dimensions{Model: r.Model, User: r.User, Tag: r.Tag, Service: r.Service}).Validate(); err != nil {
			return fmt.Errorf("config: observability.alerts.rules[%d]: %w", i, err)
		}
	}
	return nil
}

// OpenCodeZenLane is the default [proxy.agent_upstreams] lane id for
// OpenCode's built-in Zen provider (see Default()).
const OpenCodeZenLane = "opencode-zen"

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
	// The lanes' hardening ([proxy.app_lanes]) is checked with the lanes.
	return validateProxyAppLanes(p.AppLanes)
}

// validateProxyAppLanes enforces [proxy.app_lanes]' shape: a known budget
// mode, a non-negative output ceiling, and model patterns that are non-empty
// and carry no whitespace (a typo there would silently refuse every call).
func validateProxyAppLanes(a ProxyAppLanesConfig) error {
	switch a.Budget {
	case "", AppLaneBudgetEnforce, AppLaneBudgetObserve, AppLaneBudgetOff:
	default:
		return fmt.Errorf(`config: proxy.app_lanes.budget %q must be "enforce", "observe" or "off"`, a.Budget)
	}
	if a.WorstCaseOutputTokens < 0 {
		return errors.New("config: proxy.app_lanes.worst_case_output_tokens must be >= 0")
	}
	for lane, pats := range a.Models {
		if strings.TrimSpace(lane) == "" {
			return errors.New("config: proxy.app_lanes.models has an empty lane id")
		}
		for _, pat := range pats {
			if pat == "" || strings.ContainsAny(pat, " \t\r\n") {
				return fmt.Errorf("config: proxy.app_lanes.models.%s has an empty or space-bearing pattern %q", lane, pat)
			}
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

// maxEvasionWindowSeconds bounds [guard.rules].evasion_window_seconds
// (one hour): the A-613 tracker keeps that much history per session.
const maxEvasionWindowSeconds = 3600

// guardLevelNameRx is the shape of a [guard] level value: a recipe name
// (internal/guardrecipe.NameRx carries the same pattern for recipe files).
var guardLevelNameRx = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

// validGuardHostPattern checks one [guard.network] host pattern's shape: a
// host name (optionally "*." or "*"-prefixed), an IP address or a CIDR
// block. The network rules own the matching and tolerate surrounding space,
// a scheme and path, a :port, brackets and a trailing dot, so this refuses
// only a value no rule could ever honour (guardHostPatternProblem): a
// stricter check would fail config.Load, and with it the daemon, on upgrade.
func validGuardHostPattern(h string) error {
	if why := guardHostPatternProblem(h); why != "" {
		return fmt.Errorf("host pattern %q %s", h, why)
	}
	return nil
}

func validateGuard(g GuardConfig) error {
	// The keys guard recipes write or read are refused even while the
	// guard is off: a recipe apply or a later enable would otherwise meet
	// them first (sweep finding CFG-5).
	if err := validateGuardRecipeInputs(g); err != nil {
		return err
	}
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
	if g.Rules.EvasionWindowSeconds < 0 || g.Rules.EvasionWindowSeconds > maxEvasionWindowSeconds {
		return fmt.Errorf("config: guard.rules.evasion_window_seconds %d must be in [0, %d]", g.Rules.EvasionWindowSeconds, maxEvasionWindowSeconds)
	}
	if g.Rules.CEL {
		return errors.New("config: guard.rules.cel is not yet supported (CEL user rules are deferred - matchers v1)")
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

// validateGuardRecipeInputs validates the keys guard recipes write or read:
// [guard] level (a recipe name), [guard.database] prod_patterns (no empty
// pattern, no credential) and the [guard.network] host lists (a host, an IP
// or a CIDR). validateGuard runs it whether or not the guard is enabled.
func validateGuardRecipeInputs(g GuardConfig) error {
	if g.Level != "" && !guardLevelNameRx.MatchString(g.Level) {
		return fmt.Errorf("config: guard.level %q is not a recipe name (lowercase letters, digits and dashes)", g.Level)
	}
	for i, p := range g.Database.ProdPatterns {
		if strings.TrimSpace(p) == "" {
			return errors.New("config: guard.database.prod_patterns has an empty pattern")
		}
		if guardProdPatternHasCredential(p) {
			// The value is not repeated: it holds the credential.
			return fmt.Errorf("config: guard.database.prod_patterns entry %d carries a credential (a user:password@ or a password= part): name the host, database or profile without it; config.toml keeps the value in plain text", i+1)
		}
	}
	for key, hosts := range map[string][]string{"allow_hosts": g.Network.AllowHosts, "deny_hosts": g.Network.DenyHosts} {
		for _, h := range hosts {
			if err := validGuardHostPattern(h); err != nil {
				return fmt.Errorf("config: guard.network.%s: %w", key, err)
			}
		}
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
