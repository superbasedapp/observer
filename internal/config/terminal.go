package config

import "github.com/marmutapp/superbased-observer/internal/sshspec"

// This file holds the config types of [terminal] (except
// [terminal.sandbox]).

// TerminalConfig is the [terminal] surface — the embedded web-terminal
// cockpit (docs/plans/terminal-product-exploitation-plan-2026-07-12.md §8).
// LOCAL-ONLY: it never appears in [org_client.share] and is never distributed
// to an org. Terminal-wide knobs live at the top; fresh-agent launch is a
// SEPARATE, default-OFF opt-in under [terminal.launch] — it EXPANDS execution
// authority, so (unlike a plain key rename) it is never migrated
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
	// side. 0 (the default) means sshspec.DefaultReverseProxyPort
	// (8820). The LOCAL side is always this machine's own Observer proxy
	// port and is not configurable here — see
	// sshspec.DefaultObserverProxyPort.
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

// TerminalStatusConfig is the [terminal.status] block — agent-status
// detection (plan §8/F4). Default-on. Per-tool prompt patterns are shipped
// data, not config.
type TerminalStatusConfig struct {
	// Enabled gates the status classifier + the status API/WS frame. Default
	// TRUE (seeded by Default()).
	Enabled bool `toml:"enabled"`
}

// SSHProfile converts one config entry into the pure-package Profile the
// validator and argv composer operate on. It is the ONE translation point
// between the TOML shape and internal/sshspec (module-boundary rule #2), so
// a field added to the config block has exactly one place to be threaded.
func SSHProfile(p SSHProfileConfig) sshspec.Profile {
	return sshspec.Profile{
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
func SSHProfiles(c TerminalSSHConfig) []sshspec.Profile {
	if len(c.Profiles) == 0 {
		return nil
	}
	out := make([]sshspec.Profile, 0, len(c.Profiles))
	for _, p := range c.Profiles {
		out = append(out, SSHProfile(p))
	}
	return out
}

// SSHOptions maps the block's connection-tuning knobs onto the pure package's
// Options. A zero value resolves to the sshprofile defaults.
func SSHOptions(c TerminalSSHConfig) sshspec.Options {
	return sshspec.Options{
		ConnectTimeoutSeconds: c.ConnectTimeoutSeconds,
		KeepaliveSeconds:      c.KeepaliveSeconds,
	}
}
