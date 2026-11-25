package config

// This file holds the config types of [launch].

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

	// StartDaemon has a launcher that finds the Observer daemon down start
	// it, wait for its proxy, and then launch routed exactly as when the
	// daemon was up (operator ruling L-169). It starts the daemon this
	// install owns: its systemd user unit or launchd agent when one is
	// installed for this config, else `observer start` in the background
	// with its output in daemon.log beside the database. Default true. Set
	// false (or pass --no-start to one launch) to get the earlier behaviour:
	// a proxy-down launch goes direct with a notice, or refuses on a
	// managed machine whose organization owns the routes. A launch never
	// starts a daemon from inside a daemon-owned terminal or a sandbox, nor
	// when this machine's daemon runs in another OS context (WSL seen from
	// Windows). LOCAL-ONLY.
	StartDaemon bool `toml:"start_daemon"`

	// StartDaemonWaitSeconds bounds how long a launcher waits for the
	// daemon it started (or found starting) to answer on the proxy port
	// before the proxy-down fallback decides. Zero or negative means the
	// default, 30.
	StartDaemonWaitSeconds int `toml:"start_daemon_wait_seconds"`
}

// DefaultStartDaemonWaitSeconds is the default bound on a launcher's wait
// for the daemon it starts.
const DefaultStartDaemonWaitSeconds = 30

// LaunchToolConfig is one [launch.tools.<tool>] entry.
type LaunchToolConfig struct {
	// Path is an absolute path to the tool's binary. When set (and it stat-
	// checks as a file), the launcher uses it verbatim, bypassing resolution.
	// It wins over the toolresolve ladder and loses to the `--<tool>-path`
	// flag. Empty = resolve normally.
	Path string `toml:"path"`
}
