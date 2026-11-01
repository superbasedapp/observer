package config

// ShellWrapConfig is the [shell_wrap] block — the "wrapped command" shell
// integration (backlog item 7, docs/proxy-wrappers.md "Command wrapping"):
// shims that make typing `claude` run `observer claude`, put first on PATH by
// a marked block in each selected shell's start-up file.
//
// OPT-IN and LOCAL-ONLY: the zero value (enabled = false, nothing selected)
// writes nothing, and the block is never distributed to an org. The keys are
// the operator's RECORDED choice; the files are written only by `observer
// shell-wrap enable|disable` or the Settings → Terminal "Command wrapping"
// card (POST /api/shell-wrap/apply), which write this block and the files
// together. Editing the keys by hand changes nothing until one of those runs
// (`observer shell-wrap status` reports the drift). The daemon never touches
// a shell start-up file on its own, with one exception (surface-gap CLI-1b,
// operator decision D6): on a MANAGED node whose organization pinned
// shell_wrap.org_maintain, the daemon applies (ON) or removes (OFF) the
// native target's wrap through the same applier, and records OrgApplied.
type ShellWrapConfig struct {
	// Enabled records that the wrap is applied. Default false.
	Enabled bool `toml:"enabled"`
	// Tools maps a registry tool key or IDE launch id (e.g. "claude-code",
	// "codex", "vscode") to whether its command is wrapped. A false entry
	// keeps a deselected row visible in the file; a missing entry is "not
	// selected". IDE / desktop-app rows are only ever explicit choices.
	Tools map[string]bool `toml:"tools"`
	// Shells maps a shell ("bash", "zsh", "fish", "powershell") to whether
	// its start-up file is managed. Empty = auto-detect the shells in use.
	// An unknown shell name is ignored (never a load error), the same
	// fail-soft rule as an unknown tool id.
	Shells map[string]bool `toml:"shells"`
	// ShimDir overrides the shim directory. Empty (default) =
	// ~/.observer/shims.
	ShimDir string `toml:"shim_dir"`
	// Windows is the recorded choice for the WSL bridge target (T-419):
	// Windows shells on the machine whose WSL distro runs this daemon. Same
	// keys, same opt-in rule; only meaningful when the daemon runs inside
	// WSL. Zero value = off.
	Windows ShellWrapTargetConfig `toml:"windows"`
	// OrgMaintain is the org-pinned managed command-wrapping switch
	// (node.governance key shell_wrap.org_maintain, CLI-1b). It exists so
	// the pin resolves in this build's config; the daemon reads the pinned
	// value live from the governance posture
	// (govern.Effective.ShellWrapPosture) and never reads this local value,
	// which an individual node has no use for.
	OrgMaintain bool `toml:"org_maintain"`
	// OrgApplied records that the native target's wrap was applied by the
	// managed daemon for the organization (written by the applier with the
	// choice; cleared when the developer applies or disables it themselves).
	// Only a wrap with OrgApplied set is removed when the organization turns
	// managed wrapping off: a wrap the developer applied is theirs.
	OrgApplied bool `toml:"org_applied"`
}

// ShellWrapTargetConfig is one shell-wrap target's recorded choice. The
// native target's keys live directly in [shell_wrap] (ShellWrapConfig.Native);
// the WSL bridge target's in [shell_wrap.windows].
type ShellWrapTargetConfig struct {
	// Enabled records that the wrap is applied on this target.
	Enabled bool `toml:"enabled"`
	// Tools maps a registry tool key or IDE launch id to whether its command
	// is wrapped on this target.
	Tools map[string]bool `toml:"tools"`
	// Shells maps a shell name to whether its start-up file is managed.
	// Empty = auto-detect.
	Shells map[string]bool `toml:"shells"`
	// ShimDir overrides this target's shim directory (in the target OS's own
	// path notation). Empty = <home>/.observer/shims on that target.
	ShimDir string `toml:"shim_dir"`
}

// Native returns the native target's recorded choice as a target view.
func (c ShellWrapConfig) Native() ShellWrapTargetConfig {
	return ShellWrapTargetConfig{Enabled: c.Enabled, Tools: c.Tools, Shells: c.Shells, ShimDir: c.ShimDir}
}

// SetNative writes a native-target view back into [shell_wrap].
func (c *ShellWrapConfig) SetNative(v ShellWrapTargetConfig) {
	c.Enabled, c.Tools, c.Shells, c.ShimDir = v.Enabled, v.Tools, v.Shells, v.ShimDir
}
