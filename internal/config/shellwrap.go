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
// a shell start-up file on its own.
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
}
