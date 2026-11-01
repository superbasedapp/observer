package hook

import (
	"path/filepath"
)

// Config homes (surface-gap Wave 4, CC-8 and CX-4). The native Claude Code
// and Codex hook writers, the Claude Code status line writer and the install
// probe resolve their directory from an agentconfig FileRow artifact with
// Options.Getenv, so CLAUDE_CONFIG_DIR, CODEX_HOME and any rule added later
// to the row move every one of them together. NewRegistry fills a nil
// Getenv with the one pinned-home rule (crossmount.HomeEnv, R-188 F1), so a
// pinned or isolated home reads no variable. The cross-OS
// "-windows" targets keep the vendor default under the Windows home: the
// Windows side's environment is invisible from WSL.
//
// They resolve through the package's one artifact-path helper,
// Registry.artifactPath (register_homes.go, FU-74): a CLAUDE_CONFIG_DIR or
// CODEX_HOME holding a relative value (which the tool reads against its own
// working directory) is a refusal naming the variable, and nothing is
// written to ~/.claude or ~/.codex instead (FU-31, R-188 F6).
const (
	// claudeSettingsArtifact is ~/.claude/settings.json (hooks, statusLine).
	claudeSettingsArtifact = "claude-code/user-settings"
	// codexHooksArtifact is ~/.codex/hooks.json; its directory is the Codex
	// home that also holds the config.toml [features] switch and trust.
	codexHooksArtifact = "codex/user-hooks"
)

// claudeConfigDir is the native Claude Code config home (~/.claude, or
// where CLAUDE_CONFIG_DIR moves it), or the refusal for a relative
// CLAUDE_CONFIG_DIR.
func (r *Registry) claudeConfigDir() (string, error) {
	return r.artifactDir(claudeSettingsArtifact)
}

// codexHomeDir is the native Codex home (~/.codex, or where CODEX_HOME moves
// it), or the refusal for a relative CODEX_HOME.
func (r *Registry) codexHomeDir() (string, error) {
	return r.artifactDir(codexHooksArtifact)
}

// claudeInstalled is the Claude Code install probe (configHomeInstalled).
func (r *Registry) claudeInstalled() bool {
	return r.configHomeInstalled(r.claudeConfigDir, ".claude")
}

// codexInstalled is the Codex install probe (configHomeInstalled).
func (r *Registry) codexInstalled() bool {
	return r.configHomeInstalled(r.codexHomeDir, ".codex")
}

// configHomeInstalled is the install probe for a config home: the resolved
// directory exists, or, when the home's variable cannot be resolved, the
// vendor default does. The probe keeps the tool on the install list in that
// case so its writer runs and reports the refusal naming the variable,
// instead of the tool silently dropping out of registration.
func (r *Registry) configHomeInstalled(dir func() (string, error), def ...string) bool {
	if d, err := dir(); err == nil {
		return r.dirExists(d)
	}
	return r.dirExists(filepath.Join(append([]string{r.opts.HomeDir}, def...)...))
}
