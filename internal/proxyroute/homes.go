package proxyroute

import (
	"errors"
	"fmt"
	"path/filepath"
	"runtime"

	"github.com/marmutapp/superbased-observer/internal/agentconfig"
	"github.com/marmutapp/superbased-observer/internal/credfile"
)

// Config homes (surface-gap Wave 4, CC-8 and CX-4). The route files of the
// Claude Code and Codex writers and of the read-only inspectors are
// agentconfig FileRow artifacts, resolved through agentconfig.ResolveArtifact
// with the registrar's injected environment. A relocation rule on the row
// (CLAUDE_CONFIG_DIR, CODEX_HOME, or any rule added later to
// agentconfig's fileRelocations table) moves the writer, the inspector, the
// dry run that decides routability and the provenance record together, with
// no edit here.
const (
	// claudeSettingsArtifact holds env.ANTHROPIC_BASE_URL (RegisterClaudeCode).
	claudeSettingsArtifact = "claude-code/user-settings"
	// codexConfigArtifact holds [model_providers.openai-observer]
	// (RegisterCodex).
	codexConfigArtifact = "codex/user-config"
)

// claudeSettingsPath is where RegisterClaudeCode writes the route, or the
// refusal routeArtifactPath gives for it.
func (r *Registrar) claudeSettingsPath() (string, error) {
	return routeArtifactPath("proxyroute.claude", claudeSettingsArtifact, r.opts.HomeDir, r.opts.Getenv)
}

// codexConfigPath is where RegisterCodex writes the route, or the refusal
// routeArtifactPath gives for it.
func (r *Registrar) codexConfigPath() (string, error) {
	return routeArtifactPath("proxyroute.codex", codexConfigArtifact, r.opts.HomeDir, r.opts.Getenv)
}

// inspectEnv is the registrar's own machine for an inspection it runs
// (route maintenance): its home and its environment, so the pass reads the
// file the registrar then writes.
func (r *Registrar) inspectEnv() inspectEnv {
	return inspectEnv{home: r.opts.HomeDir, getenv: r.opts.Getenv}
}

// Route-file homes (surface-gap Wave 4, lane w4-homes-b; audit finding 3's
// note). The probe-lane route writers name the file they edit by its
// agentconfig artifact (crush/user-json, kimi-code/user-config,
// qwen-code/user-settings) and resolve it with the artifact's relocation
// rules through the registrar's injected lookup (RegisterOptions.Getenv),
// never os.Getenv directly: a pinned or isolated home is never relocated by
// the developer's shell (the Cline A2 rule). The hook writers resolve the
// same artifacts, so a route and its hooks never split across two homes.

// The route-file artifacts.
const (
	crushConfigArtifact = "crush/user-json"
	kimiConfigArtifact  = "kimi-code/user-config"
	qwenConfigArtifact  = "qwen-code/user-settings"
)

// routeArtifactPath is this package's one artifact-path helper (FU-74):
// every route writer, the read-only inspectors, the routability dry run and
// the provenance targets resolve their file through it, so none of them can
// name a file the others do not. It resolves artifact under homeDir with
// getenv's relocation variables (nil reads none). A variable whose relative
// value the tool reads against its own working directory is an
// *unresolvedRelocationError naming that variable: nothing falls back to the
// vendor default under the home, which the tool does not read (FU-31,
// R-188 F6). A row with no file on this OS is an error too.
func routeArtifactPath(what, artifact, homeDir string, getenv func(string) string) (string, error) {
	if getenv == nil {
		getenv = func(string) string { return "" }
	}
	got, err := agentconfig.ResolveArtifact(artifact, agentconfig.PathEnv{GOOS: runtime.GOOS, Home: homeDir, Getenv: getenv})
	if err != nil {
		return "", fmt.Errorf("%s: %w", what, err)
	}
	switch got.Status {
	case agentconfig.PathResolved:
		return filepath.Clean(got.Path), nil
	case agentconfig.PathRelocationUnresolved:
		return "", &unresolvedRelocationError{env: got.RelocatedBy, err: credfile.SafeErrorf("%s: %s is set to a relative path, which the tool reads against its own working directory; Observer cannot tell which file that names, so nothing was written (set an absolute path)", what, got.RelocatedBy)}
	}
	return "", credfile.SafeErrorf("%s: %s has no path on %s", what, artifact, runtime.GOOS)
}

// unresolvedRelocationError is routeArtifactPath's refusal for a relocation
// variable that holds a relative value. env is the variable; the message is
// a credfile.SafeError (it names a variable, never a value read from a
// file), so credfile.Withhold passes it through.
type unresolvedRelocationError struct {
	env string
	err error
}

// Error implements error.
func (e *unresolvedRelocationError) Error() string { return e.err.Error() }

// Unwrap returns the SafeError message.
func (e *unresolvedRelocationError) Unwrap() error { return e.err }

// unresolvedRelocation names the relocation variable behind err, "" when
// err is not routeArtifactPath's relative-value refusal.
func unresolvedRelocation(err error) string {
	var u *unresolvedRelocationError
	if errors.As(err, &u) {
		return u.env
	}
	return ""
}
