package hook

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/agentconfig"
	"github.com/marmutapp/superbased-observer/internal/credfile"
	"github.com/marmutapp/superbased-observer/internal/integration"
)

// Config homes (surface-gap Wave 4, lane w4-homes-b; review S-17, CLI-4,
// W-4, OI-1). A native hook writer names the vendor file it edits by its
// agentconfig artifact id and resolves it with the artifact's relocation
// rules (agentconfig.ResolveArtifact), so a tool home variable the vendor
// honours (QWEN_HOME, GROK_HOME, COPILOT_HOME, ...) moves Observer's write
// with it. The environment is the registry's own Options.Getenv (nil reads
// nothing, which is what tests want); the OS is hostGOOS. The cross-OS
// "-windows" bridges keep their own Windows-home detection: the Windows
// shell's environment is not readable from WSL (Wave 7).
//
// artifactPath is the package's one artifact-path helper (FU-74): the
// Claude Code and Codex homes (confighome.go) resolve through it too, so a
// relative relocation value writes nothing for every writer (FU-31, R-188
// F6). It resolves for hostGOOS so a test that pins the host OS gets that
// OS's row path.

// artifactPath is the absolute, host-native path of artifact id under this
// registry's home and environment. A relocation variable whose relative
// value the vendor would read against its own working directory is an
// error: nothing is written to the default location instead. The refusal
// is a credfile.SafeError (it names a variable and an artifact id, never a
// value read from a file), so a writer whose file shares a credential file
// (credentialSafeError) still reports the variable instead of withholding
// the message.
func (r *Registry) artifactPath(id string) (string, error) {
	got, err := agentconfig.ResolveArtifact(id, r.artifactEnv())
	if err != nil {
		return "", fmt.Errorf("hook: %w", err)
	}
	switch got.Status {
	case agentconfig.PathResolved, agentconfig.PathDirectory:
		return hostNative(got.Path), nil
	case agentconfig.PathRelocationUnresolved:
		return "", credfile.SafeErrorf("hook: %s is set to a relative path, which the tool reads against its own working directory; Observer cannot tell which file %s that names, so nothing was written (set an absolute path)", got.RelocatedBy, id)
	}
	return "", fmt.Errorf("hook: %s has no user path on %s (%s)", id, r.hostGOOS(), got.Status)
}

// artifactEnv is the machine a native registration resolves for: hostGOOS
// picks the row's per-OS path, and an environment value is judged absolute
// by that OS's path syntax (FU-143), so a test that pins another host OS
// judges the values as that OS would.
func (r *Registry) artifactEnv() agentconfig.PathEnv {
	return agentconfig.PathEnv{GOOS: r.hostGOOS(), Home: r.opts.HomeDir, Getenv: r.opts.Getenv}
}

// artifactDir is the directory of artifact id: the file's parent, or the
// directory itself for a directory artifact.
func (r *Registry) artifactDir(id string) (string, error) {
	got, err := r.artifactPath(id)
	if err != nil {
		return "", err
	}
	if isDirArtifact(id) {
		return got, nil
	}
	return filepath.Dir(got), nil
}

// artifactDirOr is artifactDir with a fallback for callers that only need
// a best-effort location (install detection, unregistration): an
// unresolvable relocation yields fallback, never an error.
func (r *Registry) artifactDirOr(id, fallback string) string {
	if d, err := r.artifactDir(id); err == nil {
		return d
	}
	return fallback
}

// isDirArtifact reports whether the catalogued row names a directory.
func isDirArtifact(id string) bool {
	for _, f := range agentconfig.Files() {
		if f.ID == id {
			// The first spelled path decides; a row may spell only one
			// OS (the darwin-only Xcode agent homes, FU-145).
			p := f.Paths.Linux
			for _, alt := range []string{f.Paths.Darwin, f.Paths.Windows} {
				if p == "" {
					p = alt
				}
			}
			return strings.HasSuffix(p, "/") || strings.HasSuffix(p, `\`)
		}
	}
	return false
}

// hostNative converts a resolved path to the running OS's separators and
// drops a trailing separator. PathEnv spells a path for hostGOOS; a test
// that pins hostGOOS to another OS still gets a path this host can open.
func hostNative(p string) string {
	n := filepath.FromSlash(strings.ReplaceAll(p, `\`, "/"))
	for len(n) > 1 && strings.HasSuffix(n, string(filepath.Separator)) && !(len(n) == 3 && n[1] == ':') {
		n = strings.TrimSuffix(n, string(filepath.Separator))
	}
	return n
}

// homeArtifacts names, per tool, the catalogued artifact whose directory is
// (up levels below) the tool's own home. Install detection checks that
// directory beside the default one, so a home moved by the vendor's own
// variable (GROK_HOME, KIRO_HOME, ...) is still an install signal, and
// Goose's native Windows home (%APPDATA%\Block\goose\config) is found at
// all (S-17, FU-5).
var homeArtifacts = map[string]struct {
	id string
	up int
}{
	"gemini-cli":       {"gemini-cli/user-settings", 0},
	"qwen-code":        {"qwen-code/user-settings", 0},
	"qoder":            {"qoder/user-settings", 0},
	"grok":             {"grok/user-config", 0},
	"copilot-cli":      {"copilot-cli/user-settings", 0},
	"goose":            {"goose/user-config", 0},
	"junie":            {"junie/user-config", 0},
	"crush":            {"crush/user-json", 0},
	"open-interpreter": {"open-interpreter/user-config", 0},
	"mistral-code":     {"mistral-code/user-config", 0},
	"kimi-code":        {"kimi-code/user-config", 0},
	"kiro-cli":         {kiroHomeArtifact, 1},
	// Cortex Code's data home (~/.snowflake/cortex by default), the
	// directory its hooks.json writer resolves (W-2a).
	"cortex-code": {"cortex-code/user-hooks", 0},
	// The directory of the shared Antigravity hooks file
	// (~/.gemini/config), which the CLI, the App, the IDE and the VS Code
	// extension all read (WINNODE2 item 5b): its presence is an install
	// signal beside the products' own data directories.
	"antigravity-cli": {"antigravity-cli/user-hooks", 0},
}

// homeArtifactExists reports whether tool's artifact-resolved home exists.
func (r *Registry) homeArtifactExists(tool string) bool {
	h, ok := homeArtifacts[tool]
	if !ok {
		return false
	}
	d, err := r.artifactDir(h.id)
	if err != nil {
		return false
	}
	for i := 0; i < h.up; i++ {
		d = filepath.Dir(d)
	}
	return r.dirExists(d)
}

// statusLineSettingsPath is the settings file a home-relative status-line
// spec names (StatusLineSpec.File, "~/"-relative), resolved through the
// catalogued artifact of the same tool at that default path, so the file
// follows the vendor's relocation rule (S-21: CodeBuddy's
// CODEBUDDY_CONFIG_DIR moves it; Kimchi's harness stays put because
// entry.ts forces its own dir). The artifact is found by its default path,
// never by tool name; a spec no row names keeps the home-relative path, and
// a relocation that cannot be named yields "" (not written).
func (r *Registry) statusLineSettingsPath(tool string, spec integration.StatusLineSpec) string {
	def := filepath.Join(r.opts.HomeDir, filepath.FromSlash(spec.File))
	want := "~/" + strings.TrimPrefix(filepath.ToSlash(spec.File), "/")
	for _, f := range agentconfig.Files() {
		if f.Tool != tool || f.Scope != agentconfig.ScopeUser {
			continue
		}
		if f.Paths.Linux != want && f.Paths.Windows != want && f.Paths.Darwin != want {
			continue
		}
		p, err := r.artifactPath(f.ID)
		if err != nil {
			return ""
		}
		return p
	}
	return def
}
