package codex

import (
	"os"
	"path/filepath"
	"runtime"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

// NewOpenInterpreter returns an Adapter instance retagged for Open
// Interpreter (models.ToolOpenInterpreter), a rebrand of the OpenAI
// Codex CLI Rust codebase installed under ~/.openinterpreter instead
// of ~/.codex — see the models.ToolOpenInterpreter doc comment and
// docs/openinterpreter-adapter.md for the full evidence trail.
//
// The wire format (rollout-*.jsonl under sessions/YYYY/MM/DD/,
// session_meta / event_msg / response_item / turn_context /
// world_state event types, token_count field names) is byte-identical
// to codex's — this instance reuses the entire codex parser
// unmodified (parseSessionFile) and only differs in:
//   - WatchPaths: ".openinterpreter/sessions" instead of
//     ".codex/sessions" under every cross-mount-resolved $HOME,
//     INTERPRETER_HOME instead of CODEX_HOME for a single explicit
//     override root, AND the DESKTOP app's embedded codex-home (see
//     desktopAppDir / desktopStoreRoots below).
//   - Tool tagging: every ToolEvent/TokenEvent this instance emits is
//     retagged models.ToolOpenInterpreter by the ParseSessionFile
//     wrapper's single retag seam (see adapter.go).
//   - Surface vocabulary: the desktop app's own originator token
//     (openInterpreterSurface below) resolves to desktop /
//     "open-interpreter" for THIS instance and stays unmapped on
//     codex proper.
//
// INTERPRETER_HOME is UNVERIFIED as an actual environment-variable
// read (docs/plans/openinterpreter-adapter-plan-2026-07-29.md §12.1):
// `strings` on the interpreter binary shows the token exists
// alongside ".openinterpreter", but no live smoke test has confirmed
// the fork reads it from the environment the way CODEX_HOME is read
// by codex. It's wired here on the CODEX_HOME precedent (fail-open —
// an operator who sets it and is wrong just gets the default
// ~/.openinterpreter root back, same as an unset env var); flag this
// comment if a future session confirms or refutes it.
func NewOpenInterpreter() *Adapter {
	// readsServiceTier stays false: the variant never opens its root's
	// config.toml (plaintext provider keys in the desktop codex-home —
	// security ledger OI-1; OpenAI service tiers are meaningless here).
	return &Adapter{
		scrubber:      scrub.New(),
		name:          models.ToolOpenInterpreter,
		homeEnvVar:    "INTERPRETER_HOME",
		homeDirName:   ".openinterpreter",
		desktopAppDir: interpreterDesktopAppDir,
		surface:       openInterpreterSurface,
	}
}

// NewOpenInterpreterWithOptions customizes the scrubber and/or watch
// root for the Open Interpreter variant (test/backfill use — mirrors
// codex's NewWithOptions). Pass "" watchRoot for platform-default
// cross-mount discovery under ".openinterpreter" plus the desktop
// app's embedded codex-home.
func NewOpenInterpreterWithOptions(s *scrub.Scrubber, watchRoot string) *Adapter {
	if s == nil {
		s = scrub.New()
	}
	return &Adapter{
		scrubber:      s,
		watchRoot:     watchRoot,
		name:          models.ToolOpenInterpreter,
		homeEnvVar:    "INTERPRETER_HOME",
		homeDirName:   ".openinterpreter",
		desktopAppDir: interpreterDesktopAppDir,
		surface:       openInterpreterSurface,
	}
}

// interpreterDesktopAppDir is the Electron userData directory name the
// Open Interpreter DESKTOP app (Interpreter.exe, an Electron shell over
// the same Rust binary) creates for itself. Grounded on Windows
// 2026-09-03: %APPDATA%\interpreter\.
//
// NTFS is case-insensitive, and the app itself spells the directory
// BOTH ways — the live app-config's `lastMigrationBackupPath` says
// `...\AppData\Roaming\Interpreter\config.json.pre-migration-v11`
// while every directory listing reports `interpreter`. This constant
// picks the lowercase spelling as canonical (what the OS reports, and
// what the macOS/Linux ladder rungs below would use); on a
// case-SENSITIVE filesystem an install that really used `Interpreter`
// would be missed, which is why desktopStoreRoots is additive and
// never replaces the CLI root.
const interpreterDesktopAppDir = "interpreter"

// desktopStoreSubpath is the path, relative to the Electron userData
// directory, of the embedded Codex home the desktop app drives the
// Rust binary against. Grounded 2026-09-03: the desktop app writes
// %APPDATA%\interpreter\codex-home\{sessions,state_5.sqlite,
// logs_2.sqlite,skills,memories,config.toml,config.<ts>.toml}, i.e. a
// complete second CODEX_HOME that has nothing to do with the CLI's
// ~/.openinterpreter.
//
// There is NO store-relocation key: the desktop app's own config
// (%APPDATA%\interpreter\config.json) carries `lastWorkspace` and
// `recentFolders[]` — WORKSPACE pointers, the folders the user opened
// — and no key naming the session store. The codex-home location is
// therefore treated as a fixed convention, not a value to read out of
// config. (config.json is also never read by this adapter: it carries
// `userName`, PII we have no reason to persist.)
var desktopStoreSubpath = []string{"codex-home", "sessions"}

// desktopStoreRoots returns the desktop app's embedded codex-home
// sessions root under home root h, or nil for a variant that declares
// no desktop app dir (codex proper) or a home whose OS this ladder
// does not model.
//
// The ladder is Electron's app.getPath('userData') convention:
//
//   - windows: <home>/AppData/Roaming/<app>          — GROUNDED
//     (2026-09-03, %APPDATA%\interpreter\codex-home\sessions, four
//     live rollouts). As in vscodehost.UserDir, a NATIVE Windows home
//     prefers %APPDATA% when set, because the roaming profile can live
//     off the default drive.
//   - darwin:  <home>/Library/Application Support/<app> — UNVERIFIED
//   - linux:   <home>/.config/<app>                     — UNVERIFIED
//
// The two UNVERIFIED rungs are Electron's documented per-OS
// convention, not observed installs: only a Windows desktop build
// exists on the grounding box. They are wired because the cost of
// being wrong is an inert path (crossmount candidates are already
// stat-gated by the watcher) and the cost of omitting them is silent
// zero-capture on a Mac. Re-ground and drop this note when a macOS or
// Linux desktop install is available.
func (a *Adapter) desktopStoreRoots(h crossmount.HomeRoot) []string {
	if a.desktopAppDir == "" {
		return nil
	}
	var base string
	switch h.OS {
	case crossmount.OSWindows:
		base = filepath.Join(h.Path, "AppData", "Roaming", a.desktopAppDir)
		if h.Origin == "native" && runtime.GOOS == "windows" {
			if appData := os.Getenv("APPDATA"); appData != "" {
				base = filepath.Join(appData, a.desktopAppDir)
			}
		}
	case crossmount.OSDarwin:
		base = filepath.Join(h.Path, "Library", "Application Support", a.desktopAppDir)
	case crossmount.OSLinux:
		base = filepath.Join(h.Path, ".config", a.desktopAppDir)
	default:
		return nil
	}
	return []string{filepath.Join(append([]string{base}, desktopStoreSubpath...)...)}
}

// surfaceVocabulary is ONE adapter variant's capture-surface
// vocabulary: an originator-keyed overlay consulted BEFORE the shared
// codex tables in surface.go.
//
// This is the CLAUDE.md #3 shape — the variant difference is resolved
// into a capability AT THE BOUNDARY (a value the constructor sets on
// the instance) rather than re-derived from tool identity inside the
// resolver. There is no `if a.name == models.ToolOpenInterpreter`
// anywhere on the surface path; the zero value is codex proper's
// vocabulary, so every non-variant instance keeps its exact
// pre-existing behaviour.
type surfaceVocabulary struct {
	// originatorOverlay maps a session_meta `originator` token this
	// VARIANT owns to its resolved (kind, host). It wins over the
	// `source` field, which for a rebadge is a leftover of the
	// upstream codebase rather than a statement about the surface
	// (the Interpreter desktop app writes source:"vscode" while being
	// a standalone Electron desktop app).
	originatorOverlay map[string]surfaceRow
}

// resolve returns the (kind, host) for this variant, falling through
// to the shared codex tables when the overlay does not own the
// originator. ok=false means neither resolved and the caller must
// emit no SessionSurface row.
func (v surfaceVocabulary) resolve(source, originator string) (kind, host string, ok bool) {
	if row, hit := v.originatorOverlay[originator]; hit {
		return row.kind, row.host, true
	}
	return resolveCodexSurface(source, originator)
}

// openInterpreterSurface is the Open Interpreter variant's overlay.
//
// Grounded 2026-09-03 (four live desktop rollouts under
// %APPDATA%\interpreter\codex-home\sessions): the DESKTOP app writes
// session_meta {"originator":"codex_ui","cli_version":"0.0.10",
// "source":"vscode"}. `source` is an inherited-codebase leftover — the
// app is an Electron desktop shell, not a VS Code extension — so the
// originator overrides it here and the session is stamped
// desktop/"open-interpreter".
//
// codex_ui deliberately does NOT go into surface.go's shared
// codexOriginatorHost table: it is unknown whether some OpenAI surface
// also writes it, and the honesty rule is that codex proper emits no
// stamp for a token it cannot attribute.
//
// GAP: the CLI (`interpreter` / `i`, the Rust rebuild under
// ~/.openinterpreter) has NOT been grounded for an originator token —
// the grounding box has no ~/.openinterpreter at all. It is therefore
// left to the shared codex vocabulary (codex_cli / codex_cli_rs →
// cli/"codex-cli"), which is honest about the shared lineage rather
// than inventing an "open-interpreter-cli" host. Add a row here when a
// live CLI rollout is captured.
var openInterpreterSurface = surfaceVocabulary{
	originatorOverlay: map[string]surfaceRow{
		"codex_ui": {kind: models.SurfaceDesktop, host: models.ToolOpenInterpreter},
	},
}
