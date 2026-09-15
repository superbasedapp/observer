package guilaunch

import (
	"errors"
	"fmt"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// Errors Compose returns. Both are refusals to compose a launch that could not
// possibly work, raised BEFORE any process exists — the caller maps them to a
// 500 and no run is spawned.
var (
	// ErrNoLaunchMechanism — the row resolved to no executable, carries no
	// Windows packaged-app id, and has no macOS bundle name: there is simply
	// nothing to exec. It is the honest floor for a not-found app, distinct
	// from a resolved-but-unwrappable one.
	ErrNoLaunchMechanism = errors.New("guilaunch: no launch mechanism (no resolved executable, no packaged-app id, no macOS bundle)")
	// ErrProxyURLInvalid — a non-empty proxy URL that is not http(s)://.
	// Injecting it would point the app's agent at something that is not the
	// observer proxy, so the launch is refused rather than silently mis-routed.
	ErrProxyURLInvalid = errors.New("guilaunch: proxy URL must be an http:// or https:// URL")
)

// Inputs are the host facts a GUI launch composition needs. Every one is DATA:
// the package performs no I/O of its own (see doc.go).
type Inputs struct {
	// GOOS is the DAEMON's operating system ("windows" / "darwin" / "linux").
	GOOS string
	// Bin is the resolved launch target: an executable path, a macOS .app
	// BUNDLE directory (toolresolve.ResolveGUI's darwin fallback), or "" for a
	// Windows packaged app addressed only by its AUMID.
	Bin string
	// ProjectRoot is the already-validated project directory, or "" for a bare
	// launch. It is appended to argv ONLY for a row that declares
	// ProjectDirArgv; otherwise it is ignored with a Note.
	ProjectRoot string
	// ProxyURL is the observer proxy base URL a WrapChildEnv row injects
	// (each WrapEnvVar contributes Name=ProxyURL+Suffix). Empty means no proxy
	// URL was resolved — the wrap then records as not-applied rather than
	// injecting a broken value.
	ProxyURL string
	// ViaInterop marks a WSL daemon launching a WINDOWS executable across the
	// interop boundary. The daemon's environment does NOT cross that boundary
	// without WSLENV, so a child-env wrap cannot take effect and is recorded
	// as not-applied with that reason.
	ViaInterop bool
}

// Plan is the composed launch: the argv to exec, the environment ADDITIONS
// (each "KEY=VALUE") the caller layers over the daemon's own environment, and
// the honest wrap verdict.
type Plan struct {
	// Argv is the complete command, argv[0] first. Server-derived in full: the
	// only client-influenced value that ever reaches it is the already-
	// validated project root, and only for a row that takes one.
	Argv []string
	// Env is the wrap's environment additions ("KEY=VALUE"). Empty whenever
	// WrapApplied is false.
	Env []string
	// WrapApplied reports whether the routing wrap actually reaches the child.
	// It is the value persisted on the run row and shown to the operator, so
	// it must never be optimistic — see the wrapRules table.
	WrapApplied bool
	// WrapNote is the grounded explanation of the wrap verdict: why it could
	// not be applied, or the caveat that qualifies an applied one (a
	// cold-start-only app whose running instance will not re-read its
	// environment). Empty only when an unqualified wrap applied.
	WrapNote string
	// Notes are launch-composition advisories unrelated to the wrap (today:
	// a project directory ignored because the app takes no such argument).
	Notes []string
}

// mechanism names the launch SHAPE the argv rules selected. It exists so the
// wrap table can branch on the fact that matters — an explorer-launched
// packaged app inherits no environment — without re-deriving it.
type mechanism string

const (
	// mechExe: exec the resolved executable directly.
	mechExe mechanism = "exe"
	// mechDarwinBundle: `open -a <DarwinApp>` (optionally `--args <dir>`).
	mechDarwinBundle mechanism = "darwin_bundle"
	// mechPackagedApp: `explorer.exe shell:AppsFolder\<AUMID>`.
	mechPackagedApp mechanism = "packaged_app"
)

// launchRule is one row of the ordered mechanism table. The FIRST row whose
// match fires wins, so the table reads top-down as the precedence it encodes:
// a macOS bundle and a Windows packaged app are OS-scoped special shapes; a
// resolved executable is the general case underneath them.
type launchRule struct {
	mech  mechanism
	match func(integration.GUILaunchSpec, Inputs) bool
	argv  func(integration.GUILaunchSpec, Inputs) []string
}

var launchRules = []launchRule{
	{
		// A darwin daemon with a grounded bundle name whose resolver found the
		// BUNDLE itself (toolresolve.ResolveGUI reports Bin = the .app path).
		// A real executable on PATH (`/usr/local/bin/code`) is not a bundle and
		// falls through to mechExe, which is the more direct launch. An EMPTY
		// Bin is deliberately NOT accepted: a not_found resolution must be a
		// refusal (ErrNoLaunchMechanism), never a 200 that hands `open -a` a
		// name nothing on this machine answers to.
		mech: mechDarwinBundle,
		match: func(spec integration.GUILaunchSpec, in Inputs) bool {
			return in.GOOS == "darwin" && spec.DarwinApp != "" &&
				in.Bin != "" && strings.HasSuffix(in.Bin, ".app")
		},
		argv: func(spec integration.GUILaunchSpec, in Inputs) []string {
			argv := []string{"open", "-a", spec.DarwinApp}
			if takesProjectDir(spec, in) {
				// open(1) forwards everything after --args to the application.
				argv = append(argv, "--args", in.ProjectRoot)
			}
			return argv
		},
	},
	{
		// A Windows packaged app (MSIX/AppX) with no resolvable executable.
		mech: mechPackagedApp,
		match: func(spec integration.GUILaunchSpec, in Inputs) bool {
			return in.GOOS == "windows" && in.Bin == "" && spec.AppsFolderAUMID != ""
		},
		argv: func(spec integration.GUILaunchSpec, _ Inputs) []string {
			// explorer resolves the AUMID through the shell; it takes no
			// further arguments, so a project directory can never be passed
			// here (such a row is WrapNone + ProjectDirArgv=false by
			// construction, and takesProjectDir is not consulted).
			return []string{"explorer.exe", `shell:AppsFolder\` + spec.AppsFolderAUMID}
		},
	},
	{
		// The general case: exec the resolved binary.
		mech:  mechExe,
		match: func(_ integration.GUILaunchSpec, in Inputs) bool { return in.Bin != "" },
		argv: func(spec integration.GUILaunchSpec, in Inputs) []string {
			argv := []string{in.Bin}
			if takesProjectDir(spec, in) {
				argv = append(argv, in.ProjectRoot)
			}
			return argv
		},
	},
}

// takesProjectDir reports whether this launch appends the requested project
// directory: the row must declare ProjectDirArgv AND a directory must have been
// requested. The two halves are deliberately one predicate so every mechanism
// asks the same question.
func takesProjectDir(spec integration.GUILaunchSpec, in Inputs) bool {
	return spec.ProjectDirArgv && in.ProjectRoot != ""
}

// wrapResult is one wrap rule's verdict.
type wrapResult struct {
	env     []string
	applied bool
	note    string
}

// wrapRule is one row of the WrapKind table. Unlike launchRules this is a
// LOOKUP (the kind is a closed vocabulary), so a missing kind is the honest
// zero — treated as WrapNone rather than silently claiming a wrap.
type wrapRule struct {
	kind  integration.WrapKind
	apply func(integration.GUILaunchSpec, Inputs, mechanism) wrapResult
}

var wrapRules = []wrapRule{
	{
		kind: integration.WrapChildEnv,
		apply: func(spec integration.GUILaunchSpec, in Inputs, mech mechanism) wrapResult {
			switch {
			case in.ViaInterop:
				return wrapResult{note: "interop launch: environment is not propagated across the WSL boundary (WSLENV not set)"}
			case mech == mechPackagedApp:
				return wrapResult{note: "explorer-launched packaged app inherits no environment"}
			case in.ProxyURL == "":
				return wrapResult{note: "no observer proxy URL resolved — nothing to inject"}
			case len(spec.Wrap.Env) == 0:
				// A WrapChildEnv row with no variables is a registry defect the
				// integration coverage test pins; report it honestly rather
				// than claiming an empty wrap took.
				return wrapResult{note: "no routing variables are declared for this row"}
			}
			env := make([]string, 0, len(spec.Wrap.Env))
			for _, v := range spec.Wrap.Env {
				env = append(env, v.Name+"="+in.ProxyURL+v.Suffix)
			}
			return wrapResult{env: env, applied: true}
		},
	},
	{
		kind: integration.WrapConfigWrite,
		apply: func(spec integration.GUILaunchSpec, _ Inputs, _ mechanism) wrapResult {
			tool := spec.Wrap.ConfigTool
			if tool == "" {
				tool = spec.ID
			}
			return wrapResult{note: fmt.Sprintf(
				"route is written by the %s config-lane writer (`observer init`), not at launch", tool)}
		},
	},
	{
		kind: integration.WrapNone,
		apply: func(spec integration.GUILaunchSpec, _ Inputs, _ mechanism) wrapResult {
			if reason := strings.TrimSpace(spec.Wrap.Reason); reason != "" {
				return wrapResult{note: reason}
			}
			return wrapResult{note: "no routing wrap: this app has no grounded base-URL mechanism"}
		},
	},
}

// coldStartNote is the caveat appended to a single-instance app's wrap note: an
// already-running window is handed the launch by the app itself and never
// re-reads its environment, so the wrap only takes on a genuinely cold start.
const coldStartNote = "cold-start only: an already-running instance will not re-read its environment"

// packagedAppPIDNote is the honesty note every explorer-launched packaged-app
// launch carries. `explorer.exe shell:AppsFolder\<AUMID>` is a LAUNCHER STUB:
// it asks the shell to activate the package and then exits on its own — during
// live verification (2026-09-03) it exited 1 within a second while the app it
// had just started was focused and running. So the pid the run row records, and
// the exit code the reaper reports, describe the stub, NOT the application.
// Saying so is the alternative to silently presenting a dead stub's exit as the
// app's — there is no way to recover the real process id from this launch
// mechanism, and inventing one would be worse than naming the gap.
const packagedAppPIDNote = "pid and exit code belong to the explorer.exe launcher stub, not the app; the app's own process is not tracked"

// darwinBundlePIDNote is the same honesty note for the macOS bundle
// mechanism: `open -a <App>` is likewise a launcher — it asks LaunchServices to
// activate the bundle and returns — so the pid the run row records and the exit
// the reaper reports are open(1)'s, not the application's.
const darwinBundlePIDNote = "pid and exit code belong to the open(1) launcher, not the app; the app's own process is not tracked"

// mechanismNotes is the per-mechanism advisory table (CLAUDE.md #5): a launch
// mechanism that spawns a STUB rather than the application carries its
// pid/exit caveat here, keyed on the MECHANISM so any future row using it
// inherits the note without a product-name branch. mechExe has no entry — the
// pid IS the app's.
var mechanismNotes = map[mechanism]string{
	mechPackagedApp:  packagedAppPIDNote,
	mechDarwinBundle: darwinBundlePIDNote,
}

// Compose builds the launch Plan for one GUI row. It is the SINGLE composition
// point: the cmd-side launcher resolves the binary and the proxy URL, calls
// this once, and execs Plan.Argv with Plan.Env layered over the daemon's
// environment. Errors are refusals raised before any process exists.
func Compose(spec integration.GUILaunchSpec, in Inputs) (Plan, error) {
	if in.ProxyURL != "" && !isHTTPURL(in.ProxyURL) {
		return Plan{}, fmt.Errorf("%w: %q", ErrProxyURLInvalid, in.ProxyURL)
	}

	rule, ok := matchLaunchRule(spec, in)
	if !ok {
		return Plan{}, fmt.Errorf("%w: %s", ErrNoLaunchMechanism, spec.ID)
	}
	plan := Plan{Argv: rule.argv(spec, in)}

	// A stub-spawning mechanism (explorer shell:AppsFolder, open -a) produces a
	// pid and exit code that are not the application's. The note is attached
	// to the MECHANISM through the mechanismNotes table, not to a product id,
	// so any future row on that mechanism inherits it (CLAUDE.md #3/#5).
	if note, ok := mechanismNotes[rule.mech]; ok {
		plan.Notes = append(plan.Notes, note)
	}

	// An operator can hand a project directory to any row (the picker reuses
	// one control); a row that takes no such argument ignores it — honestly,
	// with a note — rather than failing a launch the app would happily perform.
	if in.ProjectRoot != "" && !spec.ProjectDirArgv {
		plan.Notes = append(plan.Notes,
			"this app takes no project-directory argument — the requested directory was ignored")
	}

	res := applyWrap(spec, in, rule.mech)
	plan.Env = res.env
	plan.WrapApplied = res.applied
	plan.WrapNote = res.note
	return plan, nil
}

// matchLaunchRule walks the ordered mechanism table top-down.
func matchLaunchRule(spec integration.GUILaunchSpec, in Inputs) (launchRule, bool) {
	for _, r := range launchRules {
		if r.match(spec, in) {
			return r, true
		}
	}
	return launchRule{}, false
}

// applyWrap resolves the row's WrapKind through the wrapRules lookup and folds
// in the ColdStartOnly caveat. An unknown kind falls back to the WrapNone rule
// — the honest zero, never an assumed wrap.
func applyWrap(spec integration.GUILaunchSpec, in Inputs, mech mechanism) wrapResult {
	res := wrapResult{note: "no routing wrap: this app has no grounded base-URL mechanism"}
	for _, r := range wrapRules {
		if r.kind == spec.Wrap.Kind {
			res = r.apply(spec, in, mech)
			break
		}
	}
	// ColdStartOnly is a property of the child-env mechanism itself, so it
	// qualifies that kind's note whether or not the injection took: an operator
	// who sees "applied" still needs to know it only counts on a cold start.
	if spec.Wrap.Kind == integration.WrapChildEnv && spec.Wrap.ColdStartOnly {
		res.note = joinNotes(res.note, coldStartNote)
	}
	return res
}

// joinNotes concatenates note fragments with the em-dash separator the install
// / preflight surfaces already use, skipping empties.
func joinNotes(parts ...string) string {
	kept := make([]string, 0, len(parts))
	for _, p := range parts {
		if strings.TrimSpace(p) != "" {
			kept = append(kept, p)
		}
	}
	return strings.Join(kept, " — ")
}

// isHTTPURL reports whether s has an http:// or https:// scheme. It is a
// prefix test, not a net/url parse: this package must stay free of the
// stdlib's networking surface, and the value it guards is a base URL the
// daemon itself composed.
func isHTTPURL(s string) bool {
	return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")
}
