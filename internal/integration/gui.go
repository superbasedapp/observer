package integration

import "sort"

// This file is the GUI LAUNCH vocabulary: how the dashboard installs and
// launches an IDE or desktop app DETACHED (no PTY) with Observer's routing
// wrap injected, alongside the existing PTY launch shape
// (HandoffCapability.Launch). Design of record:
// docs/plans/ide-desktop-launch-plan-2026-09-03.md; grounding source:
// docs/audits/vendor-surface-inventory-2026-09-03.md §2 / §4.
//
// Operator scope (2026-09-03): install + launch ONLY. No open-in-directory
// as a feature, no resume, no continue, no attach, no model picker — a GUI
// has no PTY to hand to the daemon and no argv prompt seed. The single
// value of wrapping the launcher is that the in-app agent inherits the
// proxy route and its traffic becomes metered. Extensions are NEVER launch
// rows: an extension runs inside a host, so the host is the launch row and
// the extension's adapter is listed under Hosts.
//
// Every type here is DATA. Dispatch is on shape (LaunchKind, WrapKind,
// Grounded, Lifecycle) — never on a product name (CLAUDE.md #3/#5).

// LaunchKind names the launch SHAPE a dashboard launch request selects.
// It is the `kind` field on POST /api/terminal/launch; the dashboard
// package dispatches on it, never on the tool/product id.
type LaunchKind string

const (
	// LaunchKindTerminal (zero value / default): the existing PTY launch —
	// `observer <verb>` spawned in a pseudo-terminal streamed to xterm.js.
	LaunchKindTerminal LaunchKind = "terminal"
	// LaunchKindGUI: a detached GUI-app spawn (no PTY, no console; Windows
	// DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP, Unix setsid, darwin
	// `open -a`) with the row's WrapSpec applied to the child environment.
	LaunchKindGUI LaunchKind = "gui"
)

// WrapKind names HOW Observer injects its routing into a GUI launch
// (inventory §4 "three wrap mechanisms"). The zero value is WrapNone and
// REQUIRES a grounded Reason — never a silent nothing.
type WrapKind string

const (
	// WrapNone (zero value): launch only; capture rides the product's own
	// store / hooks. Reason is REQUIRED — the grounded negative (hard-wired
	// backend, no BYOK knob, settings held in an unwritable state.vscdb,
	// remote-sandbox inference, …). See inventory §4.2.
	WrapNone WrapKind = ""
	// WrapChildEnv: the launcher exports the base-URL env var(s) into the
	// GUI process's environment; the in-app agent inherits them. Sound ONLY
	// for a cold start of a single-instance app (a `code <dir>` that hands
	// off to an already-running window does not re-read its environment) —
	// see WrapSpec.ColdStartOnly.
	WrapChildEnv WrapKind = "child_env"
	// WrapConfigWrite: the product reads its base URL from a persisted
	// config file, never from the environment (openclaw.json, opencode.json,
	// ~/.hermes/config.yaml, ~/.zcode/cli/config.json). The route is written
	// by the EXISTING config-lane writers (`observer init` / the proxyroute
	// registrars via the adapter's ProxyProbe/Proxy row) — the GUI launch
	// itself writes nothing and records wrap_applied=false with the reason
	// naming that writer, so the operator knows which switch to flip.
	WrapConfigWrite WrapKind = "config_write"
)

// WrapEnvVar is one environment variable a WrapChildEnv launch exports:
// Name=<proxy base URL><Suffix>. Suffix follows the ProxyRoute convention
// ("/v1" for OpenAI-compatible endpoints, "" for ANTHROPIC_BASE_URL).
type WrapEnvVar struct {
	Name   string
	Suffix string
}

// WrapSpec is a GUI launch row's routing-injection contract.
type WrapSpec struct {
	// Kind selects the mechanism. Zero = WrapNone (Reason required).
	Kind WrapKind
	// Env lists the variables exported when Kind == WrapChildEnv. Required
	// non-empty for that kind (pinned by TestGUIWrapSpecsStructurallyValid).
	Env []WrapEnvVar
	// ConfigTool names the registry adapter whose config-lane writer applies
	// the route when Kind == WrapConfigWrite (e.g. "opencode", "openclaw").
	// Required non-empty for that kind; it must be a registry tool with a
	// non-nil Proxy or ProxyProbe row.
	ConfigTool string
	// Reason is the grounded explanation. REQUIRED for WrapNone (why nothing
	// can be injected); optional caveat text otherwise.
	Reason string
	// ColdStartOnly marks a WrapChildEnv row whose app is single-instance:
	// the env only reaches the agent when no instance is already running.
	// The launch records this caveat in its wrap note rather than claiming
	// the wrap took.
	ColdStartOnly bool
}

// GUILaunchSpec is one installable + launchable IDE / desktop-app row. It
// is carried either on a registry Capability (GUI field — the adapter's own
// product is the GUI: Cursor, Kiro IDE, Qoder, …) or in the guiHosts table
// (an editor host with no adapter of its own: VS Code, JetBrains IDEs).
// Both feed GUILaunchables(), the single accessor every consumer reads.
//
// Honesty rule (same as InstallHint / BinaryResolveSpec): a row is
// Grounded ONLY when its executable spelling on at least one OS has been
// grounded from the vendor's install layout or a live install; an
// UNVERIFIED row carries Grounded=false, an empty Binary, and a Note — it
// is listed for the record but is never launchable or installable.
type GUILaunchSpec struct {
	// ID is the launch id, unique across rows AND hosts (e.g. "vscode",
	// "cursor-ide", "kiro-ide", "claude-desktop"). It is the only client
	// input the launch/preflight/install endpoints take (a map key, never
	// argv).
	ID string
	// Label is the human product name ("Visual Studio Code").
	Label string
	// Surface is the capture-surface kind this launch produces:
	// models.SurfaceIDE ("ide") or models.SurfaceDesktop ("desktop"). A
	// string so this package stays stdlib-only.
	Surface string
	// Binary is the per-OS executable resolution row + grounded install
	// hints (reused verbatim from the terminal shape). For a GUI row Names
	// may be Windows-only or Unix-only (a desktop app is not required to
	// ship everywhere); at least one OS spelling is required when Grounded.
	// Prefer the REAL executable (Code.exe under %LOCALAPPDATA%\Programs)
	// over a `.cmd` PATH shim, which would spawn a console.
	Binary BinaryResolveSpec
	// ProbeOnly disables the PATH walk: the row resolves ONLY through its
	// ProbeDirs. Required when the executable name collides with an
	// unrelated PATH binary (Claude Desktop's claude.exe vs the Claude Code
	// CLI) or when the app is an MSIX with no PATH alias.
	ProbeOnly bool
	// AppsFolderAUMID, when non-empty, is the Windows packaged-app
	// (MSIX/AppX) Application User Model ID launched via
	// `explorer.exe shell:AppsFolder\<AUMID>` when no executable can be
	// resolved directly (Claude Desktop: "Claude_pzs8sxrjxfjjc!Claude").
	// A launch through explorer never inherits the daemon's environment,
	// so such a row must be WrapNone.
	AppsFolderAUMID string
	// DarwinApp is the .app bundle name for `open -a <DarwinApp>` on macOS
	// ("Visual Studio Code"). Empty = no grounded macOS bundle.
	DarwinApp string
	// ProjectDirArgv reports whether the app accepts a project directory as
	// a positional argument (`code <dir>`, `cursor <dir>`, `idea64 <dir>`).
	// False = the app is launched bare (a project root in the request is
	// ignored with a note, never an error).
	ProjectDirArgv bool
	// Wrap is the routing-injection contract.
	Wrap WrapSpec
	// Hosts lists the registry adapters whose sessions this launch produces
	// or hosts (vscode → claude-code, codex, cline, kilo-code, copilot, …).
	// A row on a registry Capability lists at least its own Tool. Every
	// entry must be a registry tool (pinned).
	Hosts []string
	// Grounded is true only when Binary carries a grounded spelling. An
	// UNVERIFIED row is false with a Note and is never launchable.
	Grounded bool
	// Note is free-text provenance / caveats (REQUIRED when Grounded is
	// false; rendered by the picker and the doctor).
	Note string
}

// Launchable reports whether the row can be offered for launch on ANY OS:
// grounded with at least one executable spelling or a packaged-app id.
// The per-OS answer (does THIS daemon resolve it?) is the preflight's job.
func (g GUILaunchSpec) Launchable() bool {
	if !g.Grounded {
		return false
	}
	return len(g.Binary.Names.Unix) > 0 || len(g.Binary.Names.Windows) > 0 ||
		g.AppsFolderAUMID != "" || g.DarwinApp != ""
}

// GUILaunchable is one entry of the unified GUI launch table: the spec plus
// the adapter it rides on ("" for a pure editor host) and the lifecycle of
// that adapter/product — so the picker, preflight, install and launch
// paths dispatch on ONE shape without knowing whether the row came from a
// Capability or from the hosts table.
type GUILaunchable struct {
	Spec GUILaunchSpec
	// Adapter is the registry tool the spec is carried on ("" for a host).
	Adapter string
	// Lifecycle is the carrying adapter's lifecycle (hosts are always
	// active — a host is not a product Observer categorises).
	Lifecycle Lifecycle
}

// Advertised reports whether this GUI row is offered on the picker: a
// launchable spec on an advertised lifecycle. THE predicate the dashboard
// GUI section, the GUI preflight and the GUI install seam consult.
func (g GUILaunchable) Advertised() bool {
	return g.Spec.Launchable() && g.Lifecycle.Advertised()
}

// GUILaunchables returns every GUI launch row — registry rows carrying a
// GUI spec plus the editor hosts — sorted by Spec.ID. It is the SINGLE
// accessor for the GUI launch surface; consumers never walk the registry
// and the host table separately.
func GUILaunchables() []GUILaunchable {
	out := make([]GUILaunchable, 0, len(guiHosts)+8)
	for _, c := range registry {
		if c.GUI != nil {
			out = append(out, GUILaunchable{Spec: *c.GUI, Adapter: c.Tool, Lifecycle: c.Lifecycle})
		}
	}
	for _, h := range guiHosts {
		out = append(out, GUILaunchable{Spec: h})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Spec.ID < out[j].Spec.ID })
	return out
}

// GUILaunchFor resolves a GUI launch id to its unified row. ok is false for
// an unknown id (the endpoints' 400).
func GUILaunchFor(id string) (GUILaunchable, bool) {
	if id == "" {
		return GUILaunchable{}, false
	}
	for _, g := range GUILaunchables() {
		if g.Spec.ID == id {
			return g, true
		}
	}
	return GUILaunchable{}, false
}
