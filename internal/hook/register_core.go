package hook

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/credfile"
	"github.com/marmutapp/superbased-observer/internal/hookdigest"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/regularfile"
	"github.com/marmutapp/superbased-observer/internal/testwriteguard"
)

// RegistrationResult summarizes a single tool registration.
type RegistrationResult struct {
	Tool       string   // claude-code[-windows] | cursor[-windows] | codex[-windows]
	ConfigPath string   // absolute path to the patched config file
	HooksAdded []string // event names that now point at the observer binary
	// HooksDropped are the events whose Observer per-node entry this pass
	// removed because a trusted administrator hooks file already runs it
	// (managedhooks.go); a non-Observer entry is never removed.
	HooksDropped []string
	AlreadySet   []string // events that already pointed at the observer (skipped)
	DryRun       bool
	Error        error

	// Skipped reports that the registrar deliberately wrote nothing.
	// SkipKind says why, and the two reasons mean opposite things for
	// enforcement (review M2-05 / M2-18):
	//
	//   - SkipCovered: the tool already carries Observer's wiring through
	//     its own packaging surface (today, the Claude Code plugin, which
	//     declares the same hook events). Not an error: the user is
	//     covered, and registering again would fire every event twice.
	//   - SkipNotApplicable: nothing CAN be registered here (an OS the
	//     vendor's hook files do not support, a cross-OS target a pinned
	//     home suppresses, every subscribed event still owing a live test).
	//     The tool has NO Observer hook on this target, so nothing may read
	//     it as registered.
	//
	// SkipReason names the artifact or the rule that decided it. All three
	// are zero on every other path. A Skipped result with an empty SkipKind
	// (a path that predates the split) is read as not applicable: the
	// fail-closed reading, since "covered" is a claim that needs evidence.
	Skipped    bool
	SkipKind   SkipKind
	SkipReason string

	// SkipAdvice is the operator-facing next step that goes with
	// SkipReason. Empty means "the default plugin advice applies" (the
	// printer supplies it), so the plugin skip path is unchanged; the
	// cross-OS sandbox skip (see crossmount.AutoDetectSuppressed) sets it
	// because the --force escape hatch deliberately does NOT apply there.
	SkipAdvice string

	// KeptEquivalent names events whose existing observer entry differed
	// from the command this binary writes but was kept because it is
	// equivalent (Options.KeepEquivalentHooks, T-725). Each is also in
	// AlreadySet.
	KeptEquivalent []string

	// Rewrites records every existing observer entry this registration
	// replaced and the rule that forced it (T-725), so the caller can log
	// what changed. Empty when nothing existing was rewritten.
	Rewrites []Rewrite

	// ProbeWarning is a NON-FATAL note: the plugin probe could not read
	// a file it needed, so the registrar registered without being able
	// to rule out a plugin already providing this wiring. Registration
	// still happened (fail-open to wiring) — this is a reporting
	// channel, never control flow. Empty on every conclusive path.
	ProbeWarning string

	// Warnings are NON-FATAL, operator-actionable notes about wiring that is
	// (or would be) in place but may not run on the host as configured
	// today, e.g. a Windows hook runner whose shell is not on the Windows
	// PATH (windowsshell.go). Registration happened exactly as without them;
	// they never change control flow. Nil on every path with nothing to say.
	Warnings []string

	// RepairCopy is where a managed repair of a neutralised Observer
	// artifact kept the bytes it replaced (T-884): a new
	// "<path>.displaced-<UTC>" file next to the artifact (keepRepairCopy).
	// Empty when the registration repaired nothing, or the artifact is
	// credential-bearing and is never copied.
	RepairCopy string

	// TrustRecorded names the events whose host-side trust record this
	// registration wrote for Observer's own entries (a host that runs a
	// hook only once it is trusted: Codex, live check 2026-10-20). Empty
	// when nothing needed recording.
	TrustRecorded []string
	// TrustNote is a NON-FATAL note: Observer's entries were registered
	// but at least one could not be trusted (the reason, never file
	// contents), so the host will not run it until the user approves it
	// there. Empty when every entry is trusted.
	TrustNote string
}

// SkipKind is RegistrationResult.SkipKind: why a registrar wrote nothing.
type SkipKind string

const (
	// SkipCovered: another surface already carries Observer's wiring for
	// the same events (the Claude Code plugin).
	SkipCovered SkipKind = "covered"
	// SkipNotApplicable: no Observer hook can exist on this target.
	SkipNotApplicable SkipKind = "not_applicable"
)

// CoveredElsewhere reports whether a skipped result is covered by another
// surface (SkipCovered). Every other skip, including one with no SkipKind,
// is not applicable: no Observer hook exists on the target.
func (r RegistrationResult) CoveredElsewhere() bool {
	return r.Skipped && r.SkipKind == SkipCovered
}

// Options parameterize RegisterAll.
type Options struct {
	// BinaryPath is the absolute path to the running observer binary
	// that hook commands will invoke. Required.
	BinaryPath string
	// WSLTwinBinaryPath is the Windows observer.exe a "-wsl" twin's hook
	// runs through WSL interop, when BinaryPath is a package manager's
	// launcher (an npm .cmd / .bat or a pip console script) that interop
	// cannot run: the binary that launcher started, which the caller is
	// (FU-214, operator ruling option 1). The twin re-points to it on every
	// registration, so an upgrade that moves it is repaired at the next
	// `observer start`. Empty: the twin runs BinaryPath.
	WSLTwinBinaryPath string
	// PinPluginPaths renders in-process plugin shims that ignore
	// OBSERVER_BIN and OBSERVER_CONFIG from the host's environment
	// (pluginshim.RenderOptions.PinPaths): set on a managed node.
	PinPluginPaths bool
	// DryRun, when true, computes the result without touching any files.
	DryRun bool
	// Force, when true, overwrites existing non-observer hook entries for
	// the events we manage. When false, conflicts are reported as errors.
	Force bool
	// HomeDir, when non-empty, overrides the default user home — used by
	// tests to sandbox registration in a temp directory.
	HomeDir string
	// ChecksumsPath overrides ~/.observer/hook_checksums.json. Empty
	// means use the default.
	ChecksumsPath string
	// ConfigPath, when non-empty, is appended to the registered hook
	// command as `--config <path>`. Used to keep the hook handler's view
	// of config (and therefore which DB it writes compaction_events /
	// pidbridge rows into) aligned with whichever proxy the user is
	// running. Without this, the hook handler always reads
	// ~/.observer/config.toml and writes to ~/.observer/observer.db,
	// even when the proxy is running against a different config (e.g.
	// the A/B harness's /tmp/ab-claude/on/observer-config.toml). D23's
	// Injector then queries the proxy's DB and finds nothing because
	// the row landed elsewhere. Surfaced 2026-05-08 dogfood.
	ConfigPath string

	// SkipEvent, when set, names events a multi-event writer must NOT
	// add (an entry already present is left exactly as it is). `observer
	// start` sets it so auto-registration writes only live-grounded or
	// grandfathered events (hook-parity audit section 7 ruling 4); nil
	// (`observer init`, consented) writes every event the writer owns.
	SkipEvent func(tool, event string) bool

	// KeepEquivalentHooks, when true, leaves an existing observer hook
	// entry exactly as it is when it is EQUIVALENT to the one this binary
	// would write (same shape, tool and event, a binary that still runs,
	// the same effective config file), even if its binary path or an
	// explicit default --config differs (T-725, hookEquivalenceRules).
	// `observer start` auto-registration and the dashboard hooks probe set
	// it; `observer init` (consented) leaves it false and refreshes every
	// entry to this binary. Applies to the Claude Code registrars.
	KeepEquivalentHooks bool

	// RepairOwnedArtifacts, when true, marks a managed node's repair pass
	// (T-872): an artifact Observer owns by NAME (a file Observer names, or
	// an entry Observer names inside a shared file) that Observer installed
	// before (hook_checksums.json records it) but that no longer reads as
	// Observer's is rewritten and reported as a repair instead of refused.
	// A genuinely foreign hook, and every artifact that is Observer's only by
	// content, is still refused (conflictRules, ownership.go). The
	// heartbeat's re-registration sets it on a managed node only; false keeps
	// the refusal every other caller has always had.
	RepairOwnedArtifacts bool

	// ToolGateFailsClosed is true when guard enforcement closes the tool
	// gate on this node (the caller resolves it from the guard posture or
	// the config, the hook failure plan's own answer). A writer whose host
	// fails OPEN on a hook failure unless told otherwise (Goose's
	// on_failure) then writes the host's fail-closed switch. False keeps
	// every host's default.
	ToolGateFailsClosed bool

	// WindowsBridgeFailClosed is true on a MANAGED node whose guard
	// enforcement closes the tool gate (the caller resolves both). A
	// cross-OS Windows registrar may then write the fail-closed hook bridge
	// (`observer hook-bridge`) for its tool-gate events, so a gated call
	// blocks when WSL cannot run the hook (surface-gap AW-37, D12). The
	// writer is switched off behind live check LC6
	// (integration.WriterKindHookBridge): while that waits, every registrar
	// writes today's wsl.exe bridge byte for byte whatever this says.
	WindowsBridgeFailClosed bool

	// Selected reports whether an optional component is SELECTED (the
	// caller's component snapshot with its opt-in rule applied). A binding
	// with RegisterWhen is written only while Selected(its component) is
	// true, and a writer removes the entry Observer wrote for it when it is
	// not (the security feedback's post-tool events, lane sec-h). nil
	// means the caller holds no component state, and leaves opt-in events
	// alone: no writer adds one and none removes one Observer already wrote
	// (the generic settings entry stays, the plugin shim keeps the post
	// block it has, the Cline script stays). Only a caller that resolves
	// the selection (observer start, observer init) changes them. On a file
	// with no opt-in entry, nil writes what the writers wrote before the
	// field existed.
	Selected func(component string) bool

	// binaryWorks overrides hookBinaryWorks in tests.
	binaryWorks func(path string) bool

	// fileExists overrides the Windows hook-shell file probe in tests
	// (windowsshell.go); nil means os.Stat on a regular file.
	fileExists func(path string) bool

	// WindowsPATH returns the PERSISTENT Windows PATH (machine then user,
	// as a newly launched program inherits it), in the form the Windows
	// hook-shell check reads for this host: `;`-separated C:\... on a
	// Windows observer, `:`-separated /mnt/<drive>/... from WSL. ok=false
	// falls back to Getenv("PATH"). nil (every test, unless it injects one)
	// means no persistent read. Production passes PersistentWindowsPATH.
	WindowsPATH func() (path string, ok bool)

	// Getenv reads the relocation variables of the files the registry
	// writes (CLAUDE_CONFIG_DIR, CODEX_HOME, the plugin-shim hosts'
	// XDG_CONFIG_HOME and PI_CODING_AGENT_DIR, and every other rule on the
	// files' agentconfig rows). nil is the one pinned-home rule
	// (crossmount.HomeEnv, R-188 F1): os.Getenv only when HomeDir is not
	// pinned and the process home is not isolated
	// (crossmount.IsolationReason), and no variable otherwise, so a pinned
	// or isolated home resolves every file under itself. Production
	// callers pass nil.
	Getenv func(string) string

	// WSLDistro names the WSL distribution to invoke via wsl.exe when
	// registering hooks against a Windows-side config dir — the
	// "cursor-windows", "claude-code-windows" and "codex-windows"
	// targets. Required for those registration targets; ignored
	// elsewhere. Empty defaults to $WSL_DISTRO_NAME at registration
	// time when running inside WSL.
	WSLDistro string

	// WindowsCursorHome, when non-empty, overrides the auto-detected
	// Windows-side .cursor directory used by the cursor-windows
	// registration target. Default: the first crossmount-detected
	// Windows home with a .cursor/ subdirectory (`<home>/.cursor`).
	WindowsCursorHome string

	// WindowsClaudeHome, when non-empty, overrides the auto-detected
	// Windows-side .claude directory used by the claude-code-windows
	// registration target. Same shape as WindowsCursorHome: pass the
	// Windows USER home (e.g. /mnt/c/Users/<u>) — the registrar
	// appends `.claude` itself. Default: the first crossmount-detected
	// Windows home with a `.claude/` subdirectory.
	WindowsClaudeHome string

	// WindowsCodexHome, when non-empty, overrides the auto-detected
	// Windows-side .codex directory used by the codex-windows
	// registration target. Same shape as WindowsCursorHome /
	// WindowsClaudeHome: pass the Windows USER home (e.g.
	// /mnt/c/Users/<u>) — the registrar appends `.codex` itself.
	// Default: the first crossmount-detected Windows home with a
	// `.codex/` subdirectory.
	//
	// Note the name collision with proxyroute.RegisterOptions'
	// identically-named field: they name the same Windows home for two
	// DIFFERENT writers (that one writes config.toml's base_url, this
	// one writes hooks.json + [features].hooks). Callers that set both
	// must pass the same value so the two Windows writers agree.
	WindowsCodexHome string

	// WindowsGeminiHome / WindowsQwenHome / WindowsFactoryHome /
	// WindowsQoderHome / WindowsPoolsideHome / WindowsCommandCodeHome
	// mirror WindowsCodexHome for the six Part B item 1/2 long-tail
	// vendors' own cross-OS bridge targets (gemini-cli-windows,
	// qwen-code-windows, droid-windows, qoder-windows, poolside-windows,
	// command-code-windows) — pass the Windows USER home (e.g.
	// /mnt/c/Users/<u>); the registrar appends the tool's own subdir
	// itself (.gemini, .qwen, .factory, .qoder, .config/poolside,
	// .commandcode respectively). Default: the first crossmount-detected
	// Windows home carrying that subdir. Devin Desktop (Windsurf Cascade)
	// is grounded on Windows (LC29) and has its own bridge,
	// devin-windows, which resolves under WindowsUserHome
	// (register_crossos_ide.go, surface-gap IDE-6).
	WindowsGeminiHome      string
	WindowsQwenHome        string
	WindowsFactoryHome     string
	WindowsQoderHome       string
	WindowsPoolsideHome    string
	WindowsCommandCodeHome string

	// WindowsCopilotHome is the same for the copilot-cli-windows bridge
	// (the registrar appends .copilot/hooks itself). Default: the one
	// crossmount-detected Windows home, owned by the current Windows user,
	// carrying a .copilot directory.
	WindowsCopilotHome string
	// WindowsUserHome is the Windows USER home (e.g. /mnt/c/Users/<u>) the
	// 2026-10-21 wave's cross-OS targets (ibm-bob-windows,
	// codebuddy-windows, deepagents-code-windows, dimcode-windows,
	// dirac-windows, vtcode-windows) resolve their vendor directory under;
	// each appends its own subdir. Default: the first crossmount-detected
	// Windows home carrying that subdir.
	WindowsUserHome string
	// WSLUserHome is the Linux user home inside a WSL distro as this Windows
	// host reaches it (\\wsl.localhost\<distro>\home\<user>), the home every
	// Windows to WSL twin ("<tool>-wsl", register_crossos_wsl.go) writes
	// under. Default: the one WSL home crossmount sees that is proven the
	// operator's (the only user directory in its distro) and carries the
	// tool. Pass it to choose among several.
	WSLUserHome string
	// GOOS is the OS whose hook-file shapes a native registration writes
	// (Dirac's per-event script form, VT Code's config path, the Kimchi
	// bash gate). Empty means the running OS; tests pin it.
	GOOS string
}

// Registry is the per-tool registration dispatcher.
type Registry struct {
	opts Options
	// homeOverride is the caller-supplied Options.HomeDir VERBATIM, kept
	// before NewRegistry defaults it to the real $HOME. Non-empty means
	// "the caller pinned this registry's home", which switches OFF
	// crossmount auto-detection for the cross-OS targets — see
	// crossmount.AutoDetectSuppressed for the 2026-07-31 incident that
	// makes this load-bearing.
	homeOverride string
	// removing marks the copy Unregister works on: a removal never creates
	// anything, so its settings lock does not create a missing vendor
	// directory (lockSettings). Before T-742 (D-551) the lock's MkdirAll made
	// every component teardown leave an empty config directory per tool,
	// and the next `observer enroll --wire-clients` detected those as
	// installed tools and wired ~20 tools the machine never had.
	removing bool
	// foreignOSTwin marks the derived registry of a Windows to WSL twin
	// (register_crossos_wsl.go): its home is another OS's, so this host's
	// administrator hooks file is not a layer of it.
	foreignOSTwin bool
}

// NewRegistry returns a registry ready to install hooks.
func NewRegistry(opts Options) (*Registry, error) {
	if opts.BinaryPath == "" {
		return nil, errors.New("hook.NewRegistry: BinaryPath is required")
	}
	homeOverride := opts.HomeDir
	if opts.HomeDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("hook.NewRegistry: UserHomeDir: %w", err)
		}
		opts.HomeDir = home
	}
	opts.Getenv = crossmount.HomeEnv(homeOverride, opts.Getenv)
	return &Registry{opts: opts, homeOverride: homeOverride}, nil
}

// Installed reports which supported tools appear to be installed, based on
// the presence of their config directories. The "<tool>-windows" entries
// surface when crossmount detects an owned Windows-side .cursor/ /
// .claude/ / .codex/ directory (the observer is running in WSL while the
// AI client runs on Windows) — those targets register wsl.exe-launched
// hooks at the Windows path so the Windows process can invoke the
// WSL-side observer binary and its hook writes land in the daemon's own
// DB.
//
// A target switched off behind a live-check gate (livegate.go, DEC-12) is
// never listed, so `observer start`, `observer init` and the dashboard,
// which all iterate this list, never reach it; InstalledLiveGated names
// the detected gated targets for the doctor.
func (r *Registry) Installed() []string {
	tools, _ := splitLiveGated(r.installedAll(false))
	return tools
}

// installedAll is Installed before the live-check gate is applied. With
// includeGated false a gated cross-OS target is not even detected (its
// detection reads another OS's home); InstalledLiveGated passes true.
func (r *Registry) installedAll(includeGated bool) []string {
	var tools []string
	if r.claudeInstalled() {
		tools = append(tools, "claude-code")
	}
	if r.dirExists(filepath.Join(r.opts.HomeDir, ".cursor")) {
		tools = append(tools, "cursor")
	}
	if r.codexInstalled() {
		tools = append(tools, "codex")
	}
	// Part B item 1: Gemini CLI, Qwen Code, Factory Droid — probed the
	// same way as every other native dir-based install (no vendor
	// binary probe here; Installed() has never shelled out to a
	// tool's own CLI, it only checks for the config directory).
	if r.dirExists(filepath.Join(r.opts.HomeDir, ".gemini")) || r.homeArtifactExists("gemini-cli") {
		tools = append(tools, "gemini-cli")
	}
	// Antigravity CLI keeps its state under ~/.gemini/antigravity-cli; its
	// PreInvocation prompt hook (registerAntigravityCLI) is only written
	// when this signal puts the tool on the auto-register list. Missing
	// before 2026-10-03: demo node 1's `observer start` registered every
	// other hook but never wrote ~/.gemini/config/hooks.json.
	//
	// Surface-gap W-2c: the Antigravity App and IDE read the same
	// ~/.gemini/config/hooks.json, so their data directories are install
	// signals for this target too (agyHookFileReaderDirs). So is the
	// shared hooks file's own directory, resolved from the catalogued
	// artifact (WINNODE2 item 5b): the Google Antigravity VS Code
	// extension and the IDE never create antigravity-cli.
	if r.agyInstalled() {
		tools = append(tools, "antigravity-cli")
	}
	if r.dirExists(filepath.Join(r.opts.HomeDir, ".qwen")) || r.homeArtifactExists("qwen-code") {
		tools = append(tools, "qwen-code")
	}
	if r.dirExists(filepath.Join(r.opts.HomeDir, ".factory")) {
		tools = append(tools, "droid")
	}
	// Part B item 2 (phase-3a): Qoder, Poolside, Devin Desktop/Cascade —
	// same convention, config-directory presence only, no vendor binary
	// probe. zcode and commandcode are deliberately absent here: zcode's
	// writer doesn't exist (AutoWired:false pending a liveness probe)
	// and commandcode's registration target (~/.commandcode/mods/) is a
	// mods directory this repo creates itself on registration, not a
	// pre-existing install signal worth probing.
	if r.dirExists(filepath.Join(r.opts.HomeDir, ".qoder")) || r.homeArtifactExists("qoder") {
		tools = append(tools, "qoder")
	}
	if r.dirExists(filepath.Join(r.opts.HomeDir, ".config", "poolside")) {
		tools = append(tools, "poolside")
	}
	// devin: Windsurf / Devin Desktop (Cascade) or the Devin CLI (T-478).
	if r.dirExists(filepath.Join(r.opts.HomeDir, ".codeium", "windsurf")) || r.dirExists(r.devinCLIConfigDir()) {
		tools = append(tools, "devin")
	}
	if r.dirExists(filepath.Join(r.opts.HomeDir, ".commandcode")) {
		tools = append(tools, "command-code")
	}
	// Hook-parity Lane A6: the tool-gate-only mechanisms, each detected by
	// the vendor's own state directory (installedToolGateDirs), or the home
	// its catalogued artifact resolves to (homeArtifacts: the vendor's own
	// relocation variable, Goose's native Windows home).
	for _, d := range installedToolGateDirs {
		found := r.homeArtifactExists(d.tool)
		for _, rel := range d.dirs {
			if found {
				break
			}
			found = r.dirExists(filepath.Join(append([]string{r.opts.HomeDir}, rel...)...))
		}
		if found {
			tools = append(tools, d.tool)
		}
	}

	// Plugin-shim hosts (hook-parity Lane D): the same config-directory
	// presence convention, resolved per host row instead of per tool name:
	// the shim directory's PARENT is the vendor's own config directory
	// (~/.config/opencode, ~/.config/kilo, ~/.pi/agent or $PI_CODING_AGENT_DIR).
	tools = append(tools, r.installedPluginShimHosts()...)
	if r.detectWindowsCursorHome() != "" {
		tools = append(tools, "cursor-windows")
	}
	if r.detectWindowsClaudeHome() != "" {
		tools = append(tools, "claude-code-windows")
	}
	if r.detectWindowsCodexHome() != "" {
		tools = append(tools, "codex-windows")
	}
	// Part B item 1/2 cross-OS bridges: the same detection convention as
	// the three above, one per long-tail vendor that plausibly ships a
	// Windows-native client. Devin Desktop's bridge (devin-windows) is
	// listed with the Wave 7 IDE targets below.
	if r.detectWindowsGeminiHome() != "" {
		tools = append(tools, "gemini-cli-windows")
	}
	if r.detectWindowsQwenHome() != "" {
		tools = append(tools, "qwen-code-windows")
	}
	if r.detectWindowsFactoryHome() != "" {
		tools = append(tools, "droid-windows")
	}
	if r.detectWindowsQoderHome() != "" {
		tools = append(tools, "qoder-windows")
	}
	if r.detectWindowsPoolsideHome() != "" {
		tools = append(tools, "poolside-windows")
	}
	if r.detectWindowsCommandCodeHome() != "" {
		tools = append(tools, "command-code-windows")
	}
	if r.detectWindowsCopilotHome() != "" {
		tools = append(tools, "copilot-cli-windows")
	}
	// The 2026-10-21 wave's cross-OS bridges (waveCrossOSTargets).
	tools = append(tools, r.installedWaveWindows()...)
	// The Windows to WSL twins (register_crossos_wsl.go); gated.
	tools = append(tools, r.installedWSLTwins(includeGated)...)
	// The Wave 7 IDE targets (register_crossos_ide.go); gated.
	tools = append(tools, r.installedIDETargets(includeGated)...)
	// The Xcode agent homes (register_xcode.go); gated.
	tools = append(tools, r.installedXcodeTargets(includeGated)...)
	return tools
}

// InstalledOutOfBand returns the detected hosts whose hooks are installed by
// their own installer rather than by Register (today Hermes, whose plugin
// directory and config.yaml are written by RegisterHermes /
// `observer init --hermes`). Same convention as Installed: a host counts
// only when its vendor home exists, here the directory the installer would
// write into. Kept off Installed() because Register cannot serve them.
func (r *Registry) InstalledOutOfBand() []string {
	var tools []string
	if h := hermesHomeFrom(r.opts.Getenv, r.opts.HomeDir, runtime.GOOS); h != "" && r.dirExists(h) {
		tools = append(tools, "hermes")
	}
	return tools
}

func (r *Registry) dirExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

// hookTargetWriters are the per-target registrars of the hook writers that
// are not tool-gate-only (modular packaging P5, lane MP-ADP: "hook register
// switch to a map"): one row per Registry target, cross-OS "-windows"
// targets included, so Register and Unregister are one lookup each and a
// target is added or removed as a row. A target in neither table falls
// through to the plugin-shim capability, else it is refused.
var hookTargetWriters = map[string]struct {
	register   func(*Registry) RegistrationResult
	unregister func(*Registry) UnregistrationResult
}{
	"claude-code":          {(*Registry).registerClaudeCode, (*Registry).unregisterClaudeCode},
	"claude-code-windows":  {(*Registry).registerClaudeCodeWindows, (*Registry).unregisterClaudeCodeWindows},
	"cursor":               {(*Registry).registerCursor, (*Registry).unregisterCursor},
	"cursor-windows":       {(*Registry).registerCursorWindows, (*Registry).unregisterCursorWindows},
	"codex":                {(*Registry).registerCodex, (*Registry).unregisterCodex},
	"codex-windows":        {(*Registry).registerCodexWindows, (*Registry).unregisterCodexWindows},
	"gemini-cli":           {(*Registry).registerGeminiCLI, (*Registry).unregisterGeminiCLI},
	"gemini-cli-windows":   {(*Registry).registerGeminiCLIWindows, (*Registry).unregisterGeminiCLIWindows},
	"qwen-code":            {(*Registry).registerQwenCode, (*Registry).unregisterQwenCode},
	"qwen-code-windows":    {(*Registry).registerQwenCodeWindows, (*Registry).unregisterQwenCodeWindows},
	"droid":                {(*Registry).registerFactoryDroid, (*Registry).unregisterFactoryDroid},
	"droid-windows":        {(*Registry).registerFactoryDroidWindows, (*Registry).unregisterFactoryDroidWindows},
	"qoder":                {(*Registry).registerQoder, (*Registry).unregisterQoder},
	"qoder-windows":        {(*Registry).registerQoderWindows, (*Registry).unregisterQoderWindows},
	"poolside":             {(*Registry).registerPoolside, (*Registry).unregisterPoolside},
	"poolside-windows":     {(*Registry).registerPoolsideWindows, (*Registry).unregisterPoolsideWindows},
	"devin":                {(*Registry).registerDevinAll, (*Registry).unregisterDevinAll},
	"command-code":         {(*Registry).registerCommandCodeAll, (*Registry).unregisterCommandCodeAll},
	"command-code-windows": {(*Registry).registerCommandCodeWindowsAll, (*Registry).unregisterCommandCodeWindowsAll},
	"antigravity-cli":      {(*Registry).registerAntigravityCLI, (*Registry).unregisterAntigravityCLI},
	// Surface-gap Wave 7 IDE targets (register_crossos_ide.go); gated.
	"antigravity-cli-windows": {(*Registry).registerAntigravityCLIWindows, (*Registry).unregisterAntigravityCLIWindows},
	"devin-windows":           {(*Registry).registerDevinWindows, (*Registry).unregisterDevinWindows},
	"devin-jetbrains":         {(*Registry).registerDevinJetBrains, (*Registry).unregisterDevinJetBrains},
	// The Xcode agent homes (register_xcode.go, FU-145, FU-160); the Gemini
	// one stays off on LCR-91's finding (no BeforeTool, FU-195).
	"claude-code-xcode": {(*Registry).registerClaudeCodeXcode, (*Registry).unregisterClaudeCodeXcode},
	"codex-xcode":       {(*Registry).registerCodexXcode, (*Registry).unregisterCodexXcode},
	"gemini-cli-xcode":  {(*Registry).registerGeminiCLIXcode, (*Registry).unregisterGeminiCLIXcode},
	// The 2026-10-21 wave (register_wave1021*.go).
	"ibm-bob":                 {(*Registry).registerIBMBob, (*Registry).unregisterIBMBob},
	"ibm-bob-windows":         waveWindowsWriter("ibm-bob"),
	"codebuddy":               {(*Registry).registerCodeBuddy, (*Registry).unregisterCodeBuddy},
	"codebuddy-windows":       waveWindowsWriter("codebuddy"),
	"deepagents-code":         {(*Registry).registerDeepAgents, (*Registry).unregisterDeepAgents},
	"deepagents-code-windows": waveWindowsWriter("deepagents-code"),
	"dimcode":                 {(*Registry).registerDimCode, (*Registry).unregisterDimCode},
	"dimcode-windows":         waveWindowsWriter("dimcode"),
	"dirac":                   {(*Registry).registerDirac, (*Registry).unregisterDirac},
	"dirac-windows":           waveWindowsWriter("dirac"),
	"autohand":                {(*Registry).registerAutohand, (*Registry).unregisterAutohand},
	"vtcode":                  {(*Registry).registerVTCode, (*Registry).unregisterVTCode},
	"vtcode-windows":          waveWindowsWriter("vtcode"),
	"kimchi":                  {(*Registry).registerKimchi, (*Registry).unregisterKimchi},
}

// waveWindowsWriter is the hookTargetWriters row of a 2026-10-21 wave
// "-windows" target.
func waveWindowsWriter(tool string) struct {
	register   func(*Registry) RegistrationResult
	unregister func(*Registry) UnregistrationResult
} {
	return struct {
		register   func(*Registry) RegistrationResult
		unregister func(*Registry) UnregistrationResult
	}{
		func(r *Registry) RegistrationResult { return r.registerWaveWindows(tool) },
		func(r *Registry) UnregistrationResult { return r.unregisterWaveWindows(tool) },
	}
}

// toolGateWriters are the hook-parity Lane A4-A6 tool-gate-only writers,
// one row per Registry target: a table so Register and Unregister stay flat
// as targets are added (Integration 5: the merged switch crossed the
// gocyclo limit once Lane D's plugin-shim default joined Lane A's cases).
var toolGateWriters = map[string]struct {
	register   func(*Registry) RegistrationResult
	unregister func(*Registry) UnregistrationResult
}{
	"grok":        {(*Registry).registerGrok, (*Registry).unregisterGrok},
	"copilot-cli": {(*Registry).registerCopilotCLI, (*Registry).unregisterCopilotCLI},
	// The cross-OS bridge (live check 2026-10-20): a WSL daemon wiring the
	// Windows Copilot CLI, which had no Observer hook at all.
	"copilot-cli-windows": {(*Registry).registerCopilotCLIWindows, (*Registry).unregisterCopilotCLIWindows},
	"goose":               {(*Registry).registerGoose, (*Registry).unregisterGoose},
	"junie":               {(*Registry).registerJunie, (*Registry).unregisterJunie},
	"crush":               {(*Registry).registerCrush, (*Registry).unregisterCrush},
	"open-interpreter":    {(*Registry).registerOpenInterpreter, (*Registry).unregisterOpenInterpreter},
	"zcode":               {(*Registry).registerZcode, (*Registry).unregisterZcode},
	"mistral-code":        {(*Registry).registerMistralVibe, (*Registry).unregisterMistralVibe},
	"cline-cli":           {(*Registry).registerCline, (*Registry).unregisterCline},
	"muse":                {(*Registry).registerMuse, (*Registry).unregisterMuse},
	"kimi-code":           {(*Registry).registerKimiCode, (*Registry).unregisterKimiCode},
	"kiro-cli":            {(*Registry).registerKiroCLI, (*Registry).unregisterKiroCLI},
}

// Register installs observer hooks into the config file for tool. Supported
// values: "claude-code", "claude-code-windows", "cursor", "cursor-windows",
// "codex", "codex-windows". Unknown tools return an error. A target whose
// registry row declares the credential-file exception
// (integration.HookSpec.HooksShareCredentialFile) also runs under
// guardCredentialRegistration (credentialfile.go). A target switched off
// behind a live-check gate (liveGateRefusal: its registry row's or its
// cross-OS target row's) writes nothing and returns a SkipLiveGated result
// instead, whoever calls it.
func (r *Registry) Register(tool string) RegistrationResult {
	if res, gated := r.liveGateRefusal(tool); gated {
		return res
	}
	return r.withWindowsShellWarning(tool, r.guardCredentialRegistration(tool, r.register(tool)))
}

// register dispatches Register to tool's writer.
func (r *Registry) register(tool string) RegistrationResult {
	if row, ok := wslTwinFor(tool); ok {
		return r.registerWSLTwin(row)
	}
	if w, ok := toolGateWriters[tool]; ok {
		return w.register(r)
	}
	if w, ok := hookTargetWriters[tool]; ok {
		return w.register(r)
	}
	if c, ok := pluginShimCapability(tool); ok {
		return r.registerPluginShim(c)
	}
	return RegistrationResult{
		Tool:   tool,
		Error:  fmt.Errorf("hook.Register: tool %q not supported for hook registration", tool),
		DryRun: r.opts.DryRun,
	}
}

// isObserverAnyHookEntry reports whether cmd is an observer
// `hook <tool> <event>` invocation in EITHER shape observer writes:
//
//   - native, as a Windows-native npm install writes it —
//     `C:\...\observer.exe hook cursor stop --config C:\...\config.toml`
//     (forward- or back-slashed, quoted or bare);
//   - the cross-OS bridge, as the `*-windows` registrars write it —
//     `[MSYS_NO_PATHCONV=1 ]wsl.exe -d <distro> -- /home/<u>/observer
//     hook cursor stop --config /home/<u>/.observer/config.toml`, or the
//     portable form (portableBridgeCommand) with `//`-escaped paths and a
//     trailing `; exit $LASTEXITCODE`.
//
// tool is the hook vocabulary token: "claude-code", "cursor" or
// "codex".
//
// This is the ownership predicate the cross-OS `*-windows` registrars
// need (class C2, docs/plans/ide-surface-capture-remediation-plan-2026-09-02.md
// §1). Before it, those registrars recognised ONLY the wsl.exe shape, so a
// NATIVE observer entry left behind by an earlier Windows-native npm
// `observer init` was classified FOREIGN: the bridge registration refused
// without --force and the stale native entry kept writing the stranded
// Windows DB — the split-brain class CLAUDE.md's "Don't try to bridge
// cross-OS hook capture at the storage layer" describes, observed live as
// audit finding IDE-11.
//
// Recognition is TOKEN-based, not substring-based: after stripping any
// leading `KEY=VALUE` env assignments and the `wsl.exe -d <distro> --`
// bridge prefix (stripHookCommandPrefix), argv[0] must NAME an observer
// binary (isObserverBinaryToken) and be followed by exactly the tokens
// `hook` `<tool>`. That strictness is what makes it safe to widen the
// Windows registrars' "ours" test: a genuinely foreign command — including
// one that merely CONTAINS ` hook cursor ` somewhere, like
// `/opt/acme/audit --note "run hook cursor stop"` — still fails argv[0]
// and is still protected by the --force conflict guard.
func isObserverAnyHookEntry(cmd, tool string) bool {
	if observerHookInvocation(cmd, tool) {
		return true
	}
	// Retry on the forward-slash-normalized command. splitCommandTokens
	// is a POSIX tokenizer, so an UNQUOTED Windows path collapses under
	// its backslash-escape rule (`C:\Users\u\observer.exe` tokenizes to
	// `C:Usersuobserver.exe`) and a genuine native registration would
	// read as foreign purely because of the quoting style whoever wrote
	// it happened to use. Forward slashes are never escapes in any of
	// the shells involved, and swapping separators can only change what
	// the BASENAME of argv[0] is — it can't invent the `hook <tool>`
	// argument pair — so the retry stays as strict as the first pass.
	if strings.Contains(cmd, `\`) {
		return observerHookInvocation(strings.ReplaceAll(cmd, `\`, "/"), tool)
	}
	return false
}

// IsObserverHookCommand reports whether cmd is a hook command Observer
// registers for any tool: isObserverAnyHookEntry asked with the tool token
// the command itself names after `hook`. It is the one recogniser the
// repository trust user-scope baseline uses to leave Observer's own hook
// entries out of what it reports as new (plans decision log P-037).
func IsObserverHookCommand(cmd string) bool {
	for _, c := range []string{cmd, strings.ReplaceAll(cmd, `\`, "/")} {
		toks := stripHookCommandPrefix(splitCommandTokens(c))
		if len(toks) >= 3 && toks[1] == "hook" && toks[2] != "" {
			return isObserverAnyHookEntry(cmd, toks[2])
		}
	}
	return false
}

// IsObserverStatuslineCommand reports whether cmd is the status line
// command Observer registers (isObserverStatuslineEntry).
func IsObserverStatuslineCommand(cmd string) bool { return isObserverStatuslineEntry(cmd) }

// IsObserverBinary reports whether an executable token names an observer
// binary by its base name (isObserverBinaryToken).
func IsObserverBinary(tok string) bool { return isObserverBinaryToken(tok) }

// observerHookInvocation is isObserverAnyHookEntry's single tokenized
// test: strip env assignments + any wsl.exe bridge prefix, then require
// argv[0] to name an observer binary followed by `hook <tool>`.
func observerHookInvocation(cmd, tool string) bool {
	cmd, _ = trimBridgeExitTrailer(cmd)
	toks := stripHookCommandPrefix(splitCommandTokens(cmd))
	if len(toks) < 3 {
		return false
	}
	return isObserverBinaryToken(toks[0]) && toks[1] == "hook" && toks[2] == tool
}

// stripHookCommandPrefix removes a leading PowerShell call operator `&`, the
// leading `KEY=VALUE` environment
// assignments and, if present, the `wsl.exe -d <distro> --` bridge that
// registerClaudeCodeWindows writes, returning the tokens of the command
// actually executed. Returns nil when a bridge prefix is present but
// malformed (no `--` separator), so a half-understood command is never
// treated as ours.
func stripHookCommandPrefix(toks []string) []string {
	// PowerShell's call operator, which the native Codex writer puts before
	// a quoted Windows binary (codexHookExe).
	if len(toks) > 1 && toks[0] == "&" {
		toks = toks[1:]
	}
	for len(toks) > 0 && strings.Contains(toks[0], "=") &&
		!strings.ContainsAny(toks[0], `/\`) {
		toks = toks[1:]
	}
	if len(toks) == 0 {
		return nil
	}
	base := strings.ToLower(strings.TrimSuffix(commandBaseName(toks[0]), ".exe"))
	if base != "wsl" {
		return toks
	}
	for i, t := range toks {
		if t == "--" {
			return toks[i+1:]
		}
	}
	return nil
}

// shellQuoteIfNeeded wraps s in single quotes when it contains
// shell-meaningful characters, otherwise returns it verbatim. Used
// for the WSL distro name in the registered hook command — distro
// names like "Ubuntu-20.04" are bare-safe; weirder names (with
// spaces or quotes) would need escaping.
//
// POSIX-strict — single-quote disables ALL shell interpretation
// (no `$VAR` expansion, no backtick substitution). Correct for
// Claude Code (always Git Bash on Windows; POSIX everywhere else)
// and the WSL-bridge registrars. WRONG for cmd.exe — cmd interprets
// `'...'` literally as part of the argument, which is why Codex on
// Windows needs the codex-specific quoter below.
func shellQuoteIfNeeded(s string) string {
	if s == "" {
		return "''"
	}
	for _, r := range s {
		if r == ' ' || r == '\'' || r == '"' || r == '`' || r == '\\' || r == '$' {
			return shellQuote(s)
		}
	}
	if strings.ContainsAny(s, "*?[](){};&|<>") {
		return shellQuote(s)
	}
	return s
}

// maxSettingsFileBytes caps how large a JSON settings/config file we are
// willing to read into memory before patching it. A real
// `settings.json` is kilobytes; anything past this is either a mistake
// (a log accidentally redirected onto the path) or hostile, and reading
// it unbounded would be a trivial memory-exhaustion foot-gun on a
// process the user runs on their own machine. Over-cap files are
// REFUSED (never truncated, never partially parsed) so we can't
// silently rewrite a file we only half-understood.
const maxSettingsFileBytes int64 = 5 << 20 // 5 MiB

// readSettingsFile reads a JSON settings/config file with the
// maxSettingsFileBytes guard applied via Stat BEFORE the read. Callers
// keep their own os.ErrNotExist handling — a missing file returns the
// wrapped fs.ErrNotExist from Stat, exactly as os.ReadFile would.
//
// Only a regular file is read, through the bounded reader
// (regularfile.Read: opened non-blocking, re-checked on the descriptor,
// capped): a FIFO, device or directory at a settings path is refused
// instead of hanging `observer init` or `uninstall` on the read. The
// refusals are composed from the path and the limit only (safeErrorf).
// settingsFileRead is the bounded read behind readSettingsFile (a variable
// so a test can return each error class without a real unreadable file).
var settingsFileRead = regularfile.Read

func readSettingsFile(path string) ([]byte, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, safeErrorf("%s is not a regular file (a FIFO, a device or a directory); refusing to read or modify it", path)
	}
	if fi.Size() > maxSettingsFileBytes {
		return nil, safeErrorf("%s is %d bytes, over observer's %d-byte settings-file limit; refusing to read or modify it", path, fi.Size(), maxSettingsFileBytes)
	}
	b, err := settingsFileRead(path, maxSettingsFileBytes)
	switch {
	case err == nil:
		return b, nil
	case errors.Is(err, os.ErrNotExist):
		return nil, err
	case errors.Is(err, regularfile.ErrNotRegular), errors.Is(err, regularfile.ErrTooLarge):
		return nil, safeErrorf("%s changed while it was read (it is no longer a regular file of at most %d bytes); refusing to read or modify it", path, maxSettingsFileBytes)
	case errors.Is(err, fs.ErrPermission):
		return nil, safeErrorf("%s is unreadable (permission denied); refusing to modify it", path)
	}
	return nil, safeErrorf("%s is unreadable (an I/O error while reading it); refusing to modify it", path)
}

// decodeSettingsObject decodes a settings/config file body into the
// top-level-key-preserving map every registrar patches, refusing two
// shapes that a plain json.Unmarshal accepts but that we cannot
// round-trip honestly:
//
//   - An explicit JSON `null`. Unmarshalling null into a map sets the
//     map to NIL (encoding/json's documented behaviour for maps,
//     slices, pointers and interfaces), so the very next
//     `settings[key] = ...` in a registrar PANICS with "assignment to
//     entry in nil map". Treating null as `{}` would be the other
//     obvious fix, but it isn't honest: an explicit null is not a
//     settings object, and silently replacing it with our own object
//     discards a deliberate (if odd) user statement about the file.
//     Refuse and name the file.
//   - Duplicate top-level keys. encoding/json keeps the LAST
//     occurrence, so a read-modify-write silently collapses the file
//     and destroys whichever duplicate the user's other tool was
//     reading. Detected by token-walking the top level (json.Decoder)
//     rather than by parsing into a map, which is exactly the
//     information json.Unmarshal throws away.
//
// Error text keeps the existing `parse <path>: <json error>` shape for
// genuinely malformed JSON so registrar error messages are unchanged.
func decodeSettingsObject(path string, raw []byte) (map[string]json.RawMessage, error) {
	settings := map[string]json.RawMessage{}
	if err := json.Unmarshal(raw, &settings); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if settings == nil {
		return nil, safeErrorf("%s contains an explicit JSON null, not a settings object; refusing to modify it (replace its contents with {} or delete the file)", path)
	}
	if key, ok := duplicateTopLevelKey(raw); ok {
		return nil, safeErrorf("%s has a duplicate top-level %q key; refusing to modify it because rewriting would silently keep only the last one (de-duplicate the file by hand first)", path, key)
	}
	return settings, nil
}

// duplicateTopLevelKey token-walks the top-level object of raw and
// reports the first key that appears twice. Syntax errors are reported
// as "no duplicate" — decodeSettingsObject has already surfaced them
// through json.Unmarshal, and this helper's only job is the one thing
// Unmarshal cannot tell us.
func duplicateTopLevelKey(raw []byte) (string, bool) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return "", false
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return "", false
	}
	seen := make(map[string]struct{})
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return "", false
		}
		key, ok := kt.(string)
		if !ok {
			return "", false
		}
		if _, dup := seen[key]; dup {
			return key, true
		}
		seen[key] = struct{}{}
		// Consume the value wholesale (any nesting) without decoding it.
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			return "", false
		}
	}
	return "", false
}

// settingsLockSuffix is appended to a settings/config path to form its
// advisory lock file. Deliberately NOT ".lock" alone: the file sits
// beside the real config in a directory the AI tool also reads, so the
// name has to be unmistakably ours.
const settingsLockSuffix = ".observer-lock"

// settingsLockStale is how long a lock file may go untouched before a
// waiting process treats it as abandoned (a crashed observer) and
// breaks it. Registration is a sub-millisecond read-modify-write, so
// anything this old is dead by definition.
const settingsLockStale = 30 * time.Second

// settingsLockTimeout bounds how long we wait for another observer
// process to finish its read-modify-write before giving up with an
// error rather than racing it.
const settingsLockTimeout = 5 * time.Second

// lockSettings acquires the advisory lock for a settings/config file
// this Registry is about to read-modify-write, returning the releaser.
// Dry runs never write, so they never lock (and never leave a lock
// file behind in a directory a --dry-run must not touch).
func (r *Registry) lockSettings(path string) (func(), error) {
	if r.opts.DryRun {
		return func() {}, nil
	}
	if r.removing {
		return LockSettingsFileIfPresent(path)
	}
	return lockSettingsFile(path)
}

// LockSettingsFileIfPresent is LockSettingsFile for a REMOVAL: when the
// file's directory does not exist there is nothing of Observer's to remove
// and nothing to race on, so it returns a no-op releaser and creates nothing
// (T-742, D-551). LockSettingsFile itself creates the directory, which is
// right for a write and wrong for an undo.
func LockSettingsFileIfPresent(path string) (func(), error) {
	if !dirPresent(filepath.Dir(path)) {
		return func() {}, nil
	}
	return lockSettingsFile(path)
}

// dirPresent reports whether p is an existing directory.
func dirPresent(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

// lockSettingsFile takes a cross-process advisory lock on path by
// O_CREATE|O_EXCL-creating `<path>.observer-lock`, breaking locks older
// than settingsLockStale, and giving up after settingsLockTimeout. The
// O_EXCL sentinel (rather than flock/LockFileEx) is deliberate: it is
// one code path on every OS this ships to, with no syscall build tags,
// and matches internal/diag/lockfile.go's existing file-based
// convention.
//
// FAIL-OPEN: any error other than "already exists" (a read-only
// directory, an exotic filesystem that rejects O_EXCL) returns a no-op
// releaser and no error — registration proceeds unserialized rather
// than breaking on filesystems where the lock cannot be represented.
// Losing serialization is strictly better than losing the ability to
// register hooks at all.
//
// RESIDUAL, disclosed honestly: this serializes OBSERVER's own writers
// against each other (two `observer init` runs, an init racing a
// `observer start` auto-register). It cannot serialize us against
// Claude Code / Cursor themselves — they write settings.json without
// consulting any lock, so a genuinely concurrent edit by the AI tool
// can still be lost. Closing that would need the tool's cooperation;
// the atomic temp+rename below at least guarantees the file is never
// observed half-written.
func lockSettingsFile(path string) (func(), error) {
	// Test-binary write guard (incident 2026-10-20): refused BEFORE the lock
	// file is created, so a test can never leave even a sentinel in a real
	// config directory. Not fail-open: the caller writes nothing.
	if err := testwriteguard.Check("write", path); err != nil {
		return func() {}, err
	}
	lockPath := path + settingsLockSuffix
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o755); err != nil {
		return func() {}, nil // fail-open: see docstring
	}
	ownerID := lockOwnerToken()
	deadline := time.Now().Add(settingsLockTimeout)
	for {
		f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			_, _ = f.WriteString(ownerID)
			_ = f.Close()
			return func() { unlockSettingsFile(lockPath, ownerID) }, nil
		}
		// lockCreateHeld (lockfs_*.go): "exists", and on Windows the
		// access-denied and sharing errors a lock being released gives.
		if !lockCreateHeld(err) {
			return func() {}, nil // fail-open: see docstring
		}
		if !errors.Is(err, os.ErrExist) && time.Now().After(deadline) {
			// Refused the whole time and no lock file is there: the
			// directory itself refuses the create (fail-open, docstring).
			if _, serr := os.Lstat(lockPath); errors.Is(serr, os.ErrNotExist) {
				return func() {}, nil
			}
		}
		// Held by someone else. Break it if it looks abandoned —
		// ownership-verified so a concurrent breaker can't win an ABA
		// race against a legitimate new owner (see breakStaleLock).
		// observeStaleLock pairs the mtime check and the content read
		// through ONE open file description, so what we hand to
		// breakStaleLock as "the specific lock instance we observed as
		// stale" is exactly that — not a fresh read taken later, which
		// would instead describe whatever happens to be at lockPath by
		// the time breakStaleLock runs (possibly a legitimate new
		// owner's lock, acquired in the gap between this check and the
		// break).
		if observed, stale := observeStaleLock(lockPath); stale {
			breakStaleLock(lockPath, observed)
		}
		if time.Now().After(deadline) {
			return nil, safeErrorf("timed out after %s waiting for %s (another observer process is writing %s; delete the lock file if no observer is running)", settingsLockTimeout, lockPath, path)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// LockSettingsFile is the exported entry to the cross-process advisory lock
// every hook registration writer takes around its read-modify-write of a
// vendor settings/config file (lockSettingsFile; same suffix, staleness,
// timeout and fail-open rules). Any other Observer writer of the same files
// (a dashboard settings editor, for one) must take this lock too, so it
// serializes against registration instead of racing it. Call the returned
// releaser when the write is done.
func LockSettingsFile(path string) (func(), error) { return lockSettingsFile(path) }

// lockOwnerToken returns a fresh, unique owner identity for a
// newly-acquired settings lock, written verbatim as the lock file's
// entire body: "pid=<pid> nonce=<hex> acquired=<RFC3339Nano>\n". The
// pid+timestamp give a human inspecting a stray lock file the same
// debugging context the previous "pid=%d acquired=%s" body gave; the
// random nonce is what makes the returned string usable as a
// compare-and-delete identity (F7) — two different acquisitions of
// the SAME lock path, even by the same pid moments apart, get
// different identities, so "does the file still hold this exact
// string" is a reliable test for "is this still the lock instance I
// created/observed".
func lockOwnerToken() string {
	return fmt.Sprintf("pid=%d nonce=%s acquired=%s\n", os.Getpid(), randomHex(16), time.Now().UTC().Format(time.RFC3339Nano))
}

// randomHex returns n random bytes hex-encoded. crypto/rand.Read is
// documented to never fail on any platform Go supports; the
// time-derived fallback only exists so a theoretical read error can't
// turn a lock/quarantine helper into a panicking code path — it is
// still unique-enough for a same-process, single-call-site use to
// avoid a same-nanosecond collision.
func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// observeStaleLock pairs "is lockPath abandoned" with "what does it
// currently contain" into a single atomic observation, by checking
// mtime and reading content off the SAME open file description rather
// than a separate os.Stat + a later os.ReadFile against the pathname.
// Two syscalls issued against a pathname a moment apart can straddle
// a concurrent unlock+relock (the file at that path is a different
// inode by the second syscall); reading from the fd returned by Open
// pins us to the exact inode that mtime was measured against. The
// remaining pathname-level race — a different file existing at
// lockPath by the time Open runs than whatever failed our O_EXCL
// attempt moments earlier — is inherent to any check-then-act sequence
// over a path and is what breakStaleLock's rename-and-reverify closes.
func observeStaleLock(lockPath string) (content []byte, stale bool) {
	// A handle-free look first: a contender that opens a live lock on
	// every poll blocks its holder's delete on Windows (sharing
	// violation), so the file is opened only when it already looks stale.
	if fi, err := os.Stat(lockPath); err != nil || time.Since(fi.ModTime()) <= settingsLockStale {
		return nil, false
	}
	f, err := os.Open(lockPath)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || time.Since(fi.ModTime()) <= settingsLockStale {
		return nil, false
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, false
	}
	return data, true
}

// breakStaleLock attempts to remove a settings lock that
// observeStaleLock has already confirmed looks abandoned, using an
// ownership-verified rename-then-recheck protocol that closes F7's
// ABA race: two contenders observing the same stale lock must not
// both conclude they broke it, and neither may remove a lock that was
// legitimately (re-)acquired between the staleness observation and
// the break.
//
// observed is exactly what observeStaleLock captured — "the specific
// lock instance we observed as stale" — NOT a fresh read taken here;
// re-reading at break time would instead describe whatever happens to
// occupy lockPath by the time this function runs, which could by then
// be a brand new, legitimately-held lock.
//
//  1. Atomically rename lockPath to a unique quarantine path beside
//     it. Rename only succeeds if a source still exists at that
//     instant, so of any number of concurrent breakers racing the
//     same stale lock, AT MOST ONE wins the rename — everyone else
//     gets ENOENT and falls through having removed nothing (no
//     double-break, no partial state). On Windows several renames can
//     succeed in a chain (a breaker that opened the source first moves
//     it on under its new name); every breaker but the last then finds
//     its quarantine gone and returns, so the last one decides alone.
//  2. Read the quarantined file and compare its bytes to observed.
//     Equal confirms the rename moved the SAME lock instance we
//     originally observed as stale — lock files are write-once
//     (created via O_EXCL, never rewritten in place, only unlinked on
//     release), so identical content after an atomic rename can only
//     mean nothing replaced it between our observation and our
//     rename. Safe to discard for good.
//  3. Unequal (or the source was already gone) means either another
//     breaker won first, or the rename actually moved a DIFFERENT,
//     freshly (and legitimately) acquired lock — the process we
//     originally observed as stale must have cleanly unlocked
//     (identity-verified by unlockSettingsFile) right as we moved to
//     break it, and a new owner raced in before our rename executed.
//     We did not "consume" anything that was ours to take;
//     best-effort restore it — only when the path is free again,
//     never clobbering whatever a still-newer owner may have created
//     since — and log the near-miss rather than silently discarding a
//     live lock.
func breakStaleLock(lockPath string, observed []byte) {
	quarantine := fmt.Sprintf("%s.broken-%d-%s", lockPath, os.Getpid(), randomHex(8))
	if err := os.Rename(lockPath, quarantine); err != nil {
		// Lost the race: someone else's break (or a legitimate
		// unlock+recreate) already moved/removed the source first.
		return
	}
	current, readErr := readQuarantinedLock(quarantine)
	if errors.Is(readErr, os.ErrNotExist) {
		// Lost the race after all. On Windows a rename is not an atomic
		// claim against a concurrent rename of the same source: a breaker
		// that opened lockPath before our rename still moves the file,
		// under its new name, into its own quarantine, so our rename can
		// succeed and the file then leave our path. That breaker reads
		// and decides; we hold nothing. (No one else knows our random
		// quarantine name, so this cannot happen on POSIX.)
		return
	}
	if readErr == nil && bytes.Equal(current, observed) {
		// Confirmed: this was genuinely the same stale-lock instance
		// we decided to break. Discard it for good.
		_ = os.Remove(quarantine)
		return
	}
	// We quarantined a lock we can't prove is the one we observed —
	// almost certainly a legitimate new owner that raced in between
	// our staleness read and our rename. Restore it if the path is
	// free again so that owner's eventual unlock still finds its own
	// lock; never overwrite whatever a still-newer owner has since
	// created there.
	if _, statErr := os.Lstat(lockPath); errors.Is(statErr, os.ErrNotExist) {
		if renameErr := os.Rename(quarantine, lockPath); renameErr == nil {
			slog.Default().Warn("hook: stale-lock break caught a live lock instead of an abandoned one; restored it", "lock_path", lockPath)
			return
		}
	}
	slog.Default().Warn("hook: stale-lock break caught a live lock instead of an abandoned one and could not restore it; its owner may need to retry", "lock_path", lockPath)
	_ = os.Remove(quarantine)
}

// quarantineReadAttempts and quarantineReadBackoff bound how long
// readQuarantinedLock waits out a peer that holds the quarantined file
// open.
const (
	quarantineReadAttempts = 20
	quarantineReadBackoff  = 2 * time.Millisecond
)

// readQuarantinedLock reads the lock file breakStaleLock just renamed to
// quarantine. A read that fails for any reason but the file being gone is
// retried briefly: on Windows a concurrent breaker's rename of the same
// file holds it open (a sharing violation here), and once that rename
// lands the file is gone from our path (os.ErrNotExist, we lost) or the
// rename failed and the read succeeds. Treating the transient failure as
// "a live lock" restored a stale lock to lockPath under contention.
func readQuarantinedLock(quarantine string) ([]byte, error) {
	var (
		b   []byte
		err error
	)
	for i := 0; i < quarantineReadAttempts; i++ {
		b, err = os.ReadFile(quarantine)
		if err == nil || errors.Is(err, os.ErrNotExist) {
			return b, err
		}
		time.Sleep(quarantineReadBackoff)
	}
	return b, err
}

// unlockSettingsFile releases a lock previously acquired by
// lockSettingsFile, but only after verifying the lock file still
// holds the exact identity string this holder wrote at acquisition
// time — closing F7's second half. Without this, an unconditional
// os.Remove here would delete a SUCCESSOR's lock out from under it
// whenever this holder's own lock was (mistakenly or not) broken
// while still held — e.g. a slow read-modify-write that ran past
// settingsLockStale and got broken by a waiting contender, then
// finished its work and called unlock believing it still owned the
// file. A mismatch (or the file already being gone) means this holder
// no longer owns the lock: log and skip, never remove.
func unlockSettingsFile(lockPath, ownerID string) {
	current, err := os.ReadFile(lockPath)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			slog.Default().Warn("hook: could not verify lock ownership before unlock", "lock_path", lockPath, "error", err)
		}
		return
	}
	if string(current) != ownerID {
		slog.Default().Warn("hook: lock file no longer matches this holder's identity at unlock time; leaving it alone (owned by a successor)", "lock_path", lockPath)
		return
	}
	removeLockFile(lockPath)
}

// pinnedTarget captures, at a single instant right after a settings
// lock is acquired and BEFORE the file is read, which physical file a
// write to `path` will land on — closing F6's symlink-retarget race.
// Resolving the symlink target separately at write time (the old
// resolveWriteTarget, called fresh inside writeJSONIndented /
// atomicWriteFile) let a link retargeted between the read and the
// write silently redirect a patch built from target A's content onto
// target B. Callers now resolve ONCE via pinWriteTarget immediately
// after locking, thread the same pinnedTarget through the read and
// the write, and call verifyUnmoved() immediately before the final
// rename so a link that moved during the read/build window is caught
// and refused rather than clobbered.
type pinnedTarget struct {
	path      string // original path (possibly a symlink)
	target    string // resolved file to actually read/write; == path when not a symlink
	isSymlink bool
	linkValue string // os.Readlink(path) at pin time; empty when !isSymlink
}

// pinWriteTarget resolves path's write target once. Must be called
// while the caller holds path's advisory settings lock, before the
// first read of the file the caller is about to patch.
func pinWriteTarget(path string) pinnedTarget {
	fi, err := os.Lstat(path)
	if err != nil || fi.Mode()&os.ModeSymlink == 0 {
		return pinnedTarget{path: path, target: path}
	}
	link, err := os.Readlink(path)
	if err != nil {
		return pinnedTarget{path: path, target: path}
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved == "" {
		// Dangling link: same fallback the old resolveWriteTarget used
		// (write through the link path itself).
		return pinnedTarget{path: path, target: path, isSymlink: true, linkValue: link}
	}
	return pinnedTarget{path: path, target: resolved, isSymlink: true, linkValue: link}
}

// verifyUnmoved re-checks, immediately before the final rename, that
// path is still the same symlink (or still a plain file) it was when
// pinned. A mismatch means the link was retargeted (or a plain file
// was replaced with a symlink, or vice versa) while this write was in
// flight against the OLD target; refusing here is the only way to
// avoid silently overwriting a file the caller never read.
func (p pinnedTarget) verifyUnmoved() error {
	fi, err := os.Lstat(p.path)
	if err != nil {
		if p.isSymlink {
			return fmt.Errorf("%s: symlink disappeared while observer was preparing to write it; refusing to write (it may have been replaced)", p.path)
		}
		return nil
	}
	isLink := fi.Mode()&os.ModeSymlink != 0
	if isLink != p.isSymlink {
		return fmt.Errorf("%s: changed between read and write (symlink-ness changed); refusing to write; re-run to pick up the new state", p.path)
	}
	if !p.isSymlink {
		return nil
	}
	link, err := os.Readlink(p.path)
	if err != nil || link != p.linkValue {
		return fmt.Errorf("%s: symlink was retargeted while observer was preparing to write it (was -> %s); refusing to write a patch built against the old target", p.path, p.linkValue)
	}
	return nil
}

// writeJSONIndented writes a map[string]json.RawMessage as stable-keyed,
// 2-space-indented JSON. Creates the parent dir if missing.
//
// Callers own the advisory lock (see lockSettings) — this function must
// never take it itself, or a caller that already holds it would
// deadlock against its own O_EXCL sentinel.
//
// pinned must have been produced by pinWriteTarget against path, right
// after the lock was acquired and before path was first read — see
// pinnedTarget's doc comment for why (F6).
func writeJSONIndented(dir string, pinned pinnedTarget, settings map[string]json.RawMessage) error {
	if err := checkTestWritePinned(pinned); err != nil {
		return fmt.Errorf("hook.write: %w", err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("hook.write: mkdir: %w", err)
	}
	keys := make([]string, 0, len(settings))
	for k := range settings {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Manually emit with sorted keys so JSON diffs stay clean.
	var buf []byte
	buf = append(buf, '{', '\n')
	for i, k := range keys {
		buf = append(buf, ' ', ' ')
		kk, _ := json.Marshal(k)
		buf = append(buf, kk...)
		buf = append(buf, ':', ' ')
		// Re-indent the value for readability — on the RAW bytes, never
		// by decoding through `any`. Decoding a value we do not own and
		// re-marshalling it is lossy in at least three ways that all
		// silently corrupt a user's file: integers beyond 2^53 are
		// mangled through float64 (9007199254740993 -> ...992), number
		// formatting is rewritten (1.0 -> 1, 1e3 -> 1000), and `<`/`>`/`&`
		// inside strings get \u-escaped. json.Indent is a pure
		// whitespace transform, so every unrelated top-level key
		// round-trips byte-identically.
		//
		// One deliberate cosmetic consequence: nested object keys keep
		// their SOURCE order instead of being alphabetized by Go's map
		// marshalling. Semantics are identical; the blocks we write
		// ourselves ("hooks", "statusLine", ...) now serialize in
		// struct-field order.
		var pretty bytes.Buffer
		if err := json.Indent(&pretty, settings[k], "  ", "  "); err == nil {
			buf = append(buf, pretty.Bytes()...)
		} else {
			buf = append(buf, settings[k]...)
		}
		if i < len(keys)-1 {
			buf = append(buf, ',')
		}
		buf = append(buf, '\n')
	}
	buf = append(buf, '}', '\n')

	// Idempotent byte for byte (T-407): a file that already holds exactly
	// this document is left alone (no rewrite on every `observer start`),
	// and a rewrite keeps the file's own line endings (a CRLF file stays
	// CRLF). Callers hold the settings lock, so this read sees the bytes
	// the caller patched.
	if cur, err := os.ReadFile(pinned.target); err == nil {
		if credfile.SameJSON(cur, buf) {
			return nil
		}
		buf = credfile.WithLineEnding(cur, buf)
	}

	// Write through a UNIQUE temp file, not a fixed `<path>.tmp`: two
	// observer processes patching the same settings.json would otherwise
	// stomp each other's half-written temp file and rename a spliced
	// body into place. Rename onto the symlink TARGET pinned at lock
	// time when path is a link, so dotfile-managed setups keep their
	// link.
	target := pinned.target
	tmpf, err := os.CreateTemp(filepath.Dir(target), filepath.Base(target)+".tmp-*")
	if err != nil {
		return fmt.Errorf("hook.write: temp: %w", err)
	}
	tmp := tmpf.Name()
	if _, err := tmpf.Write(buf); err != nil {
		_ = tmpf.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("hook.write: %w", err)
	}
	if err := tmpf.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("hook.write: %w", err)
	}
	// Re-verify immediately before the rename: the link must still
	// resolve to the target this write was built against (F6).
	if err := pinned.verifyUnmoved(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("hook.write: %w", err)
	}
	if err := os.Rename(tmp, target); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("hook.write: rename: %w", err)
	}
	return nil
}

// checkTestWritePinned applies crossmount's test-binary write guard to both
// the path a writer was handed and the symlink target it will rename onto.
func checkTestWritePinned(pinned pinnedTarget) error {
	if err := testwriteguard.Check("write", pinned.path); err != nil {
		return err
	}
	if pinned.target != pinned.path {
		return testwriteguard.Check("write", pinned.target)
	}
	return nil
}

// atomicWriteFile writes data to path via a UNIQUE temp file — never a
// fixed `<path>.tmp`, which two observer processes racing to patch the
// same file would otherwise stomp: whichever opens second truncates
// the first's still-open temp file out from under it (same inode, same
// path, no O_EXCL), so the eventual rename can land a spliced/torn
// body. Same rationale as writeJSONIndented's temp file, generalized
// here so every fixed-name writer in this package (hook_checksums.json,
// Codex's hooks.json and config.toml) can share one hardened
// implementation instead of re-deriving it.
//
// Renames onto the SYMLINK TARGET pinned at lock time when path is a
// symlink (pinWriteTarget), so a dotfile-managed config keeps its
// link — matching writeJSONIndented's symlink stance.
//
// Callers that need cross-process serialization own the advisory lock
// (see lockSettings) — this function never takes it itself, so a
// caller already holding it can't deadlock against its own O_EXCL
// sentinel.
//
// pinned must have been produced by pinWriteTarget against path, right
// after the lock was acquired and before path was first read — see
// pinnedTarget's doc comment for why (F6).
func atomicWriteFile(pinned pinnedTarget, data []byte) error {
	return atomicWriteFileMode(pinned, data, 0)
}

// atomicWriteFileMode is atomicWriteFile with the written file's permission
// bits set to mode (0 keeps the temp file's 0600). The credential-file
// writers pass the existing file's mode so a rewrite never changes it.
func atomicWriteFileMode(pinned pinnedTarget, data []byte, mode os.FileMode) error {
	if err := checkTestWritePinned(pinned); err != nil {
		return fmt.Errorf("hook.atomicWriteFile: %w", err)
	}
	target := pinned.target
	if err := testWriteRefused(target); err != nil {
		return err
	}
	dir := filepath.Dir(target)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("hook.atomicWriteFile: mkdir: %w", err)
	}
	tmpf, err := os.CreateTemp(dir, filepath.Base(target)+".tmp-*")
	if err != nil {
		return fmt.Errorf("hook.atomicWriteFile: temp: %w", err)
	}
	tmp := tmpf.Name()
	if _, err := tmpf.Write(data); err != nil {
		_ = tmpf.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("hook.atomicWriteFile: write: %w", err)
	}
	if mode != 0 {
		if err := tmpf.Chmod(mode); err != nil {
			_ = tmpf.Close()
			_ = os.Remove(tmp)
			return fmt.Errorf("hook.atomicWriteFile: chmod: %w", err)
		}
	}
	if err := tmpf.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("hook.atomicWriteFile: close: %w", err)
	}
	// Re-verify immediately before the rename: the link must still
	// resolve to the target this write was built against (F6).
	if err := pinned.verifyUnmoved(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("hook.atomicWriteFile: %w", err)
	}
	if err := os.Rename(tmp, target); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("hook.atomicWriteFile: rename: %w", err)
	}
	return nil
}

// removeEmptyConfigFile deletes path after a registrar has emptied a
// config file's last observer-owned content (its last top-level key,
// or the whole document). Honors the same symlink-preserving stance
// as writeJSONIndented/atomicWriteFile: a settings.json a dotfile
// manager maintains as a SYMLINK into a tracked repo must never be
// silently os.Remove'd. Unlinking the symlink only unlinks the
// dirent — the TARGET file (the one the AI tool, and any dotfile
// repo, actually reads) survives untouched with its stale content
// still in place, while the caller believes the removal succeeded.
// Deleting the resolved TARGET instead would be just as dishonest in
// the other direction: silently destroying a file this package does
// not own, tracked or not, on the operator's behalf.
//
// So a symlinked config is REFUSED with an error naming the file —
// the same "refuse and name it" stance readSettingsFile and
// decodeSettingsObject already take for file shapes this package
// cannot honestly rewrite. A missing file (already gone, or a race
// with another remover) is not an error.
//
// expected is the exact byte content the caller read and decided was
// empty of observer-owned content, captured BEFORE it made that
// decision. Closing F5's check-then-delete TOCTOU: the caller holds
// path's advisory settings lock across its whole
// read-decide-write-or-delete window, but that lock only serializes
// against OTHER observer processes — it does nothing against the AI
// tool itself (or the user, or a dotfile-manager sync) replacing the
// file with fresh content of its own between the caller's read and
// this delete. Re-reading path's current bytes here, immediately
// before the actual unlink, and refusing unless they still match
// exactly what the caller decided to delete turns that window into a
// safe no-op instead of a silent destructive race: whatever replaced
// the file survives, and the caller's stale delete decision is
// discarded instead of acted on.
func removeEmptyConfigFile(path string, expected []byte) error {
	if err := testwriteguard.Check("write", path); err != nil {
		return err
	}
	fi, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symlink; refusing to delete it: unlinking it would silently detach it while its target file survives untouched, and deleting the target could destroy a file tracked elsewhere; remove it by hand if that's what you want", path)
	}
	current, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if !bytes.Equal(current, expected) {
		return fmt.Errorf("%s changed since observer decided to delete it (likely written by the AI tool, or another process, in between); refusing to delete a file observer never actually read; re-run to make a fresh decision against the current content", path)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// recordChecksum computes SHA256 of the config file and records it in the
// checksums registry so `observer doctor` can detect drift.
//
// hook_checksums.json is shared by every registrar (claude-code,
// cursor, codex, statusline, ...), so this takes its OWN advisory lock
// on the checksums file — a claude-code registration and a cursor
// registration each hold a DIFFERENT settings-file lock but must still
// serialize here, or their concurrent read-modify-write of the shared
// registry loses each other's entries (and, pre-atomic-write, could
// splice their bodies together).
//
// tool is the registration target label (RegistrationResult.Tool) stored in
// the entry so the managed-integrity probe can name the tool behind a risk on
// this file (T-847). The entry's other fields (last_result, the repair
// record) are kept: before T-847 every re-record replaced the entry, which
// erased a repair record on the very next idempotent pass.
func (r *Registry) recordChecksum(tool, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("hook.recordChecksum: %w", err)
	}
	sum := sha256.Sum256(data)
	if err := r.updateChecksumEntry(path, func(entry map[string]any) {
		delete(entry, hookdigest.KeyScope)
		delete(entry, hookdigest.KeyDigest)
		entry["sha256"] = hex.EncodeToString(sum[:])
		entry["registered"] = time.Now().UTC().Format(time.RFC3339)
		entry["binary_path"] = r.opts.BinaryPath
		if tool != "" {
			entry["tool"] = tool
		}
	}); err != nil {
		return fmt.Errorf("hook.recordChecksum: %w", err)
	}
	return nil
}

// RecordAutoRegisterResult persists the outcome of an auto-register
// attempt against configPath into hook_checksums.json, independent of
// whether the registrar actually wrote configPath. Callers (the
// `observer start` auto-register loop) call it after every
// Register() invocation, success or failure, so a stuck registration
// — e.g. a stale non-observer entry blocking the Windows-Cursor
// bridge — is inspectable later via hook_checksums.json instead of
// living only as a stderr line on a long-running daemon nobody
// happens to be watching (see
// docs/audits/cursor-windows-capture-diagnosis-2026-08-07.md §4 F3).
//
// A successful Register() already calls recordChecksum, which writes
// "sha256"/"registered"/"binary_path" for configPath; this ADDS
// last_result ("ok" or "error"), last_error (present only on
// failure), and last_checked_at to that SAME entry, preserving
// whatever else is already there — so hook_checksums.json stays
// backward compatible for any reader that only knows the original
// three keys. When Register() never got far enough to write anything
// (every attempt so far has failed), this still creates a minimal
// entry so the failure is visible.
//
// regErr is the RegistrationResult.Error from Register(); nil means
// success. configPath == "" is a no-op (nothing to key the entry on).
func (r *Registry) RecordAutoRegisterResult(configPath string, regErr error) error {
	if configPath == "" {
		return nil
	}
	csPath := r.opts.ChecksumsPath
	if csPath == "" {
		csPath = filepath.Join(r.opts.HomeDir, ".observer", "hook_checksums.json")
	}

	unlock, err := r.lockSettings(csPath)
	if err != nil {
		return fmt.Errorf("hook.RecordAutoRegisterResult: %w", err)
	}
	defer unlock()

	// Pin the write target now, before the read — see pinnedTarget (F6).
	pinned := pinWriteTarget(csPath)

	current := map[string]map[string]any{}
	if raw, err := os.ReadFile(csPath); err == nil {
		_ = json.Unmarshal(raw, &current)
	}
	entry := current[configPath]
	if entry == nil {
		entry = map[string]any{}
	}
	entry["last_checked_at"] = time.Now().UTC().Format(time.RFC3339)
	if regErr != nil {
		entry["last_result"] = "error"
		entry["last_error"] = regErr.Error()
	} else {
		entry["last_result"] = "ok"
		delete(entry, "last_error")
	}
	current[configPath] = entry

	body, err := json.MarshalIndent(current, "", "  ")
	if err != nil {
		return fmt.Errorf("hook.RecordAutoRegisterResult: marshal: %w", err)
	}
	if err := atomicWriteFile(pinned, body); err != nil {
		return fmt.Errorf("hook.RecordAutoRegisterResult: %w", err)
	}
	return nil
}

// configFlagSuffix returns ` --config <path>` when ConfigPath is set,
// or empty string otherwise. The leading space lets callers concatenate
// directly onto the binary+event command. Path is single-quote shell-
// escaped (POSIX-style: every `'` becomes `'\”`) so paths containing
// spaces or quotes round-trip safely through `/bin/bash -c`. Used by
// the claudecode + cursor registrars (Git Bash / POSIX targets).
func (r *Registry) configFlagSuffix() string {
	return r.configFlagSuffixWith(shellQuote)
}

// skipEvent reports whether Options.SkipEvent excludes (tool, event) from
// this registration (false when no filter is set).
func (r *Registry) skipEvent(tool, event string) bool {
	return r.opts.SkipEvent != nil && r.opts.SkipEvent(tool, event)
}

// configFlagSuffixForwardSlash mirrors configFlagSuffix but normalizes
// the config path to forward slashes before quoting. Used by
// registerClaudeCode + registerCursor — see forwardSlashPath for the
// shell-wrapper rationale. Non-Windows-shaped paths pass through
// unchanged so Linux/macOS hook commands and their test fixtures are
// unaffected.
func (r *Registry) configFlagSuffixForwardSlash() string {
	if r.opts.ConfigPath == "" {
		return ""
	}
	return " --config " + shellQuote(forwardSlashPath(r.opts.ConfigPath))
}

// configFlagSuffixWith mirrors configFlagSuffix but lets the caller
// pick its own quoter. Used by registerCodex to apply cmd.exe-safe
// double-quote on Windows-shaped paths — `'...'` is invalid quoting
// in cmd.exe (Codex on Windows spawns hooks via cmd.exe, not Git
// Bash), so a single-quoted --config path would surface as a literal
// argument and confuse codex's flag parser.
func (r *Registry) configFlagSuffixWith(quote func(string) string) string {
	if r.opts.ConfigPath == "" {
		return ""
	}
	return " --config " + quote(r.opts.ConfigPath)
}

// shellQuote returns a single-quoted POSIX-shell literal of s with any
// embedded single-quote escaped via the standard `'\”` sequence.
// Conservative — wraps unconditionally so even sane paths get quotes,
// at the cost of two extra bytes. Callers feed the result into a
// command string that goes through bash -c, where single-quotes turn
// off all interpretation.
func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	var b []byte
	b = append(b, '\'')
	for i := 0; i < len(s); i++ {
		if s[i] == '\'' {
			b = append(b, '\'', '\\', '\'', '\'')
			continue
		}
		b = append(b, s[i])
	}
	b = append(b, '\'')
	return string(b)
}

// UnregistrationResult summarizes a single tool unregistration.
type UnregistrationResult struct {
	Tool          string   // claude-code[-windows] | cursor | codex[-windows]
	ConfigPath    string   // absolute path to the patched config file
	HooksRemoved  []string // event names where observer entries were removed
	HooksKept     []string // events where non-observer (user-authored) hooks remain
	DryRun        bool
	Skipped       bool // true when the config file does not exist — nothing to do
	ChecksumMatch bool // true when the stored install-time checksum matched pre-mutation
	Error         error
	// TrustRemoved names the events whose host-side trust record Observer
	// had written and removed with the entries (Codex). TrustNotRemoved
	// names the ones that could not be removed in place and were left (the
	// others are still removed). TrustNote is a non-fatal note when a
	// record could not be removed.
	TrustRemoved    []string
	TrustNotRemoved []string
	TrustNote       string

	// HooksKeptForeign names the events (for a whole file, its events)
	// whose entry is in Observer's `<bin> hook <tool> <event>` shape but
	// runs a binary not judged an Observer binary (FU-203): kept byte for
	// byte, for ForeignBinaryReason, with or without --force.
	HooksKeptForeign []string

	// HooksKeptForeignIn names the file of each HooksKeptForeign event
	// when a removal spans several files (Kiro: Observer's own agent and
	// the user's own agent files, FU-213); empty when every kept event is
	// in ConfigPath.
	HooksKeptForeignIn []KeptForeignFile

	// FilesKeptForeign names the whole files an unregister would delete
	// (a plugin, a mod, a manifest, a dedicated hooks file) that do not
	// read as Observer's (FU-212): kept byte for byte, with or without
	// --force, for ForeignFileReason.
	FilesKeptForeign []string
}

// KeptForeignFile is one file an unregister kept entries in for
// ForeignBinaryReason, and the events kept there.
type KeptForeignFile struct {
	Path   string
	Events []string
}

// ForeignFileReason is why an UnregistrationResult's FilesKeptForeign were
// kept, for a caller that reports them (`observer uninstall`).
const ForeignFileReason = "not an observer-managed file; observer never deletes a file it did not write"

// Unregister removes observer hook entries from tool's config file. Only
// entries whose Command starts with opts.BinaryPath are removed; any
// user-authored hooks in the same file are preserved. If the file's
// checksum doesn't match the one recorded at install time, returns an
// error unless opts.Force is set.
//
// Supported tools: "claude-code", "claude-code-windows", "cursor",
// "codex", "codex-windows". A credential-file target's error is made safe
// (guardCredentialUnregistration).
func (r *Registry) Unregister(tool string) UnregistrationResult {
	rm := *r
	rm.removing = true
	return rm.guardCredentialUnregistration(tool, rm.unregister(tool))
}

// unregister dispatches Unregister to tool's writer.
func (r *Registry) unregister(tool string) UnregistrationResult {
	if row, ok := wslTwinFor(tool); ok {
		return r.unregisterWSLTwin(row)
	}
	if w, ok := toolGateWriters[tool]; ok {
		return w.unregister(r)
	}
	if w, ok := hookTargetWriters[tool]; ok {
		return w.unregister(r)
	}
	if c, ok := pluginShimCapability(tool); ok {
		return r.unregisterPluginShim(c)
	}
	return UnregistrationResult{
		Tool:   tool,
		Error:  fmt.Errorf("hook.Unregister: tool %q not supported", tool),
		DryRun: r.opts.DryRun,
	}
}

// checksumMatches reports whether the hash stored for path in the
// checksums registry matches SHA256(data). A missing entry or missing
// registry file returns (false, nil) — caller decides policy.
func (r *Registry) checksumMatches(path string, data []byte) (bool, error) {
	csPath := r.opts.ChecksumsPath
	if csPath == "" {
		csPath = filepath.Join(r.opts.HomeDir, ".observer", "hook_checksums.json")
	}
	raw, err := os.ReadFile(csPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	current := map[string]map[string]any{}
	if err := json.Unmarshal(raw, &current); err != nil {
		return false, err
	}
	entry, ok := current[path]
	if !ok {
		return false, nil
	}
	// A credential-bearing file's entry covers its hooks subtree only
	// (credentialfile.go): drift elsewhere in the file is the user's.
	if match, scoped := scopedChecksumMatches(path, entry, data); scoped {
		return match, nil
	}
	stored, _ := entry["sha256"].(string)
	sum := sha256.Sum256(data)
	return stored == hex.EncodeToString(sum[:]), nil
}

// removeChecksum deletes path's entry from the checksums registry. When
// the registry becomes empty it is removed entirely. Missing registry is
// not an error.
//
// Takes the same per-checksums-file advisory lock as recordChecksum —
// see that docstring for why a shared registry needs its own lock
// independent of whatever settings-file lock the caller may be
// holding.
func (r *Registry) removeChecksum(path string) error {
	csPath := r.opts.ChecksumsPath
	if csPath == "" {
		csPath = filepath.Join(r.opts.HomeDir, ".observer", "hook_checksums.json")
	}

	unlock, err := r.lockSettings(csPath)
	if err != nil {
		return fmt.Errorf("hook.removeChecksum: %w", err)
	}
	defer unlock()

	// Pin the write target now, before the read — see pinnedTarget (F6).
	pinned := pinWriteTarget(csPath)

	raw, err := os.ReadFile(csPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("hook.removeChecksum: read: %w", err)
	}
	current := map[string]any{}
	if err := json.Unmarshal(raw, &current); err != nil {
		return fmt.Errorf("hook.removeChecksum: parse: %w", err)
	}
	// FU-212: the registry is deleted only when the entry this call drops
	// was its last one (the bytes it read, compared again before the
	// delete), never because a file at its path is empty of entries.
	if _, had := current[path]; !had {
		return nil
	}
	delete(current, path)
	if len(current) == 0 {
		if err := removeEmptyConfigFile(csPath, raw); err != nil {
			return fmt.Errorf("hook.removeChecksum: remove %s: %w", csPath, err)
		}
		return nil
	}
	body, err := json.MarshalIndent(current, "", "  ")
	if err != nil {
		return fmt.Errorf("hook.removeChecksum: marshal: %w", err)
	}
	if err := atomicWriteFile(pinned, body); err != nil {
		return fmt.Errorf("hook.removeChecksum: %w", err)
	}
	return nil
}

// splitCommandTokens splits a registered hook/statusline command string
// into argv-ish tokens, honouring the quoting our own writers emit
// (shellQuote's POSIX single quotes, including the close-escape-reopen
// form it emits for an embedded quote character — see shellQuote) plus
// double quotes and backslash escapes for
// hand-written entries. Deliberately small: it exists to answer "what
// is the executable, and what is its first argument", not to be a
// shell. Unbalanced quotes simply yield whatever tokens were closed,
// which the callers treat as ambiguous ⇒ foreign.
func splitCommandTokens(cmd string) []string {
	var (
		toks    []string
		cur     []byte
		started bool
		inSing  bool
		inDoub  bool
	)
	flush := func() {
		if started {
			toks = append(toks, string(cur))
			cur = cur[:0]
			started = false
		}
	}
	for i := 0; i < len(cmd); i++ {
		c := cmd[i]
		switch {
		case inSing:
			if c == '\'' {
				inSing = false
				continue
			}
			cur = append(cur, c)
		case inDoub:
			if c == '"' {
				inDoub = false
				continue
			}
			if c == '\\' && i+1 < len(cmd) {
				i++
				cur = append(cur, cmd[i])
				continue
			}
			cur = append(cur, c)
		case c == '\'':
			inSing, started = true, true
		case c == '"':
			inDoub, started = true, true
		case c == '\\' && i+1 < len(cmd):
			i++
			cur = append(cur, cmd[i])
			started = true
		case c == ' ' || c == '\t':
			flush()
		default:
			cur = append(cur, c)
			started = true
		}
	}
	flush()
	return toks
}

// anyGeminiDirExists reports whether any of dirs exists under the user's
// ~/.gemini (the Antigravity products' data directories, Installed's
// install signal for the shared agy hook file).
func (r *Registry) anyGeminiDirExists(dirs []string) bool {
	for _, dir := range dirs {
		if r.dirExists(filepath.Join(r.opts.HomeDir, ".gemini", dir)) {
			return true
		}
	}
	return false
}
