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
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/marmutapp/superbased-observer/internal/claudeplugin"
	"github.com/marmutapp/superbased-observer/internal/hook/commandcodemod"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// RegistrationResult summarizes a single tool registration.
type RegistrationResult struct {
	Tool       string   // claude-code[-windows] | cursor[-windows] | codex[-windows]
	ConfigPath string   // absolute path to the patched config file
	HooksAdded []string // event names that now point at the observer binary
	AlreadySet []string // events that already pointed at the observer (skipped)
	DryRun     bool
	Error      error

	// Skipped reports that the registrar deliberately wrote nothing
	// because the tool already carries observer's wiring through its own
	// packaging surface — today, the Claude Code plugin, which declares
	// the same hook events. Not an error: the user is already covered,
	// and registering again would fire every event twice. SkipReason
	// names the artifact that proved it. Both zero on every other path.
	Skipped    bool
	SkipReason string

	// SkipAdvice is the operator-facing next step that goes with
	// SkipReason. Empty means "the default plugin advice applies" (the
	// printer supplies it), so the plugin skip path is unchanged; the
	// cross-OS sandbox skip (see crossmount.AutoDetectSuppressed) sets it
	// because the --force escape hatch deliberately does NOT apply there.
	SkipAdvice string

	// ProbeWarning is a NON-FATAL note: the plugin probe could not read
	// a file it needed, so the registrar registered without being able
	// to rule out a plugin already providing this wiring. Registration
	// still happened (fail-open to wiring) — this is a reporting
	// channel, never control flow. Empty on every conclusive path.
	ProbeWarning string
}

// Options parameterize RegisterAll.
type Options struct {
	// BinaryPath is the absolute path to the running observer binary
	// that hook commands will invoke. Required.
	BinaryPath string
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
	// Windows home carrying that subdir. Windsurf/Devin Desktop Cascade
	// has NO Windows counterpart here — its only grounded install
	// channel is the macOS Homebrew cask (internal/integration's devin
	// row), so a cross-OS bridge would have nothing to bridge to.
	WindowsGeminiHome      string
	WindowsQwenHome        string
	WindowsFactoryHome     string
	WindowsQoderHome       string
	WindowsPoolsideHome    string
	WindowsCommandCodeHome string
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
func (r *Registry) Installed() []string {
	var tools []string
	if r.dirExists(filepath.Join(r.opts.HomeDir, ".claude")) {
		tools = append(tools, "claude-code")
	}
	if r.dirExists(filepath.Join(r.opts.HomeDir, ".cursor")) {
		tools = append(tools, "cursor")
	}
	if r.dirExists(filepath.Join(r.opts.HomeDir, ".codex")) {
		tools = append(tools, "codex")
	}
	// Part B item 1: Gemini CLI, Qwen Code, Factory Droid — probed the
	// same way as every other native dir-based install (no vendor
	// binary probe here; Installed() has never shelled out to a
	// tool's own CLI, it only checks for the config directory).
	if r.dirExists(filepath.Join(r.opts.HomeDir, ".gemini")) {
		tools = append(tools, "gemini-cli")
	}
	if r.dirExists(filepath.Join(r.opts.HomeDir, ".qwen")) {
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
	if r.dirExists(filepath.Join(r.opts.HomeDir, ".qoder")) {
		tools = append(tools, "qoder")
	}
	if r.dirExists(filepath.Join(r.opts.HomeDir, ".config", "poolside")) {
		tools = append(tools, "poolside")
	}
	if r.dirExists(filepath.Join(r.opts.HomeDir, ".codeium", "windsurf")) {
		tools = append(tools, "devin")
	}
	if r.dirExists(filepath.Join(r.opts.HomeDir, ".commandcode")) {
		tools = append(tools, "command-code")
	}
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
	// Windows-native client. Windsurf/Devin Desktop Cascade has no row
	// here — see Options.WindowsCommandCodeHome's doc comment.
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
	return tools
}

// allHomes and homeOwnedByCurrentWindowsUser are the crossmount seams (package
// vars, mirroring internal/proxyroute) so tests can inject a fixed multi-home
// layout AND a deterministic ownership verdict without a real /mnt/c mount or
// a cmd.exe interop shell (restore them in a defer).
var (
	allHomes                      = crossmount.AllHomes
	homeOwnedByCurrentWindowsUser = crossmount.HomeOwnedByCurrentWindowsUser
)

// detectWindowsClaudeHome returns the resolved Windows-side .claude
// directory used by the claude-code-windows registration target, or
// "" if none. Honors Options.WindowsClaudeHome when set; otherwise
// accepts an auto-detected OS=windows home that has a `.claude/`
// subdirectory ONLY when crossmount can prove it belongs to the current
// Windows user. Mirrors detectWindowsCursorHome and the proxy-route
// side's resolveWindowsHome R1 guard.
func (r *Registry) detectWindowsClaudeHome() string {
	return r.detectWindowsHome(r.opts.WindowsClaudeHome, ".claude")
}

// WindowsClaudeDir exposes the resolved Windows-side .claude directory
// the claude-code-windows registration target writes into, or "" when
// there is none. Exported so `observer doctor` can inspect the SAME
// directory this registrar would write to, instead of re-deriving the
// crossmount + ownership rules and drifting from them (one owner). Its
// argument mirrors Options.WindowsClaudeHome: an explicit Windows USER
// home override, or "" to auto-detect.
func WindowsClaudeDir(override string) string {
	r := &Registry{opts: Options{WindowsClaudeHome: override}}
	return r.detectWindowsClaudeHome()
}

// detectWindowsCursorHome returns the resolved Windows-side .cursor
// directory used by the cursor-windows registration target, or "" if
// none. Honors Options.WindowsCursorHome when set; otherwise accepts an
// auto-detected OS=windows home carrying `.cursor/` only when
// crossmount-ownership-verified.
func (r *Registry) detectWindowsCursorHome() string {
	return r.detectWindowsHome(r.opts.WindowsCursorHome, ".cursor")
}

// detectWindowsCodexHome returns the resolved Windows-side .codex
// directory used by the codex-windows registration target, or "" if
// none. Honors Options.WindowsCodexHome when set; otherwise accepts an
// auto-detected OS=windows home carrying `.codex/` only when
// crossmount-ownership-verified. Same contract as
// detectWindowsClaudeHome / detectWindowsCursorHome.
func (r *Registry) detectWindowsCodexHome() string {
	return r.detectWindowsHome(r.opts.WindowsCodexHome, ".codex")
}

// detectWindowsGeminiHome / detectWindowsQwenHome / detectWindowsFactoryHome
// / detectWindowsQoderHome / detectWindowsPoolsideHome /
// detectWindowsCommandCodeHome resolve the Windows-side config directory
// for each of the six Part B item 1/2 long-tail vendors' own cross-OS
// bridge target, or "" if none. Same contract as detectWindowsClaudeHome
// / detectWindowsCursorHome / detectWindowsCodexHome — honors the
// matching Options override when set, otherwise an auto-detected
// OS=windows home carrying the subdir ONLY when crossmount proves it
// belongs to the current Windows user.
func (r *Registry) detectWindowsGeminiHome() string {
	return r.detectWindowsHome(r.opts.WindowsGeminiHome, ".gemini")
}

func (r *Registry) detectWindowsQwenHome() string {
	return r.detectWindowsHome(r.opts.WindowsQwenHome, ".qwen")
}

func (r *Registry) detectWindowsFactoryHome() string {
	return r.detectWindowsHome(r.opts.WindowsFactoryHome, ".factory")
}

func (r *Registry) detectWindowsQoderHome() string {
	return r.detectWindowsHome(r.opts.WindowsQoderHome, ".qoder")
}

func (r *Registry) detectWindowsPoolsideHome() string {
	return r.detectWindowsHome(r.opts.WindowsPoolsideHome, filepath.Join(".config", "poolside"))
}

func (r *Registry) detectWindowsCommandCodeHome() string {
	return r.detectWindowsHome(r.opts.WindowsCommandCodeHome, ".commandcode")
}

// detectWindowsHome resolves the Windows-side <subdir> directory for a
// cross-OS registration target. Ownership discipline mirrors the proxy-route
// writer's resolveWindowsHome (security finding R1/F1): a WSL daemon must NOT
// install hooks into another Windows user's config just because theirs is the
// only `.claude`/`.cursor` mounted.
//
//   - An explicit override wins unconditionally — the operator named the home,
//     so ownership verification is moot; returned even if the dir doesn't exist
//     yet (the registrar mkdir's on first install).
//   - Otherwise an auto-detected OS=windows home carrying <subdir> is accepted
//     ONLY when crossmount proves it belongs to the current Windows user
//     (base name matches %USERNAME%). Zero owned homes — or an ambiguous
//     several — resolve to "" so the virtual target simply doesn't surface in
//     Installed() (the honest floor: no behaviour change on a single-user
//     machine where the name matches; a refusal to guess otherwise).
func (r *Registry) detectWindowsHome(override, subdir string) string {
	// Sandbox gate FIRST — before the override branch, because an override
	// that points OUTSIDE the pinned home is exactly the escape hatch that
	// re-opened this hole. See crossmount.AutoDetectSuppressed (incident
	// 2026-07-31). Production never pins HomeDir, so this is false on every
	// real path and a bare override still wins unconditionally.
	if r.foreignAutoDetectSuppressed(override) {
		return ""
	}
	if override != "" {
		return filepath.Join(override, subdir)
	}
	var owned []string
	for _, h := range allHomes() {
		if h.OS != crossmount.OSWindows {
			continue
		}
		dir := filepath.Join(h.Path, subdir)
		if !r.dirExists(dir) {
			continue
		}
		if homeOwnedByCurrentWindowsUser(h.Path) {
			owned = append(owned, dir)
		}
	}
	if len(owned) == 1 {
		return owned[0]
	}
	return ""
}

func (r *Registry) dirExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

// foreignAutoDetectSuppressed reports whether this registry's caller pinned
// HomeDir (a sandbox) without naming the Windows-side home for the target
// being resolved. See crossmount.AutoDetectSuppressed for the rule and the
// 2026-07-31 incident it exists to make structurally impossible.
func (r *Registry) foreignAutoDetectSuppressed(override string) bool {
	return crossmount.AutoDetectSuppressed(r.homeOverride, override)
}

// sandboxSkipResult fills res as a deliberate no-write for a cross-OS target
// the sandbox gate suppressed. It is a SKIP, not an error: nothing is wrong
// with the host — the caller pinned a home and either never said which
// Windows-side home it wanted, or named one OUTSIDE that sandbox, so there is
// no path this registry is allowed to touch. optionName is the Options field
// that unlocks the target; its value must resolve INSIDE the pinned home.
func (r *Registry) sandboxSkipResult(res *RegistrationResult, subdir, optionName, override string) {
	res.Skipped = true
	if override == "" {
		res.SkipReason = fmt.Sprintf(
			"HomeDir was pinned by the caller but no %s was given — cross-OS %s/ resolution is suppressed (incident 2026-07-31)",
			optionName, subdir,
		)
	} else {
		res.SkipReason = fmt.Sprintf(
			"%s (%s) resolves OUTSIDE the pinned HomeDir (%s) — cross-OS %s/ resolution is suppressed (incident 2026-07-31)",
			optionName, override, r.homeOverride, subdir,
		)
	}
	res.SkipAdvice = fmt.Sprintf(
		"nothing written; a sandboxed caller must set %s to a home UNDER its own HomeDir to wire this target (--force does not lift this).",
		optionName,
	)
}

// Register installs observer hooks into the config file for tool. Supported
// values: "claude-code", "claude-code-windows", "cursor", "cursor-windows",
// "codex", "codex-windows". Unknown tools return an error.
func (r *Registry) Register(tool string) RegistrationResult {
	switch tool {
	case "claude-code":
		return r.registerClaudeCode()
	case "claude-code-windows":
		return r.registerClaudeCodeWindows()
	case "cursor":
		return r.registerCursor()
	case "cursor-windows":
		return r.registerCursorWindows()
	case "codex":
		return r.registerCodex()
	case "codex-windows":
		return r.registerCodexWindows()
	case "gemini-cli":
		return r.registerGeminiCLI()
	case "gemini-cli-windows":
		return r.registerGeminiCLIWindows()
	case "qwen-code":
		return r.registerQwenCode()
	case "qwen-code-windows":
		return r.registerQwenCodeWindows()
	case "droid":
		return r.registerFactoryDroid()
	case "droid-windows":
		return r.registerFactoryDroidWindows()
	case "qoder":
		return r.registerQoder()
	case "qoder-windows":
		return r.registerQoderWindows()
	case "poolside":
		return r.registerPoolside()
	case "poolside-windows":
		return r.registerPoolsideWindows()
	case "devin":
		return r.registerCascade()
	case "command-code":
		return r.registerCommandCode()
	case "command-code-windows":
		return r.registerCommandCodeWindows()
	default:
		return RegistrationResult{
			Tool:   tool,
			Error:  fmt.Errorf("hook.Register: tool %q not supported for hook registration", tool),
			DryRun: r.opts.DryRun,
		}
	}
}

// claudeCodeEvents is the set of events we register for. The matcher "*"
// catches every tool; downstream handlers filter by tool_name.
//
// Tier 1 additions (2026-05): SessionEnd, UserPromptSubmit,
// PostToolUseFailure, StopFailure, SubagentStart, SubagentStop,
// Notification, CwdChanged. Each maps to a row in the actions table
// via cmd/observer/hook.go::handleClaudeCodeHook so dashboards can
// surface failures, sub-agent fan-out, lifecycle exit reasons, host
// notifications and cwd changes that the JSONL transcript either
// doesn't carry or carries less directly.
//
// Tier 2/3 additions (2026-05-11): Setup, UserPromptExpansion,
// PostToolBatch, PermissionRequest, PermissionDenied, InstructionsLoaded,
// ConfigChange. Shapes verified against
// docs.claude.com/docs/en/hooks. FileChanged deferred — its matcher
// takes literal filenames (split on `|`), not the wildcard `*` shape
// all other events use, so it needs a separate per-project config
// surface before registration.
var claudeCodeEvents = []string{
	"SessionStart",
	"SessionEnd",
	"Setup",
	"UserPromptSubmit",
	"UserPromptExpansion",
	"PreToolUse",
	"PostToolUse",
	"PostToolUseFailure",
	"PostToolBatch",
	"PermissionRequest",
	"PermissionDenied",
	"Stop",
	"StopFailure",
	"PreCompact",
	"PostCompact",
	"SubagentStart",
	"SubagentStop",
	"Notification",
	"CwdChanged",
	"InstructionsLoaded",
	"ConfigChange",
	// WorktreeRemove is non-blocking (logging only) so it's safe to
	// register by default. WorktreeCreate (its blocking pair) is NOT
	// in this list — see docs/claude-worktree-hook.md for the opt-in
	// procedure. Wiring it as a default hook without a verified
	// path-echo contract risks breaking every Agent spawn with
	// isolation: "worktree".
	"WorktreeRemove",
}

type claudeHookGroup struct {
	Matcher string              `json:"matcher,omitempty"`
	Hooks   []claudeHookCommand `json:"hooks"`
}

type claudeHookCommand struct {
	Type    string `json:"type"`
	Command string `json:"command"`
}

// claudeHookGroupRaw mirrors claudeHookGroup's JSON shape
// (`{"matcher":...,"hooks":[...]}`) but keeps each entry in Hooks as
// raw JSON rather than decoding it into claudeHookCommand (B5). A
// group observer appends to may already hold a SIBLING entry this
// repo doesn't own — another tool's own hook, or one the user
// hand-authored — that carries fields claudeHookCommand doesn't model
// (Claude Code's documented per-entry `timeout`, for one). Decoding
// that entry into claudeHookCommand and re-encoding it would silently
// drop those fields the moment observer registers/refreshes/removes
// its own neighboring entry in the same list. Only observer's OWN
// entry is ever constructed directly (via claudeHookCommand, then
// marshaled) since observer fully controls and knows that shape;
// every other entry round-trips as opaque json.RawMessage.
type claudeHookGroupRaw struct {
	Matcher string            `json:"matcher,omitempty"`
	Hooks   []json.RawMessage `json:"hooks"`
}

// claudeHookCommandProbe decodes just the two fields
// isObserverClaudeEntry/isObserverWindowsClaudeEntry need to recognise
// an entry as observer's own, from an otherwise-opaque raw hook entry.
// Used instead of the full claudeHookCommand so a sibling entry's
// unknown fields are never routed through — and so truncated by — a
// typed decode/re-encode round-trip.
type claudeHookCommandProbe struct {
	Type    string `json:"type"`
	Command string `json:"command"`
}

// findClaudeGroupWithObserverRaw is findClaudeGroupWithObserver's
// raw-entry counterpart (B5): it probes each entry's `type`/`command`
// fields without decoding (and thereby truncating) any other field
// the entry carries.
func findClaudeGroupWithObserverRaw(groups []claudeHookGroupRaw) int {
	for i, g := range groups {
		for _, raw := range g.Hooks {
			var probe claudeHookCommandProbe
			if err := json.Unmarshal(raw, &probe); err != nil {
				continue
			}
			if probe.Type == "command" && isObserverClaudeEntry(probe.Command) {
				return i
			}
		}
	}
	return -1
}

// hasConflictingClaudeHookRaw is hasConflictingClaudeHook's raw-entry
// counterpart (B5) — see findClaudeGroupWithObserverRaw.
func hasConflictingClaudeHookRaw(groups []claudeHookGroupRaw) bool {
	for _, g := range groups {
		if g.Matcher != "" && g.Matcher != "*" {
			continue
		}
		for _, raw := range g.Hooks {
			var probe claudeHookCommandProbe
			if err := json.Unmarshal(raw, &probe); err != nil {
				continue
			}
			if probe.Type != "command" {
				continue
			}
			if !isObserverClaudeEntry(probe.Command) {
				return true
			}
		}
	}
	return false
}

// observerCmdMatchesRaw is observerCmdMatches's raw-entry counterpart
// (B5) — see findClaudeGroupWithObserverRaw.
func observerCmdMatchesRaw(group claudeHookGroupRaw, want string) bool {
	if len(group.Hooks) != 1 {
		return false
	}
	var probe claudeHookCommandProbe
	if err := json.Unmarshal(group.Hooks[0], &probe); err != nil {
		return false
	}
	return probe.Type == "command" && probe.Command == want
}

// filterClaudeGroupsRaw is filterClaudeGroups's raw-entry counterpart
// (B5): it drops observer-owned entries by probing just their
// `type`/`command` fields, and keeps every surviving entry as the
// exact json.RawMessage bytes it was read as — so a sibling entry's
// undocumented-to-us fields (e.g. `timeout`) survive byte-identical
// even when observer's own entry in the SAME group is removed
// alongside it.
func filterClaudeGroupsRaw(groups []claudeHookGroupRaw) (out []claudeHookGroupRaw, removed, kept int) {
	for _, g := range groups {
		var survivors []json.RawMessage
		for _, raw := range g.Hooks {
			var probe claudeHookCommandProbe
			if err := json.Unmarshal(raw, &probe); err == nil && probe.Type == "command" && isObserverClaudeEntry(probe.Command) {
				removed++
				continue
			}
			survivors = append(survivors, raw)
		}
		if len(survivors) == 0 {
			continue
		}
		kept += len(survivors)
		out = append(out, claudeHookGroupRaw{Matcher: g.Matcher, Hooks: survivors})
	}
	return out, removed, kept
}

func (r *Registry) registerClaudeCode() RegistrationResult {
	res := RegistrationResult{Tool: "claude-code", DryRun: r.opts.DryRun}
	settingsDir := filepath.Join(r.opts.HomeDir, ".claude")
	path := filepath.Join(settingsDir, "settings.json")
	res.ConfigPath = path

	// Double-wiring guard: the Claude Code plugin declares exactly the
	// events below, and Claude Code merges hook config from every source,
	// so registering on top of an installed plugin fires each event
	// twice. Skip instead. --force still writes, for the operator who
	// wants both (e.g. mid-migration off the plugin).
	//
	// A skip needs AFFIRMATIVE evidence. When the probe could not read
	// settings.json it reports Uncertain and we fall through to register:
	// losing capture because a config file was corrupt would be a far
	// worse failure than a doubled event. The read below hits the same
	// file and surfaces the underlying error through res.Error.
	pd := claudeplugin.DetectInClaudeDir(settingsDir)
	if pd.Active && !r.opts.Force {
		res.Skipped = true
		res.SkipReason = pd.Reason()
		return res
	}
	res.ProbeWarning = pd.Warning()

	// Serialize observer's own writers of this file, THEN read — the
	// snapshot we mutate has to be taken after the lock, or a
	// concurrent observer's committed write is lost.
	unlock, err := r.lockSettings(path)
	if err != nil {
		res.Error = fmt.Errorf("hook.registerClaudeCode: %w", err)
		return res
	}
	defer unlock()

	// Pin the write target now, before the read — see pinnedTarget (F6).
	pinned := pinWriteTarget(path)

	raw, err := readSettingsFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		res.Error = fmt.Errorf("hook.registerClaudeCode: read: %w", err)
		return res
	}
	// Preserve unknown top-level fields via map[string]json.RawMessage.
	settings := map[string]json.RawMessage{}
	if len(raw) > 0 {
		settings, err = decodeSettingsObject(path, raw)
		if err != nil {
			res.Error = fmt.Errorf("hook.registerClaudeCode: %w", err)
			return res
		}
	}
	// Per-event hooks value is kept as json.RawMessage (B5) so an event
	// this loop never touches — and, within an event it DOES touch, a
	// sibling entry it doesn't own — round-trips byte-for-byte instead
	// of being decoded into (and truncated by) a typed struct.
	var hooksRaw map[string]json.RawMessage
	if existing, ok := settings["hooks"]; ok {
		if err := json.Unmarshal(existing, &hooksRaw); err != nil {
			res.Error = fmt.Errorf("hook.registerClaudeCode: parse hooks: %w", err)
			return res
		}
	}
	if hooksRaw == nil {
		hooksRaw = map[string]json.RawMessage{}
	}

	for _, event := range claudeCodeEvents {
		// Normalize Windows-shaped paths to forward slashes so the
		// hook command survives any shell wrapping the harness applies.
		// Background: the v1.6.25 fix at this site single-quoted the
		// backslash path (`'D:\programsx\...\observer.exe'`) so Git
		// Bash on Windows wouldn't strip backslashes as escape
		// sequences. That worked when Claude Code spawned the hook
		// directly. But the harness's per-tool-call Bash wrapper can
		// strip the single quotes on intermittent invocation patterns
		// (operator-reported 2026-06-06; reliably reproduces on
		// `wsl.exe`-shaped Bash-tool calls), leaving the unquoted
		// backslash path for bash to escape-strip — symptom is the
		// canonical `D:programsxsuperbased-observerbinobserver-hermes.exe:
		// command not found` 127 exit. Forward-slash normalization is
		// a stronger guarantee than single-quoting: `D:/programsx/...`
		// has no character any shell layer interprets specially, so
		// the path arrives at the exec syscall unmodified regardless
		// of how many wrappers stripped or re-quoted it. Same effect
		// for the --config path (see configFlagSuffixForwardSlash).
		// shellQuoteIfNeeded is still called for the safety of paths
		// with spaces (`C:\Program Files\...`); forward-slash variants
		// of those still need quoting, just with whatever quote style
		// survives without escape interpretation.
		binPath := forwardSlashPath(r.opts.BinaryPath)
		cmd := shellQuoteIfNeeded(binPath) + " hook claude-code " + hookEventArg(event) + r.configFlagSuffixForwardSlash()
		var groups []claudeHookGroupRaw
		if raw, ok := hooksRaw[event]; ok && len(raw) > 0 {
			if err := json.Unmarshal(raw, &groups); err != nil {
				res.Error = fmt.Errorf("hook.registerClaudeCode: parse hooks[%s]: %w", event, err)
				return res
			}
		}
		idx := findClaudeGroupWithObserverRaw(groups)
		if idx >= 0 {
			if observerCmdMatchesRaw(groups[idx], cmd) {
				res.AlreadySet = append(res.AlreadySet, event)
				continue
			}
			// Args drifted but the entry is already ours (recognised
			// by content-heuristic — see isObserverClaudeEntry).
			// Silently refresh; covers same-binary arg drift AND
			// cross-binary upgrade (e.g. an npm-bundled observer in
			// node_modules being replaced by a fresh local build).
			// Drop the stale group and fall through to append the
			// up-to-date one.
			groups = append(groups[:idx], groups[idx+1:]...)
		}
		// Conflict check: a non-observer hook command on "*" matcher
		// counts as an unmanaged entry.
		if !r.opts.Force && hasConflictingClaudeHookRaw(groups) {
			res.Error = fmt.Errorf("hook.registerClaudeCode: event %s already has a non-observer hook; pass --force to overwrite", event)
			return res
		}
		entryJSON, err := json.Marshal(claudeHookCommand{Type: "command", Command: cmd})
		if err != nil {
			res.Error = fmt.Errorf("hook.registerClaudeCode: marshal entry: %w", err)
			return res
		}
		groups = append(groups, claudeHookGroupRaw{
			Matcher: "*",
			Hooks:   []json.RawMessage{entryJSON},
		})
		groupsJSON, err := json.Marshal(groups)
		if err != nil {
			res.Error = fmt.Errorf("hook.registerClaudeCode: marshal hooks[%s]: %w", event, err)
			return res
		}
		hooksRaw[event] = groupsJSON
		res.HooksAdded = append(res.HooksAdded, event)
	}

	patched, err := json.Marshal(hooksRaw)
	if err != nil {
		res.Error = fmt.Errorf("hook.registerClaudeCode: marshal hooks: %w", err)
		return res
	}
	settings["hooks"] = patched

	if r.opts.DryRun {
		return res
	}
	if err := writeJSONIndented(settingsDir, pinned, settings); err != nil {
		res.Error = err
		return res
	}
	if err := r.recordChecksum(path); err != nil {
		res.Error = err
		return res
	}
	return res
}

// findClaudeGroupWithObserver returns the index of a group whose
// genericSettingsHookTarget parameterizes registerGenericSettingsHooks
// (Part B item 1, docs/plans/prompt-submit-intervention-exploration-2026-09-07.md
// §6.7): a single-event, Claude-Code-shaped
// {"hooks":{<event>:[{"hooks":[{"type":"command","command":…}]}]}}
// settings.json writer — generalized from registerClaudeCode's own
// body via the ALREADY tool-parameterized isObserverAnyHookEntry
// (the C2/IDE-11 cross-OS-ownership fix). Reused for every tool whose
// registration file matches this exact shape and needs only ONE event
// registered — Gemini CLI (BeforeAgent) and Qwen Code (UserPromptSubmit)
// today. Unlike registerClaudeCode's 21-event lifecycle registration,
// these two tools have no OTHER hook this repo captures, so a single
// event is the complete, honest scope — not a partial implementation
// of a larger one.
type genericSettingsHookTarget struct {
	// tool is the hookReceivers/`hook <tool>` dispatch token embedded in
	// the registered command — the BASE tool name (e.g. "gemini-cli"),
	// never a "-windows" suffix, because the hook receiver on the far
	// end (cmd/observer/hook.go's hookReceivers map) is keyed by base
	// tool name regardless of which config file wrote the command.
	tool string
	// resultTool is the RegistrationResult.Tool label. Empty means
	// "same as tool" (the native target); the cross-OS bridge targets
	// set this to the "-windows" name so callers can tell which config
	// file a result came from while the wire command still names the
	// base tool.
	resultTool string
	// dir is the settings directory (e.g. ~/.gemini, ~/.qwen).
	dir string
	// event is the ONE hook event this tool registers.
	event string
	// errPrefix names the calling registrar in wrapped errors.
	errPrefix string
	// wrapper prefixes every registered command; "" for the native
	// target, `MSYS_NO_PATHCONV=1 wsl.exe -d <distro> -- ` for the
	// cross-OS bridge — same convention as registerClaudeCodeWindows /
	// registerCursorWindows (these tools spawn hooks through Git Bash
	// on Windows too, per the same vendor-doc precedent those two
	// registrars already established), NOT codex's cmd.exe convention.
	wrapper string
}

// label returns t.resultTool when set, else t.tool — the
// RegistrationResult.Tool value for both registerGenericSettingsHooks
// and unregisterGenericSettingsHooks.
func (t genericSettingsHookTarget) label() string {
	if t.resultTool != "" {
		return t.resultTool
	}
	return t.tool
}

// registerGenericSettingsHooks is the shared writer behind
// registerGeminiCLI and registerQwenCode. Conflict/refresh discipline
// mirrors registerClaudeCode exactly, simplified to one event: an
// entry isObserverAnyHookEntry recognises as ours is refreshed
// silently on drift; anything else blocks without --force.
func (r *Registry) registerGenericSettingsHooks(t genericSettingsHookTarget) RegistrationResult {
	res := RegistrationResult{Tool: t.label(), DryRun: r.opts.DryRun}
	path := filepath.Join(t.dir, "settings.json")
	res.ConfigPath = path

	unlock, err := r.lockSettings(path)
	if err != nil {
		res.Error = fmt.Errorf("%s: %w", t.errPrefix, err)
		return res
	}
	defer unlock()

	// Pin the write target now, before the read — see pinnedTarget (F6).
	pinned := pinWriteTarget(path)

	raw, err := readSettingsFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		res.Error = fmt.Errorf("%s: read: %w", t.errPrefix, err)
		return res
	}
	// Preserve unknown top-level fields (model config, MCP servers, …)
	// via map[string]json.RawMessage — same discipline as
	// registerClaudeCode.
	settings := map[string]json.RawMessage{}
	if len(raw) > 0 {
		settings, err = decodeSettingsObject(path, raw)
		if err != nil {
			res.Error = fmt.Errorf("%s: %w", t.errPrefix, err)
			return res
		}
	}
	var hooks map[string][]claudeHookGroup
	if existing, ok := settings["hooks"]; ok {
		if err := json.Unmarshal(existing, &hooks); err != nil {
			res.Error = fmt.Errorf("%s: parse hooks: %w", t.errPrefix, err)
			return res
		}
	}
	if hooks == nil {
		hooks = map[string][]claudeHookGroup{}
	}

	binPath := forwardSlashPath(r.opts.BinaryPath)
	cmd := t.wrapper + shellQuoteIfNeeded(binPath) + " hook " + t.tool + " " + t.event + r.configFlagSuffixForwardSlash()
	groups := hooks[t.event]
	idx := -1
	for i, g := range groups {
		for _, h := range g.Hooks {
			if h.Type == "command" && isObserverAnyHookEntry(h.Command, t.tool) {
				idx = i
			}
		}
	}
	if idx >= 0 {
		if len(groups[idx].Hooks) == 1 && groups[idx].Hooks[0].Type == "command" && groups[idx].Hooks[0].Command == cmd {
			res.AlreadySet = append(res.AlreadySet, t.event)
			return res
		}
		// Stale-observer-args / cross-binary refresh. Drop the stale
		// group; the fresh append below restores.
		groups = append(groups[:idx], groups[idx+1:]...)
	}
	if !r.opts.Force {
		for _, g := range groups {
			for _, h := range g.Hooks {
				if h.Type == "command" && !isObserverAnyHookEntry(h.Command, t.tool) {
					res.Error = fmt.Errorf("%s: event %s already has a non-observer hook; pass --force to overwrite", t.errPrefix, t.event)
					return res
				}
			}
		}
	}
	groups = append(groups, claudeHookGroup{Hooks: []claudeHookCommand{{Type: "command", Command: cmd}}})
	hooks[t.event] = groups
	res.HooksAdded = append(res.HooksAdded, t.event)

	patched, err := json.Marshal(hooks)
	if err != nil {
		res.Error = fmt.Errorf("%s: marshal hooks: %w", t.errPrefix, err)
		return res
	}
	settings["hooks"] = patched

	if r.opts.DryRun {
		return res
	}
	if err := writeJSONIndented(t.dir, pinned, settings); err != nil {
		res.Error = err
		return res
	}
	if err := r.recordChecksum(path); err != nil {
		res.Error = err
		return res
	}
	return res
}

// registerGeminiCLI installs the prompt-submit hook into
// ~/.gemini/settings.json's "hooks" block (contract §6.7: new
// HookGeminiSettings mechanism). Single event: BeforeAgent — the ONLY
// hook this repo has a wired dialect/receiver for on this tool.
func (r *Registry) registerGeminiCLI() RegistrationResult {
	return r.registerGenericSettingsHooks(genericSettingsHookTarget{
		tool:      "gemini-cli",
		dir:       filepath.Join(r.opts.HomeDir, ".gemini"),
		event:     "BeforeAgent",
		errPrefix: "hook.registerGeminiCLI",
	})
}

// registerQwenCode installs the prompt-submit hook into
// ~/.qwen/settings.json's "hooks" block (contract §6.7: new
// HookQwenSettings mechanism). Single event: UserPromptSubmit.
func (r *Registry) registerQwenCode() RegistrationResult {
	return r.registerGenericSettingsHooks(genericSettingsHookTarget{
		tool:      "qwen-code",
		dir:       filepath.Join(r.opts.HomeDir, ".qwen"),
		event:     "UserPromptSubmit",
		errPrefix: "hook.registerQwenCode",
	})
}

// registerQoder installs the prompt-submit hook into
// ~/.qoder/settings.json's "hooks" block (Part B item 2, phase-3a:
// new HookQoderJSON mechanism). Live-fetched 2026-09-07
// (docs.qoder.com/en/cli/hooks): Qoder's settings.json hooks schema
// ({"hooks":{"UserPromptSubmit":[{"matcher":…,"hooks":[{"type":
// "command","command":…,"timeout":…}]}]}}) is byte-identical to
// Claude Code's own — the same shape registerGenericSettingsHooks
// already generalizes for Gemini CLI/Qwen Code. Single event:
// UserPromptSubmit (NIT, phase-3a review: re-counted 2026-09-07 —
// Qoder's own Event Reference overview table lists 23 distinct hook
// event names, not 24 as an earlier pass here miscounted; this repo
// has no receiver for any of the other 22).
func (r *Registry) registerQoder() RegistrationResult {
	return r.registerGenericSettingsHooks(genericSettingsHookTarget{
		tool:      "qoder",
		dir:       filepath.Join(r.opts.HomeDir, ".qoder"),
		event:     "UserPromptSubmit",
		errPrefix: "hook.registerQoder",
	})
}

// poolsideHookEntry is one entry of Poolside's settings.yaml "hooks"
// list (Part B item 2, phase-3a; live-fetched 2026-09-07,
// docs.poolside.ai/hooks):
//
//	hooks:
//	  UserPromptSubmit:
//	    - name: hook-name
//	      matcher: "*"
//	      command: "/path/to/script.sh"
//	      timeout: 60
//
// matcher is documented as required for every event ("Provide this
// field for every event... other events ignore it, so use
// matcher: \"*\"") even though UserPromptSubmit itself doesn't
// consult it.
//
// B5: this type is now used ONLY to construct observer's OWN entry
// when appending it to the (otherwise raw, generic
// map[string]any-decoded) entries list — see decodePoolsideHooksRaw
// and poolsideEntryCommand below. A sibling entry already in the list
// is never decoded into this struct, so an undocumented-to-us field
// on it (e.g. `timeout`) is never routed through — and truncated by —
// a typed decode/re-encode round-trip.
type poolsideHookEntry struct {
	Name    string `yaml:"name"`
	Matcher string `yaml:"matcher"`
	Command string `yaml:"command"`
}

const observerPoolsideHookName = "observer-guard"

// poolsideHookTarget parameterizes registerPoolsideAt for its two
// registration targets: the native `~/.config/poolside` on the
// daemon's own OS, and the cross-OS Windows-side directory the
// poolside-windows bridge writes. Mirrors codexHookTarget/
// droidHookTarget.
type poolsideHookTarget struct {
	// tool is the RegistrationResult.Tool label ("poolside" /
	// "poolside-windows").
	tool string
	// dir is the directory holding settings.yaml.
	dir string
	// wrapper prefixes every registered command; "" for the native
	// target, `MSYS_NO_PATHCONV=1 wsl.exe -d <distro> -- ` for the
	// cross-OS bridge.
	wrapper string
	// errPrefix names the calling registrar in wrapped errors.
	errPrefix string
}

// registerPoolside installs the prompt-submit hook into
// ~/.config/poolside/settings.yaml's "hooks" block (Part B item 2,
// phase-3a: new HookPoolsideYAML mechanism — this repo's FIRST
// YAML-format hook registration writer, distinct from every
// JSON-format settings/hooks.json writer above). Reuses the
// readYAMLMap/writeYAMLMap helpers already built for Hermes'
// config.yaml (internal/hook/hermes_mcp.go) UNCHANGED — the lock/pin/
// checksum hardening below (F8, phase-3a review) wraps the CALL SITE,
// the same way every JSON writer's own lock/pin/checksum trio wraps
// writeJSONIndented rather than living inside it.
//
// F8's second finding: this doc comment used to claim the round-trip
// preserves "everything else... untouched". That overstates what a
// generic map[string]any -> yaml.Marshal round-trip actually
// guarantees — writeYAMLMap's OWN doc comment is honest about this
// ("yaml.v3's map round-trip loses comments and key order"; that is
// why it backs up to path+".bak" first). What genuinely IS preserved
// here is every other top-level KEY'S VALUE (e.g. pool.api_url) — this
// function only mutates the "hooks" subtree before handing the whole
// map back to writeYAMLMap — but the file's original comments,
// blank-line layout, and key ORDER are NOT preserved; the operator's
// settings.yaml is re-serialized by the YAML library on every write,
// same as it always has been for Hermes' config.yaml.
func (r *Registry) registerPoolside() RegistrationResult {
	return r.registerPoolsideAt(poolsideHookTarget{
		tool:      "poolside",
		dir:       filepath.Join(r.opts.HomeDir, ".config", "poolside"),
		errPrefix: "hook.registerPoolside",
	})
}

// registerPoolsideAt is the shared settings.yaml writer behind
// registerPoolside and registerPoolsideWindows. Conflict/refresh
// discipline mirrors registerGenericSettingsHooks: an entry
// isObserverAnyHookEntry recognises as ours is refreshed silently on
// drift; anything else blocks without --force.
//
// F8 (phase-3a review): this writer was missing the three hardening
// steps every JSON settings writer above already has —
// r.lockSettings (cross-process advisory lock, serializes concurrent
// observer writers against each other), pinWriteTarget (resolves a
// symlink write target ONCE, right after the lock, before the first
// read — a TOCTOU guard against the target being retargeted mid-write;
// see pinnedTarget's doc comment), and r.recordChecksum (lets
// `observer doctor`/uninstall detect drift). writeYAMLMap itself is
// NOT modified — it takes a plain path exactly like before; this
// function now passes pinned.target (the resolved target, == path
// when not a symlink) instead of the raw path, and calls
// pinned.verifyUnmoved() immediately before the write exactly as
// writeJSONIndented's own pinned-target contract requires.
func (r *Registry) registerPoolsideAt(t poolsideHookTarget) RegistrationResult {
	res := RegistrationResult{Tool: t.tool, DryRun: r.opts.DryRun}
	path := filepath.Join(t.dir, "settings.yaml")
	res.ConfigPath = path

	unlock, err := r.lockSettings(path)
	if err != nil {
		res.Error = fmt.Errorf("%s: %w", t.errPrefix, err)
		return res
	}
	defer unlock()

	// Pin the write target now, before the read — see pinnedTarget (F6),
	// and F8's doc comment above for why registerPoolsideAt needed this.
	pinned := pinWriteTarget(path)

	doc, err := readYAMLMap(pinned.target)
	if err != nil {
		res.Error = fmt.Errorf("%s: read: %w", t.errPrefix, err)
		return res
	}

	hooks := decodePoolsideHooksRaw(doc)

	binPath := forwardSlashPath(r.opts.BinaryPath)
	cmd := t.wrapper + shellQuoteIfNeeded(binPath) + " hook poolside UserPromptSubmit" + r.configFlagSuffixForwardSlash()
	entries := hooks["UserPromptSubmit"]
	idx := -1
	for i, e := range entries {
		if isObserverAnyHookEntry(poolsideEntryCommand(e), "poolside") {
			idx = i
		}
	}
	if idx >= 0 {
		if poolsideEntryCommand(entries[idx]) == cmd {
			res.AlreadySet = append(res.AlreadySet, "UserPromptSubmit")
			return res
		}
		entries = append(entries[:idx], entries[idx+1:]...)
	}
	if !r.opts.Force {
		for _, e := range entries {
			if !isObserverAnyHookEntry(poolsideEntryCommand(e), "poolside") {
				res.Error = fmt.Errorf("%s: UserPromptSubmit already has a non-observer hook; pass --force to overwrite", t.errPrefix)
				return res
			}
		}
	}
	entries = append(entries, poolsideHookEntry{Name: observerPoolsideHookName, Matcher: "*", Command: cmd})
	hooks["UserPromptSubmit"] = entries
	res.HooksAdded = append(res.HooksAdded, "UserPromptSubmit")
	doc["hooks"] = hooks

	if r.opts.DryRun {
		return res
	}
	if err := pinned.verifyUnmoved(); err != nil {
		res.Error = fmt.Errorf("%s: %w", t.errPrefix, err)
		return res
	}
	if err := writeYAMLMap(pinned.target, doc); err != nil {
		res.Error = fmt.Errorf("%s: write: %w", t.errPrefix, err)
		return res
	}
	if err := r.recordChecksum(path); err != nil {
		res.Error = err
		return res
	}
	return res
}

// unregisterPoolside removes ONLY the observer-owned UserPromptSubmit
// entry from settings.yaml's "hooks" block, leaving every other key
// and every other event's entries untouched.
func (r *Registry) unregisterPoolside() UnregistrationResult {
	return r.unregisterPoolsideAt("poolside", filepath.Join(r.opts.HomeDir, ".config", "poolside"), "hook.unregisterPoolside")
}

// unregisterPoolsideAt is the shared settings.yaml cleaner behind
// unregisterPoolside and unregisterPoolsideWindows. F8 (phase-3a
// review): carries the SAME lock/pin/checksum hardening as
// registerPoolsideAt — see that function's doc comment — mirroring
// how every JSON unregister writer (e.g. unregisterGenericSettingsHooks)
// hardens its removal path identically to its own registration path.
func (r *Registry) unregisterPoolsideAt(tool, dir, errPrefix string) UnregistrationResult {
	res := UnregistrationResult{Tool: tool, DryRun: r.opts.DryRun}
	path := filepath.Join(dir, "settings.yaml")
	res.ConfigPath = path

	unlock, err := r.lockSettings(path)
	if err != nil {
		res.Error = fmt.Errorf("%s: %w", errPrefix, err)
		return res
	}
	defer unlock()

	pinned := pinWriteTarget(path)

	doc, err := readYAMLMap(pinned.target)
	if err != nil {
		res.Error = fmt.Errorf("%s: read: %w", errPrefix, err)
		return res
	}
	hooks := decodePoolsideHooksRaw(doc)
	entries := hooks["UserPromptSubmit"]
	var kept []any
	removed := false
	for _, e := range entries {
		if isObserverAnyHookEntry(poolsideEntryCommand(e), "poolside") {
			removed = true
			continue
		}
		kept = append(kept, e)
	}
	if !removed {
		return res
	}
	if len(kept) == 0 {
		delete(hooks, "UserPromptSubmit")
	} else {
		hooks["UserPromptSubmit"] = kept
	}
	res.HooksRemoved = append(res.HooksRemoved, "UserPromptSubmit")
	if len(hooks) == 0 {
		delete(doc, "hooks")
	} else {
		doc["hooks"] = hooks
	}

	if r.opts.DryRun {
		return res
	}
	if err := pinned.verifyUnmoved(); err != nil {
		res.Error = fmt.Errorf("%s: %w", errPrefix, err)
		return res
	}
	if err := writeYAMLMap(pinned.target, doc); err != nil {
		res.Error = fmt.Errorf("%s: write: %w", errPrefix, err)
		return res
	}
	if err := r.removeChecksum(path); err != nil {
		res.Error = err
		return res
	}
	return res
}

// cascadeHookEntry is one entry of Windsurf/Devin Desktop Cascade's
// hooks.json "pre_user_prompt" list (Part B item 2, phase-3a;
// live-fetched 2026-09-07, docs.devin.ai/desktop/cascade/hooks):
//
//	{"hooks":{"pre_user_prompt":[{"command":"…","powershell":"…"}]}}
//
// No matcher, no "type" field — a flat command list, the vendor's OWN
// shape distinct from every other hooks.json this repo writes.
// PowerShell is left empty here: Devin Desktop's only grounded
// install channel today is the macOS Homebrew cask (internal/
// integration's devin row, GUI.Binary.Installs) — a Windows cross-OS
// bridge is a documented, deferred gap for this mechanism, same as
// HookGeminiSettings/HookQwenSettings/HookFactoryJSON.
//
// B5: this type is now used ONLY to construct observer's OWN entry.
// A sibling entry already in the list — one this repo doesn't own,
// which may carry a documented field this struct doesn't model (e.g.
// a per-entry `timeout`) — is never decoded into it; see
// cascadeEntryProbe and readCascadeHooksFile below.
type cascadeHookEntry struct {
	Command    string `json:"command,omitempty"`
	PowerShell string `json:"powershell,omitempty"`
}

// cascadeHooksConfig describes hooks.json's body shape
// (`{"hooks": {<event>: [<entry>...]}}`) for callers (tests) that want
// a typed READ of the file this package wrote. It is never used to
// decode a file this package is about to re-write — see
// readCascadeHooksFile.
type cascadeHooksConfig struct {
	Hooks map[string][]cascadeHookEntry `json:"hooks"`
}

// cascadeEntryProbe decodes just the "command" field from an
// otherwise-opaque raw Cascade hook entry — enough for
// isObserverAnyHookEntry to tell whether the entry is observer's own,
// without decoding (and thereby truncating) any other field the entry
// carries.
type cascadeEntryProbe struct {
	Command string `json:"command"`
}

// readCascadeHooksFile reads hooks.json's top-level object and its
// "hooks" subtree with the RawMessage boundary pushed one level deeper
// than a single map[string]json.RawMessage (B5): top holds every
// top-level key verbatim (so a key beside "hooks" that Cascade itself
// — or a human — wrote round-trips byte-for-byte), and hooksByEvent
// holds, per event, the list of RAW hook entries (so an event beside
// "pre_user_prompt", and any entry within an event's list this repo
// doesn't own, both round-trip byte-for-byte too — decodePoolsideHooksRaw
// and registerClaudeCode's hooksRaw use the identical shape of fix for
// their own file formats). A missing or empty file yields empty maps
// and no error, matching every other readSettingsFile-style helper in
// this package.
func readCascadeHooksFile(path string) (map[string]json.RawMessage, map[string][]json.RawMessage, error) {
	hooksByEvent := map[string][]json.RawMessage{}
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return map[string]json.RawMessage{}, hooksByEvent, nil
		}
		return nil, nil, fmt.Errorf("hook.readCascadeHooksFile: read: %w", err)
	}
	if len(raw) == 0 {
		return map[string]json.RawMessage{}, hooksByEvent, nil
	}
	top, err := decodeSettingsObject(path, raw)
	if err != nil {
		return nil, nil, fmt.Errorf("hook.readCascadeHooksFile: %w", err)
	}
	if hRaw, ok := top["hooks"]; ok && len(hRaw) > 0 {
		if err := json.Unmarshal(hRaw, &hooksByEvent); err != nil {
			return nil, nil, fmt.Errorf("hook.readCascadeHooksFile: parse hooks: %w", err)
		}
		if hooksByEvent == nil {
			hooksByEvent = map[string][]json.RawMessage{}
		}
	}
	return top, hooksByEvent, nil
}

// registerCascade installs the prompt-submit hook into
// ~/.codeium/windsurf/hooks.json's "pre_user_prompt" list (Part B
// item 2, phase-3a: new HookCascadeJSON mechanism). Single event —
// this repo has no receiver for any other Cascade hook.
func (r *Registry) registerCascade() RegistrationResult {
	res := RegistrationResult{Tool: "devin", DryRun: r.opts.DryRun}
	dir := filepath.Join(r.opts.HomeDir, ".codeium", "windsurf")
	path := filepath.Join(dir, "hooks.json")
	res.ConfigPath = path

	unlock, err := r.lockSettings(path)
	if err != nil {
		res.Error = fmt.Errorf("hook.registerCascade: %w", err)
		return res
	}
	defer unlock()

	pinned := pinWriteTarget(path)

	top, hooksByEvent, err := readCascadeHooksFile(path)
	if err != nil {
		res.Error = err
		return res
	}

	const event = "pre_user_prompt"
	cmd := shellQuoteIfNeeded(forwardSlashPath(r.opts.BinaryPath)) + " hook devin " + event + r.configFlagSuffixForwardSlash()
	entries := hooksByEvent[event]
	idx := -1
	for i, raw := range entries {
		var probe cascadeEntryProbe
		if err := json.Unmarshal(raw, &probe); err != nil {
			continue
		}
		if isObserverAnyHookEntry(probe.Command, "devin") {
			idx = i
		}
	}
	if idx >= 0 {
		var probe cascadeEntryProbe
		if err := json.Unmarshal(entries[idx], &probe); err == nil && probe.Command == cmd {
			res.AlreadySet = append(res.AlreadySet, event)
			return res
		}
		entries = append(entries[:idx], entries[idx+1:]...)
	}
	if !r.opts.Force {
		for _, raw := range entries {
			var probe cascadeEntryProbe
			if err := json.Unmarshal(raw, &probe); err != nil {
				continue
			}
			if !isObserverAnyHookEntry(probe.Command, "devin") {
				res.Error = fmt.Errorf("hook.registerCascade: event %s already has a non-observer hook; pass --force to overwrite", event)
				return res
			}
		}
	}
	entryJSON, err := json.Marshal(cascadeHookEntry{Command: cmd})
	if err != nil {
		res.Error = fmt.Errorf("hook.registerCascade: marshal entry: %w", err)
		return res
	}
	entries = append(entries, entryJSON)
	hooksByEvent[event] = entries
	res.HooksAdded = append(res.HooksAdded, event)

	hooksJSON, err := json.Marshal(hooksByEvent)
	if err != nil {
		res.Error = fmt.Errorf("hook.registerCascade: marshal hooks: %w", err)
		return res
	}
	top["hooks"] = hooksJSON

	if r.opts.DryRun {
		return res
	}
	if err := writeJSONIndented(dir, pinned, top); err != nil {
		res.Error = err
		return res
	}
	if err := r.recordChecksum(path); err != nil {
		res.Error = err
		return res
	}
	return res
}

// unregisterCascade removes ONLY the observer-owned pre_user_prompt
// entry from ~/.codeium/windsurf/hooks.json, leaving every other
// top-level key, every other event, and every sibling entry in
// pre_user_prompt's own list byte-for-byte untouched.
func (r *Registry) unregisterCascade() UnregistrationResult {
	res := UnregistrationResult{Tool: "devin", DryRun: r.opts.DryRun}
	dir := filepath.Join(r.opts.HomeDir, ".codeium", "windsurf")
	path := filepath.Join(dir, "hooks.json")
	res.ConfigPath = path

	unlock, err := r.lockSettings(path)
	if err != nil {
		res.Error = fmt.Errorf("hook.unregisterCascade: %w", err)
		return res
	}
	defer unlock()

	pinned := pinWriteTarget(path)

	top, hooksByEvent, err := readCascadeHooksFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return res
		}
		res.Error = err
		return res
	}
	const event = "pre_user_prompt"
	entries := hooksByEvent[event]
	var kept []json.RawMessage
	removed := false
	for _, raw := range entries {
		var probe cascadeEntryProbe
		if err := json.Unmarshal(raw, &probe); err == nil && isObserverAnyHookEntry(probe.Command, "devin") {
			removed = true
			continue
		}
		kept = append(kept, raw)
	}
	if !removed {
		return res
	}
	if len(kept) == 0 {
		delete(hooksByEvent, event)
	} else {
		hooksByEvent[event] = kept
	}
	res.HooksRemoved = append(res.HooksRemoved, event)

	if len(hooksByEvent) == 0 {
		delete(top, "hooks")
	} else {
		hooksJSON, err := json.Marshal(hooksByEvent)
		if err != nil {
			res.Error = fmt.Errorf("hook.unregisterCascade: marshal hooks: %w", err)
			return res
		}
		top["hooks"] = hooksJSON
	}

	if r.opts.DryRun {
		return res
	}
	if err := writeJSONIndented(dir, pinned, top); err != nil {
		res.Error = err
		return res
	}
	if err := r.removeChecksum(path); err != nil {
		res.Error = err
		return res
	}
	return res
}

// registerCommandCode drops the go:embed'd observer-guard.ts bridge
// into ~/.commandcode/mods/ (Part B item 2, phase-3a: new
// HookCommandCodeMod mechanism — internal/hook/commandcodemod).
// Unlike every other registrar in this file, this is NOT a
// JSON/YAML config-file mutation: commandcode's Mods SDK discovers
// loose .ts files by directory presence, so "registering" means
// writing (or overwriting, on re-run) the one file. No lock/pinned-
// target machinery applies — there is no shared config file another
// process could be racing to write.
//
// FIXED (FIX cluster, item 5): this used to unconditionally overwrite
// whatever (if anything) already sat at the mod path, with no
// conflict guard and no checksum recorded — the only writer in this
// file without the takeover-refusal / --force / checksum discipline
// every JSON/YAML writer above has. Now: an existing file that
// doesn't look observer-written (commandcodemod.LooksLikeObserverPlugin)
// is refused without --force (mirroring registerCascade's own
// foreign-entry guard), backed up to path+".bak" before being
// overwritten under --force (mirroring writeYAMLMap's backup
// discipline for a lossy takeover), and a checksum is recorded after
// every successful write so unregisterCommandCode can detect
// out-of-band drift before deleting.
func (r *Registry) registerCommandCode() RegistrationResult {
	res := RegistrationResult{Tool: "command-code", DryRun: r.opts.DryRun}
	dir := filepath.Join(r.opts.HomeDir, ".commandcode", "mods")
	path := filepath.Join(dir, commandcodemod.ModFileName)
	res.ConfigPath = path

	existing, readErr := os.ReadFile(path)
	alreadyInstalled := readErr == nil
	foreign := alreadyInstalled && !commandcodemod.LooksLikeObserverPlugin(existing)
	if foreign && !r.opts.Force {
		res.Error = fmt.Errorf("hook.registerCommandCode: %s already exists and doesn't look like an observer-managed file; pass --force to overwrite", path)
		return res
	}

	if r.opts.DryRun {
		if !alreadyInstalled {
			res.HooksAdded = append(res.HooksAdded, "transformInput")
		} else {
			res.AlreadySet = append(res.AlreadySet, "transformInput")
		}
		return res
	}
	if foreign {
		if err := backupForeignCommandCodeMod(path, existing); err != nil {
			res.Error = fmt.Errorf("hook.registerCommandCode: %w", err)
			return res
		}
	}
	if err := commandcodemod.WritePlugin(dir, r.opts.BinaryPath, r.opts.ConfigPath); err != nil {
		res.Error = fmt.Errorf("hook.registerCommandCode: %w", err)
		return res
	}
	if err := r.recordChecksum(path); err != nil {
		res.Error = fmt.Errorf("hook.registerCommandCode: %w", err)
		return res
	}
	if alreadyInstalled {
		res.AlreadySet = append(res.AlreadySet, "transformInput")
	} else {
		res.HooksAdded = append(res.HooksAdded, "transformInput")
	}
	return res
}

// backupForeignCommandCodeMod writes a path+".bak" copy of data (the
// pre-overwrite content) — the same discipline writeYAMLMap already
// applies to a Poolside/Hermes settings.yaml takeover, adapted for a
// bare-file (non-JSON/YAML) target. Only called when registerCommandCode
// is about to overwrite a foreign (non-observer-written) file under
// --force, so an operator who had something else at this path can
// still recover it.
func backupForeignCommandCodeMod(path string, data []byte) error {
	info, err := os.Stat(path)
	mode := os.FileMode(0o600)
	if err == nil {
		mode = info.Mode().Perm()
	}
	if err := os.WriteFile(path+".bak", data, mode); err != nil {
		return fmt.Errorf("backup %s: %w", path, err)
	}
	return nil
}

// unregisterCommandCode removes the observer-guard.ts mod file.
//
// FIXED (FIX cluster, item 5): this used to delete purely on
// commandcodemod.Installed's presence check, with no verification
// that the on-disk file was still the one observer wrote (vs. having
// been modified since, or — now that registerCommandCode can take
// over a foreign file under --force — legitimately being someone
// else's file). Now checksum-guarded exactly like
// unregisterClaudeCode: a mismatch refuses without --force.
func (r *Registry) unregisterCommandCode() UnregistrationResult {
	res := UnregistrationResult{Tool: "command-code", DryRun: r.opts.DryRun}
	dir := filepath.Join(r.opts.HomeDir, ".commandcode", "mods")
	path := filepath.Join(dir, commandcodemod.ModFileName)
	res.ConfigPath = path

	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return res
		}
		res.Error = fmt.Errorf("hook.unregisterCommandCode: read: %w", err)
		return res
	}
	if r.opts.DryRun {
		res.HooksRemoved = append(res.HooksRemoved, "transformInput")
		return res
	}

	match, err := r.checksumMatches(path, raw)
	if err != nil {
		res.Error = fmt.Errorf("hook.unregisterCommandCode: checksum: %w", err)
		return res
	}
	res.ChecksumMatch = match
	if !match && !r.opts.Force {
		res.Error = fmt.Errorf("hook.unregisterCommandCode: %s has been modified since install (checksum mismatch); pass --force to remove anyway", path)
		return res
	}

	if err := commandcodemod.RemovePlugin(dir); err != nil {
		res.Error = fmt.Errorf("hook.unregisterCommandCode: %w", err)
		return res
	}
	if err := r.removeChecksum(path); err != nil {
		res.Error = fmt.Errorf("hook.unregisterCommandCode: %w", err)
		return res
	}
	res.HooksRemoved = append(res.HooksRemoved, "transformInput")
	return res
}

// decodePoolsideHooksRaw pulls doc["hooks"] apart into per-event RAW
// entry lists (B5) — unlike the typed decodePoolsideHooks this
// replaced, entries are never routed through poolsideHookEntry, so an
// entry this repo doesn't own keeps every field it was read with
// (e.g. the vendor's documented per-entry `timeout`) instead of being
// silently truncated to {name, matcher, command} on the next write.
// readYAMLMap already decoded the whole document generically (every
// map as map[string]any, every sequence as []any), so doc["hooks"] is
// already exactly that shape — no re-marshal/re-decode round-trip is
// needed to get raw per-entry values the way readCascadeHooksFile's
// JSON equivalent needs json.RawMessage. An event whose value isn't a
// []any (a malformed document) is skipped rather than erroring, same
// leniency the typed version had via its own best-effort YAML decode.
func decodePoolsideHooksRaw(doc map[string]any) map[string][]any {
	hooks := map[string][]any{}
	raw, ok := doc["hooks"]
	if !ok {
		return hooks
	}
	m, ok := raw.(map[string]any)
	if !ok {
		return hooks
	}
	for event, v := range m {
		if list, ok := v.([]any); ok {
			hooks[event] = list
		}
	}
	return hooks
}

// poolsideEntryCommand extracts the "command" field from an
// otherwise-opaque raw Poolside hook entry (a generic
// map[string]any, as readYAMLMap/decodePoolsideHooksRaw decode it, OR
// the poolsideHookEntry struct observer's own freshly-appended entry
// still is at this point in the same slice) — enough for
// isObserverAnyHookEntry to tell whether the entry is observer's own,
// without decoding (and thereby truncating) any other field.
func poolsideEntryCommand(e any) string {
	switch v := e.(type) {
	case map[string]any:
		cmd, _ := v["command"].(string)
		return cmd
	case poolsideHookEntry:
		return v.Command
	default:
		return ""
	}
}

// unregisterGenericSettingsHooks removes ONLY the observer-owned hook
// group for t.event from the settings.json's "hooks" block, leaving
// every other key (and every other event) untouched. Symmetric
// counterpart of registerGenericSettingsHooks.
func (r *Registry) unregisterGenericSettingsHooks(t genericSettingsHookTarget) UnregistrationResult {
	res := UnregistrationResult{Tool: t.label(), DryRun: r.opts.DryRun}
	path := filepath.Join(t.dir, "settings.json")
	res.ConfigPath = path

	unlock, err := r.lockSettings(path)
	if err != nil {
		res.Error = fmt.Errorf("%s: %w", t.errPrefix, err)
		return res
	}
	defer unlock()

	// Pin the write target now, before the read — see pinnedTarget (F6).
	pinned := pinWriteTarget(path)

	raw, err := readSettingsFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return res
		}
		res.Error = fmt.Errorf("%s: read: %w", t.errPrefix, err)
		return res
	}
	settings, err := decodeSettingsObject(path, raw)
	if err != nil {
		res.Error = fmt.Errorf("%s: %w", t.errPrefix, err)
		return res
	}
	existing, ok := settings["hooks"]
	if !ok {
		return res
	}
	var hooks map[string][]claudeHookGroup
	if err := json.Unmarshal(existing, &hooks); err != nil {
		res.Error = fmt.Errorf("%s: parse hooks: %w", t.errPrefix, err)
		return res
	}
	groups := hooks[t.event]
	kept := groups[:0]
	removed := false
	for _, g := range groups {
		isOurs := len(g.Hooks) > 0
		for _, h := range g.Hooks {
			if h.Type != "command" || !isObserverAnyHookEntry(h.Command, t.tool) {
				isOurs = false
			}
		}
		if isOurs {
			removed = true
			continue
		}
		kept = append(kept, g)
	}
	if !removed {
		return res
	}
	if len(kept) == 0 {
		delete(hooks, t.event)
	} else {
		hooks[t.event] = kept
	}
	patched, err := json.Marshal(hooks)
	if err != nil {
		res.Error = fmt.Errorf("%s: marshal hooks: %w", t.errPrefix, err)
		return res
	}
	settings["hooks"] = patched
	res.HooksRemoved = append(res.HooksRemoved, t.event)

	if r.opts.DryRun {
		return res
	}
	if err := writeJSONIndented(t.dir, pinned, settings); err != nil {
		res.Error = err
		return res
	}
	if err := r.removeChecksum(path); err != nil {
		res.Error = err
		return res
	}
	return res
}

func (r *Registry) unregisterGeminiCLI() UnregistrationResult {
	return r.unregisterGenericSettingsHooks(genericSettingsHookTarget{
		tool: "gemini-cli", dir: filepath.Join(r.opts.HomeDir, ".gemini"),
		event: "BeforeAgent", errPrefix: "hook.unregisterGeminiCLI",
	})
}

func (r *Registry) unregisterQwenCode() UnregistrationResult {
	return r.unregisterGenericSettingsHooks(genericSettingsHookTarget{
		tool: "qwen-code", dir: filepath.Join(r.opts.HomeDir, ".qwen"),
		event: "UserPromptSubmit", errPrefix: "hook.unregisterQwenCode",
	})
}

func (r *Registry) unregisterQoder() UnregistrationResult {
	return r.unregisterGenericSettingsHooks(genericSettingsHookTarget{
		tool: "qoder", dir: filepath.Join(r.opts.HomeDir, ".qoder"),
		event: "UserPromptSubmit", errPrefix: "hook.unregisterQoder",
	})
}

// droidHookTarget parameterizes registerFactoryDroidAt for its two
// registration targets: the native `~/.factory` on the daemon's own OS,
// and the cross-OS Windows-side `.factory` the droid-windows bridge
// writes. Mirrors codexHookTarget — one shared writer (CLAUDE.md #4),
// differing only in where it writes and whether the command carries the
// wsl.exe bridge wrapper. The dispatch vocabulary embedded in the
// command is always the literal "droid" (hardcoded in
// registerFactoryDroidAt), never "droid-windows" — the hook receiver on
// the far end is keyed by base tool name.
type droidHookTarget struct {
	// tool is the RegistrationResult.Tool label ("droid" / "droid-windows").
	tool string
	// dir is the .factory directory holding hooks.json.
	dir string
	// wrapper prefixes every registered command; "" for the native
	// target, `MSYS_NO_PATHCONV=1 wsl.exe -d <distro> -- ` for the
	// cross-OS bridge.
	wrapper string
	// errPrefix names the calling registrar in wrapped errors.
	errPrefix string
}

// registerFactoryDroid installs the prompt-submit hook into
// ~/.factory/hooks.json (contract §6.7: new HookFactoryJSON
// mechanism). Reuses codexHooksConfig/readCodexHooks/writeCodexHooks
// directly — Droid's hooks.json is a DEDICATED hooks-only file, the
// same shape as Codex's own (matcher+hooks groups keyed by event),
// not a shared settings.json with unrelated keys to preserve. Single
// event: UserPromptSubmit.
func (r *Registry) registerFactoryDroid() RegistrationResult {
	return r.registerFactoryDroidAt(droidHookTarget{
		tool:      "droid",
		dir:       filepath.Join(r.opts.HomeDir, ".factory"),
		errPrefix: "hook.registerFactoryDroid",
	})
}

// registerFactoryDroidAt is the shared ~/.factory/hooks.json writer
// behind registerFactoryDroid and registerFactoryDroidWindows.
// Conflict/refresh discipline mirrors registerCodexAt, simplified to
// one event: an entry isObserverAnyHookEntry recognises as ours is
// refreshed silently on drift; anything else blocks without --force.
func (r *Registry) registerFactoryDroidAt(t droidHookTarget) RegistrationResult {
	res := RegistrationResult{Tool: t.tool, DryRun: r.opts.DryRun}
	path := filepath.Join(t.dir, "hooks.json")
	res.ConfigPath = path

	unlock, err := r.lockSettings(path)
	if err != nil {
		res.Error = fmt.Errorf("%s: %w", t.errPrefix, err)
		return res
	}
	defer unlock()

	pinned := pinWriteTarget(path)

	cfg, err := readCodexHooks(path)
	if err != nil {
		res.Error = err
		return res
	}

	const event = "UserPromptSubmit"
	cmd := t.wrapper + shellQuoteIfNeeded(forwardSlashPath(r.opts.BinaryPath)) + " hook droid " + event + r.configFlagSuffixForwardSlash()
	groups := cfg.Hooks[event]
	idx := -1
	for i, g := range groups {
		for _, h := range g.Hooks {
			if h.Type == "command" && isObserverAnyHookEntry(h.Command, "droid") {
				idx = i
			}
		}
	}
	if idx >= 0 {
		if len(groups[idx].Hooks) == 1 && groups[idx].Hooks[0].Command == cmd {
			res.AlreadySet = append(res.AlreadySet, event)
			return res
		}
		groups = append(groups[:idx], groups[idx+1:]...)
	}
	if !r.opts.Force {
		for _, g := range groups {
			for _, h := range g.Hooks {
				if h.Type == "command" && !isObserverAnyHookEntry(h.Command, "droid") {
					res.Error = fmt.Errorf("%s: event %s already has a non-observer hook; pass --force to overwrite", t.errPrefix, event)
					return res
				}
			}
		}
	}
	groups = append(groups, codexHookGroup{
		Matcher: "*",
		Hooks:   []claudeHookCommand{{Type: "command", Command: cmd}},
	})
	cfg.Hooks[event] = groups
	res.HooksAdded = append(res.HooksAdded, event)

	if r.opts.DryRun {
		return res
	}
	if err := writeCodexHooks(t.dir, pinned, cfg); err != nil {
		res.Error = err
		return res
	}
	if err := r.recordChecksum(path); err != nil {
		res.Error = err
		return res
	}
	return res
}

// unregisterFactoryDroid removes ONLY the observer-owned
// UserPromptSubmit group from ~/.factory/hooks.json.
func (r *Registry) unregisterFactoryDroid() UnregistrationResult {
	return r.unregisterFactoryDroidAt("droid", filepath.Join(r.opts.HomeDir, ".factory"), "hook.unregisterFactoryDroid")
}

// unregisterFactoryDroidAt is the shared hooks.json cleaner behind
// unregisterFactoryDroid and unregisterFactoryDroidWindows.
func (r *Registry) unregisterFactoryDroidAt(tool, dir, errPrefix string) UnregistrationResult {
	res := UnregistrationResult{Tool: tool, DryRun: r.opts.DryRun}
	path := filepath.Join(dir, "hooks.json")
	res.ConfigPath = path

	unlock, err := r.lockSettings(path)
	if err != nil {
		res.Error = fmt.Errorf("%s: %w", errPrefix, err)
		return res
	}
	defer unlock()

	// Pin the write target now, before the read — see pinnedTarget (F6).
	pinned := pinWriteTarget(path)

	cfg, err := readCodexHooks(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return res
		}
		res.Error = err
		return res
	}
	const event = "UserPromptSubmit"
	groups := cfg.Hooks[event]
	kept := groups[:0]
	removed := false
	for _, g := range groups {
		isOurs := len(g.Hooks) > 0
		for _, h := range g.Hooks {
			if h.Type != "command" || !isObserverAnyHookEntry(h.Command, "droid") {
				isOurs = false
			}
		}
		if isOurs {
			removed = true
			continue
		}
		kept = append(kept, g)
	}
	if !removed {
		return res
	}
	if len(kept) == 0 {
		delete(cfg.Hooks, event)
	} else {
		cfg.Hooks[event] = kept
	}
	res.HooksRemoved = append(res.HooksRemoved, event)

	if r.opts.DryRun {
		return res
	}
	if err := writeCodexHooks(dir, pinned, cfg); err != nil {
		res.Error = err
		return res
	}
	if err := r.removeChecksum(path); err != nil {
		res.Error = err
		return res
	}
	return res
}

// registerClaudeCodeWindows installs Claude Code hooks into a Windows-
// side `.claude/settings.json` (typically
// `/mnt/c/Users/<u>/.claude/settings.json`) with each command wrapped
// in
//
//	MSYS_NO_PATHCONV=1 wsl.exe -d <distro> -- <linux-bin> hook
//	claude-code <event> [--config <wsl-path>]
//
// so the Windows Claude Desktop process can fire it from Git Bash (the
// shell Claude Code uses on Windows per code.claude.com/docs/en/hooks:
// "Git Bash on Windows"). The MSYS_NO_PATHCONV=1 prefix is load-
// bearing — without it, Git Bash's MSYS layer auto-translates the
// Linux `/home/...` path arguments into `C:/Program Files/Git/home/...`
// before they reach wsl.exe, the inner binary can't be found, and
// every hook fires exit-127. Symptom in the JSONL:
//
//	{"type":"hook_non_blocking_error","exitCode":127,
//	 "stderr":"/bin/bash: C:/Program Files/Git/home/.../observer:
//	 No such file or directory"}
//
// confirmed on Claude Desktop v2.1.138 (2026-05-20).
//
// MSYS_NO_PATHCONV is bash-only (silently ignored by macOS/Linux `sh -c`
// and by cmd.exe), so the prefix is safe to set unconditionally on
// the Windows registrar without runtime branching.
//
// Distro lookup: Options.WSLDistro → $WSL_DISTRO_NAME. Empty distro
// is an error; the command would be ambiguous on a host with multiple
// distros. Same contract as registerCursorWindows.
func (r *Registry) registerClaudeCodeWindows() RegistrationResult {
	res := RegistrationResult{Tool: "claude-code-windows", DryRun: r.opts.DryRun}

	claudeDir := r.detectWindowsClaudeHome()
	if claudeDir == "" {
		if r.foreignAutoDetectSuppressed(r.opts.WindowsClaudeHome) {
			r.sandboxSkipResult(&res, ".claude", "WindowsClaudeHome", r.opts.WindowsClaudeHome)
			return res
		}
		res.Error = errors.New("hook.registerClaudeCodeWindows: no Windows-side .claude/ detected (set WindowsClaudeHome explicitly or run on a host where crossmount sees /mnt/c/Users/<u>/.claude/)")
		return res
	}
	res.ConfigPath = filepath.Join(claudeDir, "settings.json")

	// Same double-wiring guard as the native registrar, applied to the
	// Windows-side .claude the cross-OS bridge writes into: that install
	// keeps its own plugin state there. Same fail-open-to-wiring rule.
	pdWin := claudeplugin.DetectInClaudeDir(claudeDir)
	if pdWin.Active && !r.opts.Force {
		res.Skipped = true
		res.SkipReason = pdWin.Reason()
		return res
	}
	res.ProbeWarning = pdWin.Warning()

	distro := r.opts.WSLDistro
	if distro == "" {
		distro = os.Getenv("WSL_DISTRO_NAME")
	}
	if distro == "" {
		res.Error = errors.New("hook.registerClaudeCodeWindows: WSL distro unknown — set Options.WSLDistro or run inside WSL (so $WSL_DISTRO_NAME is set)")
		return res
	}
	// MSYS_NO_PATHCONV=1 inline-env prefix — see registerClaudeCodeWindows
	// docstring for the Git Bash path-translation rationale.
	wrapperPrefix := fmt.Sprintf("MSYS_NO_PATHCONV=1 wsl.exe -d %s -- ", shellQuoteIfNeeded(distro))

	unlock, err := r.lockSettings(res.ConfigPath)
	if err != nil {
		res.Error = fmt.Errorf("hook.registerClaudeCodeWindows: %w", err)
		return res
	}
	defer unlock()

	// Pin the write target now, before the read — see pinnedTarget (F6).
	pinned := pinWriteTarget(res.ConfigPath)

	raw, err := readSettingsFile(res.ConfigPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		res.Error = fmt.Errorf("hook.registerClaudeCodeWindows: read: %w", err)
		return res
	}
	settings := map[string]json.RawMessage{}
	if len(raw) > 0 {
		settings, err = decodeSettingsObject(res.ConfigPath, raw)
		if err != nil {
			res.Error = fmt.Errorf("hook.registerClaudeCodeWindows: %w", err)
			return res
		}
	}
	var hooks map[string][]claudeHookGroup
	if existing, ok := settings["hooks"]; ok {
		if err := json.Unmarshal(existing, &hooks); err != nil {
			res.Error = fmt.Errorf("hook.registerClaudeCodeWindows: parse hooks: %w", err)
			return res
		}
	}
	if hooks == nil {
		hooks = map[string][]claudeHookGroup{}
	}

	for _, event := range claudeCodeEvents {
		cmd := wrapperPrefix + shellQuoteIfNeeded(r.opts.BinaryPath) + " hook claude-code " + hookEventArg(event) + r.configFlagSuffix()
		groups := hooks[event]
		idx := findClaudeGroupWithObserverWindows(groups)
		if idx >= 0 {
			if observerCmdMatches(groups[idx], cmd) {
				res.AlreadySet = append(res.AlreadySet, event)
				continue
			}
			// Refresh-on-drift: binary path or config flag changed but
			// the wsl-wrapped shape is still ours. Drop the stale group
			// and fall through to append the current one.
			groups = append(groups[:idx], groups[idx+1:]...)
		}
		if !r.opts.Force && hasConflictingClaudeHookWindows(groups) {
			res.Error = fmt.Errorf("hook.registerClaudeCodeWindows: event %s already has a non-observer hook; pass --force to overwrite", event)
			return res
		}
		groups = append(groups, claudeHookGroup{
			Matcher: "*",
			Hooks:   []claudeHookCommand{{Type: "command", Command: cmd}},
		})
		hooks[event] = groups
		res.HooksAdded = append(res.HooksAdded, event)
	}

	patched, err := json.Marshal(hooks)
	if err != nil {
		res.Error = fmt.Errorf("hook.registerClaudeCodeWindows: marshal hooks: %w", err)
		return res
	}
	settings["hooks"] = patched

	if r.opts.DryRun {
		return res
	}
	if err := writeJSONIndented(claudeDir, pinned, settings); err != nil {
		res.Error = err
		return res
	}
	if err := r.recordChecksum(res.ConfigPath); err != nil {
		res.Error = err
		return res
	}
	return res
}

// isObserverClaudeEntry recognises a hook command as one previously
// written by ANY observer claude-code (Linux/default) registrar.
// The ` hook claude-code ` token sequence is the stable signature,
// regardless of which observer binary path prefixes it.
// Content-heuristic rather than binary-path-prefix so a hook left
// behind by a differently-installed observer (e.g. an npm-bundled
// binary in node_modules, an upgrade that moved the install root,
// a Linux build with a renamed `$HOME`) is still recognised as ours
// and silently refreshed on the next `observer start` auto-register
// pass. Without this, the conflict guard would mis-classify those
// stale-but-ours entries as foreign third-party hooks and refuse to
// touch them without `--force`, leaving Claude Code firing the OLD
// observer binary forever — exactly the bug class that caused the
// v1.6.22 claude-code effort sidecar to silently stay empty for
// users who had a node_modules-bundled observer registered before
// upgrading to a local build.
//
// The Windows registrar's isObserverWindowsClaudeEntry is the same
// idea with an additional wsl.exe-wrapper guard; this is its
// Linux/default counterpart. To keep the two heuristics matching
// disjoint shapes (so the Linux/default registrar doesn't rewrite
// wsl-bridge entries into native-shape on hosts that have both
// configurations registered against the same settings.json), this
// helper EXCLUDES wsl.exe-wrapped commands. Any cmd that
// isObserverWindowsClaudeEntry would accept is rejected here.
//
// Trade-off: a third-party command containing the literal
// ` hook claude-code ` substring would be misclassified as observer
// and silently rewritten. The risk is acceptable — the syntax is
// distinctive enough that an accidental collision is essentially
// impossible, and the same trade-off the Windows registrar already
// accepts in production since v1.6.22.
func isObserverClaudeEntry(cmd string) bool {
	if !strings.Contains(cmd, " hook claude-code ") {
		return false
	}
	if strings.HasPrefix(cmd, "wsl.exe ") || strings.HasPrefix(cmd, "MSYS_NO_PATHCONV=1 wsl.exe ") {
		return false
	}
	return true
}

// IsObserverClaudeCodeHookCommand reports whether cmd is an observer
// `hook claude-code <event>` invocation, in either the native shape or
// the wsl.exe cross-OS bridge shape this package writes.
//
// This is the STRICT counterpart of isObserverClaudeEntry. The two exist
// for opposite reasons and must not be merged:
//
//   - isObserverClaudeEntry is deliberately loose (a bare
//     ` hook claude-code ` substring test) because the REGISTRAR has to
//     recognise its own stale entries in order to refresh them; a
//     false negative there strands a user on an old binary forever.
//   - this one is for REPORTING (the `claude-code.plugin` doctor probe),
//     where a false POSITIVE is the harm: a third-party command such as
//     `/opt/acme hook claude-code audit` would otherwise raise a
//     double-wiring warning naming wiring observer never wrote.
//
// So this tokenizes and checks an allow-list: after stripping any
// leading environment assignments and the `wsl.exe -d <distro> --`
// bridge prefix, argv[0] must NAME an observer binary
// (isObserverBinaryToken — basename `observer`/`superbased`, optional
// `.exe`, optional `-suffix`) and be followed by exactly the tokens
// `hook` `claude-code`.
func IsObserverClaudeCodeHookCommand(cmd string) bool {
	return isObserverAnyHookEntry(cmd, "claude-code")
}

// isObserverAnyHookEntry reports whether cmd is an observer
// `hook <tool> <event>` invocation in EITHER shape observer writes:
//
//   - native, as a Windows-native npm install writes it —
//     `C:\...\observer.exe hook cursor stop --config C:\...\config.toml`
//     (forward- or back-slashed, quoted or bare);
//   - the cross-OS bridge, as the `*-windows` registrars write it —
//     `[MSYS_NO_PATHCONV=1 ]wsl.exe -d <distro> -- /home/<u>/observer
//     hook cursor stop --config /home/<u>/.observer/config.toml`.
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

// observerHookInvocation is isObserverAnyHookEntry's single tokenized
// test: strip env assignments + any wsl.exe bridge prefix, then require
// argv[0] to name an observer binary followed by `hook <tool>`.
func observerHookInvocation(cmd, tool string) bool {
	toks := stripHookCommandPrefix(splitCommandTokens(cmd))
	if len(toks) < 3 {
		return false
	}
	return isObserverBinaryToken(toks[0]) && toks[1] == "hook" && toks[2] == tool
}

// stripHookCommandPrefix removes the leading `KEY=VALUE` environment
// assignments and, if present, the `wsl.exe -d <distro> --` bridge that
// registerClaudeCodeWindows writes, returning the tokens of the command
// actually executed. Returns nil when a bridge prefix is present but
// malformed (no `--` separator), so a half-understood command is never
// treated as ours.
func stripHookCommandPrefix(toks []string) []string {
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

// isObserverWindowsClaudeEntry recognises a hook command in the
// Windows-side settings.json as observer-owned, in EITHER shape:
//
//   - the cross-OS bridge this registrar writes — a `wsl.exe `
//     invocation (with or without the legacy MSYS_NO_PATHCONV=1 env
//     prefix) that ultimately calls `<bin> hook claude-code <event>`.
//     The MSYS prefix shipped in v1.6.22+; matching either lets
//     refresh-on-drift rewrite older prefix-free entries;
//   - a NATIVE `<...>\observer.exe hook claude-code <event>` entry
//     written by an earlier Windows-native npm `observer init`
//     (isObserverAnyHookEntry — class C2 / audit IDE-11).
//
// The native half is what lets the bridge REPLACE a stale native
// registration without --force. Without it the native entry read as a
// third-party hook, registration errored, and the stale entry kept
// writing the stranded Windows DB.
//
// Note the deliberate asymmetry with isObserverClaudeEntry, the
// native-target predicate, which still REJECTS wsl.exe shapes: the two
// targets must not fight over a settings.json that carries both, and
// only the Windows target is allowed to convert one shape into the
// other (native → bridge, never the reverse).
func isObserverWindowsClaudeEntry(cmd string) bool {
	if strings.Contains(cmd, " hook claude-code ") {
		if strings.HasPrefix(cmd, "wsl.exe ") {
			return true
		}
		if strings.HasPrefix(cmd, "MSYS_NO_PATHCONV=1 wsl.exe ") {
			return true
		}
	}
	return isObserverAnyHookEntry(cmd, "claude-code")
}

// findClaudeGroupWithObserverWindows returns the index of a group
// whose single hook command is a wsl-wrapped observer claude-code
// invocation, or -1.
func findClaudeGroupWithObserverWindows(groups []claudeHookGroup) int {
	for i, g := range groups {
		for _, h := range g.Hooks {
			if h.Type == "command" && isObserverWindowsClaudeEntry(h.Command) {
				return i
			}
		}
	}
	return -1
}

// hasConflictingClaudeHookWindows reports whether any group contains a
// non-observer command. Used by the Windows registrar's --force-less
// path to refuse silent overwrite of user-authored hooks.
func hasConflictingClaudeHookWindows(groups []claudeHookGroup) bool {
	for _, g := range groups {
		for _, h := range g.Hooks {
			if h.Type != "command" {
				continue
			}
			if !isObserverWindowsClaudeEntry(h.Command) {
				return true
			}
		}
	}
	return false
}

// cursorEvents is the set of Cursor hook events we register for. The first
// 5 are the original Tier 1 set (shell, MCP, file edits, prompt submit,
// stop). Tier 2 (v1.4.45) extends coverage to file reads (closing audit
// C2), tool failures, session-lifecycle markers, sub-agent fan-out, and
// pre-compact dispatch. Tier 3 (v1.4.45) adds the universal preToolUse
// to fill the long-tail-tool gap (Glob/Grep/Search/Write/etc. — tools
// the per-tool before* hooks miss) plus three paired-after observers
// registered no-row pending update-in-place: postToolUse,
// afterShellExecution, afterMCPExecution. Tier 4 (v1.6.18) adds
// afterAgentThought + afterAgentResponse: on Cursor 3.4.20-3.9.16 (the
// versions live-confirmed at the time) agent-transcripts/*.jsonl writing
// had stopped, so the JSONL walker BuildStopTranscriptEvents relied on
// as a fallback for finalized assistant prose was believed dead-code;
// live-captured payloads on those versions confirmed the events fire
// once-per-finalized-block (not per-token-delta as the v1.4.45
// docstring claimed). CORRECTION (2026-08-07, see
// docs/audits/cursor-windows-capture-diagnosis-2026-08-07.md): on
// Cursor 3.14.27 agent-transcripts/*.jsonl writing is back — it is
// currently the ONLY thing capturing Windows-IDE Cursor activity, so
// the JSONL walker is live again, not dead-code, on that version.
// Whether 3.14.27 still fires afterAgentResponse with usage fields is
// unverified (see that audit's probe P2/P3). See
// internal/adapter/cursor/adapter.go for the full rationale. Tab
// events (beforeTabFileRead, afterTabFileEdit) remain out of scope.
var cursorEvents = []string{
	"beforeSubmitPrompt", "beforeShellExecution", "afterFileEdit", "beforeMCPExecution", "stop",
	"beforeReadFile", "postToolUseFailure", "sessionStart", "sessionEnd",
	"subagentStart", "subagentStop", "preCompact",
	"preToolUse", "postToolUse", "afterShellExecution", "afterMCPExecution",
	"afterAgentThought", "afterAgentResponse",
}

type cursorHookEntry struct {
	Command string `json:"command"`
}

func (r *Registry) registerCursor() RegistrationResult {
	res := RegistrationResult{Tool: "cursor", DryRun: r.opts.DryRun}
	cursorDir := filepath.Join(r.opts.HomeDir, ".cursor")
	path := filepath.Join(cursorDir, "hooks.json")
	res.ConfigPath = path

	unlock, err := r.lockSettings(path)
	if err != nil {
		res.Error = fmt.Errorf("hook.registerCursor: %w", err)
		return res
	}
	defer unlock()

	// Pin the write target now, before the read — see pinnedTarget (F6).
	pinned := pinWriteTarget(path)

	raw, err := readSettingsFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		res.Error = fmt.Errorf("hook.registerCursor: read: %w", err)
		return res
	}
	settings := map[string]json.RawMessage{}
	if len(raw) > 0 {
		settings, err = decodeSettingsObject(path, raw)
		if err != nil {
			res.Error = fmt.Errorf("hook.registerCursor: %w", err)
			return res
		}
	}
	hooks := map[string][]cursorHookEntry{}
	if existing, ok := settings["hooks"]; ok {
		_ = json.Unmarshal(existing, &hooks)
	}

	for _, event := range cursorEvents {
		// Forward-slash-normalize the binary + config path before
		// quoting — see registerClaudeCode for the full rationale
		// (the harness can strip the single quotes upstream, leaving
		// unquoted-Windows-path backslashes for Git Bash to escape-
		// strip). Forward slashes survive any shell wrapping.
		binPath := forwardSlashPath(r.opts.BinaryPath)
		cmd := shellQuoteIfNeeded(binPath) + " hook cursor " + event + r.configFlagSuffixForwardSlash()
		if slicesContainsCommand(hooks[event], cmd) {
			res.AlreadySet = append(res.AlreadySet, event)
			continue
		}
		// Stale-observer-args case: existing command is recognised as
		// observer-written (by content-heuristic — see
		// isObserverCursorEntry) but has different args. Covers
		// same-binary arg drift (e.g. missing --config after we add a
		// new flag) AND cross-binary upgrade (e.g. an npm-bundled
		// observer in node_modules being replaced by a fresh local
		// build). Silently refresh; non-observer entries are still
		// treated as conflicts via hasCursorConflict below.
		if hasStaleObserverEntry(hooks[event], cmd) {
			hooks[event] = filterStaleObserverEntries(hooks[event], cmd)
		}
		if !r.opts.Force && hasCursorConflict(hooks[event]) {
			res.Error = fmt.Errorf("hook.registerCursor: event %s already has a non-observer hook; pass --force to overwrite", event)
			return res
		}
		hooks[event] = append(hooks[event], cursorHookEntry{Command: cmd})
		res.HooksAdded = append(res.HooksAdded, event)
	}

	settings["version"] = json.RawMessage("1")
	hookJSON, err := json.Marshal(hooks)
	if err != nil {
		res.Error = fmt.Errorf("hook.registerCursor: marshal hooks: %w", err)
		return res
	}
	settings["hooks"] = hookJSON

	if r.opts.DryRun {
		return res
	}
	if err := writeJSONIndented(cursorDir, pinned, settings); err != nil {
		res.Error = err
		return res
	}
	if err := r.recordChecksum(path); err != nil {
		res.Error = err
		return res
	}
	return res
}

// registerCursorWindows installs Cursor hooks into a Windows-side
// .cursor/hooks.json (typically `/mnt/c/Users/<u>/.cursor/hooks.json`)
// with each command wrapped in `wsl.exe -d <distro> -- <linux-bin>
// hook cursor <event> [--config <wsl-path>]`. The Windows-Cursor
// process spawns wsl.exe; wsl.exe routes stdin/stdout to the WSL-side
// observer binary; the binary processes the hook payload exactly as
// it would on a native Linux install. Uses double-dash (`--`)
// separator so wsl.exe stops parsing its own flags before the linux
// binary path; this keeps any future wsl.exe flags additions from
// silently consuming an arg meant for observer.
//
// The WSL distro name comes from Options.WSLDistro, falling back to
// $WSL_DISTRO_NAME at registration time. Empty distro is an error —
// without it, the registered command would be ambiguous on a host
// with multiple WSL distros.
func (r *Registry) registerCursorWindows() RegistrationResult {
	res := RegistrationResult{Tool: "cursor-windows", DryRun: r.opts.DryRun}

	cursorDir := r.detectWindowsCursorHome()
	if cursorDir == "" {
		if r.foreignAutoDetectSuppressed(r.opts.WindowsCursorHome) {
			r.sandboxSkipResult(&res, ".cursor", "WindowsCursorHome", r.opts.WindowsCursorHome)
			return res
		}
		res.Error = errors.New("hook.registerCursorWindows: no Windows-side .cursor/ detected (set WindowsCursorHome explicitly or run on a host where crossmount sees /mnt/c/Users/<u>/.cursor/)")
		return res
	}
	res.ConfigPath = filepath.Join(cursorDir, "hooks.json")

	distro := r.opts.WSLDistro
	if distro == "" {
		distro = os.Getenv("WSL_DISTRO_NAME")
	}
	if distro == "" {
		res.Error = errors.New("hook.registerCursorWindows: WSL distro unknown — set Options.WSLDistro or run inside WSL (so $WSL_DISTRO_NAME is set)")
		return res
	}

	unlock, err := r.lockSettings(res.ConfigPath)
	if err != nil {
		res.Error = fmt.Errorf("hook.registerCursorWindows: %w", err)
		return res
	}
	defer unlock()

	// Pin the write target now, before the read — see pinnedTarget (F6).
	pinned := pinWriteTarget(res.ConfigPath)

	raw, err := readSettingsFile(res.ConfigPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		res.Error = fmt.Errorf("hook.registerCursorWindows: read: %w", err)
		return res
	}
	settings := map[string]json.RawMessage{}
	if len(raw) > 0 {
		settings, err = decodeSettingsObject(res.ConfigPath, raw)
		if err != nil {
			res.Error = fmt.Errorf("hook.registerCursorWindows: %w", err)
			return res
		}
	}
	hooks := map[string][]cursorHookEntry{}
	if existing, ok := settings["hooks"]; ok {
		_ = json.Unmarshal(existing, &hooks)
	}

	// NO MSYS_NO_PATHCONV=1 prefix here: Cursor executes hook commands via
	// PowerShell on Windows (it runs `Get-Content <payload> -Raw | & {
	// $input | <command> }`), where a bash-style `VAR=value cmd` env-prefix
	// is not a command — PowerShell fails with "The term
	// 'MSYS_NO_PATHCONV=1' is not recognized" and the hook never fires
	// (live-confirmed against Cursor 3.9.16, session 77fefbb3). PowerShell
	// (and cmd.exe) pass the /home/... arg to wsl.exe verbatim — they don't
	// do MSYS path translation — so the prefix that Git Bash needs is both
	// unnecessary AND fatal here. The v1.6.22 MSYS prefix targeted an older
	// Cursor that ran hooks through /bin/bash (Git Bash); the current
	// surface is PowerShell. isObserverWindowsCursorEntry still recognises
	// the legacy MSYS-prefixed shape, so refresh-on-drift replaces it.
	// (claude-code's Windows bridge may share this once its hook shell is
	// confirmed — tracked separately.)
	wrapperPrefix := fmt.Sprintf("wsl.exe -d %s -- ", shellQuoteIfNeeded(distro))
	for _, event := range cursorEvents {
		cmd := wrapperPrefix + shellQuoteIfNeeded(r.opts.BinaryPath) + " hook cursor " + event + r.configFlagSuffix()
		if slicesContainsCommand(hooks[event], cmd) {
			res.AlreadySet = append(res.AlreadySet, event)
			continue
		}
		// Stale-observer-entry case: any command starting with `wsl.exe`
		// that contains ` hook cursor ` was clearly written by a prior
		// observer install — we own it regardless of which observer
		// binary path it points at. This matters across upgrades,
		// distro changes, or smoke-test artifacts: the binary path
		// changes but the entry is still ours and should be refreshed,
		// not treated as a foreign conflict. filterStaleObserverWindowsCursorEntries
		// ALSO drops dangling one-off observer debug shims (see
		// isDanglingObserverWindowsCursorShim) that never carried the
		// canonical " hook cursor " signature.
		hooks[event] = filterStaleObserverWindowsCursorEntries(hooks[event], cmd, event, r.opts.ConfigPath)
		if !r.opts.Force && hasNonObserverWindowsCursorEntry(hooks[event]) {
			res.Error = fmt.Errorf("hook.registerCursorWindows: event %s already has a non-observer hook; pass --force to overwrite", event)
			return res
		}
		hooks[event] = append(hooks[event], cursorHookEntry{Command: cmd})
		res.HooksAdded = append(res.HooksAdded, event)
	}

	settings["version"] = json.RawMessage("1")
	hookJSON, err := json.Marshal(hooks)
	if err != nil {
		res.Error = fmt.Errorf("hook.registerCursorWindows: marshal hooks: %w", err)
		return res
	}
	settings["hooks"] = hookJSON

	if r.opts.DryRun {
		return res
	}
	if err := writeJSONIndented(cursorDir, pinned, settings); err != nil {
		res.Error = err
		return res
	}
	if err := r.recordChecksum(res.ConfigPath); err != nil {
		res.Error = err
		return res
	}
	return res
}

// isObserverWindowsCursorEntry recognises an entry in the Windows-side
// hooks.json as observer-owned, in EITHER shape:
//
//   - the cross-OS bridge this registrar writes — a `wsl.exe ...`
//     invocation (with or without the legacy MSYS_NO_PATHCONV=1 env
//     prefix) that ultimately calls `<bin> hook cursor <event> ...`;
//   - a NATIVE `C:\...\observer.exe hook cursor <event>` entry written
//     by an earlier Windows-native npm `observer init`
//     (isObserverAnyHookEntry — class C2 / audit IDE-11, which found
//     exactly this in a live ~/.cursor/hooks.json).
//
// Recognising the native half is what lets refresh-on-drift REPLACE a
// stale native registration with the bridge command without --force,
// instead of erroring and leaving the native entry writing the
// stranded Windows DB. Anything else is foreign and still treated as a
// user-authored conflict.
func isObserverWindowsCursorEntry(cmd string) bool {
	if strings.Contains(cmd, " hook cursor ") {
		if strings.HasPrefix(cmd, "wsl.exe ") {
			return true
		}
		if strings.HasPrefix(cmd, "MSYS_NO_PATHCONV=1 wsl.exe ") {
			return true
		}
	}
	return isObserverAnyHookEntry(cmd, "cursor")
}

// isDanglingObserverWindowsCursorShim recognises a stale
// observer-authored debug artifact for the Windows-Cursor bridge
// that does NOT carry the canonical " hook cursor " signature
// isObserverWindowsCursorEntry looks for — e.g. a one-off tee/debug
// wrapper (`wsl.exe -d <distro> -- /tmp/cursor-tee-shim.sh <event>
// --config '<ours>'`) left behind by a prior observer debugging
// session. It is recognised as ours ONLY when ALL three hold, so a
// genuinely user-authored PowerShell/cmd.exe hook is never
// misclassified as stale and silently dropped:
//
//   - cmd invokes via the wsl.exe cross-OS bridge shape (with or
//     without the legacy MSYS_NO_PATHCONV=1 prefix);
//   - cmd's --config argument points at THIS registrar's own config
//     file (configPath, threaded from Options.ConfigPath) — an empty
//     configPath never matches anything, since without it we can't
//     attribute authorship at all;
//   - cmd names event as a bare argument token.
//
// See docs/audits/cursor-windows-capture-diagnosis-2026-08-07.md §4
// F2: a dead /tmp/cursor-tee-shim.sh entry (the shim itself long
// gone — /tmp is cleared on WSL restart) permanently blocked
// auto-register by tripping hasNonObserverWindowsCursorEntry on
// every `observer start`, because it started with `wsl.exe ` but
// never contained ` hook cursor `.
func isDanglingObserverWindowsCursorShim(cmd, event, configPath string) bool {
	if configPath == "" {
		return false
	}
	if !strings.HasPrefix(cmd, "wsl.exe ") && !strings.HasPrefix(cmd, "MSYS_NO_PATHCONV=1 wsl.exe ") {
		return false
	}
	if !strings.Contains(cmd, "--config "+shellQuote(configPath)) {
		return false
	}
	return commandArgsInclude(cmd, event)
}

// commandArgsInclude reports whether cmd contains token as a bare,
// whitespace-delimited argument (optionally single- or
// double-quoted). Splitting on whitespace is safe here: it is only
// ever called with cursorEvents members (identifiers with no
// internal whitespace), so a quoted value elsewhere in cmd (e.g. a
// --config path) can never be mistaken for a match.
func commandArgsInclude(cmd, token string) bool {
	for _, f := range strings.Fields(cmd) {
		if strings.Trim(f, `'"`) == token {
			return true
		}
	}
	return false
}

// filterStaleObserverWindowsCursorEntries drops any
// observer-recognised stale entry that doesn't match `want`,
// including dangling debug shims for this event
// (isDanglingObserverWindowsCursorShim). Used by the cursor-windows
// registrar to clear prior registrations before appending the
// canonical command. Non-observer entries pass through untouched so
// the conflict check below can flag them.
func filterStaleObserverWindowsCursorEntries(entries []cursorHookEntry, want, event, configPath string) []cursorHookEntry {
	out := make([]cursorHookEntry, 0, len(entries))
	for _, e := range entries {
		isOurs := isObserverWindowsCursorEntry(e.Command) || isDanglingObserverWindowsCursorShim(e.Command, event, configPath)
		if isOurs && e.Command != want {
			continue
		}
		out = append(out, e)
	}
	return out
}

// hasNonObserverWindowsCursorEntry reports whether the slice has any
// entry we don't recognise as observer-authored. Anything not
// matching the wsl.exe + `hook cursor` shape counts as foreign.
func hasNonObserverWindowsCursorEntry(entries []cursorHookEntry) bool {
	for _, e := range entries {
		if !isObserverWindowsCursorEntry(e.Command) {
			return true
		}
	}
	return false
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

// isWindowsPath returns true if s looks Windows-shaped (contains a
// backslash separator). Used by the codex registrar to pick a
// cmd.exe-safe quoter on Windows paths and the POSIX single-quote
// quoter on Linux/macOS paths. Path-shape rather than runtime.GOOS
// so cross-platform tests can exercise both shapes without OS
// mocking — and so a Linux host writing hooks for a Windows-side
// codex (via shared mounts, hypothetical) would also pick up the
// right quoting.
func isWindowsPath(s string) bool {
	return strings.Contains(s, `\`)
}

// forwardSlashPath converts a Windows-shaped path (backslash
// separators) into the forward-slash equivalent, leaving non-
// Windows-shaped paths untouched. Used by registerClaudeCode +
// registerCursor — both write hook commands that Claude Code on
// Windows invokes through Git Bash (per code.claude.com/docs/en/hooks:
// "Git Bash on Windows") OR through whatever inner shell the harness
// uses to wrap a single Bash-tool call (which may strip the
// single-quote wrapping the registrar applies). With backslash paths,
// every layer that loses the single quotes turns the unquoted
// backslashes into shell escape sequences and strips them —
// `D:\programsx\...` collapses to `D:programsx...` and bash exits 127
// "command not found". Forward-slash paths survive every shell
// wrapping intact: Git Bash, PowerShell, and cmd.exe all accept
// `D:/programsx/...` as a Windows file path, and forward slashes are
// never escape characters in any of those shells, so the path is
// untouched even when an upstream wrapper strips the registrar's
// quoting. This is the v1.8.2+ evolution of the v1.6.25 single-quote
// fix (see TestRegisterClaudeCodeQuotesWindowsBinaryPath for the
// original symptom); the single-quote fix worked when Claude Code
// ran the hook command directly in Git Bash but the harness's
// per-tool-call Bash wrapper would still strip the outer single
// quotes on intermittent invocation patterns (operator-reported
// 2026-06-06 across `wsl.exe`-style Bash-tool calls). Forward-slash
// normalization is the bulletproof fix because it removes the only
// character that any shell layer interprets specially.
func forwardSlashPath(s string) string {
	if !isWindowsPath(s) {
		return s
	}
	return strings.ReplaceAll(s, `\`, `/`)
}

// cmdQuoteIfNeeded wraps s in DOUBLE quotes when it contains
// cmd.exe-meaningful characters, otherwise returns it verbatim.
// Used by the codex registrar for Windows-shaped paths because
// Codex 0.133+ on Windows spawns hooks through cmd.exe, which only
// understands `"..."` quoting — `'...'` is interpreted literally
// as part of the argument (operator-reported 2026-05-23: codex
// hook fires exit 1 with `'C:\\...\\observer.exe'` because cmd
// can't find a binary whose name starts with a literal `'`).
//
// cmd.exe doesn't have backslash-as-escape inside `"..."`, so
// Windows paths round-trip cleanly without further escaping.
// Windows file names disallow `"` (NTFS-enforced), so we don't
// need to escape embedded quotes either.
//
// Trade-off vs shellQuoteIfNeeded: double-quote allows `$VAR`
// expansion in POSIX shells. Not a concern here — codex's
// codexCmdQuoteIfNeeded only routes to this when the path is
// Windows-shaped (the path will be evaluated by cmd.exe, not by
// /bin/sh).
func cmdQuoteIfNeeded(s string) string {
	if s == "" {
		return `""`
	}
	for _, r := range s {
		if r == ' ' || r == '"' || r == '&' || r == '<' || r == '>' || r == '|' || r == '^' || r == '(' || r == ')' || r == '%' {
			return `"` + s + `"`
		}
	}
	return s
}

// codexCmdQuoteIfNeeded picks between POSIX single-quote and
// cmd.exe double-quote based on the path shape. Used only by the
// codex registrar — claudecode + cursor stay on shellQuoteIfNeeded
// because Claude Code on Windows always uses Git Bash (POSIX) and
// cursor's hook execution shell on Windows-native is unverified
// (operator can re-target it if a regression appears there too).
//
// Path-shape detection rather than runtime.GOOS so cross-platform
// tests can pin both shapes without OS mocking.
func codexCmdQuoteIfNeeded(s string) string {
	if isWindowsPath(s) {
		return cmdQuoteIfNeeded(s)
	}
	return shellQuoteIfNeeded(s)
}

// hasCursorConflict reports whether any entry carries a command
// that isn't recognised as observer-shaped. Used by the force-less
// path to refuse silent overwrite of user-authored hooks.
// Content-heuristic via isObserverCursorEntry so entries from a
// different observer install path (npm bundle, cross-binary upgrade)
// fall through to the refresh path rather than being flagged as
// foreign.
func hasCursorConflict(entries []cursorHookEntry) bool {
	for _, e := range entries {
		if !isObserverCursorEntry(e.Command) {
			return true
		}
	}
	return false
}

func hookEventArg(event string) string {
	// Claude Code event names are CamelCase; we use lower-kebab on the CLI.
	switch event {
	case "SessionStart":
		return "session-start"
	case "SessionEnd":
		return "session-end"
	case "UserPromptSubmit":
		return "user-prompt-submit"
	case "PreToolUse":
		return "pre-tool"
	case "PostToolUse":
		return "post-tool"
	case "PostToolUseFailure":
		return "post-tool-failure"
	case "Stop":
		return "stop"
	case "StopFailure":
		return "stop-failure"
	case "PreCompact":
		return "pre-compact"
	case "PostCompact":
		return "post-compact"
	case "SubagentStart":
		return "subagent-start"
	case "SubagentStop":
		return "subagent-stop"
	case "Notification":
		return "notification"
	case "CwdChanged":
		return "cwd-changed"
	case "Setup":
		return "setup"
	case "UserPromptExpansion":
		return "user-prompt-expansion"
	case "PostToolBatch":
		return "post-tool-batch"
	case "PermissionRequest":
		return "permission-request"
	case "PermissionDenied":
		return "permission-denied"
	case "InstructionsLoaded":
		return "instructions-loaded"
	case "ConfigChange":
		return "config-change"
	case "WorktreeCreate":
		return "worktree-create"
	case "WorktreeRemove":
		return "worktree-remove"
	}
	return event
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
func readSettingsFile(path string) ([]byte, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if fi.Size() > maxSettingsFileBytes {
		return nil, fmt.Errorf("%s is %d bytes, over observer's %d-byte settings-file limit; refusing to read or modify it", path, fi.Size(), maxSettingsFileBytes)
	}
	return os.ReadFile(path)
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
		return nil, fmt.Errorf("%s contains an explicit JSON null, not a settings object; refusing to modify it (replace its contents with {} or delete the file)", path)
	}
	if key, ok := duplicateTopLevelKey(raw); ok {
		return nil, fmt.Errorf("%s has a duplicate top-level %q key; refusing to modify it because rewriting would silently keep only the last one (de-duplicate the file by hand first)", path, key)
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
	return lockSettingsFile(path)
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
		if !errors.Is(err, os.ErrExist) {
			return func() {}, nil // fail-open: see docstring
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
			return nil, fmt.Errorf("timed out after %s waiting for %s (another observer process is writing %s; delete the lock file if no observer is running)", settingsLockTimeout, lockPath, path)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

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
//     double-break, no partial state).
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
	current, readErr := os.ReadFile(quarantine)
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
	_ = os.Remove(lockPath)
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
		return fmt.Errorf("%s: changed between read and write (symlink-ness changed); refusing to write — re-run to pick up the new state", p.path)
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
	target := pinned.target
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
	fi, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symlink; refusing to delete it — unlinking it would silently detach it while its target file survives untouched, and deleting the target could destroy a file tracked elsewhere; remove it by hand if that's what you want", path)
	}
	current, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if !bytes.Equal(current, expected) {
		return fmt.Errorf("%s changed since observer decided to delete it (likely written by the AI tool, or another process, in between); refusing to delete a file observer never actually read — re-run to make a fresh decision against the current content", path)
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
func (r *Registry) recordChecksum(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("hook.recordChecksum: %w", err)
	}
	sum := sha256.Sum256(data)
	entry := map[string]any{
		"sha256":      hex.EncodeToString(sum[:]),
		"registered":  time.Now().UTC().Format(time.RFC3339),
		"binary_path": r.opts.BinaryPath,
	}

	csPath := r.opts.ChecksumsPath
	if csPath == "" {
		csPath = filepath.Join(r.opts.HomeDir, ".observer", "hook_checksums.json")
	}

	unlock, err := r.lockSettings(csPath)
	if err != nil {
		return fmt.Errorf("hook.recordChecksum: %w", err)
	}
	defer unlock()

	// Pin the write target now, before the read — see pinnedTarget (F6).
	pinned := pinWriteTarget(csPath)

	current := map[string]any{}
	if raw, err := os.ReadFile(csPath); err == nil {
		_ = json.Unmarshal(raw, &current)
	}
	current[path] = entry
	body, err := json.MarshalIndent(current, "", "  ")
	if err != nil {
		return fmt.Errorf("hook.recordChecksum: marshal: %w", err)
	}
	if err := atomicWriteFile(pinned, body); err != nil {
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

// observerCmdMatches reports whether group has exactly one hook command
// equal to want. Anything else (different command, multiple hooks,
// non-command type) returns false.
func observerCmdMatches(group claudeHookGroup, want string) bool {
	if len(group.Hooks) != 1 {
		return false
	}
	h := group.Hooks[0]
	return h.Type == "command" && h.Command == want
}

// slicesContainsCommand reports whether entries holds a hook with
// Command == want.
func slicesContainsCommand(entries []cursorHookEntry, want string) bool {
	for _, e := range entries {
		if e.Command == want {
			return true
		}
	}
	return false
}

// isObserverCursorEntry recognises a hook command as one previously
// written by ANY observer cursor (Linux/default) registrar. The
// ` hook cursor ` token sequence is the stable signature, regardless
// of which observer binary path prefixes it. Same content-heuristic
// rationale as isObserverClaudeEntry — lets refresh-on-drift upgrade
// entries left behind by a differently-installed observer (npm
// bundle in node_modules, cross-binary upgrade, renamed $HOME)
// without --force. See isObserverClaudeEntry for the full trade-off
// discussion; the cursor entry shape uses the same observer-internal
// syntax so the collision risk is equally negligible.
//
// Excludes wsl.exe-wrapped commands so this and
// isObserverWindowsCursorEntry match disjoint shapes — see
// isObserverClaudeEntry's docstring for the same rationale.
func isObserverCursorEntry(cmd string) bool {
	if !strings.Contains(cmd, " hook cursor ") {
		return false
	}
	if strings.HasPrefix(cmd, "wsl.exe ") || strings.HasPrefix(cmd, "MSYS_NO_PATHCONV=1 wsl.exe ") {
		return false
	}
	return true
}

// hasStaleObserverEntry reports whether entries holds an observer-
// recognised hook command that doesn't match want (i.e. an old
// registration — possibly from a different observer binary — that
// needs refreshing). Different from a non-observer conflict — those
// go through hasCursorConflict.
func hasStaleObserverEntry(entries []cursorHookEntry, want string) bool {
	for _, e := range entries {
		if isObserverCursorEntry(e.Command) && e.Command != want {
			return true
		}
	}
	return false
}

// filterStaleObserverEntries drops entries recognised as observer-
// written that don't match the canonical want. Used by the refresh
// path to clear a previous registration (including ones from a
// different observer binary path) before appending the fresh one.
// Non-observer entries (other tools the user wired in by hand) pass
// through untouched.
func filterStaleObserverEntries(entries []cursorHookEntry, want string) []cursorHookEntry {
	out := make([]cursorHookEntry, 0, len(entries))
	for _, e := range entries {
		if isObserverCursorEntry(e.Command) && e.Command != want {
			continue
		}
		out = append(out, e)
	}
	return out
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
}

// Unregister removes observer hook entries from tool's config file. Only
// entries whose Command starts with opts.BinaryPath are removed; any
// user-authored hooks in the same file are preserved. If the file's
// checksum doesn't match the one recorded at install time, returns an
// error unless opts.Force is set.
//
// Supported tools: "claude-code", "claude-code-windows", "cursor",
// "codex", "codex-windows".
func (r *Registry) Unregister(tool string) UnregistrationResult {
	switch tool {
	case "claude-code":
		return r.unregisterClaudeCode()
	case "claude-code-windows":
		return r.unregisterClaudeCodeWindows()
	case "cursor":
		return r.unregisterCursor()
	case "cursor-windows":
		return r.unregisterCursorWindows()
	case "codex":
		return r.unregisterCodex()
	case "codex-windows":
		return r.unregisterCodexWindows()
	case "gemini-cli":
		return r.unregisterGeminiCLI()
	case "gemini-cli-windows":
		return r.unregisterGeminiCLIWindows()
	case "qwen-code":
		return r.unregisterQwenCode()
	case "qwen-code-windows":
		return r.unregisterQwenCodeWindows()
	case "droid":
		return r.unregisterFactoryDroid()
	case "droid-windows":
		return r.unregisterFactoryDroidWindows()
	case "qoder":
		return r.unregisterQoder()
	case "qoder-windows":
		return r.unregisterQoderWindows()
	case "poolside":
		return r.unregisterPoolside()
	case "poolside-windows":
		return r.unregisterPoolsideWindows()
	case "devin":
		return r.unregisterCascade()
	case "command-code":
		return r.unregisterCommandCode()
	case "command-code-windows":
		return r.unregisterCommandCodeWindows()
	default:
		return UnregistrationResult{
			Tool:   tool,
			Error:  fmt.Errorf("hook.Unregister: tool %q not supported", tool),
			DryRun: r.opts.DryRun,
		}
	}
}

func (r *Registry) unregisterClaudeCode() UnregistrationResult {
	res := UnregistrationResult{Tool: "claude-code", DryRun: r.opts.DryRun}
	settingsDir := filepath.Join(r.opts.HomeDir, ".claude")
	path := filepath.Join(settingsDir, "settings.json")
	res.ConfigPath = path

	unlock, err := r.lockSettings(path)
	if err != nil {
		res.Error = fmt.Errorf("hook.unregisterClaudeCode: %w", err)
		return res
	}
	defer unlock()

	// Pin the write target now, before the read — see pinnedTarget (F6).
	pinned := pinWriteTarget(path)

	raw, err := readSettingsFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			res.Skipped = true
			return res
		}
		res.Error = fmt.Errorf("hook.unregisterClaudeCode: read: %w", err)
		return res
	}

	settings, err := decodeSettingsObject(path, raw)
	if err != nil {
		res.Error = fmt.Errorf("hook.unregisterClaudeCode: %w", err)
		return res
	}
	// Kept as json.RawMessage per event (B5) — see registerClaudeCode's
	// hooksRaw for the rationale; filterClaudeGroupsRaw preserves every
	// surviving sibling entry's unknown fields byte-for-byte.
	hooksRaw := map[string]json.RawMessage{}
	if existing, ok := settings["hooks"]; ok {
		if err := json.Unmarshal(existing, &hooksRaw); err != nil {
			res.Error = fmt.Errorf("hook.unregisterClaudeCode: parse hooks: %w", err)
			return res
		}
	}

	for event, raw := range hooksRaw {
		var groups []claudeHookGroupRaw
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &groups); err != nil {
				res.Error = fmt.Errorf("hook.unregisterClaudeCode: parse hooks[%s]: %w", event, err)
				return res
			}
		}
		newGroups, removed, kept := filterClaudeGroupsRaw(groups)
		if removed > 0 {
			res.HooksRemoved = append(res.HooksRemoved, event)
		}
		if kept > 0 {
			res.HooksKept = append(res.HooksKept, event)
		}
		if len(newGroups) == 0 {
			delete(hooksRaw, event)
			continue
		}
		newGroupsJSON, err := json.Marshal(newGroups)
		if err != nil {
			res.Error = fmt.Errorf("hook.unregisterClaudeCode: marshal hooks[%s]: %w", event, err)
			return res
		}
		hooksRaw[event] = newGroupsJSON
	}
	sort.Strings(res.HooksRemoved)
	sort.Strings(res.HooksKept)

	// No observer entries to remove — skip the checksum guard entirely
	// and treat this as a no-op regardless of file drift.
	if len(res.HooksRemoved) == 0 {
		res.Skipped = true
		return res
	}

	// There is real work to do — now verify the file hasn't drifted since
	// we installed, so we don't clobber user edits. Passing --force
	// bypasses the guard.
	match, err := r.checksumMatches(path, raw)
	if err != nil {
		res.Error = fmt.Errorf("hook.unregisterClaudeCode: checksum: %w", err)
		return res
	}
	res.ChecksumMatch = match
	if !match && !r.opts.Force {
		res.Error = fmt.Errorf("hook.unregisterClaudeCode: %s has been modified since install (checksum mismatch); pass --force to remove anyway", path)
		return res
	}

	if len(hooksRaw) == 0 {
		delete(settings, "hooks")
	} else {
		patched, err := json.Marshal(hooksRaw)
		if err != nil {
			res.Error = fmt.Errorf("hook.unregisterClaudeCode: marshal hooks: %w", err)
			return res
		}
		settings["hooks"] = patched
	}

	if r.opts.DryRun {
		return res
	}

	if len(settings) == 0 {
		if err := removeEmptyConfigFile(path, raw); err != nil {
			res.Error = fmt.Errorf("hook.unregisterClaudeCode: remove empty %s: %w", path, err)
			return res
		}
	} else {
		if err := writeJSONIndented(settingsDir, pinned, settings); err != nil {
			res.Error = err
			return res
		}
	}
	if err := r.removeChecksum(path); err != nil {
		res.Error = err
		return res
	}
	return res
}

// unregisterClaudeCodeWindows removes hook entries this registrar
// previously wrote into the Windows-side .claude/settings.json. Mirrors
// unregisterClaudeCode but matches on the wsl.exe-wrapped signature
// rather than a binary-path prefix, so user-authored hooks (and stale
// observer entries from a different distro / binary path) are still
// recognised as ours. The user's non-observer entries are preserved.
func (r *Registry) unregisterClaudeCodeWindows() UnregistrationResult {
	res := UnregistrationResult{Tool: "claude-code-windows", DryRun: r.opts.DryRun}

	claudeDir := r.detectWindowsClaudeHome()
	if claudeDir == "" {
		res.Skipped = true
		return res
	}
	res.ConfigPath = filepath.Join(claudeDir, "settings.json")

	unlock, err := r.lockSettings(res.ConfigPath)
	if err != nil {
		res.Error = fmt.Errorf("hook.unregisterClaudeCodeWindows: %w", err)
		return res
	}
	defer unlock()

	// Pin the write target now, before the read — see pinnedTarget (F6).
	pinned := pinWriteTarget(res.ConfigPath)

	raw, err := readSettingsFile(res.ConfigPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			res.Skipped = true
			return res
		}
		res.Error = fmt.Errorf("hook.unregisterClaudeCodeWindows: read: %w", err)
		return res
	}

	settings, err := decodeSettingsObject(res.ConfigPath, raw)
	if err != nil {
		res.Error = fmt.Errorf("hook.unregisterClaudeCodeWindows: %w", err)
		return res
	}
	hooks := map[string][]claudeHookGroup{}
	if existing, ok := settings["hooks"]; ok {
		if err := json.Unmarshal(existing, &hooks); err != nil {
			res.Error = fmt.Errorf("hook.unregisterClaudeCodeWindows: parse hooks: %w", err)
			return res
		}
	}

	for event, groups := range hooks {
		newGroups, removed, kept := filterClaudeGroupsWindows(groups)
		if removed > 0 {
			res.HooksRemoved = append(res.HooksRemoved, event)
		}
		if kept > 0 {
			res.HooksKept = append(res.HooksKept, event)
		}
		if len(newGroups) == 0 {
			delete(hooks, event)
		} else {
			hooks[event] = newGroups
		}
	}
	sort.Strings(res.HooksRemoved)
	sort.Strings(res.HooksKept)

	if len(res.HooksRemoved) == 0 {
		res.Skipped = true
		return res
	}

	match, err := r.checksumMatches(res.ConfigPath, raw)
	if err != nil {
		res.Error = fmt.Errorf("hook.unregisterClaudeCodeWindows: checksum: %w", err)
		return res
	}
	res.ChecksumMatch = match
	if !match && !r.opts.Force {
		res.Error = fmt.Errorf("hook.unregisterClaudeCodeWindows: %s has been modified since install (checksum mismatch); pass --force to remove anyway", res.ConfigPath)
		return res
	}

	if len(hooks) == 0 {
		delete(settings, "hooks")
	} else {
		patched, err := json.Marshal(hooks)
		if err != nil {
			res.Error = fmt.Errorf("hook.unregisterClaudeCodeWindows: marshal hooks: %w", err)
			return res
		}
		settings["hooks"] = patched
	}

	if r.opts.DryRun {
		return res
	}

	if len(settings) == 0 {
		if err := removeEmptyConfigFile(res.ConfigPath, raw); err != nil {
			res.Error = fmt.Errorf("hook.unregisterClaudeCodeWindows: remove empty %s: %w", res.ConfigPath, err)
			return res
		}
	} else {
		if err := writeJSONIndented(claudeDir, pinned, settings); err != nil {
			res.Error = err
			return res
		}
	}
	if err := r.removeChecksum(res.ConfigPath); err != nil {
		res.Error = err
		return res
	}
	return res
}

// filterClaudeGroupsWindows walks groups, drops any command
// isObserverWindowsClaudeEntry recognises as ours — the wsl.exe-wrapped
// bridge invocation this registrar writes AND a native
// `observer.exe hook claude-code …` entry from an earlier
// Windows-native npm install (class C2) — and discards groups left
// empty. Removing the native shape too is deliberate: `observer
// uninstall` must not leave behind the very entry that was writing the
// stranded Windows DB. Returns the survivors plus removed / kept counts
// so the caller can decide whether to touch the file at all.
func filterClaudeGroupsWindows(groups []claudeHookGroup) (out []claudeHookGroup, removed, kept int) {
	for _, g := range groups {
		var survivors []claudeHookCommand
		for _, h := range g.Hooks {
			if h.Type == "command" && isObserverWindowsClaudeEntry(h.Command) {
				removed++
				continue
			}
			survivors = append(survivors, h)
		}
		if len(survivors) == 0 {
			continue
		}
		kept += len(survivors)
		out = append(out, claudeHookGroup{Matcher: g.Matcher, Hooks: survivors})
	}
	return out, removed, kept
}

func (r *Registry) unregisterCursor() UnregistrationResult {
	res := UnregistrationResult{Tool: "cursor", DryRun: r.opts.DryRun}
	cursorDir := filepath.Join(r.opts.HomeDir, ".cursor")
	path := filepath.Join(cursorDir, "hooks.json")
	res.ConfigPath = path

	unlock, err := r.lockSettings(path)
	if err != nil {
		res.Error = fmt.Errorf("hook.unregisterCursor: %w", err)
		return res
	}
	defer unlock()

	// Pin the write target now, before the read — see pinnedTarget (F6).
	pinned := pinWriteTarget(path)

	raw, err := readSettingsFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			res.Skipped = true
			return res
		}
		res.Error = fmt.Errorf("hook.unregisterCursor: read: %w", err)
		return res
	}

	settings, err := decodeSettingsObject(path, raw)
	if err != nil {
		res.Error = fmt.Errorf("hook.unregisterCursor: %w", err)
		return res
	}
	hooks := map[string][]cursorHookEntry{}
	if existing, ok := settings["hooks"]; ok {
		_ = json.Unmarshal(existing, &hooks)
	}

	for event, entries := range hooks {
		var survivors []cursorHookEntry
		removed := 0
		for _, e := range entries {
			// Content-heuristic so cross-binary installs (npm bundle,
			// renamed $HOME, prior worktree binary) get cleaned up
			// when uninstalling from a different observer build.
			// Mirrors the register-side isObserverCursorEntry usage —
			// without this, byte-exact prefix-match would leave
			// orphaned entries behind on `observer uninstall cursor`.
			if isObserverCursorEntry(e.Command) {
				removed++
				continue
			}
			survivors = append(survivors, e)
		}
		if removed > 0 {
			res.HooksRemoved = append(res.HooksRemoved, event)
		}
		if len(survivors) > 0 {
			res.HooksKept = append(res.HooksKept, event)
		}
		if len(survivors) == 0 {
			delete(hooks, event)
		} else {
			hooks[event] = survivors
		}
	}
	sort.Strings(res.HooksRemoved)
	sort.Strings(res.HooksKept)

	if len(res.HooksRemoved) == 0 {
		res.Skipped = true
		return res
	}

	match, err := r.checksumMatches(path, raw)
	if err != nil {
		res.Error = fmt.Errorf("hook.unregisterCursor: checksum: %w", err)
		return res
	}
	res.ChecksumMatch = match
	if !match && !r.opts.Force {
		res.Error = fmt.Errorf("hook.unregisterCursor: %s has been modified since install (checksum mismatch); pass --force to remove anyway", path)
		return res
	}

	if len(hooks) == 0 {
		delete(settings, "hooks")
	} else {
		hookJSON, err := json.Marshal(hooks)
		if err != nil {
			res.Error = fmt.Errorf("hook.unregisterCursor: marshal hooks: %w", err)
			return res
		}
		settings["hooks"] = hookJSON
	}

	if r.opts.DryRun {
		return res
	}

	// If the only surviving keys are the "version" we manufactured at
	// install time, remove the file entirely so uninstall leaves no trace.
	if len(settings) == 1 {
		if _, onlyVersion := settings["version"]; onlyVersion {
			delete(settings, "version")
		}
	}
	if len(settings) == 0 {
		if err := removeEmptyConfigFile(path, raw); err != nil {
			res.Error = fmt.Errorf("hook.unregisterCursor: remove %s: %w", path, err)
			return res
		}
	} else {
		if err := writeJSONIndented(cursorDir, pinned, settings); err != nil {
			res.Error = err
			return res
		}
	}
	if err := r.removeChecksum(path); err != nil {
		res.Error = err
		return res
	}
	return res
}

// unregisterCursorWindows is unregisterCursor's cross-OS-bridge
// counterpart — mirrors unregisterClaudeCodeWindows's shape (FIX
// cluster, item 7b): `Register`'s switch has had a "cursor-windows"
// case (registerCursorWindows) since the bridge was built, but
// `Unregister`'s switch never got the matching case, and no
// unregisterCursorWindows function existed at all — so `observer
// uninstall --cursor` (or any direct Unregister("cursor-windows")
// call) could never remove a cursor-windows bridge entry it had
// written. Same checksum-guard discipline as unregisterClaudeCodeWindows/
// unregisterCodexWindows, and the same cross-OS home resolution
// (r.detectWindowsCursorHome/r.opts.WindowsCursorHome) registerCursorWindows
// already uses.
func (r *Registry) unregisterCursorWindows() UnregistrationResult {
	res := UnregistrationResult{Tool: "cursor-windows", DryRun: r.opts.DryRun}

	cursorDir := r.detectWindowsCursorHome()
	if cursorDir == "" {
		res.Skipped = true
		return res
	}
	path := filepath.Join(cursorDir, "hooks.json")
	res.ConfigPath = path

	unlock, err := r.lockSettings(path)
	if err != nil {
		res.Error = fmt.Errorf("hook.unregisterCursorWindows: %w", err)
		return res
	}
	defer unlock()

	// Pin the write target now, before the read — see pinnedTarget (F6).
	pinned := pinWriteTarget(path)

	raw, err := readSettingsFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			res.Skipped = true
			return res
		}
		res.Error = fmt.Errorf("hook.unregisterCursorWindows: read: %w", err)
		return res
	}

	settings, err := decodeSettingsObject(path, raw)
	if err != nil {
		res.Error = fmt.Errorf("hook.unregisterCursorWindows: %w", err)
		return res
	}
	hooks := map[string][]cursorHookEntry{}
	if existing, ok := settings["hooks"]; ok {
		_ = json.Unmarshal(existing, &hooks)
	}

	for event, entries := range hooks {
		var survivors []cursorHookEntry
		removed := 0
		for _, e := range entries {
			// isObserverWindowsCursorEntry recognises BOTH the wsl.exe
			// cross-OS bridge shape this registrar writes AND a native
			// observer.exe entry from an earlier Windows-native install
			// — mirrors filterClaudeGroupsWindows's own native+bridge
			// removal so `observer uninstall` never leaves behind the
			// entry that was writing the stranded Windows DB.
			if isObserverWindowsCursorEntry(e.Command) {
				removed++
				continue
			}
			survivors = append(survivors, e)
		}
		if removed > 0 {
			res.HooksRemoved = append(res.HooksRemoved, event)
		}
		if len(survivors) > 0 {
			res.HooksKept = append(res.HooksKept, event)
		}
		if len(survivors) == 0 {
			delete(hooks, event)
		} else {
			hooks[event] = survivors
		}
	}
	sort.Strings(res.HooksRemoved)
	sort.Strings(res.HooksKept)

	if len(res.HooksRemoved) == 0 {
		res.Skipped = true
		return res
	}

	match, err := r.checksumMatches(path, raw)
	if err != nil {
		res.Error = fmt.Errorf("hook.unregisterCursorWindows: checksum: %w", err)
		return res
	}
	res.ChecksumMatch = match
	if !match && !r.opts.Force {
		res.Error = fmt.Errorf("hook.unregisterCursorWindows: %s has been modified since install (checksum mismatch); pass --force to remove anyway", path)
		return res
	}

	if len(hooks) == 0 {
		delete(settings, "hooks")
	} else {
		hookJSON, err := json.Marshal(hooks)
		if err != nil {
			res.Error = fmt.Errorf("hook.unregisterCursorWindows: marshal hooks: %w", err)
			return res
		}
		settings["hooks"] = hookJSON
	}

	if r.opts.DryRun {
		return res
	}

	// If the only surviving keys are the "version" registerCursorWindows
	// manufactured at install time, remove the file entirely so
	// uninstall leaves no trace — mirrors unregisterCursor's own
	// version-only cleanup.
	if len(settings) == 1 {
		if _, onlyVersion := settings["version"]; onlyVersion {
			delete(settings, "version")
		}
	}
	if len(settings) == 0 {
		if err := removeEmptyConfigFile(path, raw); err != nil {
			res.Error = fmt.Errorf("hook.unregisterCursorWindows: remove %s: %w", path, err)
			return res
		}
	} else {
		if err := writeJSONIndented(cursorDir, pinned, settings); err != nil {
			res.Error = err
			return res
		}
	}
	if err := r.removeChecksum(path); err != nil {
		res.Error = err
		return res
	}
	return res
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
	delete(current, path)
	if len(current) == 0 {
		if err := os.Remove(csPath); err != nil && !errors.Is(err, os.ErrNotExist) {
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

// codexEvents is the set of Codex hook events we register for. Codex's
// hook event names are CamelCase identical to Claude Code's, but codex
// fires its own subset (no Pre/Post compact, no SubagentStart/Stop, etc.).
// Per developers.openai.com/codex/hooks (snapshot 2026-05-09), codex
// exposes 6 events; we register all 6 so observer's hook handler is the
// single point of capture / dispatch.
var codexEvents = []string{
	"SessionStart",
	"UserPromptSubmit",
	"PreToolUse",
	"PermissionRequest",
	"PostToolUse",
	"Stop",
}

// codexHooksFile is the per-event-list config; we keep hooks in
// ~/.codex/hooks.json (codex also accepts [hooks.<Event>] inside
// config.toml but the JSON file path is canonical and the diff stays
// scoped to a single file). codex 0.129.0 requires
// `[features].hooks = true` in config.toml separately to actually
// dispatch hooks — registerCodex sets both. See
// ensureCodexHooksFeatureFlag for the verified flag-name history.
const codexHooksFile = "hooks.json"

// codexHookGroup mirrors claudeHookGroup — codex inherited Claude Code's
// hooks-config schema verbatim (top-level `hooks` map → event-name
// arrays → group with matcher + nested hooks list).
type codexHookGroup struct {
	Matcher string              `json:"matcher,omitempty"`
	Hooks   []claudeHookCommand `json:"hooks"`
}

// codexHooksFile body is `{"hooks": {<event>: [<group>...]}}`.
type codexHooksConfig struct {
	Hooks map[string][]codexHookGroup `json:"hooks"`
}

// registerCodex installs observer hooks into ~/.codex/hooks.json AND
// ensures `[features].hooks = true` in ~/.codex/config.toml so codex
// actually dispatches them. Idempotent — re-running with the same
// binary path returns AlreadySet.
//
// Trust caveat: codex requires per-hook user trust approval the first
// time each entry is seen (security feature). The user must run codex
// once after registration and use `/hooks` to mark our entries trusted;
// there is no documented programmatic shortcut as of codex 0.129.0
// (the trust hash algorithm is opaque and not exposed via any
// `codex` subcommand). The CLI prints a hint after registration.
func (r *Registry) registerCodex() RegistrationResult {
	// codexCmdQuoteIfNeeded picks the right quoter based on path
	// shape: POSIX single-quote for Linux/macOS paths (codex spawns
	// hooks via /bin/sh there), cmd.exe double-quote for Windows
	// paths (codex 0.133+ on Windows spawns via cmd.exe — single
	// quotes are interpreted literally and the command fails). The
	// v1.6.25 single-quote fix here was correct for Claude Code (Git
	// Bash always) but wrong for Codex on Windows; operator report
	// 2026-05-23 surfaced the regression. See codexCmdQuoteIfNeeded
	// docstring for the full rationale + trade-off discussion.
	return r.registerCodexAt(codexHookTarget{
		tool:      "codex",
		dir:       filepath.Join(r.opts.HomeDir, ".codex"),
		quote:     codexCmdQuoteIfNeeded,
		errPrefix: "hook.registerCodex",
		matchMine: isObserverCodexEntryNative,
	})
}

// codexHookTarget parameterizes registerCodexAt for its two
// registration targets: the native `~/.codex` on the daemon's own OS,
// and the cross-OS Windows-side `.codex` the codex-windows bridge
// writes. Both produce the same hooks.json shape through ONE writer
// (CLAUDE.md #4: one owner per piece of state) — they differ only in
// where they write, how they quote, whether the command carries the
// wsl.exe bridge wrapper, and (B4 fix) which shape they'll accept as
// "already ours".
type codexHookTarget struct {
	// tool is the RegistrationResult.Tool label ("codex" /
	// "codex-windows").
	tool string
	// dir is the .codex directory holding hooks.json + config.toml.
	dir string
	// wrapper prefixes every registered command; "" for the native
	// target, `wsl.exe -d <distro> -- ` for the cross-OS bridge.
	wrapper string
	// quote quotes the binary path and the --config argument for the
	// shell codex spawns hooks through on that target.
	quote func(string) string
	// errPrefix names the calling registrar in wrapped errors so a
	// failure still points at the target the operator asked for.
	errPrefix string
	// matchMine recognises an existing hook command as belonging to
	// THIS target (used for both the "already set, don't touch" check
	// and the conflict guard). registerCodex passes the STRICT
	// isObserverCodexEntryNative (excludes the wsl.exe bridge shape);
	// registerCodexWindows passes the permissive isObserverCodexEntry
	// (matches native OR bridge). B4 fix: before this field existed,
	// registerCodexAt always used the permissive isObserverCodexEntry
	// for BOTH targets, so a native `Register("codex")` re-run against
	// a hooks.json that already held a codex-windows bridge entry (the
	// two targets DO write the identical file when WindowsCodexHome
	// resolves to the same directory HomeDir does — see
	// TestRegisterCodexNativeDoesNotClobberBridgeEntry) recognised the
	// bridge command as "already ours", found it didn't string-match
	// the NATIVE command it was about to write, and silently rewrote
	// it into native form with NO --force — exactly the flip-flop
	// isObserverWindowsClaudeEntry/isObserverWindowsCursorEntry's split
	// from their native counterparts already prevents for the other
	// two tools. Mirrors that asymmetry: the Windows target MAY still
	// convert a stale native entry into bridge form (registerCodexAt's
	// existing drift-refresh behaviour, unchanged), but the native
	// target must now treat an existing bridge entry as a foreign
	// conflict requiring --force, never the reverse.
	matchMine func(string) bool
}

// registerCodexAt is the shared codex hooks.json writer behind
// registerCodex and registerCodexWindows. Conflict / refresh discipline
// is identical on both targets modulo t.matchMine (see its doc
// comment): an entry t.matchMine recognises as ours is refreshed
// silently, anything else blocks without --force.
func (r *Registry) registerCodexAt(t codexHookTarget) RegistrationResult {
	res := RegistrationResult{Tool: t.tool, DryRun: r.opts.DryRun}
	hooksPath := filepath.Join(t.dir, codexHooksFile)
	res.ConfigPath = hooksPath

	// Serialize observer's own writers of this file, THEN read — same
	// contract as registerClaudeCode/registerCursor (see lockSettings).
	// Codex's hooks.json previously took NO lock at all here.
	unlock, err := r.lockSettings(hooksPath)
	if err != nil {
		res.Error = fmt.Errorf("%s: %w", t.errPrefix, err)
		return res
	}
	defer unlock()

	// Pin the write target now, before the read — see pinnedTarget (F6).
	pinned := pinWriteTarget(hooksPath)

	cfg, err := readCodexHooks(hooksPath)
	if err != nil {
		res.Error = err
		return res
	}

	for _, event := range codexEvents {
		cmd := t.wrapper + t.quote(r.opts.BinaryPath) + " hook codex " + event + r.configFlagSuffixWith(t.quote)
		groups := cfg.Hooks[event]
		idx := findCodexGroupWithObserver(groups, t.matchMine)
		if idx >= 0 {
			if observerCodexCmdMatches(groups[idx], cmd) {
				res.AlreadySet = append(res.AlreadySet, event)
				continue
			}
			// Stale-observer-args / cross-binary refresh — recognised
			// as ours via t.matchMine's content-heuristic. Drop the
			// stale group; the fresh append below restores.
			groups = append(groups[:idx], groups[idx+1:]...)
		}
		if !r.opts.Force && hasConflictingCodexHook(groups, t.matchMine) {
			res.Error = fmt.Errorf("%s: event %s already has a non-observer hook; pass --force to overwrite", t.errPrefix, event)
			return res
		}
		groups = append(groups, codexHookGroup{
			Matcher: "*",
			Hooks:   []claudeHookCommand{{Type: "command", Command: cmd}},
		})
		cfg.Hooks[event] = groups
		res.HooksAdded = append(res.HooksAdded, event)
	}

	if r.opts.DryRun {
		// Still report whether the feature flag would be flipped.
		return res
	}

	if err := writeCodexHooks(t.dir, pinned, cfg); err != nil {
		res.Error = err
		return res
	}
	if err := r.recordChecksum(hooksPath); err != nil {
		res.Error = err
		return res
	}
	if err := r.ensureCodexHooksFeatureFlag(t.dir); err != nil {
		res.Error = err
		return res
	}
	return res
}

// registerCodexWindows installs Codex hooks into a Windows-side
// `.codex/hooks.json` (typically `/mnt/c/Users/<u>/.codex/hooks.json`)
// with each command wrapped in
//
//	wsl.exe -d <distro> -- <linux-bin> hook codex <Event> [--config <wsl-path>]
//
// so a Windows-native Codex can fire hooks that EXECUTE inside the WSL
// daemon's OS-context and whose db.Open therefore resolves the daemon's
// own DB natively. This is the registration-layer cross-OS bridge
// CLAUDE.md's "Don't try to bridge cross-OS hook capture at the storage
// layer" prescribes; codex previously had no Windows hook target at all
// (only the identically-named codex-windows PROXY-ROUTE label in
// internal/proxyroute — a different subsystem writing config.toml's
// base_url).
//
// Quoting: cmd.exe double-quote-when-needed (cmdQuoteIfNeeded), NOT the
// POSIX single-quote the claude-code/cursor bridges use. Codex on
// Windows spawns hooks through cmd.exe, which treats `'...'` as literal
// argument text (the v1.6.25 → 2026-05-23 regression codexCmdQuoteIfNeeded
// exists for). For the same reason there is NO `MSYS_NO_PATHCONV=1`
// prefix: that is a bash-ism, and cmd.exe would try to run it as a
// program. The Linux-side paths inside the WSL command normally contain
// no cmd.exe-meaningful character, so in practice nothing is quoted at
// all and the arguments reach wsl.exe verbatim.
//
// Distro lookup: Options.WSLDistro → $WSL_DISTRO_NAME. Empty distro is
// an error; the command would be ambiguous on a host with multiple
// distros. Same contract as registerCursorWindows /
// registerClaudeCodeWindows.
//
// Like registerCodex it also ensures `[features].hooks = true` in the
// WINDOWS-side config.toml — codex reads hooks.json but never dispatches
// without that flag, and the Windows install has its own config.toml.
func (r *Registry) registerCodexWindows() RegistrationResult {
	res := RegistrationResult{Tool: "codex-windows", DryRun: r.opts.DryRun}

	codexDir := r.detectWindowsCodexHome()
	if codexDir == "" {
		if r.foreignAutoDetectSuppressed(r.opts.WindowsCodexHome) {
			r.sandboxSkipResult(&res, ".codex", "WindowsCodexHome", r.opts.WindowsCodexHome)
			return res
		}
		res.Error = errors.New("hook.registerCodexWindows: no Windows-side .codex/ detected (set WindowsCodexHome explicitly or run on a host where crossmount sees /mnt/c/Users/<u>/.codex/)")
		return res
	}

	distro := r.opts.WSLDistro
	if distro == "" {
		distro = os.Getenv("WSL_DISTRO_NAME")
	}
	if distro == "" {
		res.Error = errors.New("hook.registerCodexWindows: WSL distro unknown — set Options.WSLDistro or run inside WSL (so $WSL_DISTRO_NAME is set)")
		return res
	}

	return r.registerCodexAt(codexHookTarget{
		tool:      "codex-windows",
		dir:       codexDir,
		wrapper:   "wsl.exe -d " + cmdQuoteIfNeeded(distro) + " -- ",
		quote:     cmdQuoteIfNeeded,
		errPrefix: "hook.registerCodexWindows",
		matchMine: isObserverCodexEntry,
	})
}

func (r *Registry) unregisterCodex() UnregistrationResult {
	return r.unregisterCodexAt("codex", filepath.Join(r.opts.HomeDir, ".codex"), "hook.unregisterCodex")
}

// unregisterCodexWindows removes the hook entries the codex-windows
// bridge wrote from the Windows-side .codex/hooks.json. Mirrors
// unregisterCodex against the detected Windows home; a host with no
// Windows-side .codex is a no-op Skip, not an error (there is nothing
// to clean). isObserverCodexEntry recognises the native and the
// wsl.exe-bridge shapes alike, so a stale native
// `observer.exe hook codex …` entry is cleaned up too (class C2).
func (r *Registry) unregisterCodexWindows() UnregistrationResult {
	codexDir := r.detectWindowsCodexHome()
	if codexDir == "" {
		return UnregistrationResult{Tool: "codex-windows", DryRun: r.opts.DryRun, Skipped: true}
	}
	return r.unregisterCodexAt("codex-windows", codexDir, "hook.unregisterCodexWindows")
}

// unregisterCodexAt is the shared codex hooks.json cleaner behind
// unregisterCodex and unregisterCodexWindows. dir is the .codex
// directory; errPrefix names the calling registrar in wrapped errors.
func (r *Registry) unregisterCodexAt(tool, dir, errPrefix string) UnregistrationResult {
	res := UnregistrationResult{Tool: tool, DryRun: r.opts.DryRun}
	hooksPath := filepath.Join(dir, codexHooksFile)
	res.ConfigPath = hooksPath

	unlock, err := r.lockSettings(hooksPath)
	if err != nil {
		res.Error = fmt.Errorf("%s: %w", errPrefix, err)
		return res
	}
	defer unlock()

	// Pin the write target now, before the read — see pinnedTarget (F6).
	pinned := pinWriteTarget(hooksPath)

	raw, err := os.ReadFile(hooksPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			res.Skipped = true
			return res
		}
		res.Error = fmt.Errorf("%s: read: %w", errPrefix, err)
		return res
	}
	var cfg codexHooksConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		res.Error = fmt.Errorf("%s: parse %s: %w", errPrefix, hooksPath, err)
		return res
	}
	if cfg.Hooks == nil {
		cfg.Hooks = map[string][]codexHookGroup{}
	}

	for event, groups := range cfg.Hooks {
		newGroups, removed, kept := filterCodexGroups(groups)
		if removed > 0 {
			res.HooksRemoved = append(res.HooksRemoved, event)
		}
		if kept > 0 {
			res.HooksKept = append(res.HooksKept, event)
		}
		if len(newGroups) == 0 {
			delete(cfg.Hooks, event)
		} else {
			cfg.Hooks[event] = newGroups
		}
	}
	sort.Strings(res.HooksRemoved)
	sort.Strings(res.HooksKept)

	if len(res.HooksRemoved) == 0 {
		res.Skipped = true
		return res
	}

	match, err := r.checksumMatches(hooksPath, raw)
	if err != nil {
		res.Error = fmt.Errorf("%s: checksum: %w", errPrefix, err)
		return res
	}
	if !match && !r.opts.Force {
		res.Error = fmt.Errorf("%s: %s changed since install; pass --force to overwrite", errPrefix, hooksPath)
		return res
	}

	if r.opts.DryRun {
		return res
	}
	// When no entries remain we still write an empty `{"hooks":{}}` rather
	// than removing the file entirely; codex tolerates the empty object and
	// the user may have added their own entries we don't know about
	// (kept-rows above already short-circuit if any non-observer entries
	// remain).
	if err := writeCodexHooks(dir, pinned, cfg); err != nil {
		res.Error = err
		return res
	}
	if err := r.removeChecksum(hooksPath); err != nil {
		res.Error = err
		return res
	}
	// Note: we DO NOT flip [features].hooks = false on uninstall —
	// the user may have other hooks registered through that flag.
	return res
}

// readCodexHooks loads ~/.codex/hooks.json, returning an empty config
// when the file doesn't exist.
func readCodexHooks(path string) (codexHooksConfig, error) {
	cfg := codexHooksConfig{Hooks: map[string][]codexHookGroup{}}
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return cfg, nil
		}
		return cfg, fmt.Errorf("hook.readCodexHooks: read: %w", err)
	}
	if len(raw) == 0 {
		return cfg, nil
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return cfg, fmt.Errorf("hook.readCodexHooks: parse %s: %w", path, err)
	}
	if cfg.Hooks == nil {
		cfg.Hooks = map[string][]codexHookGroup{}
	}
	return cfg, nil
}

// writeCodexHooks marshals cfg as 2-space-indented JSON with stable
// event ordering. Creates the parent dir if missing. Callers own the
// advisory lock (see lockSettings) — this function must never take it
// itself, matching writeJSONIndented's contract.
//
// pinned must have been produced by pinWriteTarget against the hooks
// file, right after the lock was acquired and before it was first
// read — see pinnedTarget's doc comment for why (F6).
func writeCodexHooks(dir string, pinned pinnedTarget, cfg codexHooksConfig) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("hook.writeCodexHooks: mkdir: %w", err)
	}
	// Emit with sorted event keys so JSON diffs stay clean across
	// re-registrations.
	keys := make([]string, 0, len(cfg.Hooks))
	for k := range cfg.Hooks {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var buf bytes.Buffer
	buf.WriteString("{\n  \"hooks\": {")
	for i, k := range keys {
		if i > 0 {
			buf.WriteString(",")
		}
		buf.WriteString("\n    ")
		ke, _ := json.Marshal(k)
		buf.Write(ke)
		buf.WriteString(": ")
		ge, err := json.MarshalIndent(cfg.Hooks[k], "    ", "  ")
		if err != nil {
			return fmt.Errorf("hook.writeCodexHooks: encode %s: %w", k, err)
		}
		buf.Write(ge)
	}
	if len(keys) > 0 {
		buf.WriteString("\n  ")
	}
	buf.WriteString("}\n}\n")

	if err := atomicWriteFile(pinned, buf.Bytes()); err != nil {
		return fmt.Errorf("hook.writeCodexHooks: %w", err)
	}
	return nil
}

// isObserverCodexEntry recognises a hook command as one previously
// written by ANY observer codex registrar, NATIVE OR the wsl.exe
// cross-OS bridge alike. Same content-heuristic rationale as
// isObserverClaudeEntry/isObserverWindowsClaudeEntry and
// isObserverCursorEntry/isObserverWindowsCursorEntry — the
// ` hook codex ` token sequence is the stable signature regardless of
// which observer binary path (or bridge wrapper) prefixes it. Lets
// refresh-on-drift upgrade entries left behind by a differently-
// installed observer (npm bundle in node_modules, cross-binary
// upgrade, renamed $HOME) without --force.
//
// This is the PERMISSIVE half of codex's native/bridge predicate pair
// (B4 fix) — the counterpart to the STRICT isObserverCodexEntryNative.
// Used for: registerCodexWindows's own "already ours" check (so the
// bridge target may still silently convert a stale NATIVE entry into
// bridge form — the same one-directional asymmetry
// isObserverWindowsClaudeEntry documents), and BOTH unregister paths
// (uninstall must clean up either shape regardless of which target is
// asked to do it). It must NEVER be used for registerCodex's (native)
// own "already ours"/conflict check — that uses
// isObserverCodexEntryNative instead, or a native re-register would
// silently overwrite an existing bridge entry with no --force. See
// codexHookTarget.matchMine's doc comment for the incident this
// predicate split fixes.
func isObserverCodexEntry(cmd string) bool {
	return strings.Contains(cmd, " hook codex ")
}

// isObserverCodexEntryNative is the STRICT, native-only half of
// codex's predicate pair (B4 fix): it recognises the same
// ` hook codex ` signature as isObserverCodexEntry but EXCLUDES the
// wsl.exe cross-OS bridge shape registerCodexWindows writes — the
// exact split isObserverClaudeEntry/isObserverCursorEntry already
// apply for their own tools (see isObserverClaudeEntry's doc comment
// for the full "must not merge" rationale). Used ONLY by registerCodex
// (via codexHookTarget.matchMine) so a native re-register never
// mistakes an existing bridge entry for "already ours" and silently
// rewrites it into native form — that flip would need --force, exactly
// like a native claude-code/cursor register already refuses to
// overwrite an existing bridge entry without it.
func isObserverCodexEntryNative(cmd string) bool {
	if !strings.Contains(cmd, " hook codex ") {
		return false
	}
	if strings.HasPrefix(cmd, "wsl.exe ") || strings.HasPrefix(cmd, "MSYS_NO_PATHCONV=1 wsl.exe ") {
		return false
	}
	return true
}

// findCodexGroupWithObserver returns the index of a codex hook
// group whose single entry is recognised as observer-written by
// matchMine (t.matchMine — either isObserverCodexEntry or
// isObserverCodexEntryNative, see codexHookTarget's doc comment), or
// -1. Content-heuristic so cross-binary stale entries are still
// detected as ours and refreshed.
func findCodexGroupWithObserver(groups []codexHookGroup, matchMine func(string) bool) int {
	for i, g := range groups {
		for _, h := range g.Hooks {
			if h.Type == "command" && matchMine(h.Command) {
				return i
			}
		}
	}
	return -1
}

// observerCodexCmdMatches reports whether g already encodes the observer
// hook entry shape we'd write — same matcher ("*"), single command of
// type "command", same command body. Drift in any of these fields means
// the entry is stale and registerCodex should refresh it.
func observerCodexCmdMatches(g codexHookGroup, cmd string) bool {
	if g.Matcher != "*" {
		return false
	}
	if len(g.Hooks) != 1 {
		return false
	}
	h := g.Hooks[0]
	return h.Type == "command" && h.Command == cmd
}

// hasConflictingCodexHook reports whether any group carries a
// command that isn't observer-shaped per matchMine (t.matchMine —
// see codexHookTarget's doc comment). Force-less guard against
// silently overwriting user-authored hooks (or, for the native
// target, an existing bridge entry — see isObserverCodexEntryNative).
// Content-heuristic — cross-binary stale entries fall through to the
// refresh path.
func hasConflictingCodexHook(groups []codexHookGroup, matchMine func(string) bool) bool {
	for _, g := range groups {
		for _, h := range g.Hooks {
			if h.Type != "command" {
				continue
			}
			if !matchMine(h.Command) {
				return true
			}
		}
	}
	return false
}

// filterCodexGroups returns groups with all observer-owned entries
// (recognised via isObserverCodexEntry) stripped, plus counts
// (removed, kept) for the result struct. Content-heuristic so
// cross-binary stale entries are also cleaned up on uninstall —
// mirrors the register-side findCodexGroupWithObserver /
// hasConflictingCodexHook usage.
func filterCodexGroups(groups []codexHookGroup) ([]codexHookGroup, int, int) {
	var out []codexHookGroup
	var removed, kept int
	for _, g := range groups {
		var keepHooks []claudeHookCommand
		for _, h := range g.Hooks {
			if h.Type == "command" && isObserverCodexEntry(h.Command) {
				removed++
				continue
			}
			keepHooks = append(keepHooks, h)
		}
		if len(keepHooks) == 0 {
			continue
		}
		kept += len(keepHooks)
		g.Hooks = keepHooks
		out = append(out, g)
	}
	return out, removed, kept
}

// ensureCodexHooksFeatureFlag patches `[features].hooks = true` into
// ~/.codex/config.toml if not already set. Codex gates the hook
// dispatcher behind this flag — without it, hooks.json is read but
// never invoked.
//
// **Verified flag name (2026-05-11):** codex 0.129.0 prints
// "`[features].codex_hooks` is deprecated. Use `[features].hooks`
// instead." when it sees the longer form. So `hooks = true` is the
// canonical name despite some published docs (e.g. the local
// reference at tmp/codex-hooks.md) showing `codex_hooks`. Observer's
// long-standing choice of `hooks = true` is correct.
//
// **Tool-context hook coverage caveat:** even with this flag set,
// codex's `PreToolUse` / `PostToolUse` hooks only intercept "simple
// Bash calls, apply_patch edits, and MCP tool calls" (per
// docs.codex.com hooks reference). Modern codex shell calls route
// through `unified_exec` which is NOT intercepted yet. Result:
// tool-using prompts produce JSONL rows but rarely emit hook rows.
// This is a codex design limitation, not an observer bug. See
// docs/codex-hook-capture.md for the maintainer's 2026-05-11
// dogfood notes.
// A method (not a free function) so it can take its own advisory lock
// on config.toml — a DIFFERENT file than the hooks.json lock
// registerCodex already holds for the rest of its body, so this is a
// second, independent lockSettings/unlock pair, not a re-entrant one.
func (r *Registry) ensureCodexHooksFeatureFlag(dir string) error {
	path := filepath.Join(dir, "config.toml")

	// Serialize observer's own writers of this file, THEN read — same
	// contract as every other settings/config writer since WP9
	// (lockSettings' docstring). config.toml previously took no lock
	// and wrote through a FIXED `<path>.tmp`, so two concurrent
	// `observer init --codex` runs could splice a torn config.toml.
	unlock, err := r.lockSettings(path)
	if err != nil {
		return fmt.Errorf("hook.ensureCodexHooksFeatureFlag: %w", err)
	}
	defer unlock()

	// Pin the write target now, before the read — see pinnedTarget (F6).
	pinned := pinWriteTarget(path)

	raw, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("hook.ensureCodexHooksFeatureFlag: read: %w", err)
	}
	root := map[string]any{}
	if len(raw) > 0 {
		if err := toml.Unmarshal(raw, &root); err != nil {
			return fmt.Errorf("hook.ensureCodexHooksFeatureFlag: parse %s: %w", path, err)
		}
	}
	features, _ := root["features"].(map[string]any)
	if features == nil {
		features = map[string]any{}
	}
	if v, ok := features["hooks"].(bool); ok && v {
		return nil
	}
	features["hooks"] = true
	root["features"] = features

	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(root); err != nil {
		return fmt.Errorf("hook.ensureCodexHooksFeatureFlag: encode: %w", err)
	}
	if err := atomicWriteFile(pinned, buf.Bytes()); err != nil {
		return fmt.Errorf("hook.ensureCodexHooksFeatureFlag: %w", err)
	}
	return nil
}

// --- Statusline registration (docs/plans/observer-statusline-plan-2026-07-30.md §5.1) ---
//
// This is a NEW, independent registration surface — a sibling of the hook
// registration above, not a variant of it. It patches a different
// top-level key ("statusLine") in the exact same ~/.claude/settings.json
// file that registerClaudeCode patches ("hooks"), using the identical
// read-preserve-write map[string]json.RawMessage shape so unknown keys
// (and the "hooks" key itself) survive byte-for-byte. registerClaudeCode
// and every other existing function in this file are NOT modified by
// this addition — only new sibling functions are added below, and the
// entry points (RegisterClaudeCodeStatusline / UnregisterClaudeCodeStatusline)
// are deliberately NOT wired into the tool-name-dispatched Register/
// Unregister switches above, so those two functions also stay untouched.
//
// v1 scope is claude-code (native OS) ONLY — see
// runStatuslineInit's doc comment in cmd/observer/init.go for the
// cross-OS (WSL bridge) decision: a Windows-side Claude Code reached
// only via crossmount is deliberately NOT bridged here (unlike hooks,
// a statusLine command runs on every render tick, and a wsl.exe
// subprocess spawn per tick risks the plan's <100ms budget); the
// caller WARNs instead of silently doing nothing.

// claudeStatuslineEntry is the shape written into settings.json's
// top-level "statusLine" key: `{"type":"command","command":"<bin>
// statusline","padding":0}`. Distinct from claudeHookGroup/
// claudeHookCommand — the "statusLine" key is never merged with
// "hooks" (CLAUDE.md #4: one owner per piece of state; this struct
// owns exactly the "statusLine" value, nothing else in the file).
type claudeStatuslineEntry struct {
	Type    string `json:"type"`
	Command string `json:"command"`
	Padding int    `json:"padding"`
}

// isObserverStatuslineEntry recognises a "statusLine" command as one
// previously written by ANY observer registrar. Unlike
// isObserverClaudeEntry — whose ` hook claude-code ` signature is
// observer-internal syntax nobody else writes — "statusline" is a
// GENERIC word other statusline tools use as a subcommand, so a bare
// substring test is not a safe ownership signal: `node /opt/acme
// statusline --theme compact` would have been silently overwritten by
// register (or uninstalled by unregister) as if it were ours.
//
// Ownership therefore requires BOTH halves of the command shape we
// actually write (`<quoted-bin-path> statusline`):
//
//  1. the executable token's basename is an observer binary
//     (isObserverBinaryToken), and
//  2. the very next argument is exactly "statusline".
//
// Anything else — a foreign executable, "statusline" appearing only as
// a later flag value, an unparseable command — is FOREIGN, which means
// register blocks without --force and unregister leaves it alone.
// Trailing arguments after "statusline" are tolerated so a future
// flag-carrying variant of our own command still refreshes rather than
// tripping the conflict guard.
func isObserverStatuslineEntry(cmd string) bool {
	toks := splitCommandTokens(cmd)
	if len(toks) < 2 || toks[1] != "statusline" {
		return false
	}
	return isObserverBinaryToken(toks[0])
}

// isObserverBinaryToken reports whether an executable token names an
// observer binary, by basename. Accepts the plain names (`observer`,
// `superbased`, with or without a `.exe` tail) plus the
// `observer-<something>` / `superbased-<something>` family, because
// real installs DO carry suffixed names (`observer-v1.8.3` from a
// versioned download, `observer-hermes.exe`, a `/tmp/observer-A` A/B
// build) and a path-shape-strict test would misclassify our own
// earlier registration as foreign — the exact failure mode
// isObserverClaudeEntry's content-heuristic exists to avoid (a stale
// entry that can no longer be refreshed without --force).
// Case-insensitive: Windows paths are.
func isObserverBinaryToken(tok string) bool {
	base := strings.ToLower(commandBaseName(tok))
	base = strings.TrimSuffix(base, ".exe")
	if base == "observer" || base == "superbased" {
		return true
	}
	return strings.HasPrefix(base, "observer-") || strings.HasPrefix(base, "superbased-")
}

// commandBaseName returns the final path element of an executable
// token, splitting on EITHER separator — the token may be a
// forward-slash-normalized Windows path (see forwardSlashPath) or a
// native backslash one, and filepath.Base only knows the host's
// separator.
func commandBaseName(tok string) string {
	if i := strings.LastIndexAny(tok, `/\`); i >= 0 {
		return tok[i+1:]
	}
	return tok
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

// registerClaudeCodeStatusline installs (or refreshes) the
// "statusLine" top-level key in ~/.claude/settings.json, wired to
// `<binary> statusline`. Conflict discipline mirrors
// hasConflictingClaudeHook: a foreign (non-observer) existing value
// blocks without --force — more conservative here than for hooks,
// because "statusLine" is a single, visible UI slot (unlike hooks,
// which fan out across many named events with no single-slot
// contention), so clobbering a user's own statusline silently would
// be a materially worse experience than clobbering one hook event.
// An observer-recognised entry (by isObserverStatuslineEntry)
// refreshes silently on drift (binary path moved, quoting changed).
// An entry that already matches byte-for-byte is reported via
// AlreadySet and the file is NOT rewritten at all (idempotent
// re-run — no needless mtime/checksum churn), mirroring how
// registerClaudeCode's observerCmdMatches short-circuits per event.
func (r *Registry) registerClaudeCodeStatusline() RegistrationResult {
	res := RegistrationResult{Tool: "claude-code-statusline", DryRun: r.opts.DryRun}
	settingsDir := filepath.Join(r.opts.HomeDir, ".claude")
	path := filepath.Join(settingsDir, "settings.json")
	res.ConfigPath = path

	unlock, err := r.lockSettings(path)
	if err != nil {
		res.Error = fmt.Errorf("hook.registerClaudeCodeStatusline: %w", err)
		return res
	}
	defer unlock()

	// Pin the write target now, before the read — see pinnedTarget (F6).
	pinned := pinWriteTarget(path)

	raw, err := readSettingsFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		res.Error = fmt.Errorf("hook.registerClaudeCodeStatusline: read: %w", err)
		return res
	}
	// Preserve unknown top-level fields (including "hooks") via
	// map[string]json.RawMessage — identical shape to registerClaudeCode.
	settings := map[string]json.RawMessage{}
	if len(raw) > 0 {
		settings, err = decodeSettingsObject(path, raw)
		if err != nil {
			res.Error = fmt.Errorf("hook.registerClaudeCodeStatusline: %w", err)
			return res
		}
	}

	// Same forward-slash + shell-quote binary-path handling the hook
	// registrars use — see forwardSlashPath's docstring for the Git
	// Bash / harness-wrapper rationale.
	binPath := forwardSlashPath(r.opts.BinaryPath)
	desired := claudeStatuslineEntry{
		Type:    "command",
		Command: shellQuoteIfNeeded(binPath) + " statusline",
		Padding: 0,
	}

	if existing, ok := settings["statusLine"]; ok {
		var cur claudeStatuslineEntry
		parsed := json.Unmarshal(existing, &cur) == nil
		switch {
		case parsed && cur == desired:
			res.AlreadySet = append(res.AlreadySet, "statusLine")
			return res
		case parsed && isObserverStatuslineEntry(cur.Command):
			// Observer-owned but stale (binary path/quoting drifted) —
			// silently refresh; fall through to overwrite below.
		case r.opts.Force:
			// Foreign (or unparseable) value, but the operator passed
			// --force — fall through to overwrite below.
		default:
			shape := string(existing)
			if parsed {
				shape = cur.Command
			}
			res.Error = fmt.Errorf("hook.registerClaudeCodeStatusline: %s already has a non-observer \"statusLine\" command %q; pass --force to overwrite", path, shape)
			return res
		}
	}

	patched, err := json.Marshal(desired)
	if err != nil {
		res.Error = fmt.Errorf("hook.registerClaudeCodeStatusline: marshal: %w", err)
		return res
	}
	settings["statusLine"] = patched
	res.HooksAdded = append(res.HooksAdded, "statusLine")

	if r.opts.DryRun {
		return res
	}
	if err := writeJSONIndented(settingsDir, pinned, settings); err != nil {
		res.Error = err
		return res
	}
	if err := r.recordChecksum(path); err != nil {
		res.Error = err
		return res
	}
	return res
}

// unregisterClaudeCodeStatusline removes the "statusLine" top-level
// key from ~/.claude/settings.json ENTIRELY (not blanked) — so a user
// who opts out gets Claude Code's own default statusline back, not an
// empty one. Only an entry recognised as observer-written (via
// isObserverStatuslineEntry) is ever removed; a foreign/user-authored
// "statusLine" is left untouched and reported via HooksKept, mirroring
// how unregisterClaudeCode preserves non-observer hook entries without
// requiring --force to do so (Force here gates ONLY the checksum-drift
// guard below, exactly like the hook unregistrars).
func (r *Registry) unregisterClaudeCodeStatusline() UnregistrationResult {
	res := UnregistrationResult{Tool: "claude-code-statusline", DryRun: r.opts.DryRun}
	settingsDir := filepath.Join(r.opts.HomeDir, ".claude")
	path := filepath.Join(settingsDir, "settings.json")
	res.ConfigPath = path

	unlock, err := r.lockSettings(path)
	if err != nil {
		res.Error = fmt.Errorf("hook.unregisterClaudeCodeStatusline: %w", err)
		return res
	}
	defer unlock()

	// Pin the write target now, before the read — see pinnedTarget (F6).
	pinned := pinWriteTarget(path)

	raw, err := readSettingsFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			res.Skipped = true
			return res
		}
		res.Error = fmt.Errorf("hook.unregisterClaudeCodeStatusline: read: %w", err)
		return res
	}

	settings, err := decodeSettingsObject(path, raw)
	if err != nil {
		res.Error = fmt.Errorf("hook.unregisterClaudeCodeStatusline: %w", err)
		return res
	}

	existing, ok := settings["statusLine"]
	if !ok {
		res.Skipped = true
		return res
	}
	var cur claudeStatuslineEntry
	if err := json.Unmarshal(existing, &cur); err != nil || !isObserverStatuslineEntry(cur.Command) {
		// Foreign (or unparseable) "statusLine" — a user-authored
		// statusline (or another tool's). Never removed by uninstall;
		// no --force override for this case (only for checksum drift
		// below), mirroring the hook unregistrars' HooksKept posture.
		res.HooksKept = append(res.HooksKept, "statusLine")
		res.Skipped = true
		return res
	}

	// There is real work to do — verify the file hasn't drifted since
	// we installed, so we don't clobber user edits made to OTHER keys
	// in the same file. Passing --force bypasses the guard. Note the
	// checksum registry tracks this whole FILE (not the "statusLine"
	// key specifically) — the same coarse, file-granularity contract
	// registerClaudeCode's recordChecksum already uses for "hooks".
	match, err := r.checksumMatches(path, raw)
	if err != nil {
		res.Error = fmt.Errorf("hook.unregisterClaudeCodeStatusline: checksum: %w", err)
		return res
	}
	res.ChecksumMatch = match
	if !match && !r.opts.Force {
		res.Error = fmt.Errorf("hook.unregisterClaudeCodeStatusline: %s has been modified since install (checksum mismatch); pass --force to remove anyway", path)
		return res
	}

	delete(settings, "statusLine")
	res.HooksRemoved = append(res.HooksRemoved, "statusLine")

	if r.opts.DryRun {
		return res
	}

	if len(settings) == 0 {
		if err := removeEmptyConfigFile(path, raw); err != nil {
			res.Error = fmt.Errorf("hook.unregisterClaudeCodeStatusline: remove empty %s: %w", path, err)
			return res
		}
	} else {
		if err := writeJSONIndented(settingsDir, pinned, settings); err != nil {
			res.Error = err
			return res
		}
	}
	if err := r.removeChecksum(path); err != nil {
		res.Error = err
		return res
	}
	return res
}

// RegisterClaudeCodeStatusline is the exported entry point for the
// statusline registration path. Deliberately NOT reached through the
// tool-name-dispatched Register(tool string) switch above (adding a
// case there would touch an existing function this WP must leave
// byte-identical) — callers (cmd/observer/init.go's `observer init
// --statusline`) call this directly instead. Opt-in only: never
// called by `observer start`'s hook auto-register path, matching the
// MCP/proxy-route precedent (CLAUDE.md's `observer start` invariant).
func (r *Registry) RegisterClaudeCodeStatusline() RegistrationResult {
	return r.registerClaudeCodeStatusline()
}

// UnregisterClaudeCodeStatusline is the exported entry point for
// removing the statusline registration — the `observer init
// --statusline --uninstall` path. See RegisterClaudeCodeStatusline's
// doc comment for why this is a direct call rather than a Unregister
// switch case.
func (r *Registry) UnregisterClaudeCodeStatusline() UnregistrationResult {
	return r.unregisterClaudeCodeStatusline()
}

// --- Part B item 1/2 cross-OS bridges -----------------------------------
//
// The six long-tail vendors' own "<tool>-windows" registration targets:
// a WSL daemon writing a wsl.exe-bridged hook command into a Windows-side
// config file, mirroring registerClaudeCodeWindows / registerCursorWindows
// / registerCodexWindows (see CLAUDE.md's "Don't try to bridge cross-OS
// hook capture at the storage layer"). Windsurf/Devin Desktop Cascade
// deliberately has NO row here — its only grounded install channel is the
// macOS Homebrew cask (internal/integration's devin row), so there is no
// Windows-native install to bridge to.

// resolveWSLDistro returns the WSL distribution the cross-OS bridge
// registrars invoke via `wsl.exe -d <distro>`, honoring Options.WSLDistro
// before falling back to $WSL_DISTRO_NAME. errPrefix names the calling
// registrar in the wrapped error when neither is set — the command would
// be ambiguous on a host with multiple distros. Same contract as the
// inline distro resolution registerClaudeCodeWindows / registerCursorWindows
// / registerCodexWindows each already duplicate.
func (r *Registry) resolveWSLDistro(errPrefix string) (string, error) {
	distro := r.opts.WSLDistro
	if distro == "" {
		distro = os.Getenv("WSL_DISTRO_NAME")
	}
	if distro == "" {
		return "", fmt.Errorf("%s: WSL distro unknown — set Options.WSLDistro or run inside WSL (so $WSL_DISTRO_NAME is set)", errPrefix)
	}
	return distro, nil
}

// gitBashWrapper returns the "MSYS_NO_PATHCONV=1 wsl.exe -d <distro> -- "
// prefix every settings.json/hooks.json/settings.yaml *-windows bridge in
// this section wraps its command with — same convention
// registerClaudeCodeWindows / registerCursorWindows already established
// (these tools spawn hooks through Git Bash on Windows; see
// registerClaudeCodeWindows's doc comment for the MSYS_NO_PATHCONV
// rationale), NOT codex's cmd.exe convention.
func gitBashWrapper(distro string) string {
	return "MSYS_NO_PATHCONV=1 wsl.exe -d " + shellQuoteIfNeeded(distro) + " -- "
}

// registerGeminiCLIWindows installs the prompt-submit hook into a
// Windows-side .gemini/settings.json (typically
// /mnt/c/Users/<u>/.gemini/settings.json) with the command wrapped in
// the wsl.exe bridge (gitBashWrapper) so a Windows-native Gemini CLI can
// fire a hook that executes inside the WSL daemon's own OS-context.
func (r *Registry) registerGeminiCLIWindows() RegistrationResult {
	res := RegistrationResult{Tool: "gemini-cli-windows", DryRun: r.opts.DryRun}
	dir := r.detectWindowsGeminiHome()
	if dir == "" {
		if r.foreignAutoDetectSuppressed(r.opts.WindowsGeminiHome) {
			r.sandboxSkipResult(&res, ".gemini", "WindowsGeminiHome", r.opts.WindowsGeminiHome)
			return res
		}
		res.Error = errors.New("hook.registerGeminiCLIWindows: no Windows-side .gemini/ detected (set WindowsGeminiHome explicitly or run on a host where crossmount sees /mnt/c/Users/<u>/.gemini/)")
		return res
	}
	distro, err := r.resolveWSLDistro("hook.registerGeminiCLIWindows")
	if err != nil {
		res.Error = err
		return res
	}
	return r.registerGenericSettingsHooks(genericSettingsHookTarget{
		tool:       "gemini-cli",
		resultTool: "gemini-cli-windows",
		dir:        dir,
		event:      "BeforeAgent",
		errPrefix:  "hook.registerGeminiCLIWindows",
		wrapper:    gitBashWrapper(distro),
	})
}

// unregisterGeminiCLIWindows removes the hook entry the
// gemini-cli-windows bridge wrote from the Windows-side
// .gemini/settings.json. A host with no Windows-side .gemini is a no-op
// Skip, not an error.
func (r *Registry) unregisterGeminiCLIWindows() UnregistrationResult {
	dir := r.detectWindowsGeminiHome()
	if dir == "" {
		return UnregistrationResult{Tool: "gemini-cli-windows", DryRun: r.opts.DryRun, Skipped: true}
	}
	return r.unregisterGenericSettingsHooks(genericSettingsHookTarget{
		tool: "gemini-cli", resultTool: "gemini-cli-windows",
		dir: dir, event: "BeforeAgent", errPrefix: "hook.unregisterGeminiCLIWindows",
	})
}

// registerQwenCodeWindows is registerGeminiCLIWindows's Qwen Code
// counterpart: a Windows-side .qwen/settings.json, single event
// UserPromptSubmit.
func (r *Registry) registerQwenCodeWindows() RegistrationResult {
	res := RegistrationResult{Tool: "qwen-code-windows", DryRun: r.opts.DryRun}
	dir := r.detectWindowsQwenHome()
	if dir == "" {
		if r.foreignAutoDetectSuppressed(r.opts.WindowsQwenHome) {
			r.sandboxSkipResult(&res, ".qwen", "WindowsQwenHome", r.opts.WindowsQwenHome)
			return res
		}
		res.Error = errors.New("hook.registerQwenCodeWindows: no Windows-side .qwen/ detected (set WindowsQwenHome explicitly or run on a host where crossmount sees /mnt/c/Users/<u>/.qwen/)")
		return res
	}
	distro, err := r.resolveWSLDistro("hook.registerQwenCodeWindows")
	if err != nil {
		res.Error = err
		return res
	}
	return r.registerGenericSettingsHooks(genericSettingsHookTarget{
		tool:       "qwen-code",
		resultTool: "qwen-code-windows",
		dir:        dir,
		event:      "UserPromptSubmit",
		errPrefix:  "hook.registerQwenCodeWindows",
		wrapper:    gitBashWrapper(distro),
	})
}

// unregisterQwenCodeWindows is unregisterGeminiCLIWindows's Qwen Code
// counterpart.
func (r *Registry) unregisterQwenCodeWindows() UnregistrationResult {
	dir := r.detectWindowsQwenHome()
	if dir == "" {
		return UnregistrationResult{Tool: "qwen-code-windows", DryRun: r.opts.DryRun, Skipped: true}
	}
	return r.unregisterGenericSettingsHooks(genericSettingsHookTarget{
		tool: "qwen-code", resultTool: "qwen-code-windows",
		dir: dir, event: "UserPromptSubmit", errPrefix: "hook.unregisterQwenCodeWindows",
	})
}

// registerQoderWindows is registerGeminiCLIWindows's Qoder counterpart:
// a Windows-side .qoder/settings.json, single event UserPromptSubmit.
func (r *Registry) registerQoderWindows() RegistrationResult {
	res := RegistrationResult{Tool: "qoder-windows", DryRun: r.opts.DryRun}
	dir := r.detectWindowsQoderHome()
	if dir == "" {
		if r.foreignAutoDetectSuppressed(r.opts.WindowsQoderHome) {
			r.sandboxSkipResult(&res, ".qoder", "WindowsQoderHome", r.opts.WindowsQoderHome)
			return res
		}
		res.Error = errors.New("hook.registerQoderWindows: no Windows-side .qoder/ detected (set WindowsQoderHome explicitly or run on a host where crossmount sees /mnt/c/Users/<u>/.qoder/)")
		return res
	}
	distro, err := r.resolveWSLDistro("hook.registerQoderWindows")
	if err != nil {
		res.Error = err
		return res
	}
	return r.registerGenericSettingsHooks(genericSettingsHookTarget{
		tool:       "qoder",
		resultTool: "qoder-windows",
		dir:        dir,
		event:      "UserPromptSubmit",
		errPrefix:  "hook.registerQoderWindows",
		wrapper:    gitBashWrapper(distro),
	})
}

// unregisterQoderWindows is unregisterGeminiCLIWindows's Qoder
// counterpart.
func (r *Registry) unregisterQoderWindows() UnregistrationResult {
	dir := r.detectWindowsQoderHome()
	if dir == "" {
		return UnregistrationResult{Tool: "qoder-windows", DryRun: r.opts.DryRun, Skipped: true}
	}
	return r.unregisterGenericSettingsHooks(genericSettingsHookTarget{
		tool: "qoder", resultTool: "qoder-windows",
		dir: dir, event: "UserPromptSubmit", errPrefix: "hook.unregisterQoderWindows",
	})
}

// registerFactoryDroidWindows installs the prompt-submit hook into a
// Windows-side .factory/hooks.json with the command wsl.exe-bridged
// (gitBashWrapper). Single event: UserPromptSubmit.
func (r *Registry) registerFactoryDroidWindows() RegistrationResult {
	res := RegistrationResult{Tool: "droid-windows", DryRun: r.opts.DryRun}
	dir := r.detectWindowsFactoryHome()
	if dir == "" {
		if r.foreignAutoDetectSuppressed(r.opts.WindowsFactoryHome) {
			r.sandboxSkipResult(&res, ".factory", "WindowsFactoryHome", r.opts.WindowsFactoryHome)
			return res
		}
		res.Error = errors.New("hook.registerFactoryDroidWindows: no Windows-side .factory/ detected (set WindowsFactoryHome explicitly or run on a host where crossmount sees /mnt/c/Users/<u>/.factory/)")
		return res
	}
	distro, err := r.resolveWSLDistro("hook.registerFactoryDroidWindows")
	if err != nil {
		res.Error = err
		return res
	}
	return r.registerFactoryDroidAt(droidHookTarget{
		tool:      "droid-windows",
		dir:       dir,
		wrapper:   gitBashWrapper(distro),
		errPrefix: "hook.registerFactoryDroidWindows",
	})
}

// unregisterFactoryDroidWindows removes the hook group the
// droid-windows bridge wrote from the Windows-side .factory/hooks.json.
func (r *Registry) unregisterFactoryDroidWindows() UnregistrationResult {
	dir := r.detectWindowsFactoryHome()
	if dir == "" {
		return UnregistrationResult{Tool: "droid-windows", DryRun: r.opts.DryRun, Skipped: true}
	}
	return r.unregisterFactoryDroidAt("droid-windows", dir, "hook.unregisterFactoryDroidWindows")
}

// registerPoolsideWindows installs the prompt-submit hook into a
// Windows-side .config/poolside/settings.yaml with the command
// wsl.exe-bridged (gitBashWrapper). Single event: UserPromptSubmit.
func (r *Registry) registerPoolsideWindows() RegistrationResult {
	res := RegistrationResult{Tool: "poolside-windows", DryRun: r.opts.DryRun}
	dir := r.detectWindowsPoolsideHome()
	if dir == "" {
		if r.foreignAutoDetectSuppressed(r.opts.WindowsPoolsideHome) {
			r.sandboxSkipResult(&res, filepath.Join(".config", "poolside"), "WindowsPoolsideHome", r.opts.WindowsPoolsideHome)
			return res
		}
		res.Error = errors.New("hook.registerPoolsideWindows: no Windows-side .config/poolside/ detected (set WindowsPoolsideHome explicitly or run on a host where crossmount sees /mnt/c/Users/<u>/.config/poolside/)")
		return res
	}
	distro, err := r.resolveWSLDistro("hook.registerPoolsideWindows")
	if err != nil {
		res.Error = err
		return res
	}
	return r.registerPoolsideAt(poolsideHookTarget{
		tool:      "poolside-windows",
		dir:       dir,
		wrapper:   gitBashWrapper(distro),
		errPrefix: "hook.registerPoolsideWindows",
	})
}

// unregisterPoolsideWindows removes the hook entry the
// poolside-windows bridge wrote from the Windows-side settings.yaml.
func (r *Registry) unregisterPoolsideWindows() UnregistrationResult {
	dir := r.detectWindowsPoolsideHome()
	if dir == "" {
		return UnregistrationResult{Tool: "poolside-windows", DryRun: r.opts.DryRun, Skipped: true}
	}
	return r.unregisterPoolsideAt("poolside-windows", dir, "hook.unregisterPoolsideWindows")
}

// registerCommandCodeWindows installs commandcode's Mods SDK bridge into
// a Windows-side .commandcode/mods/observer-guard.ts (typically
// /mnt/c/Users/<u>/.commandcode/mods/observer-guard.ts), baking in the
// WSL distro + the Linux-side observer binary path so the mod's OWN
// runtime (observer-guard.ts's resolveExec()) shells out through
// wsl.exe when it detects it is running on win32 — see
// commandcodemod.WritePluginBridge. Unlike every hooks.json/
// settings.json/settings.yaml *-windows writer above, there is no
// wrapper string built HERE: the wsl.exe bridge decision is made at
// RUNTIME inside the TS mod (commandcode's own Node process is the one
// that knows its own platform at hook-fire time), not baked into a
// static shell command the way a JSON/YAML hooks entry is.
func (r *Registry) registerCommandCodeWindows() RegistrationResult {
	res := RegistrationResult{Tool: "command-code-windows", DryRun: r.opts.DryRun}
	winHome := r.detectWindowsCommandCodeHome()
	if winHome == "" {
		if r.foreignAutoDetectSuppressed(r.opts.WindowsCommandCodeHome) {
			r.sandboxSkipResult(&res, ".commandcode", "WindowsCommandCodeHome", r.opts.WindowsCommandCodeHome)
			return res
		}
		res.Error = errors.New("hook.registerCommandCodeWindows: no Windows-side .commandcode/ detected (set WindowsCommandCodeHome explicitly or run on a host where crossmount sees /mnt/c/Users/<u>/.commandcode/)")
		return res
	}
	distro, err := r.resolveWSLDistro("hook.registerCommandCodeWindows")
	if err != nil {
		res.Error = err
		return res
	}
	dir := filepath.Join(winHome, "mods")
	path := filepath.Join(dir, commandcodemod.ModFileName)
	res.ConfigPath = path

	alreadyInstalled := commandcodemod.Installed(dir)
	if r.opts.DryRun {
		if !alreadyInstalled {
			res.HooksAdded = append(res.HooksAdded, "transformInput")
		} else {
			res.AlreadySet = append(res.AlreadySet, "transformInput")
		}
		return res
	}
	if err := commandcodemod.WritePluginBridge(dir, r.opts.BinaryPath, distro, r.opts.ConfigPath); err != nil {
		res.Error = fmt.Errorf("hook.registerCommandCodeWindows: %w", err)
		return res
	}
	if alreadyInstalled {
		res.AlreadySet = append(res.AlreadySet, "transformInput")
	} else {
		res.HooksAdded = append(res.HooksAdded, "transformInput")
	}
	return res
}

// unregisterCommandCodeWindows removes the observer-guard.ts mod file
// from the Windows-side .commandcode/mods/. A host with no Windows-side
// .commandcode is a no-op Skip, not an error.
func (r *Registry) unregisterCommandCodeWindows() UnregistrationResult {
	winHome := r.detectWindowsCommandCodeHome()
	if winHome == "" {
		return UnregistrationResult{Tool: "command-code-windows", DryRun: r.opts.DryRun, Skipped: true}
	}
	dir := filepath.Join(winHome, "mods")
	res := UnregistrationResult{
		Tool:       "command-code-windows",
		DryRun:     r.opts.DryRun,
		ConfigPath: filepath.Join(dir, commandcodemod.ModFileName),
	}
	if !commandcodemod.Installed(dir) {
		return res
	}
	if r.opts.DryRun {
		res.HooksRemoved = append(res.HooksRemoved, "transformInput")
		return res
	}
	if err := commandcodemod.RemovePlugin(dir); err != nil {
		res.Error = fmt.Errorf("hook.unregisterCommandCodeWindows: %w", err)
		return res
	}
	res.HooksRemoved = append(res.HooksRemoved, "transformInput")
	return res
}
