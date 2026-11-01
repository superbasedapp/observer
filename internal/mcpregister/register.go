package mcpregister

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/marmutapp/superbased-observer/internal/claudeplugin"
	"github.com/marmutapp/superbased-observer/internal/credfile"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/mcp/locate"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/testwriteguard"
)

// claudeCodeMCPPath reports the config file the claude-code MCP entry
// would have been written to, for reporting on the skip path (where the
// normal locate lookup below never runs). Empty when the client is not
// in the locate table.
func (r *Registrar) claudeCodeMCPPath() string {
	if loc, ok := r.location("claude-code"); ok {
		return loc.Path
	}
	return ""
}

// claudeConfigDir is the Claude Code config home the plugin probe reads:
// the locate row's install directory (~/.claude, moved by
// CLAUDE_CONFIG_DIR through the agentconfig rule), else the vendor default.
func (r *Registrar) claudeConfigDir() string {
	if loc, ok := r.location("claude-code"); ok && loc.InstallDir != "" {
		return loc.InstallDir
	}
	return filepath.Join(r.opts.HomeDir, ".claude")
}

// ServerName is the registration entry name written into each AI tool's
// MCP config. Stable so re-running init is idempotent. It is the shared
// models.ObserverMCPServerName, the same name the Rail B managed generators
// pin (CX-8).
const ServerName = models.ObserverMCPServerName

// allHomes is the crossmount-home enumeration seam - a package var (mirroring
// internal/hook and internal/proxyroute) so a test can inject a fixed
// multi-home layout instead of depending on a real /mnt/c mount (restore it in
// a defer).
var allHomes = crossmount.AllHomes

// RegistrationResult summarizes one MCP registration.
type RegistrationResult struct {
	Tool       string // claude-code | cursor | codex
	ConfigPath string
	Added      bool
	AlreadySet bool
	DryRun     bool
	Error      error

	// Skipped reports that the registrar deliberately wrote nothing
	// because the tool already carries observer's MCP server through its
	// own packaging surface - today, the Claude Code plugin, whose
	// .mcp.json declares the same stdio server. Not an error: Claude
	// Code namespaces a plugin's server separately from a user-config
	// one (`plugin:<plugin>:<server>` vs `<server>`), so both being
	// present loads the observer tool schema TWICE per turn instead of
	// colliding. SkipReason names the artifact that proved it. Both zero
	// on every other path.
	Skipped    bool
	SkipReason string

	// SkipAdvice is the operator-facing next step that goes with
	// SkipReason. Empty means "the default plugin advice applies" (the
	// printer supplies it), so the plugin skip path is unchanged; the
	// cross-OS sandbox skip (see crossmount.AutoDetectSuppressed) sets it
	// because the --force escape hatch deliberately does NOT apply there.
	SkipAdvice string

	// ProbeWarning is a NON-FATAL note: the plugin probe could not read a
	// file it needed, so this registrar wrote its entry without being able
	// to rule out a plugin already declaring the same server. Registration
	// still happened (fail-open to wiring). A host target that wrote one of
	// its files also names here each file it did not write because a
	// symbolic link sits on its path (FU-198). Empty on every conclusive
	// path.
	ProbeWarning string
}

// RegisterOptions parameterizes Registrar.
type RegisterOptions struct {
	// BinaryPath is the absolute path to the running observer binary that
	// the AI tool will invoke as `<binary> serve`. Required.
	BinaryPath string
	// DryRun computes the result without touching files.
	DryRun bool
	// Force overwrites an existing entry that points to a different binary.
	// When false, conflicts are reported as errors.
	Force bool
	// HomeDir overrides $HOME (used by tests).
	HomeDir string
	// ConfigPath, when non-empty, is appended to the registered MCP launch
	// command as `--config <path>`. Used to keep the MCP server's view of
	// config aligned with the proxy's view when a non-default config is
	// in play (e.g. an A/B harness running its own observer-config.toml).
	// Without this, `observer init` registers `observer serve` with no
	// args, the MCP server reads ~/.observer/config.toml, and stash /
	// retrieve_stashed get out of sync with whichever proxy is actually
	// stashing bodies. Surfaced 2026-05-08 dogfood.
	ConfigPath string
	// WSLDistro names the WSL distribution invoked via wsl.exe for the
	// cross-OS "cline-windows" MCP target (mirrors hook.Options.WSLDistro).
	// Empty falls back to $WSL_DISTRO_NAME at registration time.
	WSLDistro string
	// WindowsClineHome overrides crossmount detection of the Windows-side
	// home that holds VS Code's globalStorage (e.g. /mnt/c/Users/<u>) for
	// the cline-windows target. Empty → first crossmount OS=windows home.
	WindowsClineHome string
	// WSLClineHome overrides detection of the WSL Linux home (as this
	// Windows host reaches it, \\wsl.localhost\<distro>\home\<user>) for the
	// Windows to WSL twin cline-wsl (register_clinewsl.go).
	WSLClineHome string
	// SelfBinary is the running binary's real path. An existing
	// Observer-shaped entry whose command resolves to it runs this same
	// install by another path and is refreshed without --force (U2,
	// ownership.go). Empty disables that rule.
	SelfBinary string
	// RepairOnly makes Register write ONLY an existing Observer-shaped
	// entry whose command no longer exists (the stale-observer rule): no
	// entry is added and nothing else is changed. `observer start` uses it
	// so MCP stays opt-in while a package-manager upgrade cannot leave the
	// entry pointing at a deleted binary.
	RepairOnly bool
	// Getenv reads the environment variables that relocate a client's MCP
	// file (today Cline's CLINE_MCP_SETTINGS_PATH / CLINE_DATA_DIR /
	// CLINE_DIR, S-6). Nil is the one pinned-home rule (crossmount.HomeEnv,
	// R-188 F1): os.Getenv only when HomeDir is not pinned and the process
	// home is not isolated (crossmount.IsolationReason), and NO variables
	// otherwise, so a sandboxed or isolated caller resolves every file under
	// its own home (the incident 2026-07-31 posture, as hook.Options.Getenv).
	Getenv func(string) string
	// ProvenancePath is where the registrar records whether each MCP file
	// it writes existed before (D-MU9, provenance.go), so a removal deletes
	// only a file Observer created. Empty with an unpinned HomeDir means
	// <home>/.observer/mcp-provenance.json; empty with a pinned HomeDir
	// records nothing, and a removal there then never deletes a file (it
	// writes the file back with Observer's entry cut).
	ProvenancePath string
	// commandExists overrides commandFileExists in tests.
	commandExists func(string) bool
}

// Registrar dispatches MCP registrations per tool.
type Registrar struct {
	opts RegisterOptions
	// homeOverride is the caller-supplied RegisterOptions.HomeDir VERBATIM,
	// kept before NewRegistrar defaults it to the real $HOME. Non-empty
	// means "the caller pinned this registrar's home", which switches OFF
	// crossmount auto-detection for the cross-OS "cline-windows" target -
	// see crossmount.AutoDetectSuppressed (incident 2026-07-31).
	homeOverride string
}

// NewRegistrar validates opts and returns a Registrar.
func NewRegistrar(opts RegisterOptions) (*Registrar, error) {
	if opts.BinaryPath == "" {
		return nil, errors.New("mcp.NewRegistrar: BinaryPath is required")
	}
	homeOverride := opts.HomeDir
	if opts.HomeDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("mcp.NewRegistrar: UserHomeDir: %w", err)
		}
		opts.HomeDir = home
	}
	opts.Getenv = crossmount.HomeEnv(homeOverride, opts.Getenv)
	if opts.ProvenancePath == "" && homeOverride == "" {
		opts.ProvenancePath = filepath.Join(opts.HomeDir, ".observer", ProvenanceFileName)
	}
	return &Registrar{opts: opts, homeOverride: homeOverride}, nil
}

// location is the registrar's lookup into the shared locate table, with its
// own environment applied.
func (r *Registrar) location(tool string) (locate.Location, bool) {
	return locate.ForClientEnv(tool, r.opts.HomeDir, r.opts.Getenv)
}

// installedAt reports whether loc's client is installed: its current store
// (InstallDir) is there, or the directory of its legacy file (a client that
// has not run a current build yet; for Cline, an extension whose first
// current start migrates that file into the shared one).
func (r *Registrar) installedAt(loc locate.Location) bool {
	return r.currentStoreAt(loc) || r.legacyOnlyAt(loc)
}

// currentStoreAt reports whether loc's current store directory exists.
func (r *Registrar) currentStoreAt(loc locate.Location) bool {
	return loc.InstallDir != "" && r.dirExists(loc.InstallDir)
}

// legacyOnlyAt reports a legacy-only install: the client's current store is
// absent and its legacy file's directory is present (audit finding 8).
func (r *Registrar) legacyOnlyAt(loc locate.Location) bool {
	return loc.LegacyPath != "" && !r.currentStoreAt(loc) && r.dirExists(filepath.Dir(loc.LegacyPath))
}

// Installed reports which supported tools have a config directory present.
// Mirrors hook.Registry.Installed so the CLI can detect both hook-capable and
// MCP-capable tools off the same probe. The directories are the locate
// table's install signals (agentconfig artifacts with their relocation
// rules applied). A client whose registry MCP target declares CrossOSBridge
// is followed by its "<client>-windows" target when crossmount reaches a
// Windows-side install (a WSL daemon, the cline-windows target).
func (r *Registrar) Installed() []string {
	var tools []string
	for _, loc := range locate.LocationsEnv(r.opts.HomeDir, r.opts.Getenv) {
		if r.installedAt(loc) {
			tools = append(tools, loc.Client)
		}
		if mcpCrossOSBridge(loc.Client) && r.detectWindowsSettingsDir(loc.Client) != "" {
			tools = append(tools, loc.Client+windowsSuffix)
		}
	}
	return tools
}

// windowsSuffix names a cross-OS virtual target ("cline-windows").
const windowsSuffix = "-windows"

// mcpCrossOSBridge reports whether client's registry MCP target can be
// written from a foreign-OS daemon through a wsl.exe bridge.
func mcpCrossOSBridge(client string) bool {
	c, ok := integration.For(client)
	return ok && c.MCP != nil && c.MCP.CrossOSBridge
}

// legacyOnlySkip is the finding-8 skip: a legacy-only install is left alone
// rather than given a shared file its client may not read. Which file such
// a build reads is not verified (live check LC26), and creating the shared
// file before the client's own migration ran could change what it migrates.
func legacyOnlySkip(res RegistrationResult, loc locate.Location) RegistrationResult {
	res.Skipped = true
	res.SkipReason = fmt.Sprintf("only the legacy MCP file's directory (%s) exists; the client's current store (%s) does not, so it has not run a current build yet", filepath.Dir(loc.LegacyPath), loc.InstallDir)
	res.SkipAdvice = "nothing written; start the client once so it creates its current store (and migrates the legacy file), then run `observer init` again."
	return res
}

func (r *Registrar) dirExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

// foreignAutoDetectSuppressed reports whether this registrar's caller pinned
// HomeDir (a sandbox) without naming the Windows-side home for the cross-OS
// target being resolved. See crossmount.AutoDetectSuppressed for the rule and
// the 2026-07-31 incident it exists to make structurally impossible.
func (r *Registrar) foreignAutoDetectSuppressed(override string) bool {
	return crossmount.AutoDetectSuppressed(r.homeOverride, override)
}

// Register writes (or verifies) the MCP entry for tool. Supported values:
// "claude-code", "cursor", "codex". Config paths come from the shared
// internal/mcp/locate table - the one owner of per-client MCP config
// locations (guard/mcpsec reads the same table).
func (r *Registrar) Register(tool string) RegistrationResult {
	// cline-windows is a cross-OS virtual target: its config path is
	// resolved dynamically through crossmount (not the home-based locate
	// table) and its command is a wsl.exe bridge, so it dispatches by name
	// BEFORE the locate lookup (mirrors hook.registerClaudeCodeWindows).
	if tool == "cline-windows" {
		return r.registerClineWindows()
	}
	if tool == "cline-wsl" {
		return r.registerClineWSL()
	}
	// A host's own MCP file (register_hosts.go), gated.
	if t, ok := hostMCPTargetFor(tool); ok {
		return r.registerHost(t)
	}
	// A relative relocation variable names no file: refuse before anything
	// is read or written, naming the variable (R-188 F6).
	if loc, ok := r.location(tool); ok {
		if err := loc.Refusal(); err != nil {
			return RegistrationResult{Tool: tool, Error: fmt.Errorf("mcp.Register: %w", err), DryRun: r.opts.DryRun}
		}
	}
	// Double-wiring guard, the MCP half of hook.registerClaudeCode's.
	// The Claude Code plugin bundles a .mcp.json declaring this same
	// server, and a plugin server is namespaced separately from a
	// user-config one, so writing ours on top loads the schema twice.
	// Claude Code is the only client with an in-tool plugin surface that
	// carries observer today; --force still writes.
	//
	// A skip needs AFFIRMATIVE evidence: when the probe cannot read
	// settings.json it reports Uncertain and we register anyway, carrying
	// the failure as a non-fatal ProbeWarning. Losing the MCP wiring
	// because a config file was corrupt would be the worse failure.
	var probeWarning string
	if tool == "claude-code" && !r.opts.Force {
		pd := claudeplugin.DetectInClaudeDir(r.claudeConfigDir())
		if pd.Active {
			return RegistrationResult{
				Tool:       tool,
				ConfigPath: r.claudeCodeMCPPath(),
				Skipped:    true,
				SkipReason: pd.Reason(),
				DryRun:     r.opts.DryRun,
			}
		}
		probeWarning = pd.Warning()
	}
	loc, ok := r.location(tool)
	if !ok {
		return RegistrationResult{
			Tool:   tool,
			Error:  fmt.Errorf("mcp.Register: tool %q not supported", tool),
			DryRun: r.opts.DryRun,
		}
	}
	if r.legacyOnlyAt(loc) {
		return legacyOnlySkip(RegistrationResult{Tool: tool, ConfigPath: loc.Path, DryRun: r.opts.DryRun}, loc)
	}
	var res RegistrationResult
	switch loc.Format {
	case locate.FormatCodexTOML:
		res = r.registerCodexTOML(loc.Path)
	case locate.FormatOpenCodeJSON:
		res = r.registerOpenCodeJSON(loc.Path)
	default:
		res = r.registerJSONMCP(tool, loc.Path)
	}
	res.ProbeWarning = probeWarning
	return res
}

// mcpServerEntry is the canonical shape both Claude Code and Cursor accept
// for a stdio server. Optional fields (env, working_dir) are omitted unless
// the user opts in via a separate API.
type mcpServerEntry struct {
	Command string   `json:"command"`
	Args    []string `json:"args"`
}

// registerJSONMCP handles the shared {"mcpServers": {...}} JSON shape used
// by Claude Code (~/.claude.json) and Cursor (~/.cursor/mcp.json). Other
// top-level fields are preserved verbatim so we don't clobber user config.
func (r *Registrar) registerJSONMCP(tool, path string) RegistrationResult {
	return r.registerJSONMCPEntry(tool, path, mcpServerEntry{
		Command: r.opts.BinaryPath,
		Args:    r.serveArgs(),
	})
}

// registerJSONMCPEntry is the shared {"mcpServers": {...}} writer
// parametrized by the desired server entry. The native path (claude-code /
// cursor / native cline) passes a {binary, serve} entry; the cross-OS
// cline-windows path passes a {wsl.exe, [-d distro -- binary serve]} bridge
// entry. Other top-level fields and sibling servers are preserved verbatim.
func (r *Registrar) registerJSONMCPEntry(tool, path string, desired mcpServerEntry) RegistrationResult {
	res := r.registerJSONMCPEntryBody(tool, path, desired)
	res.Error = credfile.Withhold("mcp.register "+tool, path, res.Error)
	return res
}

// registerJSONMCPEntryBody is registerJSONMCPEntry before its error is made
// safe for a credential-bearing file.
func (r *Registrar) registerJSONMCPEntryBody(tool, path string, desired mcpServerEntry) RegistrationResult {
	res := RegistrationResult{Tool: tool, ConfigPath: path, DryRun: r.opts.DryRun}
	if err := declaredMCPFile(tool); err != nil {
		res.Error = err
		return res
	}

	raw, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		res.Error = fmt.Errorf("mcp.register %s: read: %w", tool, err)
		return res
	}
	settings := map[string]json.RawMessage{}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &settings); err != nil {
			res.Error = fmt.Errorf("mcp.register %s: parse %s: %w", tool, path, err)
			return res
		}
	}
	// Sibling servers stay RAW JSON so fields this writer doesn't model
	// (url/type/headers/env/disabled on a user's other servers) survive the
	// round-trip verbatim. Decoding the whole map into mcpServerEntry used to
	// rewrite a sibling remote server as {"command":"","args":null} - a
	// config-destroying regression caught by the W4a sibling goldens.
	servers := map[string]json.RawMessage{}
	if existing, ok := settings["mcpServers"]; ok {
		if err := json.Unmarshal(existing, &servers); err != nil {
			res.Error = fmt.Errorf("mcp.register %s: parse mcpServers: %w", tool, err)
			return res
		}
	}

	if existingRaw, ok := servers[ServerName]; ok {
		var existing mcpServerEntry
		// A malformed prior entry under OUR key stays zero, so it is never
		// "already set" (ownership.go decides the rest).
		_ = json.Unmarshal(existingRaw, &existing)
		action, rule := decideMCPEntry(
			mcpEntryFacts{command: existing.Command, args: existing.Args},
			mcpEntryFacts{command: desired.Command, args: desired.Args},
			r.ownershipEnv())
		write, conflict := r.gateWrite(action, rule)
		switch {
		case action == mcpActionAlreadySet:
			res.AlreadySet = true
			return res
		case conflict:
			res.Error = mcpConflictError("mcp.register "+tool, path)
			return res
		case !write:
			return res
		}
	} else if r.opts.RepairOnly {
		return res
	}
	desiredRaw, err := json.Marshal(desired)
	if err != nil {
		res.Error = fmt.Errorf("mcp.register %s: marshal entry: %w", tool, err)
		return res
	}
	body, err := setJSONServer(raw, "mcpServers", desiredRaw, true)
	if err != nil {
		res.Error = err
		return res
	}
	if r.opts.DryRun {
		res.Added = true
		return res
	}
	_, keyPresent := settings["mcpServers"]
	if err := writeCredentialMCPFile(path, body); err != nil {
		res.Error = err
		return res
	}
	r.recordMCPWrite(path, raw != nil, keyPresent)
	res.Added = true
	return res
}

// registerClineWindows writes the observer MCP server into a Windows
// Cline's shared config (<home>\.cline\data\settings\cline_mcp_settings.json,
// read by the VS Code extension, the CLI and Cline for JetBrains) from a WSL
// daemon, using a
// `wsl.exe -d <distro> -- <linux-bin> serve` bridge command so the Windows
// host spawns the WSL-resident observer over stdio. Mirrors
// hook.registerClaudeCodeWindows: dynamic crossmount path + wsl bridge,
// gated by the cline row's MCP.CrossOSBridge capability.
func (r *Registrar) registerClineWindows() RegistrationResult {
	res := RegistrationResult{Tool: "cline-windows", DryRun: r.opts.DryRun}
	path := r.detectWindowsClineSettings()
	if home := r.detectWindowsHome("cline"); home != "" {
		if loc, ok := locate.ForWindowsHome("cline", home); ok && r.legacyOnlyAt(loc) {
			res.ConfigPath = loc.Path
			return legacyOnlySkip(res, loc)
		}
	}
	if path == "" {
		if r.foreignAutoDetectSuppressed(r.opts.WindowsClineHome) {
			// Deliberate no-write, not a host problem - see
			// crossmount.AutoDetectSuppressed (incident 2026-07-31).
			res.Skipped = true
			if r.opts.WindowsClineHome == "" {
				res.SkipReason = "HomeDir was pinned by the caller but no WindowsClineHome was given - cross-OS globalStorage resolution is suppressed (incident 2026-07-31)"
			} else {
				res.SkipReason = fmt.Sprintf(
					"WindowsClineHome (%s) resolves OUTSIDE the pinned HomeDir (%s) - cross-OS globalStorage resolution is suppressed (incident 2026-07-31)",
					r.opts.WindowsClineHome, r.homeOverride,
				)
			}
			res.SkipAdvice = "nothing written; a sandboxed caller must set WindowsClineHome to a home UNDER its own HomeDir to wire this target (--force does not lift this)."
			return res
		}
		res.Error = errors.New("mcp.registerClineWindows: no Windows-side Cline install detected (set WindowsClineHome or run where crossmount sees /mnt/c/Users/<u>/.cline/data)")
		return res
	}
	distro := r.opts.WSLDistro
	if distro == "" {
		distro = os.Getenv("WSL_DISTRO_NAME")
	}
	if distro == "" {
		res.Error = errors.New("mcp.registerClineWindows: WSL distro unknown - set WSLDistro or run inside WSL (so $WSL_DISTRO_NAME is set)")
		return res
	}
	// Cline (a Node VS Code extension) spawns the MCP command+args directly
	// via child_process - NOT through Git Bash - so no MSYS_NO_PATHCONV
	// prefix is needed (that guard is only for the shell-string hook case).
	desired := mcpServerEntry{
		Command: "wsl.exe",
		Args:    append([]string{"-d", distro, "--", r.opts.BinaryPath}, r.serveArgs()...),
	}
	return r.registerJSONMCPEntry("cline-windows", path, desired)
}

// detectWindowsClineSettings returns the Windows-side shared
// cline_mcp_settings.json path (resolved via crossmount), or "" if no Windows
// Cline install is reachable. Honors WindowsClineHome when set. The Windows
// side's own CLINE_* variables are invisible from WSL, so the vendor default
// under that home is the target.
func (r *Registrar) detectWindowsClineSettings() string {
	return r.detectWindowsSettings("cline")
}

// detectWindowsSettings returns client's MCP file under the detected
// Windows-side home (locate.ForWindowsHome), or "".
func (r *Registrar) detectWindowsSettings(client string) string {
	home := r.detectWindowsHome(client)
	if home == "" {
		return ""
	}
	loc, ok := locate.ForWindowsHome(client, home)
	if !ok {
		return ""
	}
	return loc.Path
}

// detectWindowsHome is the Windows user home detectWindowsSettings
// resolves under for client, or "". The WindowsClineHome override names the
// one cross-OS MCP target there is today (cline-windows).
func (r *Registrar) detectWindowsHome(client string) string {
	// Sandbox gate FIRST - before the override branch, because an override
	// pointing OUTSIDE the pinned home is exactly the escape hatch that
	// re-opened this hole. See crossmount.AutoDetectSuppressed (incident
	// 2026-07-31). Production never pins HomeDir, so this is false on every
	// real path and a bare override still wins unconditionally.
	if r.foreignAutoDetectSuppressed(r.opts.WindowsClineHome) {
		return ""
	}
	if r.opts.WindowsClineHome != "" {
		return r.opts.WindowsClineHome
	}
	for _, h := range allHomes() {
		if h.OS != crossmount.OSWindows {
			continue
		}
		if loc, ok := locate.ForWindowsHome(client, h.Path); ok && r.installedAt(loc) {
			return h.Path
		}
	}
	return ""
}

// detectWindowsSettingsDir reports the settings dir for Installed()
// detection - returns the parent dir of client's MCP file under a detected
// Windows-side install, "" otherwise.
func (r *Registrar) detectWindowsSettingsDir(client string) string {
	p := r.detectWindowsSettings(client)
	if p == "" {
		return ""
	}
	return filepath.Dir(p)
}

// opencodeMCPEntry is OpenCode's MCP server shape under the top-level
// "mcp" key in opencode.json: a typed local-command server. Distinct from
// the {command,args} shape Claude Code/Cursor use - OpenCode takes the
// whole launch as one command array plus an explicit enabled flag.
type opencodeMCPEntry struct {
	Type        string            `json:"type"`
	Command     []string          `json:"command"`
	Enabled     bool              `json:"enabled"`
	Environment map[string]string `json:"environment,omitempty"`
}

// registerOpenCodeJSON patches the "mcp" object in
// ~/.config/opencode/opencode.json. Other top-level keys ($schema, plugin,
// …) are preserved verbatim by writeJSON, and OTHER mcp servers are kept as
// raw JSON so we never drop fields we don't model (e.g. remote servers'
// "url"). Only the "observer" entry is authored.
func (r *Registrar) registerOpenCodeJSON(path string) RegistrationResult {
	res := r.registerOpenCodeJSONBody(path)
	res.Error = credfile.Withhold("mcp.register opencode", path, res.Error)
	return res
}

// registerOpenCodeJSONBody is registerOpenCodeJSON before its error is made
// safe for a credential-bearing file.
func (r *Registrar) registerOpenCodeJSONBody(path string) RegistrationResult {
	tool := "opencode"
	res := RegistrationResult{Tool: tool, ConfigPath: path, DryRun: r.opts.DryRun}
	if err := declaredMCPFile(tool); err != nil {
		res.Error = err
		return res
	}

	raw, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		res.Error = fmt.Errorf("mcp.register opencode: read: %w", err)
		return res
	}
	settings := map[string]json.RawMessage{}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &settings); err != nil {
			res.Error = fmt.Errorf("mcp.register opencode: parse %s: %w", path, err)
			return res
		}
	}
	// Keep sibling servers as raw JSON so unmodelled fields survive.
	servers := map[string]json.RawMessage{}
	if existing, ok := settings["mcp"]; ok {
		if err := json.Unmarshal(existing, &servers); err != nil {
			res.Error = fmt.Errorf("mcp.register opencode: parse mcp: %w", err)
			return res
		}
	}

	desired := opencodeMCPEntry{
		Type:    "local",
		Command: append([]string{r.opts.BinaryPath}, r.serveArgs()...),
		Enabled: true,
	}
	if cur, ok := servers[ServerName]; ok {
		var curEntry opencodeMCPEntry
		// A parse failure here means a malformed prior entry - fall through
		// to overwrite (curEntry stays zero, so neither guard below trips a
		// false "already set").
		_ = json.Unmarshal(cur, &curEntry)
		if curEntry.Type == desired.Type && curEntry.Enabled == desired.Enabled &&
			stringSlicesEqual(curEntry.Command, desired.Command) {
			res.AlreadySet = true
			return res
		}
		// Command drifted: ownership.go decides (the head is the program,
		// the rest its arguments). An identical head and args with another
		// type / enabled flag is a same-command refresh.
		have := mcpEntryFacts{}
		if len(curEntry.Command) > 0 {
			have = mcpEntryFacts{command: curEntry.Command[0], args: curEntry.Command[1:]}
		}
		action, rule := decideMCPEntry(have,
			mcpEntryFacts{command: r.opts.BinaryPath, args: desired.Command[1:]}, r.ownershipEnv())
		if action == mcpActionAlreadySet {
			action, rule = mcpActionRefresh, "same-command"
		}
		write, conflict := r.gateWrite(action, rule)
		if conflict {
			res.Error = mcpConflictError("mcp.register opencode", path)
			return res
		}
		if !write {
			return res
		}
	} else if r.opts.RepairOnly {
		return res
	}

	desiredRaw, err := json.Marshal(desired)
	if err != nil {
		res.Error = fmt.Errorf("mcp.register opencode: marshal entry: %w", err)
		return res
	}
	body, err := setJSONServer(raw, "mcp", desiredRaw, true)
	if err != nil {
		res.Error = err
		return res
	}
	if r.opts.DryRun {
		res.Added = true
		return res
	}
	_, keyPresent := settings["mcp"]
	if err := writeCredentialMCPFile(path, body); err != nil {
		res.Error = err
		return res
	}
	r.recordMCPWrite(path, raw != nil, keyPresent)
	res.Added = true
	return res
}

// registerCodexTOML patches ~/.codex/config.toml's [mcp_servers.observer]
// table. config.toml holds credentials, so only that table's lines change
// (internal/credfile.SetTOMLTable): every other line, comment and key order
// keeps its bytes, and an observer entry defined some other way (an inline
// table, dotted keys) is refused rather than rewritten (review T-384).
func (r *Registrar) registerCodexTOML(path string) RegistrationResult {
	res := r.registerCodexTOMLBody(path)
	res.Error = credfile.Withhold("mcp.register codex", path, res.Error)
	return res
}

// registerCodexTOMLBody is registerCodexTOML before its error is made safe.
func (r *Registrar) registerCodexTOMLBody(path string) RegistrationResult {
	tool := "codex"
	res := RegistrationResult{Tool: tool, ConfigPath: path, DryRun: r.opts.DryRun}
	if err := declaredMCPFile(tool); err != nil {
		res.Error = err
		return res
	}

	raw, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		res.Error = fmt.Errorf("mcp.register codex: read: %w", err)
		return res
	}
	root := map[string]any{}
	if len(raw) > 0 {
		if err := toml.Unmarshal(raw, &root); err != nil {
			res.Error = fmt.Errorf("mcp.register codex: parse %s: %w", path, err)
			return res
		}
	}

	servers, _ := root["mcp_servers"].(map[string]any)
	if servers == nil {
		servers = map[string]any{}
	}

	desiredArgs := r.serveArgs()
	desired := map[string]any{
		"command": r.opts.BinaryPath,
		"args":    desiredArgs,
	}
	if existing, ok := servers[ServerName].(map[string]any); ok {
		cmd, _ := existing["command"].(string)
		if cmd == r.opts.BinaryPath && tomlArgsEqual(existing["args"], desiredArgs) {
			res.AlreadySet = true
			return res
		}
		action, rule := decideMCPEntry(
			mcpEntryFacts{command: cmd, args: tomlStringArgs(existing["args"])},
			mcpEntryFacts{command: r.opts.BinaryPath, args: desiredArgs}, r.ownershipEnv())
		write, conflict := r.gateWrite(action, rule)
		if conflict {
			res.Error = mcpConflictError("mcp.register codex", path)
			return res
		}
		if !write {
			return res
		}
	} else if r.opts.RepairOnly {
		return res
	}
	body, err := credfile.SetTOMLTable(raw, []string{"mcp_servers", ServerName}, desired, true)
	if err != nil {
		res.Error = codexTableRefusal(path, err)
		return res
	}
	if r.opts.DryRun {
		res.Added = true
		return res
	}
	if err := writeCredentialMCPFile(path, body); err != nil {
		res.Error = err
		return res
	}
	r.recordMCPWrite(path, raw != nil, true)
	res.Added = true
	return res
}

// UnregistrationResult summarizes one MCP unregistration.
type UnregistrationResult struct {
	Tool       string // claude-code | cursor | codex
	ConfigPath string
	Removed    bool // observer entry was present and has been deleted
	Skipped    bool // config file missing or the observer entry was already absent
	// SkipReason says why an entry was left in place when Skipped is not
	// just "nothing there" (a link not followed, an entry that is not
	// Observer's). Empty for the plain absent case.
	SkipReason string
	DryRun     bool
	Error      error
}

// Unregister removes the "observer" MCP entry from tool's config file.
// Other MCP servers and all other top-level config keys are preserved
// verbatim. Supported tools: "claude-code", "cursor", "codex".
//
// A location that declares a legacy file (locate.Location.LegacyPath, today
// Cline's VS Code globalStorage copy, S-6) has Observer's entry removed
// there too: a capability of the location, never a tool branch (audit
// finding 4). A "<client>-windows" target of a client whose registry MCP
// target declares CrossOSBridge resolves under the detected Windows home.
func (r *Registrar) Unregister(tool string) UnregistrationResult {
	if t, ok := hostMCPTargetFor(tool); ok {
		return r.unregisterHost(t)
	}
	if base, ok := strings.CutSuffix(tool, wslSuffix); ok && mcpCrossOSBridge(base) {
		return r.unregisterWSLTwin(tool, base)
	}
	if base, ok := strings.CutSuffix(tool, windowsSuffix); ok && mcpCrossOSBridge(base) {
		home := r.detectWindowsHome(base)
		if home == "" {
			return UnregistrationResult{Tool: tool, Skipped: true, DryRun: r.opts.DryRun}
		}
		loc, _ := locate.ForWindowsHome(base, home)
		return r.unregisterLocation(tool, loc)
	}
	loc, ok := r.location(tool)
	if !ok {
		return UnregistrationResult{
			Tool:   tool,
			Error:  fmt.Errorf("mcp.Unregister: tool %q not supported", tool),
			DryRun: r.opts.DryRun,
		}
	}
	if err := loc.Refusal(); err != nil {
		return UnregistrationResult{Tool: tool, Error: fmt.Errorf("mcp.Unregister: %w", err), DryRun: r.opts.DryRun}
	}
	return r.unregisterLocation(tool, loc)
}

// unregisterLocation removes observer's entry from loc's file and from its
// declared legacy file, if any.
func (r *Registrar) unregisterLocation(tool string, loc locate.Location) UnregistrationResult {
	res := r.unregisterAt(tool, loc.Format, loc.Path)
	if loc.LegacyPath == "" {
		return res
	}
	return r.unregisterLegacy(res, loc.Format, loc.LegacyPath)
}

// unregisterAt removes observer's entry from the file at path in format.
func (r *Registrar) unregisterAt(tool string, format locate.Format, path string) UnregistrationResult {
	switch format {
	case locate.FormatCodexTOML:
		return r.unregisterCodexTOML(path)
	case locate.FormatOpenCodeJSON:
		return r.unregisterOpenCodeJSON(path)
	default:
		return r.unregisterJSONMCP(tool, path)
	}
}

// unregisterLegacy also removes the observer entry an older Observer build
// wrote into a client's legacy MCP file (Cline's VS Code globalStorage copy,
// S-6): current client builds never read that file again, so the entry there
// is dead, but it is Observer's and an uninstall takes it away. res is the
// current file's result; it keeps its ConfigPath and gains Removed / the
// first error.
func (r *Registrar) unregisterLegacy(res UnregistrationResult, format locate.Format, legacy string) UnregistrationResult {
	old := r.unregisterAt(res.Tool, format, legacy)
	if old.Removed {
		res.Removed, res.Skipped = true, false
	}
	if res.Error == nil {
		res.Error = old.Error
	}
	return res
}

func (r *Registrar) unregisterJSONMCP(tool, path string) UnregistrationResult {
	res := r.unregisterJSONServer(tool, path, "mcpServers")
	res.Error = credfile.Withhold("mcp.unregister "+tool, path, res.Error)
	return res
}

// unregisterJSONServer removes observer's entry from the server object at
// topKey of a credential-bearing JSON MCP config: only that member (and the
// object itself when it empties) is cut, every other member keeps its bytes
// and position, and the file is removed only when nothing else remains.
func (r *Registrar) unregisterJSONServer(tool, path, topKey string) UnregistrationResult {
	res := UnregistrationResult{Tool: tool, ConfigPath: path, DryRun: r.opts.DryRun}
	if err := declaredMCPFile(tool); err != nil {
		res.Error = err
		return res
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			res.Skipped = true
			return res
		}
		res.Error = fmt.Errorf("mcp.unregister %s: read: %w", tool, err)
		return res
	}
	settings := map[string]json.RawMessage{}
	if err := json.Unmarshal(raw, &settings); err != nil {
		res.Error = fmt.Errorf("mcp.unregister %s: parse %s: %w", tool, path, err)
		return res
	}
	// Raw siblings, for the same reason as registerJSONMCPEntry: never
	// re-encode a server entry this writer doesn't own.
	servers := map[string]json.RawMessage{}
	if existing, ok := settings[topKey]; ok && !isJSONNull(existing) {
		if err := json.Unmarshal(existing, &servers); err != nil {
			res.Error = fmt.Errorf("mcp.unregister %s: parse %s: %w", tool, topKey, err)
			return res
		}
	}
	if _, ok := servers[ServerName]; !ok {
		res.Skipped = true
		return res
	}
	res.Removed = true
	// D-MU9: how the file is left is decided by what it was before
	// Observer's first write (provenance.go removalRules), never by
	// whether the cut empties it: a user's pre-existing
	// `{"mcpServers": {}}` is written back as it was.
	prov, known := r.mcpProvenance(path)
	shape := removalShapeFor(prov, known)
	body, err := removeJSONServer(raw, topKey, shape != shapeKeepEmptyObject)
	if err != nil {
		res.Error = err
		return res
	}
	if r.opts.DryRun {
		return res
	}
	if rest := map[string]json.RawMessage{}; shape == shapeDeleteFileWhenEmpty && json.Unmarshal(body, &rest) == nil && len(rest) == 0 {
		if err := removeConfigFile(path, raw); err != nil && !errors.Is(err, os.ErrNotExist) {
			res.Error = fmt.Errorf("mcp.unregister %s: remove %s: %w", tool, path, err)
			return res
		}
		r.forgetMCPWrite(path)
		return res
	}
	if err := writeCredentialMCPFile(path, body); err != nil {
		res.Error = err
		return res
	}
	r.forgetMCPWrite(path)
	return res
}

// unregisterOpenCodeJSON removes the "observer" entry from the "mcp" object
// in opencode.json, preserving sibling servers (as raw JSON) and all other
// top-level keys. The "mcp" key is dropped when it empties, and the file is
// removed when nothing else remains.
func (r *Registrar) unregisterOpenCodeJSON(path string) UnregistrationResult {
	res := r.unregisterJSONServer("opencode", path, "mcp")
	res.Error = credfile.Withhold("mcp.unregister opencode", path, res.Error)
	return res
}

func (r *Registrar) unregisterCodexTOML(path string) UnregistrationResult {
	res := r.unregisterCodexTOMLBody(path)
	res.Error = credfile.Withhold("mcp.unregister codex", path, res.Error)
	return res
}

// unregisterCodexTOMLBody is unregisterCodexTOML before its error is made
// safe: only the [mcp_servers.observer] table's lines are cut.
func (r *Registrar) unregisterCodexTOMLBody(path string) UnregistrationResult {
	tool := "codex"
	res := UnregistrationResult{Tool: tool, ConfigPath: path, DryRun: r.opts.DryRun}
	if err := declaredMCPFile(tool); err != nil {
		res.Error = err
		return res
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			res.Skipped = true
			return res
		}
		res.Error = fmt.Errorf("mcp.unregister codex: read: %w", err)
		return res
	}
	root := map[string]any{}
	if err := toml.Unmarshal(raw, &root); err != nil {
		res.Error = fmt.Errorf("mcp.unregister codex: parse %s: %w", path, err)
		return res
	}
	servers, _ := root["mcp_servers"].(map[string]any)
	if servers == nil {
		res.Skipped = true
		return res
	}
	if _, ok := servers[ServerName]; !ok {
		res.Skipped = true
		return res
	}
	res.Removed = true
	body, err := credfile.SetTOMLTable(raw, []string{"mcp_servers", ServerName}, nil, false)
	if err != nil {
		res.Error = codexTableRefusal(path, err)
		return res
	}
	if r.opts.DryRun {
		return res
	}
	// D-MU9: only a config.toml Observer's provenance record says it
	// created is deleted when the cut empties it; any other file is written
	// back (empty, as it was before Observer's table).
	prov, known := r.mcpProvenance(path)
	if len(bytes.TrimSpace(body)) == 0 && removalShapeFor(prov, known) == shapeDeleteFileWhenEmpty {
		if err := removeConfigFile(path, raw); err != nil && !errors.Is(err, os.ErrNotExist) {
			res.Error = fmt.Errorf("mcp.unregister codex: remove %s: %w", path, err)
			return res
		}
		r.forgetMCPWrite(path)
		return res
	}
	if err := writeCredentialMCPFile(path, body); err != nil {
		res.Error = err
		return res
	}
	r.forgetMCPWrite(path)
	return res
}

// declaredMCPFile refuses a write to a client whose registry row does not
// declare its MCP config file under the credential-file exception
// (integration.MCPTarget.SharesCredentialFile, review T-384): only a
// declared binding may read-modify-write such a file.
func declaredMCPFile(tool string) error {
	if integration.MCPSharesCredentialFile(tool) {
		return nil
	}
	return credfile.SafeErrorf("mcp %s: the registry row does not declare this MCP config file; nothing was written", tool)
}

// mcpConflictError is the --force refusal. It never quotes the command the
// file already holds (a value read from a credential-bearing file).
func mcpConflictError(prefix, path string) error {
	return credfile.SafeErrorf("%s: the %s entry in %s points at a different command; pass --force to overwrite", prefix, ServerName, path)
}

// codexTableRefusal turns a SetTOMLTable refusal into a safe message: the
// observer entry is defined in a form the line editor does not own (an
// inline table or dotted keys), or the file does not parse.
func codexTableRefusal(path string, err error) error {
	if errors.Is(err, credfile.ErrPatch) {
		return credfile.SafeErrorf("mcp codex: %s defines [mcp_servers.%s] in a form Observer cannot edit line by line (an inline table or dotted keys), or does not parse; nothing was written", path, ServerName)
	}
	return err
}

// isJSONNull reports whether raw is the JSON null literal.
func isJSONNull(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

// setJSONServer sets (present) or removes (!present) observer's member in
// the server object at topKey of the JSON config orig, as two member
// splices (internal/credfile): the sibling servers keep their bytes and
// order inside the object, every other top-level member keeps its bytes
// and position, and the object is dropped when a removal empties it. The
// result is verified by credfile before it is returned.
func setJSONServer(orig []byte, topKey string, entry json.RawMessage, present bool) ([]byte, error) {
	settings := map[string]json.RawMessage{}
	if len(bytes.TrimSpace(orig)) > 0 {
		if err := json.Unmarshal(orig, &settings); err != nil {
			return nil, fmt.Errorf("parse: %w", err)
		}
	}
	serversRaw := settings[topKey]
	if isJSONNull(serversRaw) {
		serversRaw = nil
	}
	servers, err := credfile.SetObjectMember(serversRaw, ServerName, entry, present)
	if err != nil {
		return nil, err
	}
	servers = bytes.TrimSpace(servers)
	empty := map[string]json.RawMessage{}
	if !present && json.Unmarshal(servers, &empty) == nil && len(empty) == 0 {
		return credfile.SetObjectMember(orig, topKey, nil, false)
	}
	return credfile.SetObjectMember(orig, topKey, servers, true)
}

// removeJSONServer cuts observer's member from the server object at topKey.
// dropEmpty drops the object when the cut empties it (a file Observer
// created); otherwise the empty object stays, the shape the user's file
// had (D-MU9).
func removeJSONServer(orig []byte, topKey string, dropEmpty bool) ([]byte, error) {
	if dropEmpty {
		return setJSONServer(orig, topKey, nil, false)
	}
	settings := map[string]json.RawMessage{}
	if err := json.Unmarshal(orig, &settings); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	servers, err := credfile.SetObjectMember(settings[topKey], ServerName, nil, false)
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(servers)) == 0 {
		servers = []byte("{}")
	}
	return credfile.SetObjectMember(orig, topKey, bytes.TrimSpace(servers), true)
}

// writeCredentialMCPFile writes body atomically and durably, keeping the
// file's permission bits (0600 for a new file). It makes no backup.
func writeCredentialMCPFile(path string, body []byte) error {
	mode := os.FileMode(0o600)
	if fi, err := os.Stat(path); err == nil {
		mode = fi.Mode().Perm()
	}
	if err := writeFileSync(path, body, mode, 0o755); err != nil {
		return fmt.Errorf("mcp.write %s: %w", path, err)
	}
	return nil
}

// serveArgs returns the argv (after the binary name) that the registered
// MCP launch command will use. When ConfigPath is set, the launch
// becomes `<binary> serve --config <path>` so the MCP server reads the
// same config as the proxy that's running it.
func (r *Registrar) serveArgs() []string {
	if r.opts.ConfigPath == "" {
		return []string{"serve"}
	}
	return []string{"serve", "--config", r.opts.ConfigPath}
}

// stringSlicesEqual reports whether two string slices are element-wise
// equal. Used in the idempotency check so a change in registered args
// (e.g. new --config flag) re-writes the entry instead of being
// treated as already-set.
func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// tomlArgsEqual handles the codex TOML round-trip case: BurntSushi/toml
// unmarshals string arrays into []any rather than []string, so a strict
// type-asserted equality check would always miss. This walks both
// shapes and compares element-wise.
func tomlArgsEqual(existing any, desired []string) bool {
	existingSlice, ok := existing.([]any)
	if !ok {
		return false
	}
	if len(existingSlice) != len(desired) {
		return false
	}
	for i, v := range existingSlice {
		s, ok := v.(string)
		if !ok || s != desired[i] {
			return false
		}
	}
	return true
}

// removeConfigFile removes an MCP config file Observer emptied: expected is
// the bytes the caller read and decided on, compared again just before the
// delete, so a file changed in between is kept (FU-212, the hook registry's
// removeEmptyConfigFile rule). Inside a test binary it first refuses a path
// outside the temp directory (internal/testwriteguard, incident
// 2026-10-21).
func removeConfigFile(path string, expected []byte) error {
	if err := testwriteguard.Check("remove", path); err != nil {
		return err
	}
	current, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if !bytes.Equal(current, expected) {
		return fmt.Errorf("%s changed since observer decided to delete it; refusing to delete a file observer never read; re-run to decide against the current content", path)
	}
	return os.Remove(path)
}

// writeFileSync writes data to path atomically. Inside a test binary it
// first refuses a path outside the temp directory (internal/testwriteguard,
// incident 2026-10-21), before it creates any directory.
//
// It writes durably: temp file in the same directory, fsync, rename over
// the target, then fsync the directory (skipped on Windows, where a
// directory handle cannot be synced). dirMode is used only when the parent has to be created.
func writeFileSync(path string, data []byte, mode, dirMode os.FileMode) error {
	if err := testwriteguard.Check("write", path); err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return fmt.Errorf("open temp: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("write temp: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("fsync temp: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename: %w", err)
	}
	if runtime.GOOS != "windows" {
		if d, err := os.Open(dir); err == nil {
			_ = d.Sync()
			_ = d.Close()
		}
	}
	return nil
}
