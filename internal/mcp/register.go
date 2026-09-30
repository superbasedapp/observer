package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/marmutapp/superbased-observer/internal/claudeplugin"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/mcp/locate"
	"github.com/marmutapp/superbased-observer/internal/mcprelay/project"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// claudeCodeMCPPath reports the config file the claude-code MCP entry
// would have been written to, for reporting on the skip path (where the
// normal locate lookup below never runs). Empty when the client is not
// in the locate table.
func claudeCodeMCPPath(home string) string {
	if loc, ok := locate.ForClient("claude-code", home); ok {
		return loc.Path
	}
	return ""
}

// ServerName is the registration entry name written into each AI tool's
// MCP config. Stable so re-running init is idempotent.
const ServerName = "observer"

// allHomes is the crossmount-home enumeration seam — a package var (mirroring
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
	// own packaging surface — today, the Claude Code plugin, whose
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
	// still happened (fail-open to wiring). Empty on every conclusive path.
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
}

// Registrar dispatches MCP registrations per tool.
type Registrar struct {
	opts RegisterOptions
	// homeOverride is the caller-supplied RegisterOptions.HomeDir VERBATIM,
	// kept before NewRegistrar defaults it to the real $HOME. Non-empty
	// means "the caller pinned this registrar's home", which switches OFF
	// crossmount auto-detection for the cross-OS "cline-windows" target —
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
	return &Registrar{opts: opts, homeOverride: homeOverride}, nil
}

// Installed reports which supported tools have a config directory present.
// Mirrors hook.Registry.Installed so the CLI can detect both hook-capable and
// MCP-capable tools off the same probe.
func (r *Registrar) Installed() []string {
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
	if r.dirExists(filepath.Join(r.opts.HomeDir, ".config", "opencode")) {
		tools = append(tools, "opencode")
	}
	// Native (same-OS) Cline: VS Code globalStorage settings dir present.
	if loc, ok := locate.ForClient("cline", r.opts.HomeDir); ok && r.dirExists(filepath.Dir(loc.Path)) {
		tools = append(tools, "cline")
	}
	// Cross-OS Cline: a Windows VS Code globalStorage reachable from a WSL
	// daemon via crossmount (the cline-windows target).
	if dir := r.detectWindowsClineSettingsDir(); dir != "" {
		tools = append(tools, "cline-windows")
	}
	if r.dirExists(filepath.Join(r.opts.HomeDir, ".factory")) {
		tools = append(tools, "droid")
	}
	if r.dirExists(filepath.Join(r.opts.HomeDir, ".commandcode")) {
		tools = append(tools, "command-code")
	}
	return tools
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
// internal/mcp/locate table — the one owner of per-client MCP config
// locations (guard/mcpsec reads the same table).
func (r *Registrar) Register(tool string) RegistrationResult {
	// cline-windows is a cross-OS virtual target: its config path is
	// resolved dynamically through crossmount (not the home-based locate
	// table) and its command is a wsl.exe bridge, so it dispatches by name
	// BEFORE the locate lookup (mirrors hook.registerClaudeCodeWindows).
	if tool == "cline-windows" {
		return r.registerClineWindows()
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
		pd := claudeplugin.Detect(r.opts.HomeDir)
		if pd.Active {
			return RegistrationResult{
				Tool:       tool,
				ConfigPath: claudeCodeMCPPath(r.opts.HomeDir),
				Skipped:    true,
				SkipReason: pd.Reason(),
				DryRun:     r.opts.DryRun,
			}
		}
		probeWarning = pd.Warning()
	}
	loc, ok := locate.ForClient(tool, r.opts.HomeDir)
	if !ok {
		return RegistrationResult{
			Tool:   tool,
			Error:  fmt.Errorf("mcp.Register: tool %q not supported", tool),
			DryRun: r.opts.DryRun,
		}
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
	res := RegistrationResult{Tool: tool, ConfigPath: path, DryRun: r.opts.DryRun}

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
	// rewrite a sibling remote server as {"command":"","args":null} — a
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
		// A malformed prior entry under OUR key falls through to overwrite
		// (existing stays zero, so neither guard below trips a false
		// "already set").
		_ = json.Unmarshal(existingRaw, &existing)
		if existing.Command == desired.Command && stringSlicesEqual(existing.Args, desired.Args) {
			res.AlreadySet = true
			return res
		}
		// Args drifted but binary is ours — refresh silently (same
		// owner, just a flag change like adding/dropping --config).
		// Different binary keeps the old conflict semantics.
		if existing.Command != desired.Command && !r.opts.Force {
			res.Error = fmt.Errorf("mcp.register %s: %s already points at %q; pass --force to overwrite",
				tool, ServerName, existing.Command)
			return res
		}
	}
	desiredRaw, err := json.Marshal(desired)
	if err != nil {
		res.Error = fmt.Errorf("mcp.register %s: marshal entry: %w", tool, err)
		return res
	}
	servers[ServerName] = desiredRaw

	patched, err := json.Marshal(servers)
	if err != nil {
		res.Error = fmt.Errorf("mcp.register %s: marshal: %w", tool, err)
		return res
	}
	settings["mcpServers"] = patched

	if r.opts.DryRun {
		res.Added = true
		return res
	}
	if err := writeJSON(path, settings); err != nil {
		res.Error = err
		return res
	}
	res.Added = true
	return res
}

// registerClineWindows writes the observer MCP server into a Windows VS
// Code Cline config (cline_mcp_settings.json) from a WSL daemon, using a
// `wsl.exe -d <distro> -- <linux-bin> serve` bridge command so the Windows
// host spawns the WSL-resident observer over stdio. Mirrors
// hook.registerClaudeCodeWindows: dynamic crossmount path + wsl bridge,
// gated by the cline row's MCP.CrossOSBridge capability.
func (r *Registrar) registerClineWindows() RegistrationResult {
	res := RegistrationResult{Tool: "cline-windows", DryRun: r.opts.DryRun}
	path := r.detectWindowsClineSettings()
	if path == "" {
		if r.foreignAutoDetectSuppressed(r.opts.WindowsClineHome) {
			// Deliberate no-write, not a host problem — see
			// crossmount.AutoDetectSuppressed (incident 2026-07-31).
			res.Skipped = true
			if r.opts.WindowsClineHome == "" {
				res.SkipReason = "HomeDir was pinned by the caller but no WindowsClineHome was given — cross-OS globalStorage resolution is suppressed (incident 2026-07-31)"
			} else {
				res.SkipReason = fmt.Sprintf(
					"WindowsClineHome (%s) resolves OUTSIDE the pinned HomeDir (%s) — cross-OS globalStorage resolution is suppressed (incident 2026-07-31)",
					r.opts.WindowsClineHome, r.homeOverride,
				)
			}
			res.SkipAdvice = "nothing written; a sandboxed caller must set WindowsClineHome to a home UNDER its own HomeDir to wire this target (--force does not lift this)."
			return res
		}
		res.Error = errors.New("mcp.registerClineWindows: no Windows-side VS Code Cline globalStorage detected (set WindowsClineHome or run where crossmount sees /mnt/c/Users/<u>/AppData/Roaming/Code/.../cline_mcp_settings.json)")
		return res
	}
	distro := r.opts.WSLDistro
	if distro == "" {
		distro = os.Getenv("WSL_DISTRO_NAME")
	}
	if distro == "" {
		res.Error = errors.New("mcp.registerClineWindows: WSL distro unknown — set WSLDistro or run inside WSL (so $WSL_DISTRO_NAME is set)")
		return res
	}
	// Cline (a Node VS Code extension) spawns the MCP command+args directly
	// via child_process — NOT through Git Bash — so no MSYS_NO_PATHCONV
	// prefix is needed (that guard is only for the shell-string hook case).
	desired := mcpServerEntry{
		Command: "wsl.exe",
		Args:    append([]string{"-d", distro, "--", r.opts.BinaryPath}, r.serveArgs()...),
	}
	return r.registerJSONMCPEntry("cline-windows", path, desired)
}

// detectWindowsClineSettings returns the Windows-side cline_mcp_settings.json
// path (resolved via crossmount), or "" if no Windows VS Code Cline
// globalStorage is reachable. Honors WindowsClineHome when set.
func (r *Registrar) detectWindowsClineSettings() string {
	// Sandbox gate FIRST — before the override branch, because an override
	// pointing OUTSIDE the pinned home is exactly the escape hatch that
	// re-opened this hole. See crossmount.AutoDetectSuppressed (incident
	// 2026-07-31). Production never pins HomeDir, so this is false on every
	// real path and a bare override still wins unconditionally.
	if r.foreignAutoDetectSuppressed(r.opts.WindowsClineHome) {
		return ""
	}
	if r.opts.WindowsClineHome != "" {
		return locate.ClineSettingsPath(r.opts.WindowsClineHome, crossmount.OSWindows)
	}
	for _, h := range allHomes() {
		if h.OS != crossmount.OSWindows {
			continue
		}
		p := locate.ClineSettingsPath(h.Path, crossmount.OSWindows)
		if r.dirExists(filepath.Dir(p)) {
			return p
		}
	}
	return ""
}

// detectWindowsClineSettingsDir reports the settings dir for Installed()
// detection — returns the parent dir when a Windows Cline globalStorage is
// present, "" otherwise.
func (r *Registrar) detectWindowsClineSettingsDir() string {
	p := r.detectWindowsClineSettings()
	if p == "" {
		return ""
	}
	return filepath.Dir(p)
}

// opencodeMCPEntry is OpenCode's MCP server shape under the top-level
// "mcp" key in opencode.json: a typed local-command server. Distinct from
// the {command,args} shape Claude Code/Cursor use — OpenCode takes the
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
	tool := "opencode"
	res := RegistrationResult{Tool: tool, ConfigPath: path, DryRun: r.opts.DryRun}

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
		// A parse failure here means a malformed prior entry — fall through
		// to overwrite (curEntry stays zero, so neither guard below trips a
		// false "already set").
		_ = json.Unmarshal(cur, &curEntry)
		if curEntry.Type == desired.Type && curEntry.Enabled == desired.Enabled &&
			stringSlicesEqual(curEntry.Command, desired.Command) {
			res.AlreadySet = true
			return res
		}
		// Command drifted but the head binary is ours — refresh silently. A
		// different binary at the head keeps the conflict semantics.
		if (len(curEntry.Command) == 0 || curEntry.Command[0] != r.opts.BinaryPath) && !r.opts.Force {
			res.Error = fmt.Errorf("mcp.register opencode: %s already points at %v; pass --force to overwrite",
				ServerName, curEntry.Command)
			return res
		}
	}

	desiredRaw, err := json.Marshal(desired)
	if err != nil {
		res.Error = fmt.Errorf("mcp.register opencode: marshal entry: %w", err)
		return res
	}
	servers[ServerName] = desiredRaw

	patched, err := json.Marshal(servers)
	if err != nil {
		res.Error = fmt.Errorf("mcp.register opencode: marshal mcp: %w", err)
		return res
	}
	settings["mcp"] = patched

	if r.opts.DryRun {
		res.Added = true
		return res
	}
	if err := writeJSON(path, settings); err != nil {
		res.Error = err
		return res
	}
	res.Added = true
	return res
}

// registerCodexTOML patches ~/.codex/config.toml's [mcp_servers] table.
// Unknown TOML sections are preserved by round-tripping through a generic
// map; the order of unrelated keys may change but content is preserved.
// Comments will not survive — this is documented in the user-facing init
// output.
func (r *Registrar) registerCodexTOML(path string) RegistrationResult {
	tool := "codex"
	dir := filepath.Dir(path)
	res := RegistrationResult{Tool: tool, ConfigPath: path, DryRun: r.opts.DryRun}

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
		// Args drifted but binary is ours — refresh silently. Different
		// binary keeps the old conflict semantics.
		if cmd != r.opts.BinaryPath && !r.opts.Force {
			res.Error = fmt.Errorf("mcp.register codex: %s already points at %v; pass --force to overwrite",
				ServerName, existing["command"])
			return res
		}
	}
	servers[ServerName] = desired
	root["mcp_servers"] = servers

	if r.opts.DryRun {
		res.Added = true
		return res
	}
	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(root); err != nil {
		res.Error = fmt.Errorf("mcp.register codex: encode: %w", err)
		return res
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		res.Error = fmt.Errorf("mcp.register codex: mkdir: %w", err)
		return res
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, buf.Bytes(), 0o600); err != nil {
		res.Error = fmt.Errorf("mcp.register codex: write: %w", err)
		return res
	}
	if err := os.Rename(tmp, path); err != nil {
		res.Error = fmt.Errorf("mcp.register codex: rename: %w", err)
		return res
	}
	res.Added = true
	return res
}

// UnregistrationResult summarizes one MCP unregistration.
type UnregistrationResult struct {
	Tool       string // claude-code | cursor | codex
	ConfigPath string
	Removed    bool // observer entry was present and has been deleted
	Skipped    bool // config file missing or the observer entry was already absent
	DryRun     bool
	Error      error
}

// Unregister removes the "observer" MCP entry from tool's config file.
// Other MCP servers and all other top-level config keys are preserved
// verbatim. Supported tools: "claude-code", "cursor", "codex".
func (r *Registrar) Unregister(tool string) UnregistrationResult {
	if tool == "cline-windows" {
		path := r.detectWindowsClineSettings()
		if path == "" {
			return UnregistrationResult{Tool: tool, Skipped: true, DryRun: r.opts.DryRun}
		}
		return r.unregisterJSONMCP(tool, path)
	}
	loc, ok := locate.ForClient(tool, r.opts.HomeDir)
	if !ok {
		return UnregistrationResult{
			Tool:   tool,
			Error:  fmt.Errorf("mcp.Unregister: tool %q not supported", tool),
			DryRun: r.opts.DryRun,
		}
	}
	switch loc.Format {
	case locate.FormatCodexTOML:
		return r.unregisterCodexTOML(loc.Path)
	case locate.FormatOpenCodeJSON:
		return r.unregisterOpenCodeJSON(loc.Path)
	default:
		return r.unregisterJSONMCP(tool, loc.Path)
	}
}

func (r *Registrar) unregisterJSONMCP(tool, path string) UnregistrationResult {
	res := UnregistrationResult{Tool: tool, ConfigPath: path, DryRun: r.opts.DryRun}

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
	if existing, ok := settings["mcpServers"]; ok {
		if err := json.Unmarshal(existing, &servers); err != nil {
			res.Error = fmt.Errorf("mcp.unregister %s: parse mcpServers: %w", tool, err)
			return res
		}
	}
	if _, ok := servers[ServerName]; !ok {
		res.Skipped = true
		return res
	}
	delete(servers, ServerName)
	res.Removed = true

	if len(servers) == 0 {
		delete(settings, "mcpServers")
	} else {
		patched, err := json.Marshal(servers)
		if err != nil {
			res.Error = fmt.Errorf("mcp.unregister %s: marshal: %w", tool, err)
			return res
		}
		settings["mcpServers"] = patched
	}

	if r.opts.DryRun {
		return res
	}
	if len(settings) == 0 {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			res.Error = fmt.Errorf("mcp.unregister %s: remove %s: %w", tool, path, err)
			return res
		}
		return res
	}
	if err := writeJSON(path, settings); err != nil {
		res.Error = err
		return res
	}
	return res
}

// unregisterOpenCodeJSON removes the "observer" entry from the "mcp" object
// in opencode.json, preserving sibling servers (as raw JSON) and all other
// top-level keys. The "mcp" key is dropped when it empties, and the file is
// removed when nothing else remains.
func (r *Registrar) unregisterOpenCodeJSON(path string) UnregistrationResult {
	tool := "opencode"
	res := UnregistrationResult{Tool: tool, ConfigPath: path, DryRun: r.opts.DryRun}

	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			res.Skipped = true
			return res
		}
		res.Error = fmt.Errorf("mcp.unregister opencode: read: %w", err)
		return res
	}
	settings := map[string]json.RawMessage{}
	if err := json.Unmarshal(raw, &settings); err != nil {
		res.Error = fmt.Errorf("mcp.unregister opencode: parse %s: %w", path, err)
		return res
	}
	servers := map[string]json.RawMessage{}
	if existing, ok := settings["mcp"]; ok {
		if err := json.Unmarshal(existing, &servers); err != nil {
			res.Error = fmt.Errorf("mcp.unregister opencode: parse mcp: %w", err)
			return res
		}
	}
	if _, ok := servers[ServerName]; !ok {
		res.Skipped = true
		return res
	}
	delete(servers, ServerName)
	res.Removed = true

	if len(servers) == 0 {
		delete(settings, "mcp")
	} else {
		patched, err := json.Marshal(servers)
		if err != nil {
			res.Error = fmt.Errorf("mcp.unregister opencode: marshal mcp: %w", err)
			return res
		}
		settings["mcp"] = patched
	}

	if r.opts.DryRun {
		return res
	}
	if len(settings) == 0 {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			res.Error = fmt.Errorf("mcp.unregister opencode: remove %s: %w", path, err)
			return res
		}
		return res
	}
	if err := writeJSON(path, settings); err != nil {
		res.Error = err
		return res
	}
	return res
}

func (r *Registrar) unregisterCodexTOML(path string) UnregistrationResult {
	tool := "codex"
	dir := filepath.Dir(path)
	res := UnregistrationResult{Tool: tool, ConfigPath: path, DryRun: r.opts.DryRun}

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
	delete(servers, ServerName)
	res.Removed = true

	if len(servers) == 0 {
		delete(root, "mcp_servers")
	} else {
		root["mcp_servers"] = servers
	}

	if r.opts.DryRun {
		return res
	}
	if len(root) == 0 {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			res.Error = fmt.Errorf("mcp.unregister codex: remove %s: %w", path, err)
			return res
		}
		return res
	}
	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(root); err != nil {
		res.Error = fmt.Errorf("mcp.unregister codex: encode: %w", err)
		return res
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		res.Error = fmt.Errorf("mcp.unregister codex: mkdir: %w", err)
		return res
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, buf.Bytes(), 0o600); err != nil {
		res.Error = fmt.Errorf("mcp.unregister codex: write: %w", err)
		return res
	}
	if err := os.Rename(tmp, path); err != nil {
		res.Error = fmt.Errorf("mcp.unregister codex: rename: %w", err)
		return res
	}
	return res
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

// writeJSON serializes settings as 2-space JSON with stably ordered top-level
// keys so config diffs stay clean across re-runs of init.
func writeJSON(path string, settings map[string]json.RawMessage) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("mcp.write: mkdir: %w", err)
	}
	buf := renderJSON(settings)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, buf, 0o600); err != nil {
		return fmt.Errorf("mcp.write: %w", err)
	}
	return os.Rename(tmp, path)
}

// renderJSON is writeJSON's rendering as bytes (the relay projection stages
// exactly what writeJSON would put on disk).
func renderJSON(settings map[string]json.RawMessage) []byte {
	keys := make([]string, 0, len(settings))
	for k := range settings {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var buf bytes.Buffer
	buf.WriteByte('{')
	buf.WriteByte('\n')
	for i, k := range keys {
		buf.WriteString("  ")
		kk, _ := json.Marshal(k)
		buf.Write(kk)
		buf.WriteString(": ")
		var tmp any
		if err := json.Unmarshal(settings[k], &tmp); err == nil {
			pretty, _ := json.MarshalIndent(tmp, "  ", "  ")
			buf.Write(pretty)
		} else {
			buf.Write(settings[k])
		}
		if i < len(keys)-1 {
			buf.WriteByte(',')
		}
		buf.WriteByte('\n')
	}
	buf.WriteString("}\n")
	return buf.Bytes()
}

// ---------------------------------------------------------------------------
// Agent Access P4 — the relay's per-format config writer (doc3 §12.1/§12.2;
// Sol P3+P4 findings 2 + 7, parking decision B5).
//
// The stdio writers above register observer's OWN MCP server. The writer
// below is the project.Writer seam the relay projector drives: it STAGES
// (never touching the file) the rewrite of every existing stdio entry to
// the relay's TRUE stdio wrapper plus the upsert of the relay-owned remote
// entries, COMMITS the staged bytes atomically under a CAS on what it
// staged against, and REVERTS only the relay-owned entries in place under
// its own read-compare-write CAS. It journals NOTHING on its own: the
// sequence (backup -> journal rows -> rewrite; restore rules) is owned by
// internal/mcprelay/project's Projector, the ONE journal owner. Dispatch is
// on the client's locate.Format for the FILE shape and on its
// integration.MCPTarget.Remote row for the remote ENTRY spelling (CLAUDE.md
// #3: capability shape, never tool name). No secret ever lands in a client
// config: the relay injects Authorization at call time, the writer refuses
// an Authorization header outright, and the journal rows the projector
// derives from a stage carry env KEY names only.
// ---------------------------------------------------------------------------

// wrapWriters is the per-format writer table: the ONE place that says which
// config formats the relay can wrap TODAY (the coverage matrix's
// "writer exists" input, doc3 §12.7). A format absent here is honestly
// unwrappable (hermes' YAML: its stdio writer lives in internal/hook and
// there is no locate row).
var wrapWriters = map[locate.Format]formatWriter{
	locate.FormatMCPServersJSON: {stage: stageJSON("mcpServers", stdioSharedJSON), revert: revertJSON("mcpServers", stdioSharedJSON)},
	locate.FormatOpenCodeJSON:   {stage: stageJSON("mcp", stdioOpenCode), revert: revertJSON("mcp", stdioOpenCode)},
	locate.FormatCodexTOML:      {stage: stageCodexTOML, revert: revertCodexTOML},
}

// wrapFormats maps the integration registry's format vocabulary onto the
// locate table's (the two grew separately; this is the bridge the
// capability-shape question is answered through).
var wrapFormats = map[integration.MCPFormat]locate.Format{
	integration.MCPServersJSON:  locate.FormatMCPServersJSON,
	integration.MCPCodexTOML:    locate.FormatCodexTOML,
	integration.MCPOpenCodeJSON: locate.FormatOpenCodeJSON,
}

// WrapWriterImplemented reports whether a stdio-wrap writer exists for a
// registry MCP format - what the coverage matrix's
// ClientShape.RegistryWriterImplemented means.
func WrapWriterImplemented(f integration.MCPFormat) bool {
	lf, ok := wrapFormats[f]
	if !ok {
		return false
	}
	_, ok = wrapWriters[lf]
	return ok
}

// formatWriter is one row of wrapWriters.
type formatWriter struct {
	stage  func(raw []byte, c project.Client, d project.Desired, remote *integration.MCPRemoteTarget) (stageResult, error)
	revert func(raw []byte, rows []project.JournalRow) ([]byte, bool, error)
}

// stageResult is a format writer's staged transformation.
type stageResult struct {
	after      []byte
	wrapped    []project.StdioEntry
	remoteKeys []string
}

// RelayClients lists this registrar's projection targets: every installed
// tool (Installed) that has a locate row, with Verified = a wrap writer
// exists for its format. Client.Format carries the locate.Format string.
// The cross-OS "cline-windows" bridge target is deliberately absent: the
// wrapper would run inside the WSL daemon's OS while the ORIGINAL server is
// a Windows-side command, which the wrapper cannot spawn - an honest zero,
// never a guessed writer.
func (r *Registrar) RelayClients() []project.Client {
	var out []project.Client
	for _, tool := range r.Installed() {
		loc, ok := locate.ForClient(tool, r.opts.HomeDir)
		if !ok {
			continue
		}
		_, writer := wrapWriters[loc.Format]
		out = append(out, project.Client{Tool: tool, ConfigPath: loc.Path, Format: string(loc.Format), Verified: writer})
	}
	return out
}

// resolveClient fills an empty Client.Format from the locate table (a
// restore-time Client carries only tool + path) and resolves the writer.
func (r *Registrar) resolveClient(c project.Client) (project.Client, formatWriter, error) {
	if c.Format == "" {
		loc, ok := locate.ForClient(c.Tool, r.opts.HomeDir)
		if !ok {
			return c, formatWriter{}, fmt.Errorf("mcp.relay-writer: tool %q has no MCP config location", c.Tool)
		}
		c.Format = string(loc.Format)
		if c.ConfigPath == "" {
			c.ConfigPath = loc.Path
		}
	}
	w, ok := wrapWriters[locate.Format(c.Format)]
	if !ok {
		return c, formatWriter{}, fmt.Errorf("mcp.relay-writer: no stdio-wrap writer for format %q (%s)", c.Format, c.Tool)
	}
	return c, w, nil
}

// readConfig returns the file's verbatim bytes (nil, false when absent).
func readConfig(path string) ([]byte, bool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return raw, true, nil
}

// Stage implements project.Writer: the staged transformation of c's config
// for the desired state, never touching the file. Changed is true only
// when an entry was wrapped or a relay remote entry added / changed - a
// hand-formatted file with nothing to do stays untouched on every re-apply
// (idempotence), and observer's own server / an entry already spawning the
// wrapper are never wrapped (project.IsObserver / project.IsWrapper).
func (r *Registrar) Stage(_ context.Context, c project.Client, d project.Desired) (project.Staged, error) {
	c, w, err := r.resolveClient(c)
	if err != nil {
		return project.Staged{}, err
	}
	raw, exists, err := readConfig(c.ConfigPath)
	if err != nil {
		return project.Staged{}, fmt.Errorf("mcp.relay-writer %s: read: %w", c.Tool, err)
	}
	var remote *integration.MCPRemoteTarget
	if len(d.Remote) > 0 {
		// A client whose registry row grounds no implemented remote target
		// gets no remote entry (the matrix already labels it): the stdio
		// wrap still applies.
		if rt, rerr := remoteTargetFor(c.Tool); rerr == nil {
			remote = rt
			for _, e := range d.Remote {
				if verr := validateRemoteEntry(c.Tool, e, remote); verr != nil {
					return project.Staged{}, verr
				}
			}
		}
	}
	res, err := w.stage(raw, c, d, remote)
	if err != nil {
		return project.Staged{}, fmt.Errorf("mcp.relay-writer %s: %w", c.Tool, err)
	}
	st := project.Staged{After: res.after, Wrapped: res.wrapped, RemoteKeys: res.remoteKeys}
	if exists {
		st.Before = raw
	}
	st.Changed = len(res.wrapped) > 0 || len(res.remoteKeys) > 0
	return st, nil
}

// Commit implements project.Writer: the atomic, durable rewrite of the
// staged bytes (temp + fsync + rename + dir fsync), refused with
// project.ErrConfigChanged when the file no longer holds exactly
// Staged.Before (the CAS the §12.1 step-3 write runs under). The existing
// file mode is kept; a new file is 0600.
func (r *Registrar) Commit(_ context.Context, c project.Client, st project.Staged) error {
	c, _, err := r.resolveClient(c)
	if err != nil {
		return err
	}
	cur, exists, err := readConfig(c.ConfigPath)
	if err != nil {
		return fmt.Errorf("mcp.relay-writer %s: read: %w", c.Tool, err)
	}
	if exists != (st.Before != nil) || !bytes.Equal(cur, st.Before) {
		return fmt.Errorf("%w: %s", project.ErrConfigChanged, c.ConfigPath)
	}
	mode := os.FileMode(0o600)
	if fi, serr := os.Stat(c.ConfigPath); serr == nil {
		mode = fi.Mode().Perm()
	}
	if err := writeFileSync(c.ConfigPath, st.After, mode, 0o755); err != nil {
		return fmt.Errorf("mcp.relay-writer %s: write %s: %w", c.Tool, c.ConfigPath, err)
	}
	return nil
}

// Revert implements project.Writer: the format-aware reversal of ONLY the
// relay-owned entries named by rows - a wrapped stdio entry gets its
// journaled original command/args back (every other field of the entry,
// and every sibling, is preserved), a relay remote entry is deleted - under
// a read-compare-write CAS (the file is re-read before the write and must
// still hold the bytes the reversal was computed from, else
// project.ErrConfigChanged). An entry that is no longer the wrapper (the
// operator already put it back) is left alone. The file is never removed
// by a reversal; an empty server map drops its top-level key.
func (r *Registrar) Revert(_ context.Context, c project.Client, rows []project.JournalRow) error {
	c, w, err := r.resolveClient(c)
	if err != nil {
		return err
	}
	raw, exists, err := readConfig(c.ConfigPath)
	if err != nil {
		return fmt.Errorf("mcp.relay-writer %s: read: %w", c.Tool, err)
	}
	if !exists {
		return nil
	}
	after, changed, err := w.revert(raw, rows)
	if err != nil {
		return fmt.Errorf("mcp.relay-writer %s: revert: %w", c.Tool, err)
	}
	if !changed {
		return nil
	}
	again, _, err := readConfig(c.ConfigPath)
	if err != nil {
		return fmt.Errorf("mcp.relay-writer %s: re-read: %w", c.Tool, err)
	}
	if !bytes.Equal(again, raw) {
		return fmt.Errorf("%w: %s", project.ErrConfigChanged, c.ConfigPath)
	}
	mode := os.FileMode(0o600)
	if fi, serr := os.Stat(c.ConfigPath); serr == nil {
		mode = fi.Mode().Perm()
	}
	if err := writeFileSync(c.ConfigPath, after, mode, 0o755); err != nil {
		return fmt.Errorf("mcp.relay-writer %s: write %s: %w", c.Tool, c.ConfigPath, err)
	}
	return nil
}

// stdioShape is how one JSON config variant spells a stdio entry: how to
// read the original launch out of an entry and how to write the wrapper
// (or the original) back into it. Two rows exist - the shared
// {command,args} object and OpenCode's typed {type:"local",command:[...]}.
type stdioShape struct {
	// read extracts the launch; ok=false when the entry is not a stdio
	// server (remote, malformed, unrepresentable).
	read func(e map[string]json.RawMessage) (cmd string, args []string, cwd string, envKeys []string, ok bool)
	// write sets the launch (command + args) on the entry in place.
	write func(e map[string]json.RawMessage, cmd string, args []string)
	// remote renders the relay remote entry for this variant.
	remote func(entry project.RemoteEntry, remote *integration.MCPRemoteTarget) map[string]any
}

// stdioSharedJSON is the {"command":…,"args":[…],"cwd":…,"env":{…}} shape
// (claude-code / cursor / cline / droid / command-code).
var stdioSharedJSON = stdioShape{
	read: func(e map[string]json.RawMessage) (string, []string, string, []string, bool) {
		if _, remote := e["url"]; remote {
			return "", nil, "", nil, false
		}
		var cmd string
		if raw, ok := e["command"]; !ok || json.Unmarshal(raw, &cmd) != nil || cmd == "" {
			return "", nil, "", nil, false
		}
		var args []string
		if raw, ok := e["args"]; ok && len(raw) > 0 && string(raw) != "null" {
			if json.Unmarshal(raw, &args) != nil {
				return "", nil, "", nil, false
			}
		}
		var cwd string
		if raw, ok := e["cwd"]; ok {
			_ = json.Unmarshal(raw, &cwd)
		}
		return cmd, args, cwd, envKeysOf(e["env"]), true
	},
	write: func(e map[string]json.RawMessage, cmd string, args []string) {
		e["command"], _ = json.Marshal(cmd)
		if args == nil {
			args = []string{}
		}
		e["args"], _ = json.Marshal(args)
	},
	remote: jsonRemoteEntry,
}

// stdioOpenCode is OpenCode's {"type":"local","command":[bin, args…],
// "environment":{…}} shape.
var stdioOpenCode = stdioShape{
	read: func(e map[string]json.RawMessage) (string, []string, string, []string, bool) {
		var typ string
		if raw, ok := e["type"]; ok {
			_ = json.Unmarshal(raw, &typ)
		}
		if typ != "" && typ != "local" {
			return "", nil, "", nil, false
		}
		var command []string
		if raw, ok := e["command"]; !ok || json.Unmarshal(raw, &command) != nil || len(command) == 0 || command[0] == "" {
			return "", nil, "", nil, false
		}
		return command[0], append([]string(nil), command[1:]...), "", envKeysOf(e["environment"]), true
	},
	write: func(e map[string]json.RawMessage, cmd string, args []string) {
		e["command"], _ = json.Marshal(append([]string{cmd}, args...))
	},
	remote: opencodeRemoteEntry,
}

// envKeysOf lists an env object's KEY names, sorted; values are never read
// into anything the caller keeps.
func envKeysOf(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var env map[string]json.RawMessage
	if json.Unmarshal(raw, &env) != nil || len(env) == 0 {
		return nil
	}
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// parseJSONServers splits a JSON config into its top-level raw map and the
// server map under topKey (both empty for an absent file).
func parseJSONServers(raw []byte, topKey string) (map[string]json.RawMessage, map[string]json.RawMessage, error) {
	settings := map[string]json.RawMessage{}
	if len(bytes.TrimSpace(raw)) > 0 {
		if err := json.Unmarshal(raw, &settings); err != nil {
			return nil, nil, fmt.Errorf("parse: %w", err)
		}
	}
	servers := map[string]json.RawMessage{}
	if existing, ok := settings[topKey]; ok && len(existing) > 0 && string(existing) != "null" {
		if err := json.Unmarshal(existing, &servers); err != nil {
			return nil, nil, fmt.Errorf("parse %s: %w", topKey, err)
		}
	}
	return settings, servers, nil
}

func sortedMapKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// stageJSON builds the stage function for a JSON variant.
func stageJSON(topKey string, shape stdioShape) func([]byte, project.Client, project.Desired, *integration.MCPRemoteTarget) (stageResult, error) {
	return func(raw []byte, c project.Client, d project.Desired, remote *integration.MCPRemoteTarget) (stageResult, error) {
		settings, servers, err := parseJSONServers(raw, topKey)
		if err != nil {
			return stageResult{}, err
		}
		var res stageResult
		if d.Wrap != nil {
			for _, key := range sortedMapKeys(servers) {
				var e map[string]json.RawMessage
				if json.Unmarshal(servers[key], &e) != nil || e == nil {
					continue
				}
				cmd, args, cwd, envKeys, ok := shape.read(e)
				if !ok || project.IsObserver(cmd, *d.Wrap) || project.IsWrapper(cmd, args, *d.Wrap) {
					continue
				}
				// Only an entry bound to an approved (vserver, server) is
				// wrapped; the binding rides the staged entry (Sol P3+P4
				// fold finding 2).
				b, bound := d.Wrap.BindingFor(key)
				if !bound {
					continue
				}
				res.wrapped = append(res.wrapped, project.StdioEntry{Key: key, Command: cmd, Args: args, Cwd: cwd, EnvKeys: envKeys, VServer: b.VServer, ServerID: b.ServerID})
				shape.write(e, d.Wrap.Command, project.WrapArgs(c.Tool, key, *d.Wrap))
				servers[key], _ = json.Marshal(e)
			}
		}
		if remote != nil {
			for _, entry := range d.Remote {
				desired, _ := json.Marshal(shape.remote(entry, remote))
				if cur, ok := servers[entry.Name]; ok && jsonEquivalent(cur, desired) {
					continue
				}
				servers[entry.Name] = desired
				res.remoteKeys = append(res.remoteKeys, entry.Name)
			}
		}
		if len(res.wrapped) == 0 && len(res.remoteKeys) == 0 {
			res.after = raw
			return res, nil
		}
		settings[topKey], _ = json.Marshal(servers)
		res.after = renderJSON(settings)
		return res, nil
	}
}

// revertJSON builds the revert function for a JSON variant.
func revertJSON(topKey string, shape stdioShape) func([]byte, []project.JournalRow) ([]byte, bool, error) {
	return func(raw []byte, rows []project.JournalRow) ([]byte, bool, error) {
		settings, servers, err := parseJSONServers(raw, topKey)
		if err != nil {
			return nil, false, err
		}
		changed := false
		for _, row := range rows {
			cur, ok := servers[row.EntryKey]
			if !ok {
				continue
			}
			switch row.Kind() {
			case project.RowRemote:
				delete(servers, row.EntryKey)
				changed = true
			case project.RowStdioWrap:
				var e map[string]json.RawMessage
				if json.Unmarshal(cur, &e) != nil || e == nil {
					continue
				}
				cmd, args, _, _, ok := shape.read(e)
				if !ok || !project.IsWrapper(cmd, args, project.WrapSpec{Command: cmd}) {
					continue // already put back by hand: leave it
				}
				shape.write(e, row.OrigCommand, row.OrigArgs)
				servers[row.EntryKey], _ = json.Marshal(e)
				changed = true
			}
		}
		if !changed {
			return raw, false, nil
		}
		if len(servers) == 0 {
			delete(settings, topKey)
		} else {
			settings[topKey], _ = json.Marshal(servers)
		}
		return renderJSON(settings), true, nil
	}
}

// parseTOMLServers decodes Codex's config.toml into its generic map and the
// [mcp_servers] table (both empty for an absent file).
func parseTOMLServers(raw []byte) (map[string]any, map[string]any, error) {
	root := map[string]any{}
	if len(bytes.TrimSpace(raw)) > 0 {
		if err := toml.Unmarshal(raw, &root); err != nil {
			return nil, nil, fmt.Errorf("parse: %w", err)
		}
	}
	servers, _ := root["mcp_servers"].(map[string]any)
	if servers == nil {
		servers = map[string]any{}
	}
	return root, servers, nil
}

// tomlStdio reads a [mcp_servers.<key>] table's launch (ok=false for a
// remote `url` table or an unrepresentable one).
func tomlStdio(e map[string]any) (cmd string, args []string, cwd string, envKeys []string, ok bool) {
	if _, remote := e["url"]; remote {
		return "", nil, "", nil, false
	}
	cmd, _ = e["command"].(string)
	if cmd == "" {
		return "", nil, "", nil, false
	}
	switch v := e["args"].(type) {
	case nil:
	case []any:
		for _, a := range v {
			s, isStr := a.(string)
			if !isStr {
				return "", nil, "", nil, false
			}
			args = append(args, s)
		}
	case []string:
		args = append(args, v...)
	default:
		return "", nil, "", nil, false
	}
	cwd, _ = e["cwd"].(string)
	if env, isMap := e["env"].(map[string]any); isMap {
		envKeys = sortedMapKeys(env)
	}
	return cmd, args, cwd, envKeys, true
}

// renderTOML encodes root the way writeTOML writes it.
func renderTOML(root map[string]any) ([]byte, error) {
	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(root); err != nil {
		return nil, fmt.Errorf("encode toml: %w", err)
	}
	return buf.Bytes(), nil
}

// stageCodexTOML stages Codex's [mcp_servers] rewrite: every stdio table
// gets the wrapper (other keys - env, cwd, startup_timeout_sec - kept),
// the relay remote tables are upserted. Unrelated tables round-trip through
// the generic map exactly as registerCodexTOML's do (comments do not
// survive a rewrite - the journaled backup is what makes disable
// byte-identical).
func stageCodexTOML(raw []byte, c project.Client, d project.Desired, remote *integration.MCPRemoteTarget) (stageResult, error) {
	root, servers, err := parseTOMLServers(raw)
	if err != nil {
		return stageResult{}, err
	}
	var res stageResult
	if d.Wrap != nil {
		for _, key := range sortedMapKeys(servers) {
			e, ok := servers[key].(map[string]any)
			if !ok {
				continue
			}
			cmd, args, cwd, envKeys, ok := tomlStdio(e)
			if !ok || project.IsObserver(cmd, *d.Wrap) || project.IsWrapper(cmd, args, *d.Wrap) {
				continue
			}
			b, bound := d.Wrap.BindingFor(key)
			if !bound {
				continue
			}
			res.wrapped = append(res.wrapped, project.StdioEntry{Key: key, Command: cmd, Args: args, Cwd: cwd, EnvKeys: envKeys, VServer: b.VServer, ServerID: b.ServerID})
			e["command"] = d.Wrap.Command
			e["args"] = project.WrapArgs(c.Tool, key, *d.Wrap)
			servers[key] = e
		}
	}
	if remote != nil {
		for _, entry := range d.Remote {
			desired := codexRemoteEntry(entry)
			if cur, ok := servers[entry.Name]; ok && valuesEquivalent(cur, desired) {
				continue
			}
			servers[entry.Name] = desired
			res.remoteKeys = append(res.remoteKeys, entry.Name)
		}
	}
	if len(res.wrapped) == 0 && len(res.remoteKeys) == 0 {
		res.after = raw
		return res, nil
	}
	root["mcp_servers"] = servers
	res.after, err = renderTOML(root)
	return res, err
}

// revertCodexTOML reverses only the relay-owned [mcp_servers] tables.
func revertCodexTOML(raw []byte, rows []project.JournalRow) ([]byte, bool, error) {
	root, servers, err := parseTOMLServers(raw)
	if err != nil {
		return nil, false, err
	}
	changed := false
	for _, row := range rows {
		cur, ok := servers[row.EntryKey]
		if !ok {
			continue
		}
		switch row.Kind() {
		case project.RowRemote:
			delete(servers, row.EntryKey)
			changed = true
		case project.RowStdioWrap:
			e, ok := cur.(map[string]any)
			if !ok {
				continue
			}
			cmd, args, _, _, ok := tomlStdio(e)
			if !ok || !project.IsWrapper(cmd, args, project.WrapSpec{Command: cmd}) {
				continue
			}
			e["command"] = row.OrigCommand
			if row.OrigArgs == nil {
				delete(e, "args")
			} else {
				e["args"] = append([]string(nil), row.OrigArgs...)
			}
			servers[row.EntryKey] = e
			changed = true
		}
	}
	if !changed {
		return raw, false, nil
	}
	if len(servers) == 0 {
		delete(root, "mcp_servers")
	} else {
		root["mcp_servers"] = servers
	}
	after, err := renderTOML(root)
	return after, true, err
}

// remoteTargetFor resolves tool (or its "-windows" bridge variant) to the
// registry row's grounded remote target. Every refusal names WHY: no row,
// no grounded remote shape, grounded-but-unwired (hermes), or a bridge
// target on a client without CrossOSBridge.
func remoteTargetFor(tool string) (*integration.MCPRemoteTarget, error) {
	base, isWindows := strings.CutSuffix(tool, "-windows")
	c, ok := integration.For(base)
	if !ok {
		return nil, fmt.Errorf("mcp.relay-writer: tool %q not supported", tool)
	}
	if c.MCP == nil || c.MCP.Remote == nil {
		return nil, fmt.Errorf("mcp.relay-writer: %s has no grounded remote MCP target (registry MCPTarget.Remote is nil)", tool)
	}
	if !c.MCP.Remote.Implemented {
		return nil, fmt.Errorf("mcp.relay-writer: %s grounds a remote MCP target but no writer projects it yet (%s)", tool, c.MCP.Remote.Note)
	}
	if isWindows && !c.MCP.CrossOSBridge {
		return nil, fmt.Errorf("mcp.relay-writer: %s has no cross-OS bridge target", tool)
	}
	return c.MCP.Remote, nil
}

// remoteTransportOf maps the projector's transport word onto the registry
// vocabulary ("" = Streamable HTTP).
func remoteTransportOf(t string) integration.MCPRemoteTransport {
	if t == "sse" {
		return integration.MCPRemoteSSE
	}
	return integration.MCPRemoteStreamableHTTP
}

// validateRemoteEntry checks the entry against the client's grounded shape
// and the no-secret rule.
func validateRemoteEntry(tool string, entry project.RemoteEntry, remote *integration.MCPRemoteTarget) error {
	u, err := url.Parse(entry.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("mcp.relay-writer %s: URL %q must be an absolute http(s) URL", tool, entry.URL)
	}
	transport := remoteTransportOf(entry.Transport)
	if !remote.Supports(transport) {
		return fmt.Errorf("mcp.relay-writer %s: transport %q is not grounded for this client (supports %v)", tool, transport, remote.Transports)
	}
	if remote.TransportKey != "" {
		if _, ok := remote.Spelling[transport]; !ok {
			return fmt.Errorf("mcp.relay-writer %s: registry row carries no on-disk spelling for transport %q", tool, transport)
		}
	}
	if len(entry.Headers) > 0 && !remote.Headers {
		return fmt.Errorf("mcp.relay-writer %s: this client's config grounds no headers map", tool)
	}
	for name := range entry.Headers {
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "":
			return fmt.Errorf("mcp.relay-writer %s: empty header name", tool)
		case "authorization", "proxy-authorization":
			return fmt.Errorf("mcp.relay-writer %s: refusing to write a %s header — the relay injects credentials, config never carries a secret", tool, name)
		}
	}
	return nil
}

// jsonRemoteEntry builds the shared {"mcpServers":{…}} remote entry from the
// row's spelling table: url, the transport under TransportKey (omitted for a
// client that infers it), headers when set, and the client's static flags.
func jsonRemoteEntry(entry project.RemoteEntry, remote *integration.MCPRemoteTarget) map[string]any {
	out := map[string]any{"url": entry.URL}
	if remote.TransportKey != "" {
		out[remote.TransportKey] = remote.Spelling[remoteTransportOf(entry.Transport)]
	}
	if len(entry.Headers) > 0 {
		out["headers"] = copyHeaders(entry.Headers)
	}
	for k, v := range remote.Flags {
		out[k] = v
	}
	return out
}

// codexRemoteEntry builds Codex's [mcp_servers.<name>] remote table: `url`
// designates a Streamable HTTP server (no transport key exists) and static
// headers ride in `http_headers`. bearer_token_env_var / env_http_headers
// are never emitted — no secret, not even by reference, lands here.
func codexRemoteEntry(entry project.RemoteEntry) map[string]any {
	out := map[string]any{"url": entry.URL}
	if len(entry.Headers) > 0 {
		out["http_headers"] = copyHeaders(entry.Headers)
	}
	return out
}

// opencodeRemoteEntry builds OpenCode's typed remote server: the "mcp"
// object's `{"type":"remote","url":…,"enabled":true,"headers":{…}}` shape
// (the sibling of the {"type":"local"} entry registerOpenCodeJSON writes).
func opencodeRemoteEntry(entry project.RemoteEntry, remote *integration.MCPRemoteTarget) map[string]any {
	out := map[string]any{"type": "remote", "url": entry.URL}
	if len(entry.Headers) > 0 {
		out["headers"] = copyHeaders(entry.Headers)
	}
	for k, v := range remote.Flags {
		out[k] = v
	}
	return out
}

func copyHeaders(h map[string]string) map[string]string {
	out := make(map[string]string, len(h))
	for k, v := range h {
		out[k] = v
	}
	return out
}

// jsonEquivalent reports whether two JSON documents decode to the same
// value (key order / whitespace insensitive).
func jsonEquivalent(a, b []byte) bool {
	var va, vb any
	if json.Unmarshal(a, &va) != nil || json.Unmarshal(b, &vb) != nil {
		return false
	}
	return reflect.DeepEqual(va, vb)
}

// valuesEquivalent compares two generic values through a JSON round-trip so
// a TOML-decoded map[string]any (headers as map[string]any) equals the
// desired map[string]string-bearing entry.
func valuesEquivalent(a, b any) bool {
	ja, errA := json.Marshal(a)
	jb, errB := json.Marshal(b)
	return errA == nil && errB == nil && jsonEquivalent(ja, jb)
}

// writeFileSync writes data to path atomically and durably: temp file in
// the same directory, fsync, rename over the target, then fsync the
// directory (skipped on Windows, where a directory handle cannot be
// synced). dirMode is used only when the parent has to be created.
func writeFileSync(path string, data []byte, mode, dirMode os.FileMode) error {
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
