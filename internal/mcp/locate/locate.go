// Package locate is the single owner of "where does each AI client
// keep its user-level MCP server configuration" (guard spec §9.1).
//
// Two consumers share this table so the knowledge is never re-derived:
//
//   - internal/mcp's Registrar (observer init) writes the observer MCP
//     entry into these files;
//   - internal/guard/mcpsec (G10) reads the same files to inventory
//     and pin every configured MCP server.
//
// The package is deliberately a leaf: mcpsec sits under internal/guard,
// which internal/store imports, so it must not pull the full internal/mcp
// dependency tree (an import cycle through store would result). Its
// non-stdlib imports are internal/agentconfig, the owner of a file's
// relocation rules (surface-gap Wave 0.4), and internal/platform/crossmount
// for the pinned-home environment rule (HomeEnvAt); neither imports store
// or guard. Path or format knowledge for a new client is added HERE, nowhere
// else: a row names the client's agentconfig FileRow artifacts (its MCP
// file and its install signal), and every path is expanded through
// agentconfig.ResolveArtifact, so a relocation rule on a row moves it here
// with no edit (surface-gap Wave 4).
//
// Scope: USER-LEVEL configs only. Project-scoped MCP registries
// (claude-code's <root>/.mcp.json, cursor's <root>/.cursor/mcp.json)
// are watched by the R-304 policy rule but are not inventoried —
// enumerating every project root is the watcher's domain, not a
// static locator's (documented approximation, revisit if §9 grows a
// per-project inventory).
package locate

import (
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/agentconfig"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/platform/vscodehost"
)

// Format identifies the on-disk MCP config encoding.
type Format string

// Format values.
const (
	// FormatMCPServersJSON is the shared {"mcpServers": {...}} JSON
	// shape used by Claude Code (~/.claude.json) and Cursor
	// (~/.cursor/mcp.json).
	FormatMCPServersJSON Format = "mcpservers_json"
	// FormatCodexTOML is Codex's [mcp_servers] table inside
	// ~/.codex/config.toml.
	FormatCodexTOML Format = "codex_toml"
	// FormatOpenCodeJSON is OpenCode's own MCP shape: a "mcp" object in
	// ~/.config/opencode/opencode.json whose entries are typed local-
	// command servers ({"type":"local","command":[…],"enabled":true}),
	// NOT the {"mcpServers":{…}} {command,args} shape Claude Code/Cursor
	// use. It needs its own writer (registerOpenCodeJSON).
	FormatOpenCodeJSON Format = "opencode_json"
)

// Location is one client's user-level MCP config file.
type Location struct {
	// Client is the canonical client name ("claude-code", "cursor",
	// "codex") — the same vocabulary hook registration and the
	// adapters use.
	Client string
	// Path is the absolute config file path under home.
	Path string
	// Format selects the parser for the file.
	Format Format
	// InstallDir is the directory whose presence shows the client is
	// installed under home (its config home, or for Cline the shared data
	// dir every current client creates at startup). Resolved, like Path,
	// from an agentconfig artifact with its relocation rules.
	InstallDir string
	// LegacyPath is an MCP file of the same Format that an older client
	// build read and Observer once wrote, "" when the client has none. A
	// current client never reads it again, so it is never written; an
	// uninstall still removes Observer's entry there, and its directory is
	// an install signal of a client that has not run a current build yet.
	LegacyPath string
	// Unresolved names the relocation variable whose relative value hides
	// the MCP file: the client reads it against its own working directory,
	// so Observer cannot name the file. Path is "" then, and a writer
	// returns Refusal instead of writing anywhere (FU-31, R-188 F6). "" when
	// Path names the file.
	Unresolved string
}

// Refusal is the error a writer returns for loc instead of writing: nil
// when Path names the file, otherwise an error naming the relocation
// variable (a variable name, never its value).
func (l Location) Refusal() error {
	if l.Unresolved == "" {
		return nil
	}
	return errors.New(l.Reason())
}

// Reason is why Path is empty, for a reader to report instead of skipping
// the client silently (FU-130): "" when Path names the file, otherwise a
// sentence naming the relocation variable (never its value).
func (l Location) Reason() string {
	if l.Unresolved == "" {
		return ""
	}
	return fmt.Sprintf("%s MCP config: %s is set to a relative path, which the client reads against its own working directory; Observer cannot tell which file that names, so nothing was written (set an absolute path)", l.Client, l.Unresolved)
}

// locRow is one row of the locator table. Every path comes from an
// agentconfig FileRow artifact, expanded through agentconfig.ResolveArtifact
// with the caller's environment, so a relocation rule added to a row reaches
// the MCP registrar and the guard inventory with no edit here (surface-gap
// Wave 4).
type locRow struct {
	client string
	// artifact is the FileRow of the MCP config file.
	artifact string
	format   Format
	// install is the FileRow whose directory is the install signal.
	install string
	// fallback is the vendor default under home, used only when artifact
	// has no file on this OS (unreachable while the row exists; TestLocations
	// pins every row). Never used for a relative relocation variable.
	fallback []string
	// legacy builds LegacyPath for a home whose VS Code (or other host)
	// layout is that of goos; nil = the client has no legacy file.
	legacy func(home, goos string) string
}

// locRows is the locator table, in Locations order.
var locRows = []locRow{
	// Claude Code keeps user-scope MCP servers in ~/.claude.json, which
	// CLAUDE_CONFIG_DIR moves to $CLAUDE_CONFIG_DIR/.claude.json (CC-8,
	// grounded by MAC-4; the artifact's relocation rule carries it); the
	// install signal is the ~/.claude directory, which the variable moves
	// too.
	{client: "claude-code", artifact: "claude-code/global-config", format: FormatMCPServersJSON, install: "claude-code/user-settings", fallback: []string{".claude.json"}},
	{client: "cursor", artifact: "cursor/user-mcp", format: FormatMCPServersJSON, install: "cursor/user-mcp", fallback: []string{".cursor", "mcp.json"}},
	{client: "codex", artifact: "codex/user-config", format: FormatCodexTOML, install: "codex/user-config", fallback: []string{".codex", "config.toml"}},
	// OpenCode reads a global config at ~/.config/opencode/opencode.json
	// (and per-project opencode.json files). We register globally so MCP is
	// available in every project, mirroring claude-code/cursor.
	{client: "opencode", artifact: "opencode/user-config", format: FormatOpenCodeJSON, install: "opencode/user-config", fallback: []string{".config", "opencode", "opencode.json"}},
	// Cline (VS Code extension `saoudrizwan.claude-dev`, Cline CLI and Cline
	// for JetBrains) reads ONE shared MCP file,
	// ~/.cline/data/settings/cline_mcp_settings.json, relocated by
	// CLINE_MCP_SETTINGS_PATH > CLINE_DATA_DIR > CLINE_DIR (S-6). The VS Code
	// globalStorage copy older Observer builds wrote is migrated once by the
	// extension and never read again (the legacy file). The install signal
	// is the data dir (globalState.json's directory). This is the NATIVE
	// (same-OS) row; the cross-OS Windows path (a WSL daemon writing a
	// Windows Cline) is ForWindowsHome, used by the registrar's
	// cline-windows virtual target.
	{client: "cline", artifact: clineMCPArtifact, format: FormatMCPServersJSON, install: "cline/global-state", fallback: []string{".cline", "data", "settings", "cline_mcp_settings.json"}, legacy: ClineLegacySettingsPath},
	// Factory AI's droid CLI reuses claude-code/cursor's {"mcpServers":{}}
	// shape in its OWN file, grounded live 2026-07-29
	// (docs/plans/factory-droid-adapter-plan-2026-07-29.md). Note: the droid
	// adapter deliberately never reads ~/.factory's root-level
	// settings.json/auth files (plaintext BYOK keys live there); this row
	// only ever touches mcp.json, a sibling file.
	{client: "droid", artifact: "droid/user-mcp", format: FormatMCPServersJSON, install: "droid/user-mcp", fallback: []string{".factory", "mcp.json"}},
	// commandcode.ai's npm CLI reuses the same {"mcpServers":{}} shape in
	// its own file, grounded 2026-07-29 from the npm package's cli.mjs
	// getUserMcpConfigPath + bundled reference/mcp.md. The commandcode
	// adapter never reads ~/.commandcode/auth.json (API keys); this row only
	// ever touches mcp.json, a sibling file.
	{client: "command-code", artifact: "command-code/user-mcp", format: FormatMCPServersJSON, install: "command-code/user-mcp", fallback: []string{".commandcode", "mcp.json"}},
}

// Locations returns every supported client's MCP config location for
// the given home directory, in stable order. The relocation variables are
// read under the pinned-home rule (crossmount.HomeEnvAt, R-188 F1; FU-129):
// the process environment applies only when home is this process's own,
// unisolated home, so a caller naming another home (a test, a sandboxed
// dashboard, a foreign-OS home) resolves every file under that home.
// Existence is NOT checked: callers decide whether a missing file matters.
func Locations(home string) []Location {
	return LocationsEnv(home, crossmount.HomeEnvAt(home, nil))
}

// LocationsEnv is Locations with the environment read through getenv (nil
// reads none, so every row resolves under home).
func LocationsEnv(home string, getenv func(string) string) []Location {
	out := make([]Location, 0, len(locRows))
	for _, row := range locRows {
		out = append(out, row.location(home, runtime.GOOS, getenv))
	}
	return out
}

// ForWSLHome returns client's location under a Linux user home inside a WSL
// distro seen from a Windows daemon (\\wsl.localhost\<distro>\home\<user>):
// the files are resolved with the Linux layout, the distro's own environment
// is invisible (so each file is the vendor default), and every path is
// joined in the daemon's own separators. The mirror of ForWindowsHome for the
// Windows to WSL twins (surface-gap DEC-10). false when the client has no
// location.
func ForWSLHome(client, home string) (Location, bool) {
	for _, row := range locRows {
		if row.client == client {
			loc := row.locationFor(home, "linux", "linux", nil)
			if row.legacy != nil {
				// A Cline inside a distro runs in VS Code Server (a
				// Remote-WSL window), whose user data is the server
				// layout, not the desktop one.
				loc.LegacyPath = clineLegacyUnder(vscodeUserDir(home, "linux", ".vscode-server"))
			}
			return loc, true
		}
	}
	return Location{}, false
}

// ForWindowsHome returns client's location under a Windows user home seen
// from a daemon on another OS (a WSL daemon reaching /mnt/c/Users/<u>):
// every path is joined in the daemon's own separators, the Windows side's
// environment is invisible (so each file is the vendor default), and the
// legacy file follows the Windows VS Code layout. false when the client
// has no location.
func ForWindowsHome(client, home string) (Location, bool) {
	for _, row := range locRows {
		if row.client == client {
			return row.location(home, "windows", nil), true
		}
	}
	return Location{}, false
}

// location resolves one row under home. layoutGOOS is the OS whose host
// layout the legacy file follows; every artifact resolves for the running
// OS.
func (row locRow) location(home, layoutGOOS string, getenv func(string) string) Location {
	return row.locationFor(home, runtime.GOOS, layoutGOOS, getenv)
}

// locationFor is location with the OS whose artifact paths the row resolves
// named (pathGOOS): the running OS for a native or Windows home, linux for
// a WSL home reached from Windows.
func (row locRow) locationFor(home, pathGOOS, layoutGOOS string, getenv func(string) string) Location {
	path, unresolved := artifactPathFor(row.artifact, home, pathGOOS, getenv, row.fallback)
	loc := Location{
		Client:     row.client,
		Path:       path,
		Format:     row.format,
		Unresolved: unresolved,
	}
	if p, _ := artifactPathFor(row.install, home, pathGOOS, getenv, nil); p != "" {
		loc.InstallDir = filepath.Dir(p)
	}
	if row.legacy != nil {
		loc.LegacyPath = row.legacy(home, layoutGOOS)
	}
	return loc
}

// artifactPathFor resolves one agentconfig FileRow for goos under
// home with getenv's relocation variables. A relocation variable holding a
// relative value names no file: path is "" and unresolved is the variable,
// never the vendor default under home, which the client does not read
// (R-188 F6). Any other unresolved row yields the fallback under home (""
// for a nil fallback).
// The path is joined in the running OS's separators.
func artifactPathFor(id, home, goos string, getenv func(string) string, fallback []string) (path, unresolved string) {
	got, err := agentconfig.ResolveArtifact(id, agentconfig.PathEnv{GOOS: goos, Home: home, Getenv: getenv})
	if err == nil && got.Status == agentconfig.PathRelocationUnresolved {
		return "", got.RelocatedBy
	}
	if err != nil || got.Status != agentconfig.PathResolved || got.Path == "" {
		if fallback == nil {
			return "", ""
		}
		return filepath.Join(append([]string{home}, fallback...)...), ""
	}
	return filepath.Clean(filepath.FromSlash(got.Path)), ""
}

// clineMCPArtifact is the agentconfig FileRow that owns the shared Cline MCP
// file's path and its relocation rules.
const clineMCPArtifact = "cline/mcp-settings"

// ClineMCPSettingsPath is the shared Cline MCP file for a home directory on
// goos, with the vendor's relocation variables read through getenv (nil
// reads none: the cross-OS case, whose environment the daemon cannot see).
// The path is joined natively for goos, so a WSL daemon resolving a Windows
// home under /mnt/c passes its own GOOS. A relocation variable holding a
// relative value names no file: path is "" and unresolved names the
// variable, as Location.Unresolved does for the table rows, never the
// vendor default the client does not read (FU-130, R-188 F6). A value is
// judged absolute by goos's path syntax (FU-143).
func ClineMCPSettingsPath(home, goos string, getenv func(string) string) (path, unresolved string) {
	got, err := agentconfig.ResolveArtifact(clineMCPArtifact, agentconfig.PathEnv{GOOS: goos, Home: home, Getenv: getenv})
	if err == nil && got.Status == agentconfig.PathRelocationUnresolved {
		return "", got.RelocatedBy
	}
	if err != nil || got.Path == "" {
		// Unreachable while the catalogue row exists (pinned by
		// TestLocations); the vendor default is the honest fallback.
		return filepath.Join(home, ".cline", "data", "settings", "cline_mcp_settings.json"), ""
	}
	return got.Path, ""
}

// ClineDataDir is the Cline data directory every current Cline client
// creates at startup (~/.cline/data; CLINE_DATA_DIR > CLINE_DIR/data). Its
// presence is how the registrar knows Cline is installed. dir is "" and
// unresolved names the variable when a relocation variable holds a
// relative value (FU-130).
func ClineDataDir(home, goos string, getenv func(string) string) (dir, unresolved string) {
	p, unresolved := ClineMCPSettingsPath(home, goos, envWithout(getenv, "CLINE_MCP_SETTINGS_PATH"))
	if unresolved != "" {
		return "", unresolved
	}
	return parentFor(goos, parentFor(goos, p)), ""
}

// parentFor is filepath.Dir for a path written in goos's separators (a
// Windows path resolved on a Linux daemon included). The parent of "" is "".
func parentFor(goos, p string) string {
	if p == "" {
		return ""
	}
	if goos == runtime.GOOS {
		return filepath.Dir(p)
	}
	seps := "/"
	if goos == "windows" {
		seps = `/\`
	}
	if i := strings.LastIndexAny(p, seps); i > 0 {
		return p[:i]
	}
	return p
}

// envWithout is getenv with one variable hidden.
func envWithout(getenv func(string) string, name string) func(string) string {
	return func(k string) string {
		if k == name || getenv == nil {
			return ""
		}
		return getenv(k)
	}
}

// clineSettingsRelparts is the globalStorage tail of Cline's legacy MCP
// settings file under a VS Code-family User directory, shared by every
// resolver so the shape has ONE owner; the User directory itself comes from
// vscodehost (the owner of the per-OS and remote layouts, IDE-1).
var clineSettingsRelparts = []string{"globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json"}

// vscodeUserDir is product dir's User directory under home for goos, from
// vscodehost's table ("" when the product is unknown).
func vscodeUserDir(home, goos, dir string) string {
	for _, p := range vscodehost.Products() {
		if p.Dir == dir {
			// Origin is never "native" here: the path follows home, not
			// this process's %APPDATA%.
			return vscodehost.UserDir(crossmount.HomeRoot{Path: home, OS: goos, Origin: "locate"}, p)
		}
	}
	return ""
}

// clineLegacyUnder is the legacy Cline file under a User directory.
func clineLegacyUnder(userDir string) string {
	if userDir == "" {
		return ""
	}
	return filepath.Join(append([]string{userDir}, clineSettingsRelparts...)...)
}

// ClineLegacySettingsPath builds the LEGACY VS Code globalStorage
// cline_mcp_settings.json path for a home directory under the given OS's VS
// Code config-root convention: windows %APPDATA% (home/AppData/Roaming),
// darwin ~/Library/Application Support, linux (and anything else) XDG
// ~/.config. Current Cline builds copy this file into the shared one once and
// never read it again, so Observer no longer writes it: the registrar only
// detects an install by it and removes the observer entry an older build
// left there. goos uses runtime.GOOS values ("windows"/"darwin"/"linux").
func ClineLegacySettingsPath(home, goos string) string {
	if goos != "windows" && goos != "darwin" {
		goos = "linux"
	}
	return clineLegacyUnder(vscodeUserDir(home, goos, "Code"))
}

// ForClient returns the location for one client, false when the
// client has no known MCP config. The environment follows Locations' rule
// (crossmount.HomeEnvAt).
func ForClient(client, home string) (Location, bool) {
	return ForClientEnv(client, home, crossmount.HomeEnvAt(home, nil))
}

// ForClientEnv is ForClient with the environment read through getenv.
func ForClientEnv(client, home string, getenv func(string) string) (Location, bool) {
	for _, loc := range LocationsEnv(home, getenv) {
		if loc.Client == client {
			return loc, true
		}
	}
	return Location{}, false
}
