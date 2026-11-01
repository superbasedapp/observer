package mcpregister

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/adapter/aiderdesk"
	"github.com/marmutapp/superbased-observer/internal/agentconfig"
	"github.com/marmutapp/superbased-observer/internal/cfgfmt"
	"github.com/marmutapp/superbased-observer/internal/credfile"
	"github.com/marmutapp/superbased-observer/internal/hostfile"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/platform/jetbrainshost"
)

// # Host MCP targets (surface-gap lane w8-writers: S-1, S-3, S-4, S-5)
//
// A host application that keeps its own MCP config, outside the locate
// table's per-client rows: Zed (context_servers in its settings.json,
// offered to Zed's own agent and forwarded over ACP), Visual Studio
// (servers in the user-global %USERPROFILE%\.mcp.json), Gemini Code Assist
// for JetBrains (mcpServers in each IDE configuration directory's
// mcp.json) and AiderDesk (mcpServers in its home's mcp-servers.json).
//
// Each target is one row of hostMCPTargets: the file (resolved through a
// catalogued agentconfig artifact or the jetbrainshost vendor root, never a
// literal home path), its syntax, the object key the servers sit under and
// the entry's shape. The write is one member, <topKey>.superbased-observer,
// through internal/hostfile (member splice that keeps comments and every
// other byte, the host's directory must exist, no link followed, a backup
// ring, an atomic write). An entry already under that key that runs another
// command is refused without --force; the same command is AlreadySet.
//
// Every target is BUILT AND SWITCHED OFF (DEC-12) behind the live check its
// integration WriterKindHostMCP row names: Register refuses before reading
// anything, and nothing lists the targets for `observer init`, `observer
// start` or the dashboard. Unregister is never gated.

// hostMCPTarget is one host's MCP file.
type hostMCPTarget struct {
	// target is the Register / Unregister id.
	target string
	// gateTool is the integration rowless gate's tool for this target.
	gateTool string
	// format is the file's syntax.
	format cfgfmt.Format
	// topKey is the object the servers sit under.
	topKey string
	// typed adds "type": "stdio" to the entry (Visual Studio's mcp.json
	// shape).
	typed bool
	// files resolves the files the target writes on this machine.
	files func(r *Registrar) ([]string, error)
	// credential says why the file may hold a credential beside the
	// servers (a sibling server's env or headers, a provider key): the
	// HOOKCRED-1 declaration for this writer, which edits one member only
	// (internal/hostfile) and never surfaces a value read from the file.
	credential string
}

// hostMCPTargets is the table of host MCP targets.
var hostMCPTargets = []hostMCPTarget{
	// Hosts (S-1, S-3, S-4, S-5).
	{target: "zed", gateTool: "zed", format: cfgfmt.FormatJSONC, topKey: "context_servers", files: artifactFiles("zed/user-settings"), credential: credSiblingEnv},
	{target: "visual-studio", gateTool: "copilot", format: cfgfmt.FormatJSON, topKey: "servers", typed: true, files: artifactFiles("copilot/visual-studio-user-mcp"), credential: credSiblingHeaders},
	{target: "gemini-code-assist-jetbrains", gateTool: "gemini-code-assist", format: cfgfmt.FormatJSON, topKey: "mcpServers", files: jetbrainsConfigFiles("mcp.json"), credential: credSiblingEnv},
	{target: "aider-desk", gateTool: "aider-desk", format: cfgfmt.FormatJSON, topKey: "mcpServers", files: aiderDeskFiles, credential: credSiblingEnv},
	// Tools whose own MCP file has no Observer writer, for the surfaces
	// that read it (S-5, DEC-13): each file and its mcpServers key are
	// catalogued, each gated on its surface's grounding run.
	{target: "codebuddy", gateTool: "codebuddy", format: cfgfmt.FormatJSON, topKey: "mcpServers", files: artifactFiles("codebuddy/user-mcp"), credential: credSiblingEnv},
	{target: "cortex-code", gateTool: "cortex-code", format: cfgfmt.FormatJSON, topKey: "mcpServers", files: artifactFiles("cortex-code/user-mcp"), credential: credSiblingEnv},
	{target: "dimcode", gateTool: "dimcode", format: cfgfmt.FormatJSON, topKey: "mcpServers", files: artifactFiles("dimcode/user-mcp"), credential: credSiblingEnv},
	{target: "gemini-cli", gateTool: "gemini-cli", format: cfgfmt.FormatJSONC, topKey: "mcpServers", files: artifactFiles("gemini-cli/user-settings"), credential: credSettingsFile},
	{target: "ibm-bob", gateTool: "ibm-bob", format: cfgfmt.FormatJSON, topKey: "mcpServers", files: artifactFiles("ibm-bob/user-mcp"), credential: credSiblingEnv},
	{target: "junie", gateTool: "junie", format: cfgfmt.FormatJSON, topKey: "mcpServers", files: artifactFiles("junie/user-mcp"), credential: credSiblingEnv},
	{target: "kimchi", gateTool: "kimchi", format: cfgfmt.FormatJSON, topKey: "mcpServers", files: artifactFiles("kimchi/harness-mcp"), credential: credSiblingEnv},
	{target: "qoder", gateTool: "qoder", format: cfgfmt.FormatJSON, topKey: "mcpServers", files: artifactFiles("qoder/user-settings"), credential: credSettingsFile},
	{target: "qwen-code", gateTool: "qwen-code", format: cfgfmt.FormatJSONC, topKey: "mcpServers", files: artifactFiles("qwen-code/user-settings"), credential: credSettingsFile},
}

// The credential-file declarations of the host MCP targets (HOOKCRED-1).
//
//nolint:gosec // G101: reasons naming why a file may hold a credential, never a credential.
const (
	credSiblingEnv     = "an MCP server file whose other servers may carry tokens in env"
	credSiblingHeaders = "an MCP server file whose other servers may carry tokens in headers"
	credSettingsFile   = "a settings file that may hold a provider key or other servers' env beside mcpServers"
)

// hostGOOS is the OS whose catalogue paths a host target resolves (the
// running OS; tests pin it).
var hostGOOS = func() string { return runtime.GOOS }

// runLiveGatedHostWriters lets this package's tests run a gated host
// writer's real logic. Production code never sets it: switching a writer on
// is deleting its integration row.
var runLiveGatedHostWriters = false

// hostMCPTargetFor returns the row of target.
func hostMCPTargetFor(target string) (hostMCPTarget, bool) {
	for _, t := range hostMCPTargets {
		if t.target == target {
			return t, true
		}
	}
	return hostMCPTarget{}, false
}

// HostMCPTargets lists the host MCP target ids, sorted.
func HostMCPTargets() []string {
	out := make([]string, 0, len(hostMCPTargets))
	for _, t := range hostMCPTargets {
		out = append(out, t.target)
	}
	sort.Strings(out)
	return out
}

// HostMCPLiveGate returns the live checks target waits on (empty when it is
// switched on).
func HostMCPLiveGate(target string) integration.LiveGates {
	t, ok := hostMCPTargetFor(target)
	if !ok {
		return nil
	}
	return integration.RowlessWriterGates(t.gateTool, integration.WriterKindHostMCP)
}

// artifactFiles resolves the catalogued file artifact on this OS with the
// registrar's home and environment (relocation rules applied). A row with
// no path on this OS resolves to no file; a relocation the tool would read
// relative is a refusal.
func artifactFiles(id string) func(r *Registrar) ([]string, error) {
	return func(r *Registrar) ([]string, error) {
		got, err := agentconfig.ResolveArtifact(id, agentconfig.PathEnv{GOOS: hostGOOS(), Home: r.opts.HomeDir, Getenv: r.opts.Getenv})
		if err != nil {
			return nil, fmt.Errorf("mcp: %w", err)
		}
		switch got.Status {
		case agentconfig.PathResolved:
			// The row's path is spelled for hostGOOS; a test that pins
			// another OS still gets a path this host can open.
			return []string{filepath.Clean(filepath.FromSlash(strings.ReplaceAll(got.Path, `\`, "/")))}, nil
		case agentconfig.PathRelocationUnresolved:
			return nil, credfile.SafeErrorf("mcp: %s is set to a relative path, which the tool reads against its own working directory; nothing was written (set an absolute path)", got.RelocatedBy)
		}
		return nil, nil
	}
}

// aiderDeskFiles is AiderDesk's global mcp-servers.json, resolved by the
// one owner of AiderDesk's layout (internal/adapter/aiderdesk: its home
// variable AIDER_DESK_HOME_DIR, a relative value refused). AiderDesk has no
// registry row yet, so no catalogue artifact can name the file.
func aiderDeskFiles(r *Registrar) ([]string, error) {
	p, err := aiderdesk.MCPServersPath(r.opts.HomeDir, r.opts.Getenv)
	if err != nil {
		return nil, credfile.SafeErrorf("mcp: %s", err.Error())
	}
	return []string{p}, nil
}

// jetbrainsConfigFiles resolves leaf in every JetBrains product
// configuration directory under the registrar's home (the jetbrainshost
// vendor root on this OS).
func jetbrainsConfigFiles(leaf string) func(r *Registrar) ([]string, error) {
	return func(r *Registrar) ([]string, error) {
		// A pinned home is not "native": jetbrainshost then reads no
		// APPDATA and stays under the pinned home on Windows.
		origin := "native"
		if r.homeOverride != "" {
			origin = "pinned"
		}
		root := jetbrainshost.VendorRoot(crossmount.HomeRoot{Path: r.opts.HomeDir, OS: runtime.GOOS, Origin: origin})
		if root == "" {
			return nil, nil
		}
		entries, err := os.ReadDir(root)
		if err != nil {
			return nil, nil //nolint:nilerr // no JetBrains vendor root: no IDE, nothing to write
		}
		var out []string
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			if _, ok := jetbrainshost.ProductForDir(e.Name()); ok {
				out = append(out, filepath.Join(root, e.Name(), leaf))
			}
		}
		return out, nil
	}
}

// hostEntry is Observer's server entry for t.
func (r *Registrar) hostEntry(t hostMCPTarget) map[string]any {
	args := make([]any, 0, 3)
	for _, a := range r.serveArgs() {
		args = append(args, a)
	}
	e := map[string]any{"command": r.opts.BinaryPath, "args": args}
	if t.typed {
		e["type"] = "stdio"
	}
	return e
}

// hostFileResult is one file's outcome inside a host target's registration.
type hostFileResult struct {
	Path       string
	Added      bool
	AlreadySet bool
	Error      error
}

// registerHost is Register for a host target: one RegistrationResult over
// every file the target resolves (ConfigPath is the first). A file whose
// host directory does not exist is passed over; any other refusal stops.
func (r *Registrar) registerHost(t hostMCPTarget) RegistrationResult {
	res := RegistrationResult{Tool: t.target, DryRun: r.opts.DryRun}
	if gates := HostMCPLiveGate(t.target); gates.Waiting() && !runLiveGatedHostWriters {
		res.Skipped = true
		res.SkipReason = gates.Text()
		res.SkipAdvice = "nothing written; this target is switched off until its live check passes on a real host (--force does not lift this)."
		return res
	}
	files, err := t.files(r)
	if err != nil {
		res.Error = err
		return res
	}
	if len(files) == 0 {
		res.Skipped = true
		res.SkipReason = "the host's MCP file has no location on this machine"
		return res
	}
	res.ConfigPath = files[0]
	wrote, set := 0, 0
	var linked []string
	for _, p := range files {
		one := r.registerHostFile(t, p)
		switch {
		case one.Error != nil && errors.Is(one.Error, hostfile.ErrNoHostDir):
			continue
		case one.Error != nil && errors.Is(one.Error, hostfile.ErrLink):
			// The hostfile error names the linked component (FU-198).
			linked = append(linked, "not written to "+p+": "+one.Error.Error())
			continue
		case one.Error != nil:
			res.Error = one.Error
			return res
		case one.Added:
			wrote++
		case one.AlreadySet:
			set++
		}
	}
	// A linked file is reported even when another file of the target was
	// written or already set (a non-fatal note then), never dropped.
	note := strings.Join(linked, "; ")
	switch {
	case wrote > 0:
		res.Added = true
		res.ProbeWarning = note
	case set > 0:
		res.AlreadySet = true
		res.ProbeWarning = note
	case len(linked) > 0:
		res.Skipped = true
		res.SkipReason = note
	default:
		res.Skipped = true
		res.SkipReason = "the host has not created its config directory on this machine (Observer never creates it)"
	}
	return res
}

// registerHostFile writes Observer's entry into one file of t.
func (r *Registrar) registerHostFile(t hostMCPTarget, path string) hostFileResult {
	out := hostFileResult{Path: path}
	member := []string{t.topKey, ServerName}
	want := r.hostEntry(t)
	have, found, err := hostfile.Value(path, t.format, member)
	if err != nil {
		out.Error = err
		return out
	}
	if found {
		hf := hostEntryFacts(have)
		action, rule := decideMCPEntry(hf, mcpEntryFacts{command: r.opts.BinaryPath, args: r.serveArgs()}, r.ownershipEnv())
		write, conflict := r.gateWrite(action, rule)
		switch {
		case action == mcpActionAlreadySet && (!t.typed || typedStdio(have)):
			out.AlreadySet = true
			return out
		case conflict:
			out.Error = mcpConflictError("mcp.register "+t.target, path)
			return out
		case !write && action != mcpActionAlreadySet:
			out.AlreadySet = true
			return out
		}
	} else if r.opts.RepairOnly {
		return out
	}
	res, err := hostfile.Apply(hostfile.Edit{Path: path, Format: t.format, Member: member, Value: want, DryRun: r.opts.DryRun, NoBackup: t.credential != ""})
	if err != nil {
		out.Error = err
		return out
	}
	out.Added = res.Changed
	out.AlreadySet = !res.Changed
	return out
}

// hostEntryFacts reads command and args from a decoded entry.
func hostEntryFacts(v any) mcpEntryFacts {
	m, ok := v.(map[string]any)
	if !ok {
		return mcpEntryFacts{}
	}
	cmd, _ := m["command"].(string)
	return mcpEntryFacts{command: cmd, args: tomlStringArgs(m["args"])}
}

// typedStdio reports whether a decoded entry carries "type": "stdio".
func typedStdio(v any) bool {
	m, ok := v.(map[string]any)
	return ok && m["type"] == "stdio"
}

// unregisterHost removes Observer's entry from every file of t; never gated.
// An entry under Observer's name is removed only when the ownership rules
// read it as Observer's (decideMCPEntry: this command, an Observer-shaped
// entry whose command is gone, or this install by another path), or under
// --force; a file reached through a symbolic link is passed over with a
// reason, never followed.
func (r *Registrar) unregisterHost(t hostMCPTarget) UnregistrationResult {
	res := UnregistrationResult{Tool: t.target, DryRun: r.opts.DryRun}
	files, err := t.files(r)
	if err != nil {
		res.Error = err
		return res
	}
	if len(files) > 0 {
		res.ConfigPath = files[0]
	}
	member := []string{t.topKey, ServerName}
	var reasons []string
	for _, p := range files {
		have, found, err := hostfile.Value(p, t.format, member)
		switch {
		case errors.Is(err, hostfile.ErrNoHostDir) || (err == nil && !found):
			continue
		case errors.Is(err, hostfile.ErrLink):
			reasons = append(reasons, "nothing removed from "+p+": "+err.Error())
			continue
		case err != nil:
			res.Error = err
			return res
		}
		if !r.hostEntryIsObservers(have) {
			reasons = append(reasons, "the "+ServerName+" entry in "+p+" runs another command, so it is not Observer's; left in place (pass --force to remove it)")
			continue
		}
		if _, err := hostfile.Apply(hostfile.Edit{Path: p, Format: t.format, Member: member, Remove: true, DryRun: r.opts.DryRun, NoBackup: t.credential != ""}); err != nil {
			res.Error = err
			return res
		}
		res.Removed = true
	}
	res.Skipped = !res.Removed
	res.SkipReason = strings.Join(reasons, "; ")
	return res
}

// hostEntryIsObservers reports whether an existing entry under Observer's
// name is Observer's own by the ownership rules (any rule but "foreign"
// decided without --force), or --force is set.
func (r *Registrar) hostEntryIsObservers(have any) bool {
	if r.opts.Force {
		return true
	}
	env := r.ownershipEnv()
	env.force = false
	_, rule := decideMCPEntry(hostEntryFacts(have), mcpEntryFacts{command: r.opts.BinaryPath, args: r.serveArgs()}, env)
	return rule != "foreign"
}
