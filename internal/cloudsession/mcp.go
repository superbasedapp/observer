package cloudsession

import (
	"encoding/json"
	"fmt"
	"strings"
)

// mcp.go registers Observer's project-knowledge MCP server in the sandbox
// (lane CA-C2, plan section 7.3): opt-in at init (--mcp). The server is the
// ordinary `observer serve` stdio server (the plan's "observer mcp"; today
// `observer mcp` is the Agent Access relay surface and `serve` is the
// project-knowledge server `observer init` registers locally). The setup
// script runs `observer cloud-session setup --mcp` after installing, so the
// database (and, only with --codeintel, the code-intelligence index of the
// repository) is built during setup and lands in the vendor snapshot instead
// of being built on the session's first MCP call.

// MCPServerName is the server key Observer owns in a repository MCP config.
// It is not "superbased-observer" so it never shadows a developer's own local
// registration of the same server.
const MCPServerName = "superbased-observer-cloud"

// ClaudeMCPPath is Claude Code's repository MCP config.
const ClaudeMCPPath = ".mcp.json"

// SandboxMCPConfig is where `cloud-session setup --codeintel` writes the
// small config the MCP server reads (code intelligence on), relative to the
// sandbox user's home. Only the server reads it; the hooks and the flush keep
// the defaults, so code intelligence never slows a flush.
const SandboxMCPConfig = ".observer/cloud-session/mcp-config.toml"

// serveArgv returns the observer arguments of the MCP server.
func serveArgv(opts PlanOptions) []string {
	if opts.CodeIntel {
		return []string{"serve", "--config"}
	}
	return []string{"serve"}
}

// mcpCommand renders the shell the repository MCP entry runs: the server,
// only inside the vendor's cloud and only when the setup step installed
// observer; elsewhere it exits 0 at once (the client then reports the server
// as not started, which is the honest state on a developer machine).
func mcpCommand(a Agent, opts PlanOptions) string {
	bin := shellQuote(opts.installDir() + "/observer")
	argv := serveArgv(opts)
	quoted := make([]string, len(argv))
	for i, s := range argv {
		quoted[i] = shellQuote(s)
	}
	run := strings.Join(quoted, " ")
	if opts.CodeIntel {
		run += ` "$HOME/` + SandboxMCPConfig + `"`
	}
	return fmt.Sprintf("%s && [ -x %s ] && exec %s %s; exit 0 %s", markerGate(a), bin, bin, run, OwnerTag)
}

// mcpEntryOwned reports whether an mcpServers entry is Observer's: its shell
// command ends in OwnerTag.
func mcpEntryOwned(n *jnode) bool {
	if n == nil || n.kind != jObject {
		return false
	}
	args := n.get("args")
	if args == nil || args.kind != jArray {
		return false
	}
	for _, it := range args.items {
		if s, ok := it.stringValue(); ok && isOwnedCommand(s) {
			return true
		}
	}
	return false
}

// stripOwnedMCP removes Observer's entries from mcpServers and reports how
// many it removed.
func stripOwnedMCP(servers *jnode) int {
	if servers == nil || servers.kind != jObject {
		return 0
	}
	n := 0
	for _, k := range append([]string(nil), servers.keys...) {
		if mcpEntryOwned(servers.get(k)) {
			servers.del(k)
			n++
		}
	}
	return n
}

// insertClaudeMCP merges Observer's server into .mcp.json (the file may hold
// the team's own servers). A server of the team's own under MCPServerName is
// refused rather than overwritten.
func insertClaudeMCP(a Agent, opts PlanOptions, before string, existed bool) (string, string, []string, error) {
	doc, note, err := loadEditable(before, existed, opts.Reformat)
	if err != nil {
		return "", "", nil, err
	}
	servers, err := childObject(doc.root, "mcpServers")
	if err != nil {
		return "", "", nil, err
	}
	stripOwnedMCP(servers)
	if servers.get(MCPServerName) != nil {
		return "", "", nil, fmt.Errorf("an MCP server named %q that Observer did not write is already configured", MCPServerName)
	}
	args := &jnode{kind: jArray, items: []*jnode{jString("-c"), jString(mcpCommand(a, opts))}}
	servers.set(MCPServerName, jObj("command", jString("sh"), "args", args))
	return doc.render(), note, nil, nil
}

// removeClaudeMCP takes Observer's server back out; when nothing else was in
// the file, the file is deleted.
func removeClaudeMCP(_ Agent, before string) (string, bool, string, error) {
	doc, err := loadJSONDoc(before)
	if err != nil || doc.root.kind != jObject {
		return before, false, "kept: not a JSON object, remove Observer's server by hand", nil
	}
	servers := doc.root.get("mcpServers")
	if stripOwnedMCP(servers) == 0 {
		return before, false, "", nil
	}
	if len(servers.keys) == 0 {
		doc.root.del("mcpServers")
	}
	if len(doc.root.keys) == 0 {
		return "", true, "", nil
	}
	return doc.render(), false, "", nil
}

// holdsOwnedMCP reports whether .mcp.json still holds Observer's server.
func holdsOwnedMCP(content string) bool {
	root, err := parseJSON(content)
	if err != nil || root.kind != jObject {
		return false
	}
	servers := root.get("mcpServers")
	if servers == nil || servers.kind != jObject {
		return false
	}
	for _, k := range servers.keys {
		if mcpEntryOwned(servers.get(k)) {
			return true
		}
	}
	return false
}

// mcpManualStep is the step for an agent whose MCP config lives outside the
// repository (a vendor settings page): the JSON to paste. The command is the
// installed binary directly; the vendor runs it only in its own sandbox.
func mcpManualStep(a Agent, opts PlanOptions) string {
	command, args := opts.installDir()+"/observer", serveArgv(opts)
	if opts.CodeIntel {
		// The config path is under the sandbox user's home, which only a
		// shell expands.
		command, args = "sh", []string{"-c", "exec " + shellQuote(opts.installDir()+"/observer") + ` serve --config "$HOME/` + SandboxMCPConfig + `"`}
	}
	entry := map[string]any{
		"mcpServers": map[string]any{
			MCPServerName: map[string]any{"type": "local", "command": command, "args": args, "tools": []string{"*"}},
		},
	}
	raw, _ := json.MarshalIndent(entry, "", "  ")
	return "In " + a.MCPSettings + ", add Observer's MCP server (not live-checked in the cloud agent yet):\n" + string(raw)
}
