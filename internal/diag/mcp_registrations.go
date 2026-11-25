package diag

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/marmutapp/superbased-observer/internal/installshape"
	"github.com/marmutapp/superbased-observer/internal/mcpregister"
	"github.com/marmutapp/superbased-observer/internal/remedy"
)

// mcp_registrations.go holds the MCP registration family of `observer
// doctor`: checkMCPRegistrations, the stable-command note and the JSON and
// TOML entry readers. Moved out of doctor.go unchanged.

// checkMCPRegistrations probes the three MCP config locations and reports
// which contain an observer entry pointing at the registration command
// (binaryPath, the launcher U1 registers for an npm / pip install). A
// mismatched entry's advice names the exact command that will fix it (U2):
// `observer init --skip-hooks --skip-proxy-route` when init would refresh it
// on its own (a stale entry whose binary is gone, or this same install by
// another path), with --force only when init would really refuse.
func checkMCPRegistrations(homeDir, binaryPath, realBinary string, getenv func(string) string, stableCommand bool) Check {
	c := checkMCPRegistrationsAt(homeDir, binaryPath, realBinary, getenv, stableCommand)
	c.Details = append(c.Details, stableMCPCommandNote(stableCommand))
	if !stableCommand {
		// The opt-in lives in Settings > Observer (its More settings).
		c.Remediations = append(c.Remediations, remedy.Of(remedy.OpenSettings, "observer"))
	}
	return c
}

// stableMCPCommandNote is the DEC-12 line for the managed-node bare MCP
// command (surface-gap FU-24): built, and switched off until its live check
// passes unless the operator opted in.
func stableMCPCommandNote(on bool) string {
	if on {
		return "stable MCP command ([observer.mcp] stable_command): ON by opt-in, so an org-managed Linux or macOS node registers the bare observer when PATH runs this install; not live-verified, waiting on " + installshape.PathNameLiveCheck
	}
	return "stable MCP command for managed nodes: built, waiting on " + installshape.PathNameLiveCheck + "; off by default (opt in with [observer.mcp] stable_command = true, in Settings > Observer)"
}

// checkMCPRegistrationsAt is checkMCPRegistrations before the DEC-12 note.
func checkMCPRegistrationsAt(homeDir, binaryPath, realBinary string, getenv func(string) string, stableCommand bool) Check {
	if binaryPath == "" {
		return Check{Name: "mcp.registrations", Status: StatusWarn, Message: "binary path unknown"}
	}
	cases := []struct {
		tool string
		path string
		read func(string) (mcpEntry, bool, error)
	}{
		{"claude-code", claudeGlobalConfigPath(homeDir, getenv), readJSONMCPEntry},
		{"cursor", filepath.Join(homeDir, ".cursor", "mcp.json"), readJSONMCPEntry},
		{"codex", filepath.Join(homeDir, ".codex", "config.toml"), readTOMLMCPEntry},
	}
	var registered, mismatched, absent []string
	needsForce := false
	for _, c := range cases {
		entry, ok, err := c.read(c.path)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			absent = append(absent, c.tool+": "+err.Error())
			continue
		}
		switch {
		case !ok:
			absent = append(absent, c.tool)
		case entry.command == binaryPath:
			registered = append(registered, c.tool)
		case stableCommand && entry.command == "observer" && mcpregister.SameInstallCommand(entry.command, realBinary):
			// The stable bare form the opt-in registers (FU-24): PATH runs
			// this install, so it is registered, not a mismatch.
			registered = append(registered, c.tool)
		default:
			mismatched = append(mismatched, c.tool)
			if !mcpregister.InitRefreshes(entry.command, entry.args, binaryPath, realBinary) {
				needsForce = true
			}
		}
	}
	if len(mismatched) > 0 {
		fix := mcpRefreshRemedy
		why := "init refreshes them without --force (the old binary is gone, or it is this same install by another path)"
		if needsForce {
			fix = mcpForceRemedy
			why = "at least one names another program that still exists, so init only replaces it with --force"
		}
		return Check{
			Name: "mcp.registrations", Status: StatusWarn,
			Message:      fmt.Sprintf("MCP entries for %s point at a different command - run %s (%s)", strings.Join(mismatched, ", "), remedy.Quote(fix), why),
			Details:      append([]string{"registered: " + strings.Join(registered, ", ")}, "absent: "+strings.Join(absent, ", ")),
			Remediations: []remedy.Remediation{fix},
		}
	}
	if len(registered) == 0 {
		return Check{
			Name: "mcp.registrations", Status: StatusWarn,
			Message:      "no MCP registrations found - run " + remedy.Quote(initAll) + " to register",
			Details:      []string{"absent: " + strings.Join(absent, ", ")},
			Remediations: []remedy.Remediation{initAll},
		}
	}
	return Check{
		Name: "mcp.registrations", Status: StatusOK,
		Message: fmt.Sprintf("registered: %s", strings.Join(registered, ", ")),
	}
}

// mcpEntry is an observer MCP entry as doctor reads it.
type mcpEntry struct {
	command string
	args    []string
}

// mcpRefreshRemedy / mcpForceRemedy are the exact commands that rewrite only
// the MCP entries (hooks and routes untouched).
var (
	mcpRefreshRemedy = remedy.Of(remedy.Init, "--skip-hooks --skip-proxy-route")
	mcpForceRemedy   = remedy.Of(remedy.Init, "--skip-hooks --skip-proxy-route --force")
)

func readJSONMCPEntry(path string) (mcpEntry, bool, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return mcpEntry{}, false, err
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(body, &top); err != nil {
		return mcpEntry{}, false, err
	}
	servers := map[string]struct {
		Command string   `json:"command"`
		Args    []string `json:"args"`
	}{}
	if raw, ok := top["mcpServers"]; ok {
		_ = json.Unmarshal(raw, &servers)
	}
	entry, ok := servers[mcpregister.ServerName]
	if !ok {
		return mcpEntry{}, false, nil
	}
	return mcpEntry{command: entry.Command, args: entry.Args}, true, nil
}

func readTOMLMCPEntry(path string) (mcpEntry, bool, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return mcpEntry{}, false, err
	}
	root := map[string]any{}
	if err := toml.Unmarshal(body, &root); err != nil {
		return mcpEntry{}, false, err
	}
	servers, _ := root["mcp_servers"].(map[string]any)
	entry, _ := servers[mcpregister.ServerName].(map[string]any)
	if entry == nil {
		return mcpEntry{}, false, nil
	}
	cmd, _ := entry["command"].(string)
	return mcpEntry{command: cmd, args: mcpregister.TOMLStringArgs(entry["args"])}, true, nil
}
