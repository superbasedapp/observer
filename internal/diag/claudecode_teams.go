package diag

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/hook"
)

// checkClaudeCodeTeams verifies the native-console (Claude Code Teams) ingest
// path end to end (native-console template §4.3). It self-gates on
// [ingest.otel].enabled — like checkOrgEnrolment — so a non-native install gets
// a single informational OK rather than spurious warnings. When enabled it
// reports four sub-checks as Details: receiver listening, managed-settings
// present + parseable, the MCP pin resolvable, and the OTLP endpoint reachable.
// Gaps are WARN (deploy/runtime conditions the operator fixes), never FAIL.
func checkClaudeCodeTeams(cfg config.Config) Check {
	const name = "claude-code-teams"
	if !cfg.Ingest.OTel.Enabled {
		return Check{Name: name, Status: StatusOK, Message: "native-console ingest disabled ([ingest.otel].enabled=false)"}
	}

	var details []string
	worst := StatusOK
	note := func(status Status, msg string) {
		details = append(details, msg)
		if status > worst {
			worst = status
		}
	}

	// (a/d) Receiver listening / OTLP endpoint reachable. The daemon owns the
	// listener, so a dial failure usually means `observer start` isn't running.
	for _, addr := range []string{cfg.Ingest.OTel.GRPCAddr, cfg.Ingest.OTel.HTTPAddr} {
		if addr == "" {
			continue
		}
		if dialable(addr) {
			note(StatusOK, fmt.Sprintf("OTLP receiver reachable at %s", addr))
		} else {
			note(StatusWarn, fmt.Sprintf("OTLP receiver NOT reachable at %s - is `observer start` running with [ingest.otel].enabled?", addr))
		}
	}

	// (b) Managed-settings present + parseable.
	if path, ok := managedSettingsPath(); ok {
		if err := parseableJSON(path); err != nil {
			note(StatusWarn, fmt.Sprintf("managed-settings at %s is not valid JSON: %v", path, err))
		} else {
			note(StatusOK, fmt.Sprintf("Claude Code managed-settings present + parseable (%s)", path))
		}
	} else {
		note(StatusWarn, fmt.Sprintf("Claude Code managed-settings not found - deploy with `observer org emit-managed-settings` (file channel: %s)", hook.ClaudeManagedPaths(runtime.GOOS).Settings))
	}

	// (c) MCP pin resolvable: the managed-mcp.json pin runs `npx -y
	// @superbased/observer …`, so npx must be on PATH for the pin to start.
	// The pin is opt-in (`--exclusive-mcp`, surface-gap D2), so npx only
	// matters where a managed-mcp.json is deployed.
	if path, ok := managedMCPPath(); !ok {
		note(StatusOK, "no managed-mcp.json - Observer's MCP server is the one `observer init` registers per node")
	} else if _, err := exec.LookPath("npx"); err == nil {
		note(StatusOK, fmt.Sprintf("npx present - the managed-mcp.json pin (%s) can bootstrap the MCP server", path))
	} else {
		note(StatusWarn, fmt.Sprintf("npx not on PATH - the managed-mcp.json (%s) `npx -y @superbased/observer` pin will not start", path))
	}

	msg := "native-console ingest enabled - all checks passed"
	if worst != StatusOK {
		msg = "native-console ingest enabled - see warnings below"
	}
	return Check{Name: name, Status: worst, Message: msg, Details: details}
}

// dialable reports whether a TCP connection to addr succeeds within a short
// timeout (a host:port like 127.0.0.1:4317).
func dialable(addr string) bool {
	conn, err := net.DialTimeout("tcp", addr, 750*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// managedSettingsPath returns this OS's Claude Code managed-settings path if
// it exists. The path is the agentconfig FileRow's, through
// hook.ClaudeManagedPaths (CC-5): /etc/claude-code on Linux and WSL, the
// system Application Support dir on macOS, C:\Program Files\ClaudeCode on
// Windows (never the legacy C:\ProgramData path, which Claude Code does not
// read).
func managedSettingsPath() (string, bool) {
	return existingPath(hook.ClaudeManagedPaths(runtime.GOOS).Settings)
}

// managedMCPPath returns this OS's Claude Code managed-mcp.json if it exists.
func managedMCPPath() (string, bool) {
	return existingPath(hook.ClaudeManagedPaths(runtime.GOOS).MCP)
}

func existingPath(p string) (string, bool) {
	if p == "" {
		return "", false
	}
	if _, err := os.Stat(p); err == nil { //nolint:gosec // G703: a metadata read of the user's own local path; no privilege boundary is crossed
		return p, true
	}
	return "", false
}

// parseableJSON confirms a file holds syntactically valid JSON.
func parseableJSON(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var v any
	return json.Unmarshal(b, &v)
}
