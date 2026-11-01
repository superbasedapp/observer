package diag

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// codexManagedPaths are the system-channel locations the Codex managed-config
// artifacts deploy to on this OS (native-console Workstream B).
// requirements.toml is the enforced layer; managed_config.toml is the
// defaults layer.
var codexManagedPaths = codexManagedPathsFor(runtime.GOOS, os.Getenv)

// codexManagedPathsFor is the per-OS table (vendor source
// codex-rs/config/src/loader/mod.rs). On Linux and macOS both files live in
// /etc/codex. On Windows the system requirements file is
// %ProgramData%\OpenAI\Codex\requirements.toml (C:\ProgramData when the
// variable is unset, as Codex falls back), and managed_config.toml lives in
// the user's own Codex home, which is not a system channel (surface-gap
// review S-7: this probe used to look only at /etc/codex, so a Windows
// deployment always read "not deployed").
func codexManagedPathsFor(goos string, getenv func(string) string) []string {
	if goos == "windows" {
		pd := strings.TrimRight(getenv("ProgramData"), `\`)
		if pd == "" {
			pd = `C:\ProgramData`
		}
		return []string{pd + `\OpenAI\Codex\requirements.toml`}
	}
	return []string{
		"/etc/codex/requirements.toml",
		"/etc/codex/managed_config.toml",
	}
}

// checkCodexTeams verifies the Codex native-console managed-config deployment
// (native-console template §4.3, instance #2). Unlike the Claude Code check it
// has no [ingest.otel] gate to key off — Codex's rails are config-distributed —
// so it self-gates on the PRESENCE of a system-channel managed artifact: with
// none deployed it returns one informational OK; with one present it reports
// sub-checks as Details (artifacts parseable, MCP pin resolvable, OTLP endpoint
// reachable when the receiver is configured). Gaps are WARN, never FAIL.
func checkCodexTeams(cfg config.Config) Check {
	const name = "codex-teams"

	present := presentCodexManagedPaths()
	if len(present) == 0 {
		return Check{Name: name, Status: StatusOK, Message: "codex managed-config not deployed (no /etc/codex/*.toml - run `observer org emit-managed-settings --provider codex`)"}
	}

	var details []string
	worst := StatusOK
	note := func(status Status, msg string) {
		details = append(details, msg)
		if status > worst {
			worst = status
		}
	}

	// (a) Managed artifacts present + parseable TOML.
	for _, p := range present {
		if err := parseableTOML(p); err != nil {
			note(StatusWarn, "codex managed artifact "+p+" is not valid TOML: "+err.Error())
		} else {
			note(StatusOK, "codex managed artifact present + parseable ("+p+")")
		}
	}

	// (a2) Managed hooks: allow_managed_hooks_only switches off Observer's
	// per-node ~/.codex/hooks.json, so Observer's hooks must be managed
	// hooks there (CX-2).
	for _, p := range present {
		if filepath.Base(strings.ReplaceAll(p, `\`, "/")) != "requirements.toml" {
			continue
		}
		if b, err := os.ReadFile(p); err == nil {
			for _, f := range codexManagedHookFindings(p, b, runtime.GOOS, fileExists) {
				note(f.status, f.msg)
			}
		}
	}

	// (b) MCP pin resolvable: the [mcp_servers.observer] pin runs
	// `npx -y @superbased/observer …`, so npx must be on PATH to start it.
	pin := "[mcp_servers." + models.ObserverMCPServerName + "]"
	if _, err := exec.LookPath("npx"); err == nil {
		note(StatusOK, "npx present - the "+pin+" pin can bootstrap the MCP server")
	} else {
		note(StatusWarn, "npx not on PATH - the "+pin+" `npx -y @superbased/observer` pin will not start")
	}

	// (c) When the OTLP receiver is configured (Rail A enabled), confirm it is
	// reachable — a managed_config.toml [otel] redirect targets it.
	if cfg.Ingest.OTel.Enabled {
		for _, addr := range []string{cfg.Ingest.OTel.GRPCAddr, cfg.Ingest.OTel.HTTPAddr} {
			if addr == "" {
				continue
			}
			if dialable(addr) {
				note(StatusOK, "OTLP receiver reachable at "+addr+" (Rail A redirect target)")
			} else {
				note(StatusWarn, "OTLP receiver NOT reachable at "+addr+" - is `observer start` running with [ingest.otel].enabled?")
			}
		}
	}

	msg := "codex managed-config deployed - all checks passed"
	if worst != StatusOK {
		msg = "codex managed-config deployed - see warnings below"
	}
	return Check{Name: name, Status: worst, Message: msg, Details: details}
}

// presentCodexManagedPaths returns the subset of codexManagedPaths that exist.
func presentCodexManagedPaths() []string {
	var out []string
	for _, p := range codexManagedPaths {
		if _, err := os.Stat(p); err == nil {
			out = append(out, p)
		}
	}
	return out
}

// parseableTOML confirms a file holds syntactically valid TOML.
func parseableTOML(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var v map[string]any
	return toml.Unmarshal(b, &v)
}

// codexFinding is one managed-hook doctor line.
type codexFinding struct {
	status Status
	msg    string
}

// codexRequirementsHooks is the part of requirements.toml the managed-hook
// check reads (vendor shape: codex-rs/config/src/hook_config.rs
// ManagedHooksRequirementsToml, codex-rs/protocol/src/hooks.rs).
type codexRequirementsHooks struct {
	AllowManagedHooksOnly *bool          `toml:"allow_managed_hooks_only"`
	Hooks                 map[string]any `toml:"hooks"`
}

// codexManagedHookFindings checks one requirements.toml for Observer's
// managed hooks (CX-2). Pure over its inputs: data is the file, goos picks
// command or commandWindows and the managed directory the way Codex does,
// exists probes a script path.
//
// Coverage rows, first match wins:
//   - allow_managed_hooks_only = true and no managed Observer hook: WARN, the
//     node runs no Observer hook at all.
//   - allow_managed_hooks_only = true and some Observer hook event without a
//     managed Observer command: WARN, those events run no Observer hook.
//   - allow_managed_hooks_only = true, every event covered: OK.
//   - managed Observer hooks WITHOUT allow_managed_hooks_only: WARN, Codex
//     also runs the per-node hooks.json, so those events fire twice.
//
// Then one WARN per Observer managed command whose script is missing from
// the managed directory (Codex fails that hook).
func codexManagedHookFindings(path string, data []byte, goos string, exists func(string) bool) []codexFinding {
	var doc codexRequirementsHooks
	if _, err := toml.Decode(string(data), &doc); err != nil {
		return nil
	}
	only := doc.AllowManagedHooksOnly != nil && *doc.AllowManagedHooksOnly
	covered := map[string]bool{}
	var missingScripts []string
	for ev, raw := range doc.Hooks {
		groups, ok := raw.([]map[string]any)
		if !ok {
			continue
		}
		for _, g := range groups {
			handlers, _ := g["hooks"].([]map[string]any)
			for _, h := range handlers {
				cmd, _ := h["command"].(string)
				if goos == "windows" {
					if w, ok := h["commandWindows"].(string); ok {
						cmd = w
					} else if w, ok := h["command_windows"].(string); ok {
						cmd = w
					}
				}
				if cmd == "" || !hook.IsObserverCodexManagedHookCommand(cmd) {
					continue
				}
				covered[ev] = true
				if script := codexManagedScriptPath(cmd); script != "" && !exists(script) {
					missingScripts = append(missingScripts, script)
				}
			}
		}
	}
	var out []codexFinding
	var missing []string
	for _, ev := range hook.CodexHookEvents() {
		if !covered[ev] {
			missing = append(missing, ev)
		}
	}
	switch {
	case only && len(covered) == 0:
		out = append(out, codexFinding{StatusWarn, path + " sets allow_managed_hooks_only but declares none of Observer's hooks as managed [hooks]: " +
			"Codex skips Observer's per-node hooks, so this node runs no Observer hook. Regenerate with `observer org emit-managed-settings --provider codex --enforce-managed-hooks`"})
	case only && len(missing) > 0:
		out = append(out, codexFinding{StatusWarn, path + " sets allow_managed_hooks_only but its managed [hooks] miss Observer's " + strings.Join(missing, ", ") +
			": Codex runs no Observer hook for those events"})
	case only:
		out = append(out, codexFinding{StatusOK, path + " sets allow_managed_hooks_only and carries Observer's hooks as managed [hooks] (trusted by policy)"})
	case len(covered) > 0:
		out = append(out, codexFinding{StatusWarn, path + " declares Observer's hooks as managed [hooks] without allow_managed_hooks_only: " +
			"Codex also runs the per-node ~/.codex/hooks.json, so those events fire twice"})
	}
	sort.Strings(missingScripts)
	seen := map[string]bool{}
	for _, s := range missingScripts {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, codexFinding{StatusWarn, "Observer's Codex managed hook script " + s + " is missing: deploy it from the emit-managed-settings output, or Codex fails the hook"})
	}
	return out
}

// codexManagedScriptPath extracts the managed hook script path from an
// Observer managed command ("<path> <Event>", the path double-quoted when
// it holds a space; on Windows "& '<path>' <Event>", a PowerShell literal
// behind the call operator, FU-162); "" when the command runs observer
// directly.
func codexManagedScriptPath(cmd string) string {
	cmd = strings.TrimSpace(cmd)
	var p string
	if rest, ok := strings.CutPrefix(cmd, "& '"); ok {
		var b strings.Builder
		for i := 0; i < len(rest); i++ {
			if rest[i] != '\'' {
				b.WriteByte(rest[i])
				continue
			}
			if i+1 < len(rest) && rest[i+1] == '\'' {
				b.WriteByte('\'')
				i++
				continue
			}
			p = b.String()
			break
		}
	} else if strings.HasPrefix(cmd, `"`) {
		end := strings.Index(cmd[1:], `"`)
		if end < 0 {
			return ""
		}
		p = cmd[1 : 1+end]
	} else {
		p, _, _ = strings.Cut(cmd, " ")
	}
	if strings.HasSuffix(p, hook.CodexManagedHookScriptPOSIX) || strings.HasSuffix(p, hook.CodexManagedHookScriptWindows) {
		return p
	}
	return ""
}
