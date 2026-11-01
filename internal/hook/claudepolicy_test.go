package hook

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestClaudeManagedPaths pins CC-5: the managed paths come from the one
// agentconfig FileRow, per GOOS, independent of the host OS. The Windows row
// is C:\Program Files\ClaudeCode (Claude Code no longer reads the legacy
// C:\ProgramData path), with Windows separators on any host.
func TestClaudeManagedPaths(t *testing.T) {
	cases := []struct {
		goos string
		want ClaudeManagedPathSet
	}{
		{"windows", ClaudeManagedPathSet{
			Settings:  `C:\Program Files\ClaudeCode\managed-settings.json`,
			DropInDir: `C:\Program Files\ClaudeCode\managed-settings.d`,
			MCP:       `C:\Program Files\ClaudeCode\managed-mcp.json`,
		}},
		{"darwin", ClaudeManagedPathSet{
			Settings:  "/Library/Application Support/ClaudeCode/managed-settings.json",
			DropInDir: "/Library/Application Support/ClaudeCode/managed-settings.d",
			MCP:       "/Library/Application Support/ClaudeCode/managed-mcp.json",
		}},
		{"linux", ClaudeManagedPathSet{
			Settings:  "/etc/claude-code/managed-settings.json",
			DropInDir: "/etc/claude-code/managed-settings.d",
			MCP:       "/etc/claude-code/managed-mcp.json",
		}},
		// Another unix reads where Linux does.
		{"freebsd", ClaudeManagedPathSet{
			Settings:  "/etc/claude-code/managed-settings.json",
			DropInDir: "/etc/claude-code/managed-settings.d",
			MCP:       "/etc/claude-code/managed-mcp.json",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.goos, func(t *testing.T) {
			if got := ClaudeManagedPaths(tc.goos); got != tc.want {
				t.Fatalf("ClaudeManagedPaths(%q) =\n %+v\nwant\n %+v", tc.goos, got, tc.want)
			}
		})
	}
	if strings.Contains(ClaudeManagedPaths("windows").Settings, "ProgramData") {
		t.Fatal("the Windows managed settings path is the legacy ProgramData one Claude Code no longer reads")
	}
}

func writePolicyFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func tempClaudePaths(t *testing.T) ClaudeManagedPathSet {
	dir := t.TempDir()
	return ClaudeManagedPathSet{
		Settings:  filepath.Join(dir, "managed-settings.json"),
		DropInDir: filepath.Join(dir, "managed-settings.d"),
		MCP:       filepath.Join(dir, "managed-mcp.json"),
	}
}

// TestReadClaudeManagedFiles pins the file channel: managed-settings.json
// first, then the drop-ins in name order (hidden and non-.json files
// skipped), lists combined; managed-mcp.json read beside them.
func TestReadClaudeManagedFiles(t *testing.T) {
	p := tempClaudePaths(t)
	writePolicyFile(t, p.Settings, `{"managedSourcesBehavior":"first-wins","allowedMcpServers":[{"serverName":"a"}]}`)
	writePolicyFile(t, filepath.Join(p.DropInDir, "20-mcp.json"), `{"allowedMcpServers":[{"serverCommand":["observer","serve"]}],"managedSourcesBehavior":"merge"}`)
	writePolicyFile(t, filepath.Join(p.DropInDir, "10-helper.json"), `{"policyHelper":{"path":"/usr/local/bin/helper"}}`)
	writePolicyFile(t, filepath.Join(p.DropInDir, ".hidden.json"), `{not json`)
	writePolicyFile(t, filepath.Join(p.DropInDir, "notes.txt"), `{not json`)
	writePolicyFile(t, p.MCP, `{"mcpServers":{"superbased-observer":{"type":"stdio","command":"npx","args":["-y","@superbased/observer","serve"]}}}`)

	src, mcp := ReadClaudeManagedFiles(p)
	if !src.Found || src.Problem != "" {
		t.Fatalf("file source = %+v, want found and usable", src)
	}
	d := src.Doc
	if !d.PolicyKeys || !d.HasPolicyHelper || d.PolicyHelper != "/usr/local/bin/helper" {
		t.Errorf("policy keys / helper not merged: %+v", d)
	}
	if d.ManagedSourcesBehavior != "merge" {
		t.Errorf("a later drop-in's single value must replace the earlier one, got %q", d.ManagedSourcesBehavior)
	}
	if !d.AllowedSet || len(d.AllowedMcpServers) != 2 {
		t.Errorf("allowedMcpServers lists must combine, got %+v", d.AllowedMcpServers)
	}
	if !mcp.Found || mcp.Problem != "" || mcp.Servers != 1 || !mcp.ObserverServer {
		t.Errorf("managed-mcp.json = %+v, want one Observer server", mcp)
	}

	// A malformed drop-in makes the whole file channel unusable.
	writePolicyFile(t, filepath.Join(p.DropInDir, "30-bad.json"), `[1,2]`)
	src, _ = ReadClaudeManagedFiles(p)
	if !src.Found || !strings.Contains(src.Problem, "30-bad.json is not a JSON object") {
		t.Fatalf("malformed drop-in: %+v", src)
	}

	// Nothing there: nothing found.
	src, mcp = ReadClaudeManagedFiles(tempClaudePaths(t))
	if src.Found || mcp.Found {
		t.Fatalf("empty dir reads as deployed: %+v %+v", src, mcp)
	}
}

// TestClaudeFileChannelLocation pins FU-109 (MAC-4): the file channel is
// named by the file that exists. With only a managed-settings.d/ drop-in
// the source is that drop-in, never the absent managed-settings.json.
func TestClaudeFileChannelLocation(t *testing.T) {
	cases := []struct {
		name    string
		base    bool
		dropIns []string
		want    func(p ClaudeManagedPathSet) string
	}{
		{"base only", true, nil, func(p ClaudeManagedPathSet) string { return p.Settings }},
		{"base and a drop-in", true, []string{"50-probe.json"}, func(p ClaudeManagedPathSet) string { return p.Settings }},
		{"one drop-in, no base", false, []string{"50-probe.json"}, func(p ClaudeManagedPathSet) string { return filepath.Join(p.DropInDir, "50-probe.json") }},
		{"two drop-ins, no base", false, []string{"10-a.json", "20-b.json"}, func(p ClaudeManagedPathSet) string { return p.DropInDir + " (2 drop-ins)" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := tempClaudePaths(t)
			if tc.base {
				writePolicyFile(t, p.Settings, `{"deniedMcpServers":[{"serverName":"x"}]}`)
			}
			for _, n := range tc.dropIns {
				writePolicyFile(t, filepath.Join(p.DropInDir, n), `{"deniedMcpServers":[{"serverName":"x"}]}`)
			}
			src, _ := ReadClaudeManagedFiles(p)
			if !src.Found || src.Problem != "" {
				t.Fatalf("source = %+v, want found and usable", src)
			}
			if want := tc.want(p); src.Location != want {
				t.Errorf("Location = %q, want %q", src.Location, want)
			}
		})
	}
	// Nothing there: the base path stays the name of the (absent) channel.
	p := tempClaudePaths(t)
	if src, _ := ReadClaudeManagedFiles(p); src.Found || src.Location != p.Settings {
		t.Errorf("empty channel: %+v", src)
	}
}

func fileSource(t *testing.T, body string) ClaudePolicySource {
	t.Helper()
	d, err := ParseClaudePolicyDocument([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	return ClaudePolicySource{Kind: ClaudeSourceFile, Location: "/etc/claude-code/managed-settings.json", Found: true, Doc: d}
}

// claudeManagedHooksBody is a managed document with allowManagedHooksOnly
// and Observer's hook for each event.
func claudeManagedHooksBody(events []string) string {
	hooks := map[string]any{}
	for _, ev := range events {
		hooks[ev] = []any{map[string]any{"matcher": "*", "hooks": []any{map[string]any{"type": "command", "command": "observer hook claude-code " + ev}}}}
	}
	b, _ := json.Marshal(map[string]any{"allowManagedHooksOnly": true, "hooks": hooks})
	return string(b)
}

func mdmSource(t *testing.T, body string) ClaudePolicySource {
	t.Helper()
	d, err := ParseClaudePolicyDocument([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	return ClaudePolicySource{Kind: ClaudeSourceMDM, Location: `HKLM\SOFTWARE\Policies\ClaudeCode\Settings`, Found: true, Doc: d}
}

func hkcuSource(t *testing.T, body string) ClaudePolicySource {
	t.Helper()
	d, err := ParseClaudePolicyDocument([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	return ClaudePolicySource{Kind: ClaudeSourceHKCU, Location: `HKCU\SOFTWARE\Policies\ClaudeCode\Settings`, Found: true, Doc: d}
}

// TestClaudePolicyFindings pins every row of claudePolicyRules (S-9 and the
// CC-6 doctor half), plus the no-finding cases that keep it quiet.
func TestClaudePolicyFindings(t *testing.T) {
	observer := &ClaudeMCPEntry{Name: "observer", Command: "/usr/local/bin/observer", Args: []string{"serve"}}
	allowed := `{"serverCommand":["/usr/local/bin/observer","serve"]}`
	cases := []struct {
		name     string
		policy   func(t *testing.T) ClaudeManagedPolicy
		observer *ClaudeMCPEntry
		want     map[string]ClaudePolicySeverity // rule id -> severity
		contains string
	}{
		{
			name:   "nothing deployed",
			policy: func(*testing.T) ClaudeManagedPolicy { return ClaudeManagedPolicy{} },
			want:   map[string]ClaudePolicySeverity{},
		},
		{
			name: "source-unusable: malformed admin file",
			policy: func(*testing.T) ClaudeManagedPolicy {
				return assembleClaudePolicy(ClaudeManagedMCP{}, ClaudePolicySource{Kind: ClaudeSourceFile, Location: "/etc/claude-code/managed-settings.json", Found: true, Problem: "is not a JSON object"})
			},
			want:     map[string]ClaudePolicySeverity{"source-unusable": ClaudePolicyWarn},
			contains: "refuses to start",
		},
		{
			name: "source-unusable: malformed HKCU is only a notice",
			policy: func(*testing.T) ClaudeManagedPolicy {
				return assembleClaudePolicy(ClaudeManagedMCP{}, ClaudePolicySource{Kind: ClaudeSourceHKCU, Location: `HKCU\...`, Found: true, Problem: "is not a string value"})
			},
			want: map[string]ClaudePolicySeverity{"source-unusable": ClaudePolicyInfo},
		},
		{
			name: "hooks-disabled: an HKLM value turns every hook off (FU-36)",
			policy: func(t *testing.T) ClaudeManagedPolicy {
				return assembleClaudePolicy(ClaudeManagedMCP{}, mdmSource(t, `{"disableAllHooks":true}`))
			},
			want:     map[string]ClaudePolicySeverity{"hooks-disabled": ClaudePolicyWarn},
			contains: `HKLM\SOFTWARE\Policies\ClaudeCode\Settings sets disableAllHooks`,
		},
		{
			name: "hooks-disabled: an HKCU value applies when no administrator source exists",
			policy: func(t *testing.T) ClaudeManagedPolicy {
				return assembleClaudePolicy(ClaudeManagedMCP{}, hkcuSource(t, `{"disableAllHooks":true}`))
			},
			want: map[string]ClaudePolicySeverity{"hooks-disabled": ClaudePolicyWarn},
		},
		{
			name: "hooks-disabled: false is quiet",
			policy: func(t *testing.T) ClaudeManagedPolicy {
				return assembleClaudePolicy(ClaudeManagedMCP{}, mdmSource(t, `{"disableAllHooks":false}`))
			},
			want: map[string]ClaudePolicySeverity{},
		},
		{
			name: "managed-hooks-only: Observer's user hooks are skipped",
			policy: func(t *testing.T) ClaudeManagedPolicy {
				return assembleClaudePolicy(ClaudeManagedMCP{}, mdmSource(t, `{"allowManagedHooksOnly":true}`))
			},
			want:     map[string]ClaudePolicySeverity{"managed-hooks-only": ClaudePolicyWarn},
			contains: "skips the user-level hooks Observer registers",
		},
		{
			name: "managed-hooks-only: managed settings that carry every Observer hook are a notice",
			policy: func(t *testing.T) ClaudeManagedPolicy {
				return assembleClaudePolicy(ClaudeManagedMCP{}, mdmSource(t, claudeManagedHooksBody(claudeCodeEvents)))
			},
			want: map[string]ClaudePolicySeverity{"managed-hooks-only": ClaudePolicyInfo},
		},
		{
			name: "sources-ignored: first-wins drops the file under an HKLM policy",
			policy: func(t *testing.T) ClaudeManagedPolicy {
				return assembleClaudePolicy(ClaudeManagedMCP{}, fileSource(t, `{"env":{"ANTHROPIC_BASE_URL":"http://127.0.0.1:8820"}}`), mdmSource(t, `{"model":"opus"}`))
			},
			want:     map[string]ClaudePolicySeverity{"sources-ignored": ClaudePolicyWarn},
			contains: `applies its managed policy from HKLM\SOFTWARE\Policies\ClaudeCode\Settings and ignores /etc/claude-code/managed-settings.json`,
		},
		{
			name: "sources-ignored: a control-key-only higher source is skipped, not selected",
			policy: func(t *testing.T) ClaudeManagedPolicy {
				return assembleClaudePolicy(ClaudeManagedMCP{}, mdmSource(t, `{"wslInheritsWindowsSettings":true}`), fileSource(t, `{"model":"opus"}`))
			},
			want: map[string]ClaudePolicySeverity{},
		},
		{
			name: "sources-ignored: HKCU never applies beneath an admin document",
			policy: func(t *testing.T) ClaudeManagedPolicy {
				return assembleClaudePolicy(ClaudeManagedMCP{}, fileSource(t, `{"model":"opus"}`), hkcuSource(t, `{"model":"sonnet"}`))
			},
			want: map[string]ClaudePolicySeverity{"sources-ignored": ClaudePolicyWarn},
		},
		{
			name: "sources-merge: managedSourcesBehavior merge applies both",
			policy: func(t *testing.T) ClaudeManagedPolicy {
				return assembleClaudePolicy(ClaudeManagedMCP{}, mdmSource(t, `{"managedSourcesBehavior":"merge","model":"opus"}`), fileSource(t, `{"env":{"A":"1"}}`))
			},
			want: map[string]ClaudePolicySeverity{"sources-merge": ClaudePolicyInfo},
		},
		{
			name: "policy-helper: the selected source names a helper",
			policy: func(t *testing.T) ClaudeManagedPolicy {
				return assembleClaudePolicy(ClaudeManagedMCP{}, fileSource(t, `{"policyHelper":{"path":"/opt/acme/policy"}}`))
			},
			want:     map[string]ClaudePolicySeverity{"policy-helper": ClaudePolicyWarn},
			contains: "/opt/acme/policy",
		},
		{
			name: "policy-helper: a helper in an ignored source does not run",
			policy: func(t *testing.T) ClaudeManagedPolicy {
				return assembleClaudePolicy(ClaudeManagedMCP{}, mdmSource(t, `{"model":"opus"}`), fileSource(t, `{"policyHelper":{"path":"/opt/acme/policy"}}`))
			},
			want: map[string]ClaudePolicySeverity{"sources-ignored": ClaudePolicyWarn},
		},
		{
			name: "parent-settings-merge",
			policy: func(t *testing.T) ClaudeManagedPolicy {
				return assembleClaudePolicy(ClaudeManagedMCP{}, fileSource(t, `{"parentSettingsBehavior":"merge"}`))
			},
			want:     map[string]ClaudePolicySeverity{"parent-settings-merge": ClaudePolicyInfo},
			contains: "strictMcpConfig",
		},
		{
			name: "managed-mcp-exclusive: without Observer's server",
			policy: func(*testing.T) ClaudeManagedPolicy {
				return ClaudeManagedPolicy{ManagedMCP: ClaudeManagedMCP{Path: "/etc/claude-code/managed-mcp.json", Found: true, Servers: 1}}
			},
			observer: observer,
			want:     map[string]ClaudePolicySeverity{"managed-mcp-exclusive": ClaudePolicyWarn},
			contains: "exclusive MCP control",
		},
		{
			name: "managed-mcp-exclusive: carrying Observer's server",
			policy: func(*testing.T) ClaudeManagedPolicy {
				return ClaudeManagedPolicy{ManagedMCP: ClaudeManagedMCP{Path: "/etc/claude-code/managed-mcp.json", Found: true, Servers: 1, ObserverServer: true}}
			},
			want: map[string]ClaudePolicySeverity{"managed-mcp-exclusive": ClaudePolicyInfo},
		},
		{
			name: "managed-mcp-exclusive: unparseable",
			policy: func(*testing.T) ClaudeManagedPolicy {
				return ClaudeManagedPolicy{ManagedMCP: ClaudeManagedMCP{Path: "/etc/claude-code/managed-mcp.json", Found: true, Problem: "is not a JSON object"}}
			},
			want: map[string]ClaudePolicySeverity{"managed-mcp-exclusive": ClaudePolicyWarn},
		},
		{
			name: "mcp-allowlist: a command allowlist without Observer's entry",
			policy: func(t *testing.T) ClaudeManagedPolicy {
				return assembleClaudePolicy(ClaudeManagedMCP{}, fileSource(t, `{"allowedMcpServers":[{"serverCommand":["npx","-y","other"]}]}`))
			},
			observer: observer,
			want:     map[string]ClaudePolicySeverity{"mcp-allowlist": ClaudePolicyWarn},
			contains: `{"serverCommand":["/usr/local/bin/observer","serve"]}`,
		},
		{
			name: "mcp-allowlist: the lock makes it final",
			policy: func(t *testing.T) ClaudeManagedPolicy {
				return assembleClaudePolicy(ClaudeManagedMCP{}, fileSource(t, `{"allowManagedMcpServersOnly":true,"allowedMcpServers":[]}`))
			},
			observer: observer,
			want:     map[string]ClaudePolicySeverity{"mcp-allowlist": ClaudePolicyWarn},
			contains: "allowManagedMcpServersOnly locks",
		},
		{
			name: "mcp-allowlist: the lock in a lower source still reads the highest-ranked list",
			policy: func(t *testing.T) ClaudeManagedPolicy {
				return assembleClaudePolicy(ClaudeManagedMCP{}, mdmSource(t, `{"model":"opus","allowedMcpServers":[`+allowed+`]}`), fileSource(t, `{"allowManagedMcpServersOnly":true,"allowedMcpServers":[]}`))
			},
			observer: observer,
			want:     map[string]ClaudePolicySeverity{"sources-ignored": ClaudePolicyWarn},
		},
		{
			name: "mcp-allowlist: Observer's exact command is admitted",
			policy: func(t *testing.T) ClaudeManagedPolicy {
				return assembleClaudePolicy(ClaudeManagedMCP{}, fileSource(t, `{"allowManagedMcpServersOnly":true,"allowedMcpServers":[`+allowed+`]}`))
			},
			observer: observer,
			want:     map[string]ClaudePolicySeverity{},
		},
		{
			name: "mcp-allowlist: a serverName entry counts only without command entries",
			policy: func(t *testing.T) ClaudeManagedPolicy {
				return assembleClaudePolicy(ClaudeManagedMCP{}, fileSource(t, `{"allowedMcpServers":[{"serverName":"observer"}]}`))
			},
			observer: observer,
			want:     map[string]ClaudePolicySeverity{},
		},
		{
			name: "mcp-allowlist: a serverName entry beside a command entry does not admit it",
			policy: func(t *testing.T) ClaudeManagedPolicy {
				return assembleClaudePolicy(ClaudeManagedMCP{}, fileSource(t, `{"allowedMcpServers":[{"serverName":"observer"},{"serverCommand":["npx","x"]}]}`))
			},
			observer: observer,
			want:     map[string]ClaudePolicySeverity{"mcp-allowlist": ClaudePolicyWarn},
		},
		{
			name: "mcp-allowlist: skipped when Observer registered no MCP entry",
			policy: func(t *testing.T) ClaudeManagedPolicy {
				return assembleClaudePolicy(ClaudeManagedMCP{}, fileSource(t, `{"allowedMcpServers":[]}`))
			},
			want: map[string]ClaudePolicySeverity{},
		},
		{
			name: "mcp-denylist: blocked by name",
			policy: func(t *testing.T) ClaudeManagedPolicy {
				return assembleClaudePolicy(ClaudeManagedMCP{}, fileSource(t, `{"deniedMcpServers":[{"serverName":"observer"}]}`))
			},
			observer: observer,
			want:     map[string]ClaudePolicySeverity{"mcp-denylist": ClaudePolicyWarn},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.policy(t).Findings(tc.observer)
			ids := map[string]ClaudePolicySeverity{}
			var all []string
			for _, f := range got {
				ids[f.ID] = f.Severity
				all = append(all, f.ID+": "+f.Message)
			}
			if len(ids) != len(tc.want) {
				t.Fatalf("findings = %v, want ids %v", all, tc.want)
			}
			for id, sev := range tc.want {
				if g, ok := ids[id]; !ok || g != sev {
					t.Fatalf("finding %s: got severity %v present=%v, want %v; all: %v", id, g, ok, sev, all)
				}
			}
			if tc.contains != "" && !strings.Contains(strings.Join(all, "\n"), tc.contains) {
				t.Fatalf("findings %v do not mention %q", all, tc.contains)
			}
		})
	}
}

// TestClaudePolicyRulesCovered keeps the rule table and its test table in
// step: every rule id has at least one case above that fires it.
func TestClaudePolicyRulesCovered(t *testing.T) {
	fired := map[string]bool{
		"source-unusable": true, "sources-ignored": true, "sources-merge": true, "policy-helper": true,
		"parent-settings-merge": true, "managed-mcp-exclusive": true, "mcp-allowlist": true, "mcp-denylist": true,
		"hooks-disabled": true, "managed-hooks-only": true,
	}
	for _, r := range claudePolicyRules {
		if !fired[r.id] {
			t.Errorf("rule %q has no test case in TestClaudePolicyFindings", r.id)
		}
		delete(fired, r.id)
	}
	for id := range fired {
		t.Errorf("test names rule %q, which the table no longer has", id)
	}
}

// TestClaudeRunsObserverMCP pins what counts as Observer's server inside a
// managed-mcp.json: the per-node binary or the npx pin, in either Windows
// launch form.
func TestClaudeRunsObserverMCP(t *testing.T) {
	cases := []struct {
		command string
		args    []string
		want    bool
	}{
		{"/usr/local/bin/observer", []string{"serve"}, true},
		{`C:\Users\a\observer.exe`, []string{"serve", "--config", `C:\x.toml`}, true},
		{"npx", []string{"-y", "@superbased/observer", "serve"}, true},
		{"cmd", []string{"/c", "npx", "-y", "@superbased/observer@1.9.0", "serve"}, true},
		{"npx", []string{"-y", "@modelcontextprotocol/server-filesystem", "."}, false},
		{"/usr/local/bin/observer", []string{"hook", "claude-code"}, false},
	}
	for _, tc := range cases {
		if got := claudeRunsObserverMCP(tc.command, tc.args); got != tc.want {
			t.Errorf("claudeRunsObserverMCP(%q, %v) = %v, want %v", tc.command, tc.args, got, tc.want)
		}
	}
}

// TestReadClaudeManagedPolicyIsInertInTests pins that the host reader never
// reads the developer's real policy from a test binary.
func TestReadClaudeManagedPolicyIsInertInTests(t *testing.T) {
	if p := ReadClaudeManagedPolicy(); p.Deployed() {
		t.Fatalf("ReadClaudeManagedPolicy read a host policy in a test: %+v", p)
	}
}

// TestClaudeUserSettingsLabel pins the doctor's name for the user settings
// file to its agentconfig artifact (no literal tool-home path in the reader).
func TestClaudeUserSettingsLabel(t *testing.T) {
	if got := claudeUserSettingsLabel(); got != "~/.claude/settings.json" {
		t.Errorf("claudeUserSettingsLabel() = %q, want ~/.claude/settings.json", got)
	}
}
