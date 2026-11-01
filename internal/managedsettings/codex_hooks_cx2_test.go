package managedsettings

import (
	"errors"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"

	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/testsupport/psparse"
)

// testCodexManagedHooks builds the managed-hook set the way
// `observer org emit-managed-settings --provider codex` does: from the
// per-node hook writer, so the test also pins that the two cannot drift.
func testCodexManagedHooks() *CodexManagedHooks {
	posix, win, err := hook.CodexManagedHookScripts("", "")
	if err != nil {
		panic(err)
	}
	return &CodexManagedHooks{
		Events:        hook.CodexHookEvents(),
		Script:        CodexHookScript{Name: hook.CodexManagedHookScriptPOSIX, Body: posix},
		WindowsScript: CodexHookScript{Name: hook.CodexManagedHookScriptWindows, Body: win},
	}
}

// TestCodexMCPNameIsTheSharedConstant pins CX-8 on the Rail B side: the
// Codex pin and its identity rule use models.ObserverMCPServerName, the
// constant internal/mcpregister registers under on a node
// (TestServerNameIsTheSharedConstant there). Before the fix Rail B wrote
// [mcp_servers.superbased-observer] beside the node's [mcp_servers.observer].
func TestCodexMCPNameIsTheSharedConstant(t *testing.T) {
	if CodexMCPServerName != models.ObserverMCPServerName {
		t.Fatalf("CodexMCPServerName = %q, want models.ObserverMCPServerName %q", CodexMCPServerName, models.ObserverMCPServerName)
	}
	arts, err := GenerateCodex(CodexOptions{IncludeMCP: true})
	if err != nil {
		t.Fatalf("GenerateCodex: %v", err)
	}
	var mc struct {
		MCPServers map[string]any `toml:"mcp_servers"`
	}
	if _, err := toml.Decode(string(arts.ManagedConfigTOML), &mc); err != nil {
		t.Fatalf("decode managed_config.toml: %v", err)
	}
	if _, ok := mc.MCPServers[models.ObserverMCPServerName]; !ok || len(mc.MCPServers) != 1 {
		t.Errorf("managed_config.toml mcp_servers = %v, want exactly %q", mc.MCPServers, models.ObserverMCPServerName)
	}
	if !strings.Contains(string(arts.RequirementsTOML), "# [mcp_servers."+models.ObserverMCPServerName+".identity]") {
		t.Errorf("requirements.toml identity rule must name %q:\n%s", models.ObserverMCPServerName, arts.RequirementsTOML)
	}
}

// TestGenerateCodex_EnforceManagedHooksNeedsObserverHooks pins the CX-2
// invariant: allow_managed_hooks_only is never emitted without Observer's
// managed hooks, because Codex would then skip Observer's per-node hooks
// and the node would run none. The old generator emitted the flag alone.
func TestGenerateCodex_EnforceManagedHooksNeedsObserverHooks(t *testing.T) {
	base := func() CodexOptions {
		return CodexOptions{OpenAIBaseURL: DefaultCodexProxyBaseURL, IncludeProxyRoute: true, EnforceManagedHooksOnly: true}
	}
	full := testCodexManagedHooks()
	for _, tc := range []struct {
		name  string
		hooks *CodexManagedHooks
	}{
		{"no managed hooks", nil},
		{"no events", &CodexManagedHooks{Script: full.Script, WindowsScript: full.WindowsScript}},
		{"no POSIX script", &CodexManagedHooks{Events: full.Events, WindowsScript: full.WindowsScript}},
		{"no Windows script", &CodexManagedHooks{Events: full.Events, Script: full.Script}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := base()
			o.ManagedHooks = tc.hooks
			_, err := GenerateCodex(o)
			if !errors.Is(err, ErrCodexManagedHooksMissing) {
				t.Fatalf("err = %v, want ErrCodexManagedHooksMissing", err)
			}
		})
	}
}

// codexRequirementsDoc is the vendor shape of the managed hooks in
// requirements.toml (codex-rs/config/src/hook_config.rs
// ManagedHooksRequirementsToml; codex-rs/protocol/src/hooks.rs).
type codexRequirementsDoc struct {
	AllowManagedHooksOnly bool           `toml:"allow_managed_hooks_only"`
	Hooks                 map[string]any `toml:"hooks"`
}

func TestGenerateCodex_ManagedHooks(t *testing.T) {
	for _, tc := range []struct {
		name                          string
		dir, winDir                   string
		wantCmdPrefix, wantWinPrefix  string
		wantScriptPath, wantWinScript string
	}{
		{
			name:          "defaults",
			wantCmdPrefix: "/etc/codex/hooks/observer-codex-hook.sh ", wantWinPrefix: `C:\ProgramData\OpenAI\Codex\hooks\observer-codex-hook.cmd `,
			wantScriptPath: "/etc/codex/hooks/observer-codex-hook.sh", wantWinScript: `C:\ProgramData\OpenAI\Codex\hooks\observer-codex-hook.cmd`,
		},
		{
			name: "admin dirs with a space and trailing separators", dir: "/opt/corp hooks/", winDir: `D:\Corp Hooks\`,
			wantCmdPrefix: `"/opt/corp hooks/observer-codex-hook.sh" `, wantWinPrefix: `& 'D:\Corp Hooks\observer-codex-hook.cmd' `,
			wantScriptPath: "/opt/corp hooks/observer-codex-hook.sh", wantWinScript: `D:\Corp Hooks\observer-codex-hook.cmd`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := testCodexManagedHooks()
			h.Dir, h.WindowsDir = tc.dir, tc.winDir
			arts, err := GenerateCodex(CodexOptions{
				OpenAIBaseURL: DefaultCodexProxyBaseURL, IncludeProxyRoute: true, IncludeMCP: true,
				EnforceManagedHooksOnly: true, ManagedHooks: h,
			})
			if err != nil {
				t.Fatalf("GenerateCodex: %v", err)
			}
			var doc codexRequirementsDoc
			if _, err := toml.Decode(string(arts.RequirementsTOML), &doc); err != nil {
				t.Fatalf("decode requirements.toml: %v\n%s", err, arts.RequirementsTOML)
			}
			if !doc.AllowManagedHooksOnly {
				t.Error("allow_managed_hooks_only not set")
			}
			for _, ev := range hook.CodexHookEvents() {
				groups, _ := doc.Hooks[ev].([]map[string]any)
				if len(groups) != 1 {
					t.Fatalf("hooks.%s = %v, want one group", ev, doc.Hooks[ev])
				}
				if groups[0]["matcher"] != "*" {
					t.Errorf("hooks.%s matcher = %v", ev, groups[0]["matcher"])
				}
				handlers, _ := groups[0]["hooks"].([]map[string]any)
				if len(handlers) != 1 || handlers[0]["type"] != "command" {
					t.Fatalf("hooks.%s.hooks = %v", ev, groups[0]["hooks"])
				}
				if got, want := handlers[0]["command"], tc.wantCmdPrefix+ev; got != want {
					t.Errorf("hooks.%s command = %q, want %q", ev, got, want)
				}
				if got, want := handlers[0]["commandWindows"], tc.wantWinPrefix+ev; got != want {
					t.Errorf("hooks.%s commandWindows = %q, want %q", ev, got, want)
				}
				// Codex on Windows runs commandWindows through PowerShell
				// (FU-162): it must parse as the one script call.
				if argv, err := psparse.Parse(handlers[0]["commandWindows"].(string)); err != nil || len(argv) != 2 || argv[0] != tc.wantWinScript || argv[1] != ev {
					t.Errorf("hooks.%s commandWindows in PowerShell = %q, %v; want [%s %s]", ev, argv, err, tc.wantWinScript, ev)
				}
				if !hook.IsObserverCodexManagedHookCommand(handlers[0]["command"].(string)) {
					t.Errorf("hooks.%s command not recognised as Observer's", ev)
				}
			}
			if len(arts.HookScripts) != 2 || arts.HookScripts[0].DeployPath != tc.wantScriptPath || arts.HookScripts[1].DeployPath != tc.wantWinScript {
				t.Fatalf("HookScripts = %+v", arts.HookScripts)
			}
			if !strings.Contains(string(arts.HookScripts[0].Body), "exec observer hook codex \"$@\"") ||
				!strings.Contains(string(arts.HookScripts[1].Body), "observer hook codex %*\r\n") {
				t.Errorf("scripts do not run `observer hook codex`:\n%s\n%s", arts.HookScripts[0].Body, arts.HookScripts[1].Body)
			}
			if !strings.Contains(arts.Readme, tc.wantScriptPath) || !strings.Contains(arts.Readme, tc.wantWinScript) {
				t.Errorf("README does not name the script deploy paths:\n%s", arts.Readme)
			}
		})
	}
}

// TestGenerateCodex_ManagedHooksOnlyWithTheFlag: without
// allow_managed_hooks_only Codex also runs the per-node hooks.json, so
// managed hooks would fire every event twice; the generator emits none.
func TestGenerateCodex_ManagedHooksOnlyWithTheFlag(t *testing.T) {
	arts, err := GenerateCodex(CodexOptions{
		OpenAIBaseURL: DefaultCodexProxyBaseURL, IncludeProxyRoute: true, ManagedHooks: testCodexManagedHooks(),
	})
	if err != nil {
		t.Fatalf("GenerateCodex: %v", err)
	}
	var doc codexRequirementsDoc
	if _, err := toml.Decode(string(arts.RequirementsTOML), &doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if doc.Hooks != nil || doc.AllowManagedHooksOnly || arts.HookScripts != nil {
		t.Errorf("managed hooks emitted without the flag: %+v %v", doc, arts.HookScripts)
	}
}

func TestGenerateCodex_ManagedHookDirsRefused(t *testing.T) {
	for _, tc := range []struct{ name, dir, winDir string }{
		{"relative POSIX dir", "etc/codex/hooks", ""},
		{"POSIX dir with $", "/opt/$HOME", ""},
		{"POSIX dir with a backslash", `/opt/a\b`, ""},
		{"Windows dir not drive-absolute", "", `\\server\share`},
		{"Windows dir with %", "", `C:\%ProgramData%\hooks`},
		{"Windows dir with a quote", "", `C:\a"b`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := testCodexManagedHooks()
			h.Dir, h.WindowsDir = tc.dir, tc.winDir
			if _, err := GenerateCodex(CodexOptions{IncludeMCP: true, EnforceManagedHooksOnly: true, ManagedHooks: h}); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

// TestCodexReadme_PrecedenceAndWindowsPaths pins S-7's README fixes: the
// requirements precedence reads highest first in the vendor's order
// (codex-rs/config/src/loader/mod.rs: system < cloud < legacy
// managed_config.toml < macOS MDM), where the old README put cloud above
// MDM and system; and the Windows requirements path is named.
func TestCodexReadme_PrecedenceAndWindowsPaths(t *testing.T) {
	arts, err := GenerateCodex(CodexOptions{IncludeMCP: true})
	if err != nil {
		t.Fatalf("GenerateCodex: %v", err)
	}
	r := arts.Readme
	i := strings.Index(r, "Requirements precedence (highest→lowest)")
	if i < 0 {
		t.Fatalf("README has no precedence line:\n%s", r)
	}
	order := []string{"macOS MDM", "legacy `/etc/codex/managed_config.toml`", "cloud-managed requirements", "system `requirements.toml`"}
	last := i
	for _, w := range order {
		j := strings.Index(r[i:], w)
		if j < 0 || i+j < last {
			t.Fatalf("precedence out of vendor order at %q:\n%s", w, r[i:])
		}
		last = i + j
	}
	for _, w := range []string{`%ProgramData%\OpenAI\Codex\requirements.toml`, `SOFTWARE\Policies\OpenAI\Codex`} {
		if !strings.Contains(r, w) {
			t.Errorf("README missing %q", w)
		}
	}
}
