package shellwrap

import (
	"reflect"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

var testBridge = &WSLBridge{Distro: "Ubuntu-20.04"}

func bridgeHost() Host {
	return Host{GOOS: "windows", Home: `C:\Users\u`, Bridge: testBridge}
}

// TestCommandRulesTable pins resolveCommands, one case per rule row: the
// target's own spellings, the Windows-name-with-a-space fallback to the Unix
// stem (T-419 gap 1, `Qoder IDE.exe`), and the Unix-only tool reached through
// the WSL bridge (T-419 gap 2, Muse). Each case asserts the registry SHAPE it
// relies on first, so a registry edit fails here loudly instead of silently
// testing nothing.
func TestCommandRulesTable(t *testing.T) {
	native := Host{GOOS: "windows", Home: `C:\Users\u`}
	tests := []struct {
		name     string
		id       string
		shape    func(w integration.WrappedCommand) bool
		host     Host
		wantOK   bool
		wantCmds []string
		wantSide Side
	}{
		{
			"linux takes the unix spelling", "claude-code",
			func(w integration.WrappedCommand) bool { return len(w.Replaces.Unix) > 0 },
			Host{GOOS: "linux"},
			true,
			[]string{"claude"},
			SideHost,
		},
		{
			"windows takes the windows spellings, extension stripped", "claude-code",
			func(w integration.WrappedCommand) bool { return len(w.Replaces.Windows) > 0 },
			native, true,
			[]string{"claude"},
			SideHost,
		},
		{
			"a windows name with a space falls back to the unix stem (native)", "qoder-ide",
			func(w integration.WrappedCommand) bool {
				return len(w.Replaces.Windows) == 1 && strings.Contains(w.Replaces.Windows[0], " ") && len(w.Replaces.Unix) > 0
			}, native, true,
			[]string{"qoder"},
			SideHost,
		},
		{
			"a windows name with a space falls back to the unix stem (bridge)", "qoder-ide",
			func(w integration.WrappedCommand) bool {
				return strings.Contains(strings.Join(w.Replaces.Windows, ""), " ")
			},
			bridgeHost(), true,
			[]string{"qoder"},
			SideHost,
		},
		{
			"a unix-only tool is not wrappable on a native windows target", "muse",
			func(w integration.WrappedCommand) bool {
				return len(w.Replaces.Windows) == 0 && len(w.Replaces.Unix) > 0
			},
			native, false, nil, SideHost,
		},
		{
			"a unix-only tool runs inside WSL on the bridge target", "muse",
			func(w integration.WrappedCommand) bool {
				return len(w.Replaces.Windows) == 0 && w.Kind == integration.LaunchKindTerminal
			}, bridgeHost(), true,
			[]string{"muse"},
			SideWSL,
		},
		{
			"a windows-built tool stays a windows program on the bridge target", "codex",
			func(w integration.WrappedCommand) bool { return len(w.Replaces.Windows) > 0 },
			bridgeHost(), true,
			[]string{"codex"},
			SideHost,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w, ok := integration.WrappedCommandFor(tt.id)
			if !ok || !tt.shape(w) {
				t.Fatalf("%s: registry shape changed (%+v); update this row", tt.id, w.Replaces)
			}
			cmds, side, got := resolveCommands(w, tt.host)
			if got != tt.wantOK || !reflect.DeepEqual(cmds, tt.wantCmds) || (got && side != tt.wantSide) {
				t.Fatalf("resolveCommands = %v %q %v, want %v %q %v", cmds, side, got, tt.wantCmds, tt.wantSide, tt.wantOK)
			}
			c, cok := CandidateOn(tt.id, tt.host)
			if cok != tt.wantOK || (cok && (!reflect.DeepEqual(c.Commands, tt.wantCmds) || c.Side != tt.wantSide)) {
				t.Fatalf("CandidateOn = %+v %v", c, cok)
			}
		})
	}
}

// TestBridgeEnvForTable pins one case per bridgeEnvRules row.
func TestBridgeEnvForTable(t *testing.T) {
	tests := []struct {
		name  string
		id    string
		shape func() bool
		want  []EnvVar
	}{
		{"GUI child-env wrap carries its variables", "vscode", func() bool {
			g, ok := integration.GUILaunchFor("vscode")
			return ok && g.Spec.Wrap.Kind == integration.WrapChildEnv && len(g.Spec.Wrap.Env) == 3
		}, []EnvVar{{"ANTHROPIC_BASE_URL", ""}, {"OPENAI_BASE_URL", "/v1"}, {"GOOGLE_GEMINI_BASE_URL", ""}}},
		{"GUI row with no wrap carries nothing", "cursor-ide", func() bool {
			g, ok := integration.GUILaunchFor("cursor-ide")
			return ok && g.Spec.Wrap.Kind == integration.WrapNone
		}, nil},
		{"no proxy route", "muse", func() bool { c, ok := integration.For("muse"); return ok && c.Proxy == nil }, nil},
		{"config-file route has no variable", "codex", func() bool {
			c, ok := integration.For("codex")
			return ok && c.Proxy != nil && c.Proxy.EnvVar == ""
		}, nil},
		{"gated route", "copilot-cli", func() bool {
			c, ok := integration.For("copilot-cli")
			return ok && c.Proxy != nil && c.Proxy.Gate != nil && c.Proxy.EnvVar != ""
		}, nil},
		{"opt-in launcher-flag route", "goose", func() bool {
			c, ok := integration.For("goose")
			return ok && c.Proxy != nil && c.Proxy.LaunchFlag != "" && c.Proxy.Lane == nil && c.Proxy.Gate == nil && c.Proxy.EnvVar != ""
		}, nil},
		{"lane route", "grok", func() bool {
			c, ok := integration.For("grok")
			return ok && c.Proxy != nil && c.Proxy.Lane != nil && c.Proxy.Gate == nil && c.Proxy.EnvVar != ""
		}, nil},
		{"env-settings route", "claude-code", func() bool {
			c, ok := integration.For("claude-code")
			return ok && c.Proxy != nil && c.Proxy.Kind == integration.RouteEnvSettings
		}, []EnvVar{{"ANTHROPIC_BASE_URL", ""}}},
		{"launcher route", "opencode", func() bool {
			c, ok := integration.For("opencode")
			return ok && c.Proxy != nil && c.Proxy.Kind == integration.RouteLauncher && c.Proxy.Gate == nil
		}, []EnvVar{{"OPENAI_BASE_URL", "/v1"}}},
		{"unknown id", "no-such-tool", func() bool { return true }, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !tt.shape() {
				t.Fatalf("%s: registry shape changed; update this row", tt.id)
			}
			if got := BridgeEnvFor(tt.id); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("BridgeEnvFor(%s) = %+v, want %+v", tt.id, got, tt.want)
			}
		})
	}
}

// TestBridgeCandidateHonesty: on the bridge target a Windows program routes
// only through the variables its shim carries, and nothing is claimed proven.
func TestBridgeCandidateHonesty(t *testing.T) {
	h := bridgeHost()
	for _, tt := range []struct {
		id   string
		want Honesty
	}{
		{"claude-code", HonestyProofOwed}, // routed natively; unproven through a bridge shim
		{"copilot-cli", HonestyLaunchOnly},
		{"codex", HonestyLaunchOnly},
		{"muse", HonestyLaunchOnly},
		{"vscode", HonestyProofOwed},
	} {
		c, ok := CandidateOn(tt.id, h)
		if !ok {
			t.Fatalf("%s not wrappable on the bridge", tt.id)
		}
		if c.Honesty != tt.want {
			t.Errorf("%s: honesty %q, want %q", tt.id, c.Honesty, tt.want)
		}
		if c.Where == "" {
			t.Errorf("%s: bridge candidate without a where line", tt.id)
		}
	}
	// The native candidate is unchanged by the bridge vocabulary.
	if c, _ := CandidateFor("claude-code", "linux"); c.Honesty != HonestyRouted || c.Where != "" || c.Side != SideHost {
		t.Fatalf("native claude-code candidate changed: %+v", c)
	}
}

func bridgeSpec(id, name string, side Side) ShimSpec {
	w, _ := integration.WrappedCommandFor(id)
	s := ShimSpec{
		Name: name, ToolID: id, Kind: w.Kind, Args: w.Args,
		ObserverPath: "/home/u/.local/bin/observer", ShimDir: `C:\Users\u\.observer\shims`,
		Bridge: testBridge, Side: side, Env: BridgeEnvFor(id),
	}
	if g, ok := integration.GUILaunchFor(id); ok {
		s.ProjectDirArgv, s.HandoffSegments = g.Spec.ProjectDirArgv, g.Spec.Wrap.HandoffPathSegments
	}
	return s
}

func TestBridgeCmdShimShape(t *testing.T) {
	host, err := RenderBridgeCmdShim(bridgeSpec("claude-code", "claude", SideHost))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"@echo off\r\n",
		`set "SBO_DISTRO=Ubuntu-20.04"`,
		`set "SBO_OBSERVER=/home/u/.local/bin/observer"`,
		`set "SBO_WSL=%SystemRoot%\System32\wsl.exe"`,
		// the distro is bare: wsl.exe does not strip quotes from -d
		"`\"\"%SBO_WSL%\" -d %SBO_DISTRO% -e \"%SBO_OBSERVER%\" shell-wrap launch-env claude-code\"`",
		`if defined WSLENV (set "WSLENV=ANTHROPIC_BASE_URL/u:%WSLENV%") else (set "WSLENV=ANTHROPIC_BASE_URL/u")`,
		`if "%%A"=="SBO_ENV" if /i "%%B"=="ANTHROPIC_BASE_URL" set "ANTHROPIC_BASE_URL=%%C"`,
		`if defined SBO_WSLENV (set "WSLENV=%SBO_WSLENV%") else (set "WSLENV=")`,
		`if defined SBO_DENY exit /b 1`,
		`"%SBO_REAL%" %*`,
		`if defined SBO_SHIM_BYPASS goto sbo_real`,
		`if "%~x1"=="" exit /b 0`,
	} {
		if !strings.Contains(host, want) {
			t.Errorf("host-side bridge shim missing %q\n%s", want, host)
		}
	}
	if strings.Contains(strings.ReplaceAll(host, "\r\n", ""), "\n") {
		t.Error("bridge shim must use CRLF line endings")
	}
	if p, ok := EmbeddedObserverPath(host); !ok || p != "/home/u/.local/bin/observer" {
		t.Fatalf("EmbeddedObserverPath = %q %v", p, ok)
	}
	if tool, cmd, _, ok := ParseMarkerLine(host); !ok || tool != "claude-code" || cmd != "claude" {
		t.Fatalf("marker %q %q %v", tool, cmd, ok)
	}

	wsl, err := RenderBridgeCmdShim(bridgeSpec("muse", "muse", SideWSL))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`"%SBO_WSL%" -d %SBO_DISTRO% -e "%SBO_OBSERVER%" muse -- %*`,
		`"%SBO_WSL%" -d %SBO_DISTRO% -e /bin/sh -c "[ -x \"$0\" ]" "%SBO_OBSERVER%"`,
		`"%SBO_WSL%" -d %SBO_DISTRO% -e /bin/sh -lc "exec \"$0\" \"$@\"" muse %*`,
		`if defined SBO_SHIM_BYPASS goto sbo_real`,
	} {
		if !strings.Contains(wsl, want) {
			t.Errorf("wsl-side bridge shim missing %q\n%s", want, wsl)
		}
	}
	if strings.Contains(wsl, "launch-env") || strings.Contains(wsl, "where ") {
		t.Errorf("a wsl-side shim never resolves a Windows program\n%s", wsl)
	}

	gui, err := RenderBridgeCmdShim(bridgeSpec("vscode", "Code", SideHost))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`if not "%SBO_REAL:\remote-cli\=%"=="%SBO_REAL%" goto sbo_real`,
		`if "%~2"=="" if exist "%~1\" goto sbo_dir`,
		"\r\n\"%SBO_REAL%\" \"%~1\"\r\n",
		`set "WSLENV=ANTHROPIC_BASE_URL/u:OPENAI_BASE_URL/u:GOOGLE_GEMINI_BASE_URL/u:%WSLENV%"`,
	} {
		if !strings.Contains(gui, want) {
			t.Errorf("gui bridge shim missing %q\n%s", want, gui)
		}
	}
	// The real program may itself be a batch file (VS Code's bin\code.cmd);
	// cmd.exe chains into it, and a chain from inside a parenthesized block
	// ends the caller's script too (found live, 2026-10-05). So the real
	// program is only ever started at the top level of the shim.
	for _, shim := range []string{host, gui} {
		depth := 0
		for _, line := range strings.Split(shim, "\r\n") {
			if depth > 0 && strings.Contains(line, `"%SBO_REAL%"`) {
				t.Errorf("the real program is started inside a block: %q\n%s", line, shim)
			}
			trimmed := strings.TrimSpace(line)
			if strings.HasSuffix(trimmed, "(") {
				depth++
			}
			if trimmed == ")" {
				depth--
			}
		}
	}
}

func TestBridgeShimValidation(t *testing.T) {
	bad := map[string]func(s *ShimSpec){
		"distro with a space":     func(s *ShimSpec) { s.Bridge = &WSLBridge{Distro: "Ubuntu 20.04"} },
		"quoted distro":           func(s *ShimSpec) { s.Bridge = &WSLBridge{Distro: `"Ubuntu"`} },
		"distro metacharacter":    func(s *ShimSpec) { s.Bridge = &WSLBridge{Distro: "a&b"} },
		"relative observer":       func(s *ShimSpec) { s.ObserverPath = "bin/observer" },
		"windows observer":        func(s *ShimSpec) { s.ObserverPath = `C:\o\observer.exe` },
		"ampersand in observer":   func(s *ShimSpec) { s.ObserverPath = "/home/a&b/observer" },
		"paren in observer":       func(s *ShimSpec) { s.ObserverPath = "/home/a(b)/observer" },
		"percent in observer":     func(s *ShimSpec) { s.ObserverPath = "/home/100%/observer" },
		"dotdot in observer":      func(s *ShimSpec) { s.ObserverPath = "/home/../observer" },
		"bad variable name":       func(s *ShimSpec) { s.Env = []EnvVar{{Name: "A B"}} },
		"unknown side":            func(s *ShimSpec) { s.Side = "elsewhere" },
		"no bridge":               func(s *ShimSpec) { s.Bridge = nil },
		"name with a space":       func(s *ShimSpec) { s.Name = "Qoder IDE" },
		"tool id metacharacter":   func(s *ShimSpec) { s.ToolID = "a&b" },
		"newline in observer":     func(s *ShimSpec) { s.ObserverPath = "/o\n/observer" },
		"trailing slash observer": func(s *ShimSpec) { s.ObserverPath = "/home/u/" },
	}
	for name, mut := range bad {
		t.Run(name, func(t *testing.T) {
			s := bridgeSpec("claude-code", "claude", SideHost)
			mut(&s)
			if out, err := RenderBridgeCmdShim(s); err == nil {
				t.Fatalf("accepted an unsafe spec:\n%s", out)
			}
		})
	}
	ok := bridgeSpec("claude-code", "claude", SideHost)
	ok.ObserverPath = "/home/my user/.local/bin/observer"
	if _, err := RenderBridgeCmdShim(ok); err != nil {
		t.Fatalf("a path with a space must be accepted: %v", err)
	}
}

// TestBuildPlanBridge: the bridge plan writes .cmd bridge shims under the
// Windows home and the PowerShell profile block, with Windows separators.
func TestBuildPlanBridge(t *testing.T) {
	h := bridgeHost()
	docs := `C:\Users\u\Documents`
	h.DocumentsDir = docs
	h.Exists = func(p string) bool {
		return p == docs+`\PowerShell\Microsoft.PowerShell_profile.ps1` || p == docs+`\PowerShell`
	}
	p, err := BuildPlan(PlanInput{
		Host: h, ShimDir: DefaultShimDir(h), ObserverPath: "/home/u/.local/bin/observer",
		Selection: Selection{Tools: []string{"claude-code", "muse"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Shims) != 2 {
		t.Fatalf("shims %+v", p.Shims)
	}
	byName := map[string]ShimFile{}
	for _, s := range p.Shims {
		byName[s.FileName] = s
	}
	if s := byName["claude.cmd"]; s.Path != `C:\Users\u\.observer\shims\claude.cmd` || !strings.Contains(s.Content, "launch-env claude-code") {
		t.Fatalf("claude shim %+v", s)
	}
	if s := byName["muse.cmd"]; !strings.Contains(s.Content, `-e "%SBO_OBSERVER%" muse -- %*`) {
		t.Fatalf("muse shim %+v", s)
	}
	if len(p.RC) != 1 || p.RC[0].Shell != ShellPowerShell || p.RC[0].Path != docs+`\PowerShell\Microsoft.PowerShell_profile.ps1` {
		t.Fatalf("rc %+v", p.RC)
	}
	if !strings.Contains(p.RC[0].Body, `$sboShimDir = 'C:\Users\u\.observer\shims'`) {
		t.Fatalf("rc body %s", p.RC[0].Body)
	}
}

// TestPlanRefreshBridge: a bridge shim whose in-distro observer is gone is
// re-rendered as a bridge shim at the running observer.
func TestPlanRefreshBridge(t *testing.T) {
	old := bridgeSpec("claude-code", "claude", SideHost)
	old.ObserverPath = "/old/observer"
	content, err := RenderBridgeCmdShim(old)
	if err != nil {
		t.Fatal(err)
	}
	if tool, cmd, ver, ok := ParseMarkerLine(content); !ok || tool != "claude-code" || cmd != "claude" || ver != ShimVersion {
		t.Fatalf("marker %q %q %q %v", tool, cmd, ver, ok)
	}
	plan, err := PlanRefresh(RefreshInput{
		GOOS: "windows", Bridge: testBridge, Enabled: true, Selected: []string{"claude-code"},
		ShimDir: `C:\Users\u\.observer\shims`, ObserverPath: "/new/observer",
		Exists: func(string) bool { return false },
		Shims: []OnDiskShim{{
			FileName: "claude.cmd", Path: `C:\Users\u\.observer\shims\claude.cmd`,
			ToolID: "claude-code", Command: "claude", Version: ShimVersion, Content: content,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	rw := plan.Rewrites()
	if len(rw) != 1 || rw[0].OldObserverPath != "/old/observer" {
		t.Fatalf("plan %+v", plan)
	}
	if !strings.Contains(rw[0].Content, `set "SBO_OBSERVER=/new/observer"`) || !strings.Contains(rw[0].Content, "launch-env claude-code") {
		t.Fatalf("rewrite is not a bridge shim:\n%s", rw[0].Content)
	}
}

// TestNativeCmdShimSkipsExtensionlessHits: an npm install puts a POSIX `sh`
// stub named `claude` beside claude.cmd and `where` lists the stub first
// (grounded live 2026-10-05). The shim never takes an extensionless hit as the
// real command; the walk goes on to a runnable one.
func TestNativeCmdShimSkipsExtensionlessHits(t *testing.T) {
	out, err := RenderCmdShim(ShimSpec{
		Name: "claude", ToolID: "claude-code", Kind: integration.LaunchKindTerminal, Args: []string{"claude"},
		ObserverPath: `C:\o\observer.exe`, ShimDir: `C:\u\.observer\shims`,
	})
	if err != nil {
		t.Fatal(err)
	}
	at := strings.Index(out, ":sbo_consider")
	if at < 0 {
		t.Fatalf("no :sbo_consider label:\n%s", out)
	}
	consider := out[at:]
	skip := strings.Index(consider, `if "%~x1"=="" exit /b 0`)
	set := strings.Index(consider, `set "SBO_REAL=%~1"`)
	if skip < 0 || set < 0 || skip > set {
		t.Fatalf(":sbo_consider must refuse an extensionless hit before accepting one:\n%s", consider)
	}
}

func TestParseRegQueryValue(t *testing.T) {
	out := "\r\n" + `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders` + "\r\n" +
		`    Personal    REG_EXPAND_SZ    %USERPROFILE%\OneDrive - Acme Inc\Documents` + "\r\n\r\n"
	if got, ok := ParseRegQueryValue(out, "Personal"); !ok || got != `%USERPROFILE%\OneDrive - Acme Inc\Documents` {
		t.Fatalf("got %q %v", got, ok)
	}
	for name, in := range map[string]string{
		"absent":        `HKEY_CURRENT_USER\x` + "\r\n",
		"no data":       "    Personal    REG_SZ\r\n",
		"prefix only":   `    PersonalX    REG_SZ    C:\x` + "\r\n",
		"not a reg row": "    Personal    is not here\r\n",
	} {
		if got, ok := ParseRegQueryValue(in, "Personal"); ok {
			t.Errorf("%s: parsed %q", name, got)
		}
	}
}
