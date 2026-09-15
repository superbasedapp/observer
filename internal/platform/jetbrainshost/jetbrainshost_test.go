package jetbrainshost

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

func TestVendorRoot(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		h    crossmount.HomeRoot
		want string
	}{
		{
			name: "windows foreign home (WSL /mnt/c)",
			h:    crossmount.HomeRoot{Path: "/mnt/c/Users/auzy", OS: crossmount.OSWindows, Origin: "wsl-mnt:auzy"},
			want: filepath.Join("/mnt/c/Users/auzy", "AppData", "Roaming", "JetBrains"),
		},
		{
			name: "darwin",
			h:    crossmount.HomeRoot{Path: "/Users/auzy", OS: crossmount.OSDarwin, Origin: "native"},
			want: filepath.Join("/Users/auzy", "Library", "Application Support", "JetBrains"),
		},
		{
			name: "linux",
			h:    crossmount.HomeRoot{Path: "/home/auzy", OS: crossmount.OSLinux, Origin: "native"},
			want: filepath.Join("/home/auzy", ".config", "JetBrains"),
		},
		{
			name: "unknown os",
			h:    crossmount.HomeRoot{Path: "/x", OS: "plan9", Origin: "native"},
			want: "",
		},
	}
	for _, tc := range cases {
		if got := VendorRoot(tc.h); got != tc.want {
			t.Errorf("%s: VendorRoot = %q want %q", tc.name, got, tc.want)
		}
	}
}

func TestProductForDir(t *testing.T) {
	t.Parallel()
	cases := []struct {
		dir      string
		wantHost string
		wantOK   bool
	}{
		{"IntelliJIdea2026.2", "jetbrains-idea", true},
		{"IdeaIC2025.2", "jetbrains-idea", true},
		{"IdeaIU2025.3", "jetbrains-idea", true},
		{"PyCharmCE2025.3", "jetbrains-pycharm", true},
		{"PyCharm2026.1", "jetbrains-pycharm", true},
		{"GoLand2026.1", "jetbrains-goland", true},
		{"AndroidStudio2025.2", "jetbrains-android-studio", true},
		// Vendor-root siblings that are NOT product dirs.
		{"acp-agents", "", false},
		{"consentOptions", "", false},
		{"PermanentDeviceId", "", false},
		{"IntelliJIdea", "", false}, // no version suffix
		{"IdeaICx", "", false},      // suffix must start with a digit
		{"", "", false},
	}
	for _, tc := range cases {
		p, ok := ProductForDir(tc.dir)
		if ok != tc.wantOK || p.Host != tc.wantHost {
			t.Errorf("ProductForDir(%q) = (%q, %v) want (%q, %v)", tc.dir, p.Host, ok, tc.wantHost, tc.wantOK)
		}
	}
}

func TestHostForClientName(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in       string
		wantHost string
		wantOK   bool
	}{
		// Grounded live 2026-09-03: codex session_meta.originator and
		// copilot-cli workspace.yaml client_name both carry this.
		{"JetBrains.IntelliJ IDEA", "jetbrains-idea", true},
		{"JetBrains.PyCharm", "jetbrains-pycharm", true},
		{"JetBrains.intellij idea", "jetbrains-idea", true},
		{"JetBrains.Fleet", HostGeneric, true},
		{"JetBrains.", HostGeneric, true},
		{"Codex Desktop", "", false},
		{"codex_vscode", "", false},
		{"", "", false},
	}
	for _, tc := range cases {
		host, ok := HostForClientName(tc.in)
		if ok != tc.wantOK || host != tc.wantHost {
			t.Errorf("HostForClientName(%q) = (%q, %v) want (%q, %v)", tc.in, host, ok, tc.wantHost, tc.wantOK)
		}
	}
}

func TestTaskHistoryDirs(t *testing.T) {
	t.Parallel()
	h := crossmount.HomeRoot{Path: "/home/auzy", OS: crossmount.OSLinux, Origin: "native"}
	root := filepath.Join("/home/auzy", ".config", "JetBrains")

	listing := func(path string) ([]string, error) {
		if path != root {
			return nil, errors.New("unexpected path " + path)
		}
		return []string{"IdeaIC2025.2", "IntelliJIdea2026.2", "acp-agents", "consentOptions", "PyCharmCE2025.3"}, nil
	}
	got := TaskHistoryDirs(h, listing)
	want := []TaskHistoryDir{
		{Path: filepath.Join(root, "IdeaIC2025.2", "aia-task-history"), ProductDir: "IdeaIC2025.2"},
		{Path: filepath.Join(root, "IntelliJIdea2026.2", "aia-task-history"), ProductDir: "IntelliJIdea2026.2"},
		{Path: filepath.Join(root, "PyCharmCE2025.3", "aia-task-history"), ProductDir: "PyCharmCE2025.3"},
	}
	if len(got) != len(want) {
		t.Fatalf("TaskHistoryDirs = %+v want %d entries", got, len(want))
	}
	for i := range want {
		if got[i].Path != want[i].Path || got[i].ProductDir != want[i].ProductDir {
			t.Errorf("[%d] = %+v want %+v", i, got[i], want[i])
		}
	}
	if got[0].Product.Host != "jetbrains-idea" || got[2].Product.Host != "jetbrains-pycharm" {
		t.Errorf("product hosts = %q / %q", got[0].Product.Host, got[2].Product.Host)
	}

	// Vendor root absent → nil, never an error surfaced.
	if got := TaskHistoryDirs(h, func(string) ([]string, error) { return nil, errors.New("ENOENT") }); got != nil {
		t.Errorf("absent root: got %+v want nil", got)
	}
	if got := TaskHistoryDirs(h, nil); got != nil {
		t.Errorf("nil readDir: got %+v want nil", got)
	}
	if got := TaskHistoryDirs(crossmount.HomeRoot{Path: "/x", OS: "plan9"}, listing); got != nil {
		t.Errorf("unknown os: got %+v want nil", got)
	}
}

func TestParseAgentSession(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		in     string
		want   AgentSession
		wantOK bool
	}{
		// The four grounded tokens (ids anonymized to the fixture shape).
		{"junie", "acp.registry.junie:session-260101-120000-ab12", AgentSession{Agent: "junie", SessionID: "session-260101-120000-ab12", Tool: models.ToolJunie}, true},
		{"claude-acp", "acp.registry.claude-acp:11111111-2222-4333-8444-555555555555\n", AgentSession{Agent: "claude-acp", SessionID: "11111111-2222-4333-8444-555555555555", Tool: models.ToolClaudeCode}, true},
		{"codex-acp crlf", "acp.registry.codex-acp:01900000-0000-7000-8000-000000000001\r\n", AgentSession{Agent: "codex-acp", SessionID: "01900000-0000-7000-8000-000000000001", Tool: models.ToolCodex}, true},
		{"github-copilot", "acp.registry.github-copilot:22222222-3333-4444-8555-666666666666", AgentSession{Agent: "github-copilot", SessionID: "22222222-3333-4444-8555-666666666666", Tool: models.ToolCopilotCLI}, true},
		// mistral-vibe: the pointer carries the full uuid; the acpAgents
		// NormalizeSessionID truncates it to the 8-hex form the mistral-code
		// adapter stores as sessions.id.
		{"mistral-vibe normalized", "acp.registry.mistral-vibe:002d67cb-2300-2d9f-60f3-09445460cbcc", AgentSession{Agent: "mistral-vibe", SessionID: "002d67cb", Tool: models.ToolMistralCode}, true},
		{"antigravity-acp verbatim", "acp.registry.antigravity-acp:b684c1a6-fd7e-4b3c-9cb6-2974e0a8e6aa", AgentSession{Agent: "antigravity-acp", SessionID: "b684c1a6-fd7e-4b3c-9cb6-2974e0a8e6aa", Tool: models.ToolAntigravityCLI}, true},
		// Unknown agent: parses, Tool stays "" (honesty rule).
		{"unknown agent", "acp.registry.qwen-code:abc", AgentSession{Agent: "qwen-code", SessionID: "abc"}, true},
		{"empty", "", AgentSession{}, false},
		{"no prefix", "junie:session-1", AgentSession{}, false},
		{"no colon", "acp.registry.junie", AgentSession{}, false},
		{"empty agent", "acp.registry.:sid", AgentSession{}, false},
		{"empty sid", "acp.registry.junie:", AgentSession{}, false},
		{"path-shaped sid", "acp.registry.junie:../x", AgentSession{}, false},
	}
	for _, tc := range cases {
		got, ok := ParseAgentSession(tc.in)
		if ok != tc.wantOK || got != tc.want {
			t.Errorf("%s: ParseAgentSession = (%+v, %v) want (%+v, %v)", tc.name, got, ok, tc.want, tc.wantOK)
		}
	}
}

func TestToolForACPAgentAndTable(t *testing.T) {
	t.Parallel()
	if tool, ok := ToolForACPAgent("codex-acp"); !ok || tool != models.ToolCodex {
		t.Errorf("ToolForACPAgent(codex-acp) = %q,%v", tool, ok)
	}
	if _, ok := ToolForACPAgent("nope"); ok {
		t.Error("unknown agent must not resolve")
	}
	// The 2026-09-04 JetBrains run added cline/kilo/devin/opencode, whose
	// pointer sid equals the owner adapter's sessions.id exactly.
	for agent, want := range map[string]string{
		"cline":    models.ToolClineCLI,
		"kilo":     models.ToolKiloCodeCLI,
		"devin":    models.ToolDevin,
		"opencode": models.ToolOpenCode,
		// mistral-vibe resolves too — its owner id mismatch is bridged by
		// the acpAgents NormalizeSessionID, not by absence.
		"mistral-vibe": models.ToolMistralCode,
		// antigravity-acp: the agy backend's third tree, captured as
		// ToolAntigravityCLI; the conversation uuid is the pointer sid.
		"antigravity-acp": models.ToolAntigravityCLI,
	} {
		if tool, ok := ToolForACPAgent(agent); !ok || tool != want {
			t.Errorf("ToolForACPAgent(%s) = %q,%v want %q", agent, tool, ok, want)
		}
	}
	// poolside (2026-09-05): its own trajectory filename carries the
	// exact ACP pointer sid, so the enricher stamp lands.
	if tool, ok := ToolForACPAgent("poolside"); !ok || tool != models.ToolPoolside {
		t.Errorf("ToolForACPAgent(poolside) = %q,%v want %q", tool, ok, models.ToolPoolside)
	}
	// pi-acp (JetBrains writes no pointer) and cortex-code (no capturable
	// store at all — see the acpAgents doc comment) are deliberately
	// absent — a bare row would not stamp them.
	for _, absent := range []string{"pi-acp", "cortex-code", "kimi", "goose"} {
		if _, ok := ToolForACPAgent(absent); ok {
			t.Errorf("ToolForACPAgent(%s) must NOT resolve yet", absent)
		}
	}
	tbl := ACPAgents()
	if len(tbl) != 11 {
		t.Errorf("ACPAgents() has %d rows, want 11 grounded agents", len(tbl))
	}
	tbl["x"] = "y"
	if _, ok := ToolForACPAgent("x"); ok {
		t.Error("ACPAgents() must return a copy")
	}
	ps := Products()
	ps[0].Host = "mutated"
	if products[0].Host == "mutated" {
		t.Error("Products() must return a copy")
	}
}

func TestSurface(t *testing.T) {
	t.Parallel()
	p, _ := ProductForDir("IntelliJIdea2026.2")
	got := Surface("sid-1", p)
	want := models.SessionSurface{SessionID: "sid-1", Surface: models.SurfaceIDE, SurfaceHost: "jetbrains-idea", Hosted: true}
	if got != want {
		t.Errorf("Surface = %+v want %+v", got, want)
	}
	if got := Surface("sid-2", Product{}); got.SurfaceHost != HostGeneric || !got.Hosted {
		t.Errorf("zero product: %+v", got)
	}
	for _, p := range products {
		if !models.KnownSurface(models.SurfaceIDE) || p.Host == "" || p.DisplayName == "" || len(p.DirPrefixes) == 0 {
			t.Errorf("product row incomplete: %+v", p)
		}
	}
}
