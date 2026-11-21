package remedy

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestEveryActionRendersForBothAudiences: every action in the closed set has
// a dashboard control (an in-app link: a Settings section, or a page tab
// for the few fixes that live elsewhere), and a command unless it is one of
// the documented command-less fixes.
func TestEveryActionRendersForBothAudiences(t *testing.T) {
	commandless := map[Action]bool{CodexTrust: true, OrgClientEnable: true, RestartDaemon: true, OpenSettings: true, OpenScanners: true}
	outsideSettings := map[Action]string{OpenScanners: "/code-security?"}
	for _, a := range Actions() {
		r := Of(a, "cursor")
		c, ok := ControlFor(r)
		prefix := "/settings?"
		if p, ok := outsideSettings[a]; ok {
			prefix = p
		}
		if !ok || c.Label == "" || !strings.HasPrefix(c.Href, prefix) {
			t.Errorf("%s: control = %+v", a, c)
		}
		if got := Command(r); (got == "") != commandless[a] {
			t.Errorf("%s: command = %q", a, got)
		}
	}
	if Known("nope") || Command(Of("nope", "")) != "" {
		t.Error("an unknown action must render nothing")
	}
}

// TestCommandsMatchTheCLIVocabulary pins the spellings the findings embed.
func TestCommandsMatchTheCLIVocabulary(t *testing.T) {
	for _, tc := range []struct {
		r    Remediation
		want string
	}{
		{Of(Init, ""), "observer init"},
		{Of(InitTool, "codex"), "observer init --codex"},
		{Of(InitTool, "droid"), "observer init --all"},
		{Of(InitToolForce, "cursor"), "observer init --cursor --force"},
		{Of(InitToolRoute, "claude-code"), "observer init --claude-code --skip-hooks --skip-mcp"},
		{Of(InitMCP, ""), "observer init --skip-hooks --skip-proxy-route"},
		{Of(InitMCP, "codex"), "observer init --codex --skip-hooks --skip-proxy-route"},
		{Of(InitMCPForce, ""), "observer init --skip-hooks --skip-proxy-route --force"},
		{Of(UninstallTool, "claude-code"), "observer uninstall --claude-code"},
		{Of(InitWindowsHome, "cursor-windows"), "observer init --windows-cursor-home <path>"},
		{Of(InitWindowsRoute, "codex-windows"), "observer init"},
		{Of(OrgEnroll, ""), "observer enroll --link <url>"},
		{Of(OrgUnenroll, ""), "observer unenroll"},
		{Of(DoctorTool, ""), "observer doctor <tool>"},
		{Of(DoctorTool, "cursor"), "observer doctor cursor"},
		{Of(DoctorDBIntegrity, ""), "observer doctor db"},
		{Of(BrowserHostSetup, ""), "observer init --browser"},
		// No one-tool uninstall flag: --all would remove every tool, so
		// the dashboard Remove panel is the only form (no command).
		{Of(UninstallTool, "ibm-bob"), ""},
		{Of(OpenSettings, "proxy"), ""},
	} {
		if got := Command(tc.r); got != tc.want {
			t.Errorf("Command(%+v) = %q, want %q", tc.r, got, tc.want)
		}
	}
	if q := Quote(Of(Init, "")); q != "`observer init`" {
		t.Errorf("Quote = %q", q)
	}
	if !Mentions("re-run `observer init` now", Of(Init, "")) || Mentions("nothing", Of(OrgUnenroll, "")) {
		t.Error("Mentions")
	}
}

// TestControlLinks pins the deep links the dashboard follows (the Connected
// tools wizard, its Remove panel, the Windows-home control, lane B's checks).
func TestControlLinks(t *testing.T) {
	for _, tc := range []struct {
		r    Remediation
		want string
	}{
		{Of(InitTool, "cursor"), "/settings?open=setup&section=tools&tool=cursor"},
		{Of(UninstallTool, "claude-code"), "/settings?open=remove&section=tools&tool=claude-code"},
		{Of(InitWindowsHome, "codex-windows"), "/settings?open=windows-home&section=tools&target=codex-windows"},
		{Of(DoctorTool, "cursor"), "/settings?open=doctor&section=tools&tool=cursor"},
		{Of(DoctorDBIntegrity, ""), "/settings?section=health#integrity"},
		{Of(RestartDaemon, ""), "/settings?section=health#daemon"},
		{Of(UninstallTool, "ibm-bob"), "/settings?open=remove&section=tools&tool=ibm-bob"},
		{Of(BrowserHostSetup, ""), "/settings?section=browser"},
		{Of(OpenSettings, "org"), "/settings?section=org"},
		{Of(OpenSettings, "process"), "/settings?section=process"},
		{Of(OpenScanners, ""), "/code-security?tab=scanners"},
	} {
		if c, _ := ControlFor(tc.r); c.Href != tc.want {
			t.Errorf("ControlFor(%+v).Href = %q, want %q", tc.r, c.Href, tc.want)
		}
	}
	if f, ok := WindowsHomeFlag("claude-code-windows"); !ok || f != "--windows-claude-home" {
		t.Error("WindowsHomeFlag")
	}
	if got := WindowsHomeTargets(); len(got) != 3 || got[0] != "claude-code-windows" {
		t.Errorf("WindowsHomeTargets = %v", got)
	}
}

// TestOpenSettingsLabels: a known section reads as the rail names it; an
// unknown one still links, with a generic label.
func TestOpenSettingsLabels(t *testing.T) {
	for _, tc := range []struct {
		section, label string
	}{
		{"proxy", "Open Settings > Proxy"},
		{"org", "Open Settings > Org sharing"},
		{"process", "Open Settings > Process capture"},
		{"antigravity", "Open Settings > Antigravity"},
		{"watcher", "Open Settings > Watcher"},
		{"observer", "Open Settings > Observer"},
		{"no-such-section", "Open Settings"},
	} {
		c, ok := ControlFor(Of(OpenSettings, tc.section))
		if !ok || c.Label != tc.label {
			t.Errorf("OpenSettings(%q) label = %q, want %q", tc.section, c.Label, tc.label)
		}
	}
	if l, ok := SettingsSectionLabel("browser"); !ok || l != "Browser capture" {
		t.Errorf("SettingsSectionLabel(browser) = %q, %v", l, ok)
	}
	if _, ok := SettingsSectionLabel("nope"); ok {
		t.Error("an unknown section must not resolve")
	}
}

// TestPackageIsPure keeps remedy free of I/O and of other observer packages.
func TestPackageIsPure(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{"database/sql", "net/http", "os", "os/exec"},
		Custom: func(_, p string) string {
			if strings.Contains(p, "superbased-observer/internal/") || strings.Contains(p, "fsnotify") {
				return "observer package or fsnotify"
			}
			return ""
		},
		Reason: "internal/remedy must stay pure",
	})
}
