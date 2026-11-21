package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/service"
	"github.com/marmutapp/superbased-observer/internal/setup"
)

func alwaysActive(string) bool { return true }

func TestStatuslineDashRoundTrip(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	settings := filepath.Join(home, ".claude", "settings.json")
	d := &statuslineDash{configPath: filepath.Join(home, "config.toml"), binary: "/usr/local/bin/observer", homeDir: home, gate: alwaysActive}
	ctx := context.Background()

	st, err := d.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Supported || st.State != dashapi.StatuslineAbsent {
		t.Fatalf("fresh status = %+v", st)
	}

	// A preview writes nothing.
	out, err := d.Apply(ctx, dashapi.SetupInstall, true, false)
	if err != nil || !out.Changed || !out.DryRun {
		t.Fatalf("preview = %+v, err %v", out, err)
	}
	if _, serr := os.Stat(settings); serr == nil {
		t.Fatal("a preview wrote settings.json")
	}

	out, err = d.Apply(ctx, dashapi.SetupInstall, false, false)
	if err != nil || !out.Changed || out.Refused {
		t.Fatalf("install = %+v, err %v", out, err)
	}
	raw, err := os.ReadFile(settings)
	if err != nil || !strings.Contains(string(raw), "statusLine") || !strings.Contains(string(raw), "statusline") {
		t.Fatalf("settings.json = %q, err %v", raw, err)
	}
	if st, _ = d.Status(ctx); st.State != dashapi.StatuslineInstalled {
		t.Fatalf("after install state = %q", st.State)
	}

	// A second install is a no-op, not a rewrite.
	out, _ = d.Apply(ctx, dashapi.SetupInstall, false, false)
	if out.Changed {
		t.Fatalf("second install changed something: %+v", out)
	}

	out, err = d.Apply(ctx, dashapi.SetupRemove, false, false)
	if err != nil || !out.Changed {
		t.Fatalf("remove = %+v, err %v", out, err)
	}
	if st, _ = d.Status(ctx); st.State != dashapi.StatuslineAbsent {
		t.Fatalf("after remove state = %q", st.State)
	}
}

func TestStatuslineDashForeignEntry(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".claude")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	settings := filepath.Join(dir, "settings.json")
	foreign := `{"statusLine":{"type":"command","command":"/opt/my-own-line"}}`
	if err := os.WriteFile(settings, []byte(foreign), 0o644); err != nil {
		t.Fatal(err)
	}
	d := &statuslineDash{configPath: filepath.Join(home, "config.toml"), binary: "/usr/local/bin/observer", homeDir: home, gate: alwaysActive}
	ctx := context.Background()

	if st, _ := d.Status(ctx); st.State != dashapi.StatuslineForeign {
		t.Fatalf("state = %q, want foreign", st.State)
	}
	out, err := d.Apply(ctx, dashapi.SetupInstall, false, false)
	if err != nil || !out.Refused || !strings.Contains(out.Reason, "did not write") {
		t.Fatalf("install over a foreign line = %+v, err %v", out, err)
	}
	if strings.Contains(out.Reason, "--force") {
		t.Errorf("reason names a CLI flag: %q", out.Reason)
	}
	out, err = d.Apply(ctx, dashapi.SetupRemove, false, false)
	if err != nil || !out.Refused {
		t.Fatalf("remove of a foreign line = %+v, err %v", out, err)
	}
	if raw, _ := os.ReadFile(settings); string(raw) != foreign {
		t.Fatalf("a foreign status line was modified: %q", raw)
	}
	// Replacing it is an explicit choice.
	out, err = d.Apply(ctx, dashapi.SetupInstall, false, true)
	if err != nil || !out.Changed {
		t.Fatalf("forced install = %+v, err %v", out, err)
	}
}

func TestStatuslineDashRefusals(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mkClaud bool
		gate    func(string) bool
		want    string
	}{
		{"claude code absent", false, alwaysActive, "not found"},
		{"component off", true, func(string) bool { return false }, "Settings > Components"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			if tc.mkClaud {
				if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			d := &statuslineDash{configPath: filepath.Join(home, "config.toml"), binary: "/usr/local/bin/observer", homeDir: home, gate: tc.gate}
			out, err := d.Apply(context.Background(), dashapi.SetupInstall, true, false)
			if err != nil || !out.Refused || !strings.Contains(out.Reason, tc.want) {
				t.Fatalf("outcome = %+v, err %v; want a refusal containing %q", out, err, tc.want)
			}
		})
	}
}

func TestStatuslineSupport(t *testing.T) {
	for _, tc := range []struct {
		name      string
		installed []string
		ok        bool
	}{
		{"native", []string{"cursor", "claude-code"}, true},
		{"windows side only", []string{"claude-code-windows"}, false},
		{"none", nil, false},
	} {
		if ok, why := statuslineSupport(tc.installed); ok != tc.ok || (!ok && why == "") {
			t.Errorf("%s: ok=%v why=%q", tc.name, ok, why)
		}
	}
}

// loginStartFakes stands in for a systemd host: a pinned home, no real
// systemctl, and a probe that records every command it is asked to run.
func loginStartFakes(t *testing.T) (*loginStartDash, *[]string, string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	savedSD, savedLD := systemdAvailable, launchdAvailable
	systemdAvailable = func() bool { return true }
	launchdAvailable = func() bool { return false }
	t.Cleanup(func() { systemdAvailable, launchdAvailable = savedSD, savedLD })

	var cmds []string
	probe := &serviceProbe{
		run: func(c service.Command) error {
			cmds = append(cmds, c.Name+" "+strings.Join(c.Args, " "))
			return nil
		},
		show:         func(service.Scope) (bool, int, error) { return false, 0, nil },
		readExe:      func(int) (string, error) { return "", errors.New("none") },
		proxySockets: func(int) (bool, int, error) { return false, 0, nil },
		routes:       func(string, int) ([]string, error) { return nil, nil },
	}
	d := &loginStartDash{
		configPath: filepath.Join(home, "config.toml"),
		deps: serviceInstallDeps{
			exe:      "/opt/observer/observer",
			pathDirs: func() []string { return nil },
			linger:   func() string { return "" },
			probe:    probe,
		},
		query: func(_ context.Context, c service.Command) (string, error) {
			if strings.Contains(strings.Join(c.Args, " "), "is-enabled") {
				return "enabled", nil
			}
			return "inactive", errors.New("inactive")
		},
	}
	return d, &cmds, service.UnitPath(service.ScopeUser, home)
}

// TestLoginStartSystemdNeverStartsOrStops pins B-CS6: install writes and
// enables the unit, remove disables and deletes it, and neither ever starts,
// stops or restarts the daemon or uses --now.
func TestLoginStartSystemdNeverStartsOrStops(t *testing.T) {
	d, cmds, unit := loginStartFakes(t)
	ctx := context.Background()

	st, err := d.Status(ctx)
	if err != nil || !st.Supported || st.Manager != loginManagerSystemd || st.Installed {
		t.Fatalf("fresh status = %+v, err %v", st, err)
	}

	out, err := d.Apply(ctx, dashapi.SetupInstall, true)
	if err != nil || out.Changed || len(out.Lines) == 0 {
		t.Fatalf("preview = %+v, err %v", out, err)
	}
	if _, serr := os.Stat(unit); serr == nil || len(*cmds) != 0 {
		t.Fatalf("a preview wrote the unit or ran a command: %v", *cmds)
	}

	out, err = d.Apply(ctx, dashapi.SetupInstall, false)
	if err != nil || !out.Changed {
		t.Fatalf("install = %+v, err %v", out, err)
	}
	body, rerr := os.ReadFile(unit)
	if rerr != nil || !strings.Contains(string(body), "/opt/observer/observer") {
		t.Fatalf("unit = %q, err %v", body, rerr)
	}
	joined := strings.Join(*cmds, "\n")
	if !strings.Contains(joined, "daemon-reload") || !strings.Contains(joined, "enable observer.service") {
		t.Fatalf("commands = %q, want daemon-reload and enable", joined)
	}

	st, _ = d.Status(ctx)
	if !st.Installed || !st.Enabled || !strings.Contains(st.Command, "/opt/observer/observer") {
		t.Fatalf("status after install = %+v", st)
	}

	// An existing entry is reported, never overwritten.
	before, _ := os.ReadFile(unit)
	out, err = d.Apply(ctx, dashapi.SetupInstall, false)
	if err != nil || !out.Refused || !strings.Contains(out.Reason, "already exists") {
		t.Fatalf("second install = %+v, err %v", out, err)
	}
	if after, _ := os.ReadFile(unit); string(after) != string(before) {
		t.Fatal("an existing unit was rewritten")
	}

	out, err = d.Apply(ctx, dashapi.SetupRemove, true)
	if err != nil || out.Changed {
		t.Fatalf("remove preview = %+v, err %v", out, err)
	}
	if _, serr := os.Stat(unit); serr != nil {
		t.Fatal("a remove preview deleted the unit")
	}
	out, err = d.Apply(ctx, dashapi.SetupRemove, false)
	if err != nil || !out.Changed {
		t.Fatalf("remove = %+v, err %v", out, err)
	}
	if _, serr := os.Stat(unit); serr == nil {
		t.Fatal("the unit survived a remove")
	}

	for _, c := range *cmds {
		for _, bad := range []string{" start", " stop", "restart", "--now", "try-restart"} {
			if strings.Contains(c, bad) {
				t.Errorf("command %q would start or stop the daemon (%q)", c, bad)
			}
		}
	}
	if !strings.Contains(strings.Join(*cmds, "\n"), "disable observer.service") {
		t.Errorf("remove should disable the unit: %v", *cmds)
	}
}

func TestLoginStartUnsupportedHost(t *testing.T) {
	savedSD, savedLD := systemdAvailable, launchdAvailable
	systemdAvailable = func() bool { return false }
	launchdAvailable = func() bool { return false }
	t.Cleanup(func() { systemdAvailable, launchdAvailable = savedSD, savedLD })
	d := &loginStartDash{}
	st, err := d.Status(context.Background())
	if err != nil || st.Supported || st.Reason == "" {
		t.Fatalf("status = %+v, err %v", st, err)
	}
	out, err := d.Apply(context.Background(), dashapi.SetupInstall, false)
	if err != nil || !out.Refused || out.Changed {
		t.Fatalf("install on an unsupported host = %+v, err %v", out, err)
	}
}

func TestLoginStartWindowsRunEntry(t *testing.T) {
	savedSD, savedLD := systemdAvailable, launchdAvailable
	systemdAvailable = func() bool { return false }
	launchdAvailable = func() bool { return false }
	t.Cleanup(func() { systemdAvailable, launchdAvailable = savedSD, savedLD })

	dir := t.TempDir()
	cur := ""
	var writes []string
	deletes := 0
	d := &loginStartDash{
		exeDir: dir,
		sys: setupOS{
			readRun:   func() (string, error) { return cur, nil },
			writeRun:  func(v string) error { cur = v; writes = append(writes, v); return nil },
			deleteRun: func() error { cur = ""; deletes++; return nil },
		},
	}
	ctx := context.Background()

	st, err := d.Status(ctx)
	if err != nil || !st.Supported || st.Manager != loginManagerWinRun || st.Installed {
		t.Fatalf("status = %+v, err %v", st, err)
	}
	// Without the windowless launcher the install says why and writes nothing.
	out, err := d.Apply(ctx, dashapi.SetupInstall, false)
	if err != nil || !out.Refused || !strings.Contains(out.Reason, setup.WindowlessName) || len(writes) != 0 {
		t.Fatalf("install without the launcher = %+v, err %v", out, err)
	}
	if err := os.WriteFile(filepath.Join(dir, setup.WindowlessName), []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	out, err = d.Apply(ctx, dashapi.SetupInstall, true)
	if err != nil || out.Changed || len(writes) != 0 || len(out.Lines) == 0 {
		t.Fatalf("preview = %+v, writes %v, err %v", out, writes, err)
	}
	out, err = d.Apply(ctx, dashapi.SetupInstall, false)
	if err != nil || !out.Changed || len(writes) != 1 || writes[0] != setup.RunValue(filepath.Join(dir, setup.WindowlessName)) {
		t.Fatalf("install = %+v, writes %v, err %v", out, writes, err)
	}
	if out, _ = d.Apply(ctx, dashapi.SetupInstall, false); !out.Refused {
		t.Fatalf("second install should be refused: %+v", out)
	}
	if out, err = d.Apply(ctx, dashapi.SetupRemove, false); err != nil || !out.Changed || deletes != 1 {
		t.Fatalf("remove = %+v, deletes %d, err %v", out, deletes, err)
	}
}

func TestBrowserOutcomeLines(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []string
		want []string
	}{
		{"plain lines are kept", []string{"browser: wrote native-messaging host → /h"}, []string{"browser: wrote native-messaging host → /h"}},
		{
			"the CLI follow-up block becomes one sentence",
			[]string{
				"browser: wrote native-messaging host → /h",
				`browser: no extension id supplied - wrote the placeholder "x" in allowed_origins.`,
				"  after `load-unpacked` in chrome://extensions, copy the extension id and either:",
				"    re-run: observer init --browser-extension-id <id>",
				"      /h/manifest.json",
				"browser (chrome): wrote native-messaging host manifest → /m",
			},
			[]string{"browser: wrote native-messaging host → /h", browserPlaceholderNote, "browser (chrome): wrote native-messaging host manifest → /m"},
		},
		{"empty", nil, []string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := browserOutcomeLines(tc.in)
			if strings.Join(got, "|") != strings.Join(tc.want, "|") {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestBrowserLinesChanged(t *testing.T) {
	for _, tc := range []struct {
		lines []string
		want  bool
	}{
		{[]string{"browser: would write native-messaging host (a + b) → /h"}, true},
		{[]string{"browser: wrote native-messaging host → /h"}, true},
		{[]string{"browser (chrome): native-messaging host manifest already set in /m"}, false},
		{[]string{"browser: no Chromium-family browser detected - install one and re-run, or load the extension elsewhere."}, false},
		{nil, false},
	} {
		if got := browserLinesChanged(tc.lines); got != tc.want {
			t.Errorf("%q: got %v, want %v", tc.lines, got, tc.want)
		}
	}
}

func TestBrowserDashRefusals(t *testing.T) {
	d := &browserDash{configPath: filepath.Join(t.TempDir(), "config.toml"), home: t.TempDir(), winHomes: []string{}, gate: alwaysActive}
	if _, err := d.Apply(context.Background(), "not-an-id", true); !errors.Is(err, dashapi.ErrSetupInput) {
		t.Fatalf("bad id error = %v, want ErrSetupInput", err)
	}
	d.gate = func(string) bool { return false }
	out, err := d.Apply(context.Background(), "", true)
	if err != nil || !out.Refused || !strings.Contains(out.Reason, "Settings > Components") {
		t.Fatalf("component off = %+v, err %v", out, err)
	}
	d.gate = alwaysActive
	st, err := d.Status(context.Background())
	if err != nil || !st.Supported || st.Installed || len(st.HostFiles) != 0 {
		t.Fatalf("status = %+v, err %v", st, err)
	}
}
