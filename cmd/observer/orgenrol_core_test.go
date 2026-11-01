package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/diag"
	"github.com/marmutapp/superbased-observer/internal/govern"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/orgenrol"
)

// T-642: runEnrolSequence is the ONE enrolment sequence `observer enroll` and
// Settings > Enrolment both run. These rows pin what it does for each input
// shape, so a surface that stopped calling it (or a change to it) shows here.

func enrolSequenceBundle(t *testing.T, cfgBody string) (orgBundle, string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	cfgPath := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(cfgPath, []byte(cfgBody), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(config.LoadOptions{GlobalPath: cfgPath})
	if err != nil {
		t.Fatal(err)
	}
	st := idpTestStore(t)
	return orgBundle{client: idpTestOrgClient(t, st), store: st, cfg: cfg, cleanup: func() {}}, cfgPath
}

func TestRunEnrolSequence(t *testing.T) {
	const fresh = "[observer]\nlog_level = \"warn\"\n"
	const withBlock = fresh + "\n[org_client]\nenabled = false\n"
	cases := []struct {
		name        string
		tenancy     string
		cfg         string
		writeBlock  bool
		wantBind    bool
		wantAdded   bool
		wantSkipped bool
		wantFull    bool
		wantPush    bool
		// wantEdited: an existing block got only its enabled and
		// org_server_url lines (T-728); the rest of the file is unchanged.
		wantEdited bool
	}{
		{name: "individual writes the opt-in block", tenancy: orgcontract.TenancyIndividual, cfg: fresh, writeBlock: true, wantAdded: true},
		{name: "managed binds and writes full content", tenancy: orgcontract.TenancyManaged, cfg: fresh, writeBlock: true, wantBind: true, wantAdded: true, wantFull: true},
		{name: "--write-block=false skips the block", tenancy: orgcontract.TenancyIndividual, cfg: fresh, writeBlock: false, wantSkipped: true},
		{name: "an existing block gets only enabled and the address (T-728)", tenancy: orgcontract.TenancyManaged, cfg: withBlock, writeBlock: true, wantBind: true, wantFull: true, wantEdited: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			org := newEnrolFakeOrg(t, tc.tenancy, nil)
			b, cfgPath := enrolSequenceBundle(t, tc.cfg)
			before, _ := os.ReadFile(cfgPath)
			seq, err := runEnrolSequence(context.Background(), b, cfgPath, org.url, idpTestEnrolCode, tc.writeBlock)
			if err != nil {
				t.Fatalf("runEnrolSequence: %v", err)
			}
			if seq.enr == nil || seq.enr.OrgID != "org-1" || org.enrolCalls != 1 {
				t.Fatalf("enrolment = %+v after %d enrol calls", seq.enr, org.enrolCalls)
			}
			if seq.managed != (tc.tenancy == orgcontract.TenancyManaged) || seq.bindTried != tc.wantBind {
				t.Fatalf("managed=%v bindTried=%v, want bind %v", seq.managed, seq.bindTried, tc.wantBind)
			}
			if seq.blockAdded != tc.wantAdded || seq.blockSkipped != tc.wantSkipped || seq.blockErr != nil || seq.cfgPathErr != nil {
				t.Fatalf("block: added=%v skipped=%v err=%v pathErr=%v", seq.blockAdded, seq.blockSkipped, seq.blockErr, seq.cfgPathErr)
			}
			if seq.posture.fullContent != tc.wantFull {
				t.Fatalf("posture full_content = %v, want %v", seq.posture.fullContent, tc.wantFull)
			}
			after, _ := os.ReadFile(cfgPath)
			switch {
			case tc.wantAdded:
				want := "full_content = " + map[bool]string{true: "true", false: "false"}[tc.wantFull]
				if !strings.Contains(string(after), "[org_client]") || !strings.Contains(string(after), want) {
					t.Fatalf("block not written as the CLI writes it:\n%s", after)
				}
			case tc.wantEdited:
				want := fresh + "\n[org_client]\nenabled = true\norg_server_url = \"" + org.url + "\"\n"
				if string(after) != want || !seq.cfgEdit.Wrote || !seq.pushEnabledNow {
					t.Fatalf("existing block after enrol (wrote=%v):\n%s\nwant:\n%s", seq.cfgEdit.Wrote, after, want)
				}
			default:
				if string(after) != string(before) {
					t.Fatalf("config changed when no block write was due:\n%s", after)
				}
			}
			if tc.wantSkipped && seq.blockConfigPath() != "" {
				t.Fatalf("a skipped block step must not hand the policy write a path, got %q", seq.blockConfigPath())
			}
			if !tc.wantSkipped && seq.blockConfigPath() != cfgPath {
				t.Fatalf("blockConfigPath = %q, want %q", seq.blockConfigPath(), cfgPath)
			}
		})
	}
}

// TestRunEnrolSequenceRefusalWritesNothing: a refused code returns the client
// error unchanged (each surface classifies it its own way) and touches no
// config.
func TestRunEnrolSequenceRefusalWritesNothing(t *testing.T) {
	org := newEnrolFakeOrg(t, orgcontract.TenancyIndividual, nil)
	org.enrolStatus = http.StatusUnauthorized
	b, cfgPath := enrolSequenceBundle(t, "[observer]\n")
	before, _ := os.ReadFile(cfgPath)
	_, err := runEnrolSequence(context.Background(), b, cfgPath, org.url, idpTestEnrolCode, true)
	if !errors.Is(err, orgclient.ErrAuthFailed) {
		t.Fatalf("err = %v, want orgclient.ErrAuthFailed", err)
	}
	if after, _ := os.ReadFile(cfgPath); string(after) != string(before) {
		t.Fatalf("a refused enrolment wrote config:\n%s", after)
	}
}

// TestWriteAcceptedGrantPolicy: the W-5 step both surfaces run after an
// accepted grant writes only for an accepted managed grant that governs a
// family, and never without a config path.
func TestWriteAcceptedGrantPolicy(t *testing.T) {
	authority := []string{govern.AuthorityDashboardVisibility}
	cases := []struct {
		name      string
		g         grantOutcome
		noPath    bool
		wantWrite bool
	}{
		{name: "accepted managed grant writes", g: grantOutcome{Accepted: true, Managed: true, Authority: authority}, wantWrite: true},
		{name: "individual grant never writes", g: grantOutcome{Accepted: true, Managed: false, Authority: authority}},
		{name: "declined grant never writes", g: grantOutcome{Accepted: false, Managed: true, Authority: authority}},
		{name: "no config path never writes", g: grantOutcome{Accepted: true, Managed: true, Authority: authority}, noPath: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfgPath := filepath.Join(t.TempDir(), "config.toml")
			if err := os.WriteFile(cfgPath, []byte("[observer]\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			path := cfgPath
			if tc.noPath {
				path = ""
			}
			families, added, err := writeAcceptedGrantPolicy(path, tc.g)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := os.ReadFile(cfgPath)
			wrote := strings.Contains(string(body), "accept_families")
			if wrote != tc.wantWrite || added != tc.wantWrite || (len(families) > 0) != tc.wantWrite {
				t.Fatalf("wrote=%v added=%v families=%v, want %v\n%s", wrote, added, families, tc.wantWrite, body)
			}
		})
	}
}

// TestEnrolWireBinary pins the --wire-clients binary choice (T-642): an enrol
// run from another build registers against the running daemon's binary.
func TestEnrolWireBinary(t *testing.T) {
	const self, daemon, other, db = "/opt/new/observer", "/opt/daemon/observer", "/opt/other/observer", "/h/.observer/observer.db"
	onDisk := func(p string) bool { return filepath.ToSlash(p) != "/opt/gone/observer" }
	lock := func(bin, dbPath string) diag.LockInfo { return diag.LockInfo{PID: 1, BinaryPath: bin, DBPath: dbPath} }
	cases := []struct {
		name     string
		live     []diag.LockInfo
		want     string
		wantNote bool
	}{
		{name: "no daemon", want: self},
		{name: "daemon is this binary", live: []diag.LockInfo{lock(self, db)}, want: self},
		{name: "daemon runs another binary", live: []diag.LockInfo{lock(daemon, db)}, want: daemon, wantNote: true},
		{name: "daemon on another database is ignored", live: []diag.LockInfo{lock(daemon, "/elsewhere/observer.db")}, want: self},
		{name: "daemons disagree", live: []diag.LockInfo{lock(daemon, db), lock(other, db)}, want: self, wantNote: true},
		{name: "daemon binary gone", live: []diag.LockInfo{lock("/opt/gone/observer", db)}, want: self, wantNote: true},
		{name: "lock without a binary is ignored", live: []diag.LockInfo{lock("", db)}, want: self},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, note := enrolWireBinary(self, db, tc.live, onDisk)
			// The binary path is cleaned with the host's separator.
			if filepath.Clean(got) != filepath.Clean(tc.want) || (note != "") != tc.wantNote {
				t.Fatalf("enrolWireBinary = (%q, %q), want %q with note=%v", got, note, tc.want, tc.wantNote)
			}
			if strings.ContainsAny(note, "\u2014\u2013") {
				t.Fatalf("note carries a dash: %q", note)
			}
		})
	}
}

// TestWireAIClientsHonoursBinaryPath: the hook command written is the binary
// the caller named, not this test binary (T-642).
func TestWireAIClientsHonoursBinaryPath(t *testing.T) {
	requireComponents(t, "integration.hooks")
	requireActiveAdapters(t, "claude-code")
	requireAdapter(t, "claude-code")
	home := interactiveHome(t)
	const daemon = "/opt/daemon/observer"
	if _, _, _, _, err := wireAIClients(WireAIClientsOptions{
		HomeDir: home, BinaryPath: daemon, OnlyClaudeCode: true,
		SkipMCP: true, SkipProxy: true, SkipExtension: true,
	}); err != nil {
		t.Fatalf("wireAIClients: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(home, ".claude", "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), daemon+" hook") {
		t.Fatalf("hook command does not invoke %s:\n%s", daemon, raw)
	}
	self, _ := absoluteBinaryPath()
	if self != "" && strings.Contains(string(raw), self+" hook") {
		t.Fatalf("hook command still invokes this process's binary %s", self)
	}
}

// TestConfiguredPushInterval: push-status and Settings > Enrolment show the
// ceiling the push loop actually uses (T-642; the CLI used to fall back to a
// stale 900 s).
func TestConfiguredPushInterval(t *testing.T) {
	for _, tc := range []struct{ in, want int }{
		{in: 300, want: 300},
		{in: 0, want: config.DefaultPushIntervalSeconds},
		{in: -5, want: config.DefaultPushIntervalSeconds},
	} {
		if got := configuredPushInterval(config.OrgClientConfig{PushIntervalSeconds: tc.in}); got != tc.want {
			t.Fatalf("configuredPushInterval(%d) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

// TestEnrolDashboardOverviewCarriesPushCadence: the overview carries
// `observer org push-status`'s push interval (T-642 parity).
func TestEnrolDashboardOverviewCarriesPushCadence(t *testing.T) {
	ctx := context.Background()
	org := newEnrolFakeOrg(t, orgcontract.TenancyIndividual, nil)
	d, _, _ := testEnrolDashboard(t)
	if _, err := d.Enrol(ctx, dashapi.EnrolRequest{Method: "code", OrgURL: org.url, Token: idpTestEnrolCode}); err != nil {
		t.Fatalf("Enrol: %v", err)
	}
	ov, err := d.Overview(ctx)
	if err != nil || !ov.Enrolled {
		t.Fatalf("overview = %+v (%v)", ov, err)
	}
	if ov.PushIntervalSeconds != config.DefaultPushIntervalSeconds {
		t.Fatalf("push interval = %d, want %d", ov.PushIntervalSeconds, config.DefaultPushIntervalSeconds)
	}
}

// TestEnrolDashboardResync (T-642): Settings > Enrolment's Re-send changed
// rows runs the CLI's resync performer with its default window; an
// unenrolled machine is refused, classified.
func TestEnrolDashboardResync(t *testing.T) {
	ctx := context.Background()
	d, _, _ := testEnrolDashboard(t)
	_, err := d.Resync(ctx, false)
	wantFailure(t, err, orgenrol.CodeNotEnrolled)

	org := newEnrolFakeOrg(t, orgcontract.TenancyIndividual, nil)
	if _, err := d.Enrol(ctx, dashapi.EnrolRequest{Method: "code", OrgURL: org.url, Token: idpTestEnrolCode}); err != nil {
		t.Fatalf("Enrol: %v", err)
	}
	for _, confirm := range []bool{false, true} {
		rep, err := d.Resync(ctx, confirm)
		if err != nil {
			t.Fatalf("Resync(confirm=%v): %v", confirm, err)
		}
		if rep.Confirmed != confirm || rep.WindowDays != 30 || rep.Limit != resyncDefaultLimit || len(rep.Tables) == 0 {
			t.Fatalf("Resync(confirm=%v) = %+v", confirm, rep)
		}
		// A fresh enrolment has pushed nothing, so nothing can be re-sent.
		if rep.Queued != 0 || rep.Manifests != 0 {
			t.Fatalf("a fresh enrolment queued %d rows / %d manifests", rep.Queued, rep.Manifests)
		}
	}
}

// TestEnrolWireBinaryWindowsCase (WINFIX2 audit finding 10): Windows file
// names are case-insensitive, so a daemon lock spelling this binary or the
// database in another case is the same binary on the same database there,
// and two such spellings are not "daemons disagree". On Linux they stay
// different files.
func TestEnrolWireBinaryWindowsCase(t *testing.T) {
	const self, db = `C:\Tools\Observer\observer.exe`, `C:\Users\dev\.observer\observer.db`
	const selfOther, dbOther = `c:\tools\observer\OBSERVER.EXE`, `c:\users\DEV\.observer\observer.db`
	onDisk := func(string) bool { return true }
	lock := func(bin, dbPath string) diag.LockInfo { return diag.LockInfo{PID: 1, BinaryPath: bin, DBPath: dbPath} }
	cases := []struct {
		name, goos string
		live       []diag.LockInfo
		wantNote   bool
	}{
		{"this binary in another case", "windows", []diag.LockInfo{lock(selfOther, dbOther)}, false},
		{"two spellings of one daemon binary", "windows", []diag.LockInfo{lock(selfOther, db), lock(self, db)}, false},
		{"on linux another case is another binary", "linux", []diag.LockInfo{lock(selfOther, db)}, true},
	}
	for _, tc := range cases {
		got, note := enrolWireBinaryOn(tc.goos, self, db, tc.live, onDisk)
		if (note != "") != tc.wantNote {
			t.Errorf("%s: enrolWireBinaryOn = (%q, %q), want a note = %v", tc.name, got, note, tc.wantNote)
		}
		if !tc.wantNote && !samePathOn(tc.goos, got, self) {
			t.Errorf("%s: picked %q, want this binary", tc.name, got)
		}
	}
	if !samePathOn("windows", self, selfOther) || samePathOn("linux", self, selfOther) {
		t.Fatal("samePathOn does not fold case on windows only")
	}
}
