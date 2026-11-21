package dashboard

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// TestHealthDoctor pins the endpoint shape: every diag check arrives
// with a name, a string status from the ok/warn/fail vocabulary, and
// counts that sum to the check count. Statuses themselves are NOT
// asserted (they depend on the machine); the home is sandboxed via
// setupWizardHome so hook/MCP checks read a temp dir, not the
// developer's real config.
func TestHealthDoctor(t *testing.T) {
	server, _ := wizardTestServer(t) // sandboxes setupWizardHome + temp config/DB

	rr := httptest.NewRecorder()
	server.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/health/doctor", nil))
	if rr.Code != 200 {
		t.Fatalf("status: %d body=%s", rr.Code, rr.Body.String())
	}
	var got struct {
		Checks []struct {
			Name   string `json:"name"`
			Status string `json:"status"`
		} `json:"checks"`
		OK    int  `json:"ok"`
		Warn  int  `json:"warn"`
		Fail  int  `json:"fail"`
		AllOK bool `json:"all_ok"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if len(got.Checks) == 0 {
		t.Fatal("no checks returned")
	}
	valid := map[string]bool{"ok": true, "warn": true, "fail": true}
	for _, c := range got.Checks {
		if c.Name == "" || !valid[c.Status] {
			t.Errorf("bad check row: %+v", c)
		}
	}
	if got.OK+got.Warn+got.Fail != len(got.Checks) {
		t.Errorf("counts %d+%d+%d != %d checks", got.OK, got.Warn, got.Fail, len(got.Checks))
	}
	if got.AllOK != (got.Warn == 0 && got.Fail == 0) {
		t.Errorf("all_ok inconsistent: %v vs warn=%d fail=%d", got.AllOK, got.Warn, got.Fail)
	}

	// Method guard.
	rr = httptest.NewRecorder()
	server.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/health/doctor", nil))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST: got %d want 405", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// pathRedactor unit table
// ---------------------------------------------------------------------------

// TestPathRedactor exercises the substitution rules against the SHAPES the
// real checks emit, enumerated from a live `observer doctor --json` run:
// a literal path written into a detail (antigravity.family), a path that
// arrives ONLY through err.Error() and appears twice in one line
// (hooks.checksums), a cross-OS Windows home (windows proxy routes), and the
// many rows that quote no path at all and must survive byte-identical.
func TestPathRedactor(t *testing.T) {
	// The nesting that makes ordering load-bearing: config + db + exe all
	// live under home, and one Windows home name is a prefix of another.
	r := newPathRedactor([]pathSub{
		{"/home/dev/superbased-observer/bin/observer", redactExe},
		{"/home/dev/.observer/config.toml", redactConfig},
		{"/home/dev/.observer/observer.db", redactDB},
		{"/home/dev", redactHome},
		{"/tmp", redactTemp},
		{"/mnt/c/Users/Default", redactOtherHome},
		{"/mnt/c/Users/Default User", redactOtherHome + "-2"},
		{"/srv/etw/process-bridge-token", redactTokenFile},
	})

	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			// antigravity.family, measured verbatim on a live host.
			name: "literal path in a detail",
			in:   "desktop: /home/dev/.gemini/antigravity/conversations (38 .pb files)",
			want: "desktop: ~/.gemini/antigravity/conversations (38 .pb files)",
		},
		{
			// hooks.checksums missing-detail, measured verbatim. The path is
			// written once by the check and once by err.Error(); the check's
			// own source line for the second one contains no path at all.
			name: "path arriving only via err.Error()",
			in: "/home/dev/.claude/settings.json: open /home/dev/.claude/settings.json: " +
				"no such file or directory",
			want: "~/.claude/settings.json: open ~/.claude/settings.json: no such file or directory",
		},
		{
			// db.size — the whole path is inside the stat error.
			name: "db path inside a stat error",
			in:   "stat db: stat /home/dev/.observer/observer.db: no such file or directory",
			want: "stat db: stat <db>: no such file or directory",
		},
		{
			// NESTED ROOT ORDERING. Shortest-first would yield
			// "~/.observer/config.toml" here, a mangled hybrid that names the
			// home layout the filter exists to remove.
			name: "nested root: config wins over home",
			in:   "config.toml at /home/dev/.observer/config.toml could not be read",
			want: "config.toml at <config> could not be read",
		},
		{
			// hooks.binary, measured verbatim — and the residue case: the
			// REGISTERED path is under no known root and survives.
			name: "exe redacted, foreign install path is residue",
			in: "/home/dev/.claude/settings.json: registered=/opt/other/observer " +
				"running=/home/dev/superbased-observer/bin/observer",
			want: "~/.claude/settings.json: registered=/opt/other/observer running=<exe>",
		},
		{
			// windows proxy routes, measured verbatim: the Windows user name
			// the sibling ETW route already withholds.
			name: "cross-OS home",
			in: "claude-code-windows: /mnt/c/Users/Default/.claude/settings.json present " +
				"but NOT routed - run `observer init` to point it at the WSL proxy",
			want: "claude-code-windows: <other-home>/.claude/settings.json present " +
				"but NOT routed - run `observer init` to point it at the WSL proxy",
		},
		{
			// Two cross-OS homes, one a string prefix of the other. Longest
			// first keeps them DISTINCT — the ownership warning's whole point
			// is that several homes carry the same config, and collapsing them
			// onto one placeholder would render it as nonsense.
			name: "two cross-OS homes stay distinct, longest first",
			in: "multiple Windows-side homes carry the config " +
				"(/mnt/c/Users/Default/.claude, /mnt/c/Users/Default User/.claude)",
			want: "multiple Windows-side homes carry the config (<other-home>/.claude, <other-home>-2/.claude)",
		},
		{
			// process observability, quoting the daemon's verbatim
			// transport-unavailable reason — the same string the sibling ETW
			// status route drops. The token VALUE never appears in doctor
			// output; only its file path does.
			name: "relocated ETW token file path",
			in: "the cross-OS capture transport was REQUESTED but is NOT running: " +
				"could not open /srv/etw/process-bridge-token (permission denied)",
			want: "the cross-OS capture transport was REQUESTED but is NOT running: " +
				"could not open <token-file> (permission denied)",
		},
		{
			name: "no path at all passes through untouched",
			in:   "24 adapter(s) with local data, 7 idle",
			want: "24 adapter(s) with local data, 7 idle",
		},
		{
			// The remediation hint must stay actionable after redaction.
			name: "remediation hint survives readable",
			in:   "read checksums: open /home/dev/.observer/hook_checksums.json: no such file or directory",
			want: "read checksums: open ~/.observer/hook_checksums.json: no such file or directory",
		},
		{
			// OS-convention system path: documented residue, left readable on
			// purpose (no identity, no layout beyond the OS's own convention).
			name: "system path is documented residue",
			in:   "codex managed-config not deployed (no /etc/codex/*.toml)",
			want: "codex managed-config not deployed (no /etc/codex/*.toml)",
		},
		{
			// Documented OVER-redaction: matching is plain substring, so a
			// root that is a string prefix of unrelated text is substituted
			// too. Confusing beats disclosing; pinned so the behaviour is a
			// decision, not a surprise.
			name: "over-redacts an unrelated prefix",
			in:   "/tmpfs is not a temp dir",
			want: "<tmp>fs is not a temp dir",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := r.redact(tc.in); got != tc.want {
				t.Errorf("redact:\n got %q\nwant %q", got, tc.want)
			}
		})
	}

	// nil details stay nil so an absent list does not become an empty array.
	if got := r.redactAll(nil); got != nil {
		t.Errorf("redactAll(nil) = %v, want nil", got)
	}
	if got := r.redactAll([]string{"/home/dev/x", "plain"}); len(got) != 2 ||
		got[0] != "~/x" || got[1] != "plain" {
		t.Errorf("redactAll = %q", got)
	}
}

// TestNewPathRedactorDropsDegenerateRoots pins the safety floor: a root short
// enough to match nearly every sentence is DISCARDED, not applied. Discarding
// under-redacts, which is why it is named in pathRedactor's residue note
// rather than treated as a safe fallback.
func TestNewPathRedactorDropsDegenerateRoots(t *testing.T) {
	r := newPathRedactor([]pathSub{
		{"", redactHome},
		{"   ", redactHome},
		{"/", redactHome},
		{".", redactHome},
		{"C:", redactOtherHome},
		{"/home/dev", ""}, // no placeholder is as useless as no root
	})
	if !r.empty() {
		t.Fatalf("degenerate roots survived: %+v", r.subs)
	}
	const s = "nothing here should change: / . C: /home/dev"
	if got := r.redact(s); got != s {
		t.Errorf("empty redactor rewrote %q -> %q", s, got)
	}

	// Duplicate roots collapse, first placeholder wins, and a trailing
	// separator does not create a second root. The roots are OS-native; on
	// Windows the forward-slash spelling of the same root is registered on
	// purpose (TestNewPathRedactorSeparatorSpellings), and must carry the
	// same first-wins placeholder.
	r2 := newPathRedactor([]pathSub{
		{filepath.FromSlash("/home/dev/"), redactHome},
		{filepath.FromSlash("/home/dev"), redactDB},
	})
	wantRoots := map[string]bool{filepath.FromSlash("/home/dev"): true, "/home/dev": true}
	if len(r2.subs) != len(wantRoots) {
		t.Fatalf("dedupe: %+v, want one entry per spelling in %v", r2.subs, wantRoots)
	}
	for _, sub := range r2.subs {
		if !wantRoots[sub.root] || sub.placeholder != redactHome {
			t.Fatalf("dedupe: %+v, want roots %v all carrying %q", r2.subs, wantRoots, redactHome)
		}
	}

	// A root given in un-cleaned form is registered BOTH ways, so text quoting
	// either spelling is covered. Registering only the cleaned form would be a
	// silent miss — the checks quote whatever string they were handed.
	r3 := newPathRedactor([]pathSub{{"/home/dev/./sub/", redactHome}})
	if got := r3.redact("a=/home/dev/sub/x b=/home/dev/./sub/x"); got != "a=~/x b=~/x" {
		t.Errorf("uncleaned root: got %q", got)
	}
}

// TestNewPathRedactorSeparatorSpellings pins that a root is redacted whichever
// separator the text quotes it with on Windows, where filepath.Clean rewrites
// "/" to `\` and text arrives both ways (a TOML value or a ToSlash'd path
// versus a filepath.Join result). On POSIX a backslash is an ordinary
// filename byte, so only the given spelling is a root there.
func TestNewPathRedactorSeparatorSpellings(t *testing.T) {
	windows := filepath.Separator == '\\'
	tests := []struct {
		name, root, in   string
		wantWin, wantPSX string
	}{
		{
			"backslash root, slash text", `C:\Users\dev`, "C:/Users/dev/.claude",
			"~/.claude", "C:/Users/dev/.claude",
		},
		{
			"backslash root, backslash text", `C:\Users\dev`, `C:\Users\dev\.claude`,
			`~\.claude`, `~\.claude`,
		},
		{
			"slash root, backslash text", "C:/Users/dev", `C:\Users\dev\.claude`,
			`~\.claude`, `C:\Users\dev\.claude`,
		},
		{
			"slash root, slash text", "C:/Users/dev", "C:/Users/dev/.claude",
			"~/.claude", "~/.claude",
		},
		{
			"posix root", "/home/dev", "/home/dev/.claude and /home/dev",
			"~/.claude and ~", "~/.claude and ~",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			want := tc.wantPSX
			if windows {
				want = tc.wantWin
			}
			r := newPathRedactor([]pathSub{{tc.root, redactHome}})
			if got := r.redact(tc.in); got != want {
				t.Errorf("redact(%q) with root %q = %q, want %q", tc.in, tc.root, got, want)
			}
		})
	}
}

// TestDoctorRedactorRootSources pins WHICH roots the builder actually harvests
// — the failure mode here is silent: a root the builder forgets is a root that
// never matches, and the response then looks redacted while still naming the
// machine. Each root is asserted through a sentence shaped like the check that
// emits it.
func TestDoctorRedactorRootSources(t *testing.T) {
	server, home := wizardTestServer(t) // sandboxes setupWizardHome to `home`

	cfg := config.Default()
	cfg.Observer.DBPath = "~/.observer/observer.db" // tilde form, as config carries it
	cfg.Observer.Process.ETW.TokenPath = "/srv/etw/process-bridge-token"
	exe := "/opt/sbo/bin/observer"

	r := server.doctorRedactor(cfg, exe)
	if r.empty() {
		t.Fatal("builder produced no roots")
	}

	cases := []struct{ name, in, want string }{
		{"home", "desktop: " + home + "/.gemini/x", "desktop: ~/.gemini/x"},
		{"config", "config.toml at " + server.opts.ConfigPath + " unreadable", "config.toml at <config> unreadable"},
		// diag.checkDBSize expands the tilde with filepath.Join, so the
		// quoted path carries the OS separator.
		{"db from config, tilde-expanded", "stat db: " + filepath.Join(home, ".observer", "observer.db") + " missing", "stat db: <db> missing"},
		{"exe", "running=" + exe, "running=<exe>"},
		{"etw token file", "could not open /srv/etw/process-bridge-token (denied)", "could not open <token-file> (denied)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := r.redact(tc.in); got != tc.want {
				t.Errorf("redact:\n got %q\nwant %q", got, tc.want)
			}
		})
	}

	// The real host home is NOT the sandbox home under this override, so it
	// arrives as a cross-OS/other home rather than "~". Over-redaction, and the
	// property that matters: the developer's own username never survives.
	if realHome, err := os.UserHomeDir(); err == nil && realHome != home {
		if got := r.redact(realHome + "/.claude"); strings.Contains(got, realHome) {
			t.Errorf("real host home survived redaction: %q", got)
		}
	}
}

// ---------------------------------------------------------------------------
// handler-level disclosure policy
// ---------------------------------------------------------------------------

// doctorGet issues GET /api/health/doctor, optionally through the
// remote-exposed provenance marker the remote authz chain stamps — i.e. as a
// PAIRED REMOTE DEVICE rather than the local owner.
func doctorGet(t *testing.T, s *Server, remote bool) doctorReport {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/health/doctor", nil)
	if remote {
		req = req.WithContext(withRemoteExposed(req.Context()))
	}
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rr.Code, rr.Body.String())
	}
	var resp doctorReport
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v (body=%s)", err, rr.Body.String())
	}
	return resp
}

func doctorCheckByName(t *testing.T, rep doctorReport, name string) doctorCheck {
	t.Helper()
	for _, c := range rep.Checks {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("check %q not in report (%d checks)", name, len(rep.Checks))
	return doctorCheck{}
}

// seedDoctorPathEmitters plants the two files that make the sandboxed home
// show up in doctor's free text through BOTH routes measured on a live host:
//
//   - antigravity.family writes the conversations dir into a detail LITERALLY;
//   - hooks.checksums names a registered config that does not exist, so the
//     path arrives inside err.Error() — the class whose emitting source line
//     contains no path token at all.
func seedDoctorPathEmitters(t *testing.T, home string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(home, ".gemini", "antigravity", "conversations"), 0o755); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(home, ".claude", "gone", "settings.json")
	if err := os.MkdirAll(filepath.Join(home, ".observer"), 0o755); err != nil {
		t.Fatal(err)
	}
	// json.Marshal, not string splicing: a Windows path's backslashes are
	// invalid JSON escapes when pasted into a literal.
	body, err := json.Marshal(map[string]map[string]string{
		missing: {"sha256": "deadbeef", "registered": "x", "binary_path": "/opt/other/observer"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".observer", "hook_checksums.json"), body, 0o644); err != nil {
		t.Fatal(err)
	}
	return missing
}

// TestHealthDoctorLocalCallerGetsEverything pins the other half of the policy:
// the OWNER on the loopback listener still sees their real machine. A filter
// that also redacted the local view would be solving a disclosure problem by
// hiding the operator's own remediation hints from them.
func TestHealthDoctorLocalCallerGetsEverything(t *testing.T) {
	server, home := wizardTestServer(t)
	seedDoctorPathEmitters(t, home)

	rep := doctorGet(t, server, false)
	if rep.LocalDetailWithheld {
		t.Error("local caller got local_detail_withheld=true")
	}
	anti := doctorCheckByName(t, rep, "antigravity.family")
	if !strings.Contains(strings.Join(anti.Details, "\n"), home) {
		t.Errorf("local caller did not get the real home in details: %q", anti.Details)
	}
	hooks := doctorCheckByName(t, rep, "hooks.checksums")
	if !strings.Contains(hooks.Message+strings.Join(hooks.Details, "\n"), home) {
		t.Errorf("local caller did not get the real home in hooks.checksums: %+v", hooks)
	}
}

// TestHealthDoctorRemoteRedactsLocalPaths closes the disclosure gap: the route
// is capability VIEW, so a PAIRED REMOTE DEVICE reaches it, and its free text
// otherwise carries the operator's absolute filesystem layout and user name —
// the very facts the sibling GET /api/process/etw/status already withholds.
func TestHealthDoctorRemoteRedactsLocalPaths(t *testing.T) {
	server, home := wizardTestServer(t)
	seedDoctorPathEmitters(t, home)

	rep := doctorGet(t, server, true)
	if !rep.LocalDetailWithheld {
		t.Error("remote caller did not get local_detail_withheld=true")
	}

	// No check, anywhere in the report, may still quote the home directory —
	// this is the whole-surface assertion, not a per-check spot check.
	for _, c := range rep.Checks {
		blob := c.Message + "\n" + strings.Join(c.Details, "\n")
		if strings.Contains(blob, home) {
			t.Errorf("check %q leaked the home dir: %s", c.Name, blob)
		}
	}

	// Literal-path emitter: redacted but still readable.
	anti := doctorCheckByName(t, rep, "antigravity.family")
	joined := strings.Join(anti.Details, "\n")
	// The checks build paths with filepath.Join, so the redacted text keeps
	// the OS separator after the "~" placeholder.
	if !strings.Contains(joined, redactHome+string(filepath.Separator)+filepath.Join(".gemini", "antigravity", "conversations")) {
		t.Errorf("antigravity detail lost its remediation meaning: %q", anti.Details)
	}

	// err.Error()-only emitter: the path inside the error is redacted too.
	hooks := doctorCheckByName(t, rep, "hooks.checksums")
	joined = hooks.Message + "\n" + strings.Join(hooks.Details, "\n")
	if !strings.Contains(joined, redactHome+string(filepath.Separator)+filepath.Join(".claude", "gone", "settings.json")) {
		t.Errorf("hooks.checksums detail lost its remediation meaning: %q", joined)
	}
	if !strings.Contains(joined, notExistText(t)) {
		t.Errorf("hooks.checksums lost the error text entirely: %q", joined)
	}
}

// TestHealthDoctorRemoteFlagIsUnconditional pins the distinction the sibling
// ETW route's doc comment makes: local_detail_withheld reports WHICH
// PROJECTION the caller is reading, not whether this particular run happened
// to contain a path. A check whose text names nothing local comes back
// byte-identical to the local caller's — and the flag is set anyway.
func TestHealthDoctorRemoteFlagIsUnconditional(t *testing.T) {
	server, _ := wizardTestServer(t)

	local := doctorGet(t, server, false)
	remote := doctorGet(t, server, true)

	if !remote.LocalDetailWithheld {
		t.Fatal("remote response did not set local_detail_withheld")
	}
	if len(local.Checks) != len(remote.Checks) {
		t.Fatalf("remote dropped checks: %d local vs %d remote", len(local.Checks), len(remote.Checks))
	}
	// Same checks, same verdicts: WHICH checks failed is the legitimate remote
	// read, and the projection must not change it.
	if local.OK != remote.OK || local.Warn != remote.Warn || local.Fail != remote.Fail {
		t.Errorf("counts differ: local %d/%d/%d remote %d/%d/%d",
			local.OK, local.Warn, local.Fail, remote.OK, remote.Warn, remote.Fail)
	}
	identical := 0
	for i := range local.Checks {
		if local.Checks[i].Name != remote.Checks[i].Name ||
			local.Checks[i].Status != remote.Checks[i].Status {
			t.Errorf("check %d changed name/status between projections", i)
		}
		if local.Checks[i].Message == remote.Checks[i].Message {
			identical++
		}
	}
	if identical == 0 {
		t.Error("expected at least one path-free check to survive byte-identical " +
			"(the flag would then be indistinguishable from a did-we-drop-anything signal)")
	}
}

// notExistText is this OS's wording for a missing file ("no such file or
// directory" on POSIX, "The system cannot find the path specified." on
// Windows), taken from a real failed stat so the assertion is not
// POSIX-only.
func notExistText(t *testing.T) string {
	t.Helper()
	_, err := os.Stat(filepath.Join(t.TempDir(), "absent", "file"))
	var pe *os.PathError
	if !errors.As(err, &pe) {
		t.Fatalf("stat of a missing file returned %v, want *os.PathError", err)
	}
	return pe.Err.Error()
}
