package secdiffobs

import (
	"testing"
	"time"
)

// diff builds one file's change from removed and added lines (numbered
// from 1 in each).
func diff(p string, removed, added []string) FileDiff {
	f := FileDiff{Path: p}
	for i, l := range removed {
		f.Removed = append(f.Removed, Line{N: i + 1, Text: l})
	}
	for i, l := range added {
		f.Added = append(f.Added, Line{N: i + 1, Text: l})
	}
	return f
}

// TestInferenceTable is one row per inference shape, with near-miss rows
// that must not fire.
func TestInferenceTable(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		f    FileDiff
		want string // "" for none
	}{
		// S-762: a removed or bypassed authentication check.
		{"removed login_required", diff("app/views.py", []string{"@login_required", "def dashboard(request):"}, []string{"def dashboard(request):"}), "S-762"},
		{"removed express auth middleware", diff("server.js", []string{"app.use(authMiddleware);"}, nil), "S-762"},
		{"removed Spring PreAuthorize", diff("Ctl.java", []string{`    @PreAuthorize("hasRole('ADMIN')")`}, nil), "S-762"},
		{"auth switched off by flag", diff("settings.py", nil, []string{"SKIP_AUTH = True"}), "S-762"},
		{"DRF AllowAny", diff("api/views.py", nil, []string{"    permission_classes = [AllowAny]"}), "S-762"},
		{"near miss: decorator moved", diff("app/views.py", []string{"@login_required"}, []string{"@login_required"}), ""},
		{"near miss: comment removed", diff("app/views.py", []string{"# @login_required was here"}, nil), ""},
		{"near miss: auth flag kept on", diff("settings.py", nil, []string{"SKIP_AUTH = False"}), ""},
		// S-763: a debug branch returning a privileged identity.
		{"debug returns admin role", diff("auth.py", nil, []string{`if DEBUG: return {"role": "admin"}`}), "S-763"},
		{"debug branch on the next line", diff("auth.py", nil, []string{"    if settings.DEBUG:", `        return {"is_admin": True}`}), "S-763"},
		{"near miss: debug logs admin", diff("auth.py", nil, []string{"if DEBUG:", `    log.debug("admin")`}), ""},
		{"near miss: admin role without debug", diff("auth.py", nil, []string{`return {"role": "admin"}`}), ""},
		{"near miss: privileged return far away", diff("auth.py", nil, []string{"if DEBUG:", "  a()", "  b()", "  c()", "  d()", `  return {"role": "admin"}`}), ""},
		// S-764: a CSRF exemption added.
		{"csrf_exempt", diff("views.py", nil, []string{"@csrf_exempt"}), "S-764"},
		{"Flask-WTF off", diff("config.py", nil, []string{"WTF_CSRF_ENABLED = False"}), "S-764"},
		{"Spring csrf disabled", diff("Sec.java", nil, []string{"http.csrf().disable();"}), "S-764"},
		{"Rails skip", diff("app.rb", nil, []string{"skip_before_action :verify_authenticity_token"}), "S-764"},
		{"near miss: csrf on", diff("config.py", nil, []string{"WTF_CSRF_ENABLED = True"}), ""},
		{"near miss: csrf comment", diff("views.py", nil, []string{"# never use @csrf_exempt here"}), ""},
		// S-765: CORS opened with credentials.
		{"fastapi wildcard with credentials", diff("main.py", nil, []string{`app.add_middleware(CORSMiddleware, allow_origins=["*"],`, "    allow_credentials=True)"}), "S-765"},
		{"express origin true with credentials", diff("server.js", nil, []string{"app.use(cors({ origin: true, credentials: true }));"}), "S-765"},
		{"header pair", diff("h.go", nil, []string{`w.Header().Set("Access-Control-Allow-Origin", "*")`, `w.Header().Set("Access-Control-Allow-Credentials", "true")`}), "S-765"},
		{"near miss: wildcard without credentials", diff("main.py", nil, []string{`allow_origins=["*"]`}), ""},
		{"near miss: credentials for one origin", diff("main.py", nil, []string{`allow_origins=["https://app.example.com"]`, "allow_credentials=True"}), ""},
		// S-766: a rate limit removed.
		{"flask limiter removed", diff("api.py", []string{`@limiter.limit("5/minute")`}, nil), "S-766"},
		{"express rate limit removed", diff("app.js", []string{"app.use(rateLimit({ windowMs: 60000, max: 10 }));"}, nil), "S-766"},
		{"near miss: limiter moved", diff("api.py", []string{`@limiter.limit("5/minute")`}, []string{`@limiter.limit("5/minute")`}), ""},
		{"near miss: limiter added", diff("api.py", nil, []string{`@limiter.limit("5/minute")`}), ""},
	}
	for _, tc := range cases {
		got := ObserveWith([]FileDiff{tc.f}, Options{Inferences: true})
		var ids []string
		for _, o := range got {
			ids = append(ids, o.RuleID)
			if o.RuleID != "S-761" && !o.Inference {
				t.Errorf("%s: %s not labelled an inference", tc.name, o.RuleID)
			}
		}
		switch {
		case tc.want == "" && len(ids) != 0:
			t.Errorf("%s: fired %v", tc.name, ids)
		case tc.want != "" && (len(ids) != 1 || ids[0] != tc.want):
			t.Errorf("%s: got %v, want [%s]", tc.name, ids, tc.want)
		}
	}
}

// TestObserveKeepsInferencesOff: the commit and post-write callers keep
// using Observe and get no inference.
func TestObserveKeepsInferencesOff(t *testing.T) {
	t.Parallel()
	f := diff("views.py", []string{"@login_required", `@limiter.limit("1/s")`}, []string{"@csrf_exempt", `if DEBUG: return {"role": "admin"}`})
	if got := Observe([]FileDiff{f}); len(got) != 0 {
		t.Fatalf("Observe fired inferences: %+v", got)
	}
	if got := ObserveWith([]FileDiff{f}, Options{}); len(got) != 0 {
		t.Fatalf("zero options fired: %+v", got)
	}
}

// TestScopeDriftTable: one row per path class, with the near misses (the
// prompt names the class; no prompt at all).
func TestScopeDriftTable(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, path, prompt, want string
	}{
		{"auth file, prompt about the navbar", "src/auth/session.ts", "make the navbar blue", "auth"},
		{"workflow, prompt about a bug", ".github/workflows/ci.yml", "fix the off-by-one in paging", "ci"},
		{"terraform, prompt about docs", "infra/main.tf", "reword the README intro", "iac"},
		{"lockfile, prompt about a typo", "package-lock.json", "fix the typo in the header", "lockfile"},
		{"test file, prompt about a feature", "pkg/paging_test.go", "add a page size option", "test"},
		{"near miss: prompt names auth", "src/auth/session.ts", "the login session expires too early", ""},
		{"near miss: prompt names the pipeline", ".github/workflows/ci.yml", "speed up the CI pipeline", ""},
		{"near miss: prompt names a dependency bump", "go.sum", "bump the yaml dependency", ""},
		{"near miss: prompt names tests", "pkg/paging_test.go", "add tests for paging", ""},
		{"near miss: plain source file", "pkg/paging.go", "make the navbar blue", ""},
		{"near miss: no prompt available", "src/auth/session.ts", "", ""},
	}
	for _, tc := range cases {
		got := ScopeDrift([]FileDiff{{Path: tc.path}}, tc.prompt)
		switch {
		case tc.want == "" && len(got) != 0:
			t.Errorf("%s: fired %+v", tc.name, got)
		case tc.want != "" && (len(got) != 1 || got[0].PathClass != tc.want || got[0].TermClass != tc.want):
			t.Errorf("%s: got %+v, want %s", tc.name, got, tc.want)
		}
	}
	// Through ObserveWith: labelled an inference, the message names the
	// class only, never the prompt.
	obs := ObserveWith([]FileDiff{{Path: "src/auth/x.go"}}, Options{Prompt: &Prompt{Text: "rename SECRETWORD in the navbar"}})
	if len(obs) != 1 || obs[0].RuleID != "S-770" || !obs[0].Inference {
		t.Fatalf("got %+v", obs)
	}
	if contains(obs[0].Message, "SECRETWORD") || contains(obs[0].Message, "navbar") {
		t.Fatalf("prompt text in the observation: %q", obs[0].Message)
	}
	if got := ObserveWith([]FileDiff{{Path: "src/auth/x.go"}}, Options{Prompt: nil}); len(got) != 0 {
		t.Fatalf("no prompt fired: %+v", got)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// TestDecideFixTable is one row per decision row of DecideFix.
func TestDecideFixTable(t *testing.T) {
	t.Parallel()
	t0 := time.Date(2026, 10, 23, 10, 0, 0, 0, time.UTC)
	after := t0.Add(time.Minute)
	cases := []struct {
		name string
		ev   FixEvidence
		want string
		ok   bool
	}{
		{"go test exit 0 after the edit", FixEvidence{LastEditAt: t0, EditedPaths: []string{"pkg/a.go"}, Commands: []SessionCommand{{At: after, Command: "go test ./pkg/...", ExitKnown: true}}}, FixVerified, true},
		{"pytest via python -m", FixEvidence{LastEditAt: t0, Commands: []SessionCommand{{At: after, Command: "cd x && python -m pytest -q", ExitKnown: true}}}, FixVerified, true},
		{"no AI edit known", FixEvidence{Commands: []SessionCommand{{At: after, Command: "go test ./...", ExitKnown: true}}}, FixNoEdit, false},
		{"a test file edited in the change", FixEvidence{LastEditAt: t0, EditedPaths: []string{"pkg/a.go", "pkg/a_test.go"}, Commands: []SessionCommand{{At: after, Command: "go test ./...", ExitKnown: true}}}, FixTestFileEdited, false},
		{"test ran before the edit only", FixEvidence{LastEditAt: t0, Commands: []SessionCommand{{At: t0.Add(-time.Minute), Command: "go test ./...", ExitKnown: true}}}, FixNoTestCommand, false},
		{"not a test command", FixEvidence{LastEditAt: t0, Commands: []SessionCommand{{At: after, Command: "go build ./...", ExitKnown: true}}}, FixNoTestCommand, false},
		{"exit unknown", FixEvidence{LastEditAt: t0, Commands: []SessionCommand{{At: after, Command: "npm test"}}}, FixExitUnknown, false},
		{"last test failed", FixEvidence{LastEditAt: t0, Commands: []SessionCommand{{At: after, Command: "go test ./...", ExitKnown: true}, {At: after.Add(time.Minute), Command: "go test ./...", ExitKnown: true, ExitCode: 1}}}, FixTestCommandFailed, false},
	}
	for _, tc := range cases {
		v := DecideFix(tc.ev)
		if v.Verified && contains(v.Detail(), "host reported success") {
			t.Errorf("%s: an exit code read as a success flag: %q", tc.name, v.Detail())
		}
		if v.Reason != tc.want || v.Verified != tc.ok {
			t.Errorf("%s: got %+v", tc.name, v)
		}
		if v.Verified && (contains(v.Detail(), "passed") || !contains(v.Detail(), "observed test command")) {
			t.Errorf("%s: wording %q", tc.name, v.Detail())
		}
	}
}

// TestClaimsFix: the fix-claim phrase table and its near misses.
func TestClaimsFix(t *testing.T) {
	t.Parallel()
	for s, want := range map[string]bool{
		"fix SQL injection in search":           true,
		"Security fix for the upload handler":   true,
		"patch CVE-2026-12345 in the parser":    true,
		"harden auth token checks":              true,
		"fix typo in README":                    false,
		"add security docs":                     false,
		"refactor the injection container (DI)": false,
	} {
		if got := ClaimsFix(s); got != want {
			t.Errorf("%q: %v", s, got)
		}
	}
}

func TestTestCommandClass(t *testing.T) {
	t.Parallel()
	for cmd, want := range map[string]string{
		"go test -race ./...": "go_test", "pytest -x": "pytest", "pnpm run test": "js_test", "npx vitest run": "js_test",
		"cargo nextest run": "cargo_test", "dotnet test": "dotnet_test", "./gradlew test": "jvm_test", "make check": "make_test",
		"go vet ./...": "", "echo pytest": "", "cat test.txt": "", "cd svc && CGO_ENABLED=0 go test ./...": "go_test",
	} {
		if got := TestCommandClass(cmd); got != want {
			t.Errorf("%q: %q, want %q", cmd, got, want)
		}
	}
}

// TestFixDetailSaysWhatTheHostReported: a success flag with no exit code is
// recorded as "host reported success", never as "exit code 0" (audit
// finding 5); an exit code of 0 is recorded as one.
func TestFixDetailSaysWhatTheHostReported(t *testing.T) {
	t.Parallel()
	t0 := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	flag := DecideFix(FixEvidence{LastEditAt: t0, Commands: []SessionCommand{{At: t0.Add(time.Minute), Command: "go test ./...", ExitKnown: true, HostReportedSuccess: true}}})
	if !flag.Verified || !flag.HostReportedSuccess || !contains(flag.Detail(), "host reported success") || contains(flag.Detail(), "exit code 0") {
		t.Errorf("success flag: %+v %q", flag, flag.Detail())
	}
	code := DecideFix(FixEvidence{LastEditAt: t0, Commands: []SessionCommand{{At: t0.Add(time.Minute), Command: "go test ./...", ExitKnown: true}}})
	if !code.Verified || code.HostReportedSuccess || !contains(code.Detail(), "exit code 0") {
		t.Errorf("exit code: %+v %q", code, code.Detail())
	}
}
