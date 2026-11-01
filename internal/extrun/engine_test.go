package extrun_test

import (
	"context"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/extrun"
	"github.com/marmutapp/superbased-observer/internal/extrun/extruntest"
)

func TestClassifyExit(t *testing.T) {
	t.Parallel()
	og, osv := &extrun.OpengrepEngine, &extrun.OSVScannerEngine
	cases := []struct {
		name    string
		e       *extrun.Engine
		outcome extrun.Outcome
		code    int
		want    extrun.ExitMeaning
	}{
		{"no engine", nil, extrun.OutcomeOK, 0, extrun.ExitUnclassified},
		{"opengrep 0 is read the SARIF", og, extrun.OutcomeOK, 0, extrun.ExitResult},
		{"opengrep 1 with --error", og, extrun.OutcomeExitNonZero, 1, extrun.ExitFindings},
		{"opengrep 2 crash", og, extrun.OutcomeExitNonZero, 2, extrun.ExitFailure},
		{"opengrep 7 bad rules", og, extrun.OutcomeExitNonZero, 7, extrun.ExitFailure},
		{"opengrep unknown code", og, extrun.OutcomeExitNonZero, 3, extrun.ExitFailure},
		{"osv 0 clean", osv, extrun.OutcomeOK, 0, extrun.ExitClean},
		{"osv 1 is a result", osv, extrun.OutcomeExitNonZero, 1, extrun.ExitFindings},
		{"osv 128 nothing scanned, never clean", osv, extrun.OutcomeExitNonZero, 128, extrun.ExitNoInput},
		{"osv 127 every error", osv, extrun.OutcomeExitNonZero, 127, extrun.ExitFailure},
		{"a killed run is not classified", osv, extrun.OutcomeTimeout, 0, extrun.ExitUnclassified},
		{"a refused run is not classified", og, extrun.OutcomeRefused, 0, extrun.ExitUnclassified},
	}
	for _, tc := range cases {
		if got := extrun.ClassifyExit(tc.e, tc.outcome, tc.code); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestGitHardeningEnv(t *testing.T) {
	t.Parallel()
	unix := extrun.GitHardeningEnv("linux")
	want := []string{
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_PARAMETERS='core.fsmonitor=false' 'core.hooksPath=/dev/null'",
		"GIT_TERMINAL_PROMPT=0",
		"GIT_LFS_SKIP_SMUDGE=1",
	}
	if !reflect.DeepEqual(unix, want) {
		t.Fatalf("linux: %q", unix)
	}
	for _, kv := range extrun.GitHardeningEnv("windows") {
		if strings.Contains(kv, "/dev/null") {
			t.Fatalf("windows names /dev/null: %q", kv)
		}
	}
}

// engineFiles is the file table of the engine tests.
var engineFiles = extruntest.Files{
	"/opt/og/opengrep":     {Digest: "d-og"},
	"/usr/bin/git":         {Digest: "d-git"},
	"/usr/local/go/bin/go": {Digest: "d-go"},
	"/usr/local/bin/go":    {LinkTo: "/usr/local/go/bin/go"},
	"/opt/gosec/gosec":     {Digest: "d-gosec"},
}

func TestEngineEnvironment(t *testing.T) {
	t.Parallel()
	ex := &extruntest.Executor{}
	r := extruntest.NewRunner("linux", engineFiles, ex, nil)
	res := r.Run(context.Background(), extrun.Request{
		Component: "security",
		Program: extrun.Program{
			Path:           "/opt/og/opengrep",
			CompanionExecs: []extrun.CompanionExec{{Path: "/usr/bin/git", OnPath: true}},
		},
		CacheDir: "/home/u/.observer/cache/opengrep",
		Engine:   &extrun.OpengrepEngine,
	})
	if res.Outcome != extrun.OutcomeOK || res.Engine != "opengrep" || res.ExitMeaning != extrun.ExitResult {
		t.Fatalf("result %s engine %q meaning %q (%s)", res.Outcome, res.Engine, res.ExitMeaning, res.Detail)
	}
	plan := ex.Calls()[0]
	env := strings.Join(plan.Env, "\n")
	for _, want := range []string{
		"GIT_CONFIG_NOSYSTEM=1",
		"HOME=/home/u/.observer/cache/opengrep/home",
		"XDG_CACHE_HOME=/home/u/.observer/cache/opengrep/xdg-cache",
		"LC_ALL=C.UTF-8",
		"PATH=/usr/bin",
	} {
		if !strings.Contains(env, want) {
			t.Errorf("env lacks %s:\n%s", want, env)
		}
	}
	if !reflect.DeepEqual(plan.MakeDirs, []string{"/home/u/.observer/cache/opengrep/home", "/home/u/.observer/cache/opengrep/xdg-cache"}) {
		t.Errorf("MakeDirs %q", plan.MakeDirs)
	}
	if res.CacheDir != "/home/u/.observer/cache/opengrep" || len(res.Toolchain) != 1 || res.Toolchain[0].Digest != "d-git" {
		t.Errorf("record: cache %q toolchain %+v", res.CacheDir, res.Toolchain)
	}
	if res.Digests.Companions["/usr/bin/git"] != "d-git" {
		t.Errorf("companion digests %+v", res.Digests.Companions)
	}
}

func TestEngineRefusals(t *testing.T) {
	t.Parallel()
	base := func() extrun.Request {
		return extrun.Request{Component: "security", Program: extrun.Program{Path: "/opt/gosec/gosec"}}
	}
	cases := []struct {
		name string
		mod  func(*extrun.Request)
		want extrun.RefuseReason
	}{
		{"own home without a cache dir", func(r *extrun.Request) { r.Engine = &extrun.OSVScannerEngine }, extrun.RefuseBadRequest},
		{"a relative cache dir", func(r *extrun.Request) { r.CacheDir = "cache" }, extrun.RefuseNotAbsolute},
		{"the caller sets HOME the engine owns", func(r *extrun.Request) {
			r.Engine, r.CacheDir, r.Env.Set = &extrun.OSVScannerEngine, "/c", []string{"HOME=/home/u"}
		}, extrun.RefuseEnv},
		{"a companion digest mismatch", func(r *extrun.Request) {
			r.Program.CompanionExecs = []extrun.CompanionExec{{Path: "/usr/local/go/bin/go", Expect: "d-other"}}
		}, extrun.RefuseDigestMismatch},
		{"a symlinked companion", func(r *extrun.Request) {
			r.Program.CompanionExecs = []extrun.CompanionExec{{Path: "/usr/local/bin/go"}}
		}, extrun.RefuseSymlink},
		{"a missing companion", func(r *extrun.Request) {
			r.Program.CompanionExecs = []extrun.CompanionExec{{Path: "/usr/bin/nope"}}
		}, extrun.RefuseNotFound},
	}
	for _, tc := range cases {
		ex := &extruntest.Executor{}
		req := base()
		tc.mod(&req)
		res := extruntest.NewRunner("linux", engineFiles, ex, nil).Run(context.Background(), req)
		if res.Outcome != extrun.OutcomeRefused || res.Reason != tc.want {
			t.Errorf("%s: %s %s (%s)", tc.name, res.Outcome, res.Reason, res.Detail)
		}
		if len(ex.Calls()) != 0 {
			t.Errorf("%s: a refused run started %d processes", tc.name, len(ex.Calls()))
		}
	}
}

// TestToolchainVersionIsRecorded: a companion with a version probe is asked
// first (under the run's environment) and its version lands in the record;
// a second run with the same digest answers from the cache.
func TestToolchainVersionIsRecorded(t *testing.T) {
	t.Parallel()
	ex := &extruntest.Executor{Facts: func(p extrun.Plan) extrun.ExecFacts {
		if p.Path == "/usr/local/go/bin/go" {
			return extrun.ExecFacts{Stdout: []byte("go version go1.27.2 linux/amd64\n"), PeakChildren: -1}
		}
		return extrun.ExecFacts{PeakChildren: -1}
	}}
	r := extruntest.NewRunner("linux", engineFiles, ex, nil)
	req := extrun.Request{
		Component: "security",
		Program: extrun.Program{
			Path: "/opt/gosec/gosec",
			CompanionExecs: []extrun.CompanionExec{{
				Path: "/usr/local/go/bin/go", Expect: "d-go", OnPath: true,
				// "go1.27.2" has no word boundary before the digits, so the
				// go toolchain needs its own pattern.
				Version: &extrun.VersionProbe{Args: []string{"version"}, Pattern: regexp.MustCompile(`\bgo(\d+\.\d+(?:\.\d+)?)`)},
			}},
		},
		Env: extrun.EnvSpec{Set: []string{"GOTOOLCHAIN=local"}},
	}
	res := r.Run(context.Background(), req)
	if res.Outcome != extrun.OutcomeOK || len(res.Toolchain) != 1 {
		t.Fatalf("outcome %s toolchain %+v (%s)", res.Outcome, res.Toolchain, res.Detail)
	}
	if tv := res.Toolchain[0]; tv.Version != "1.27.2" || tv.Digest != "d-go" || tv.Path != "/usr/local/go/bin/go" {
		t.Fatalf("toolchain %+v", tv)
	}
	calls := ex.Calls()
	if len(calls) != 2 || calls[0].Path != "/usr/local/go/bin/go" || calls[1].Path != "/opt/gosec/gosec" {
		t.Fatalf("calls %+v", calls)
	}
	if !reflect.DeepEqual(calls[0].Env, calls[1].Env) {
		t.Fatalf("the probe saw %q, the run %q", calls[0].Env, calls[1].Env)
	}
	if res2 := r.Run(context.Background(), req); res2.Toolchain[0].Version != "1.27.2" || len(ex.Calls()) != 3 {
		t.Fatalf("second run: toolchain %+v, %d calls (the probe should be cached)", res2.Toolchain, len(ex.Calls()))
	}
}
