package extrun_test

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/extrun"
	"github.com/marmutapp/superbased-observer/internal/extrun/extruntest"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/toolresolve"
)

// files is the shared in-memory file table.
var files = extruntest.Files{
	"/usr/bin/git":            {Digest: "d-git"},
	"/usr/local/bin/tool":     {LinkTo: "/opt/tool/bin/tool"},
	"/opt/tool/bin/tool":      {Digest: "d-tool"},
	"/opt/tool/lib/engine.so": {Digest: "d-engine"},
	"/opt/tool/lib/link.so":   {LinkTo: "/opt/tool/lib/engine.so"},
	"/usr/bin":                {Dir: true},
	"/usr/bin/bwrap":          {Digest: "d-bwrap"},
}

// fakeIsolation wraps a plan in bwrap, or fails.
type fakeIsolation struct{ fail bool }

func (fakeIsolation) Name() string { return "fake-bwrap" }
func (f fakeIsolation) Wrap(_ context.Context, p extrun.Plan) (extrun.Plan, error) {
	if f.fail {
		return extrun.Plan{}, errors.New("no user namespaces")
	}
	p.Args = append([]string{"--unshare-net", "--", p.Path}, p.Args...)
	p.Path = "/usr/bin/bwrap"
	return p, nil
}

func TestRunnerRefusals(t *testing.T) {
	t.Parallel()
	spec := &integration.BinaryResolveSpec{Names: integration.BinaryNames{Unix: []string{"git"}}}
	cases := []struct {
		name    string
		req     extrun.Request
		resolve toolresolve.Verdict
		iso     extrun.IsolationProvider
		want    extrun.RefuseReason
	}{
		{name: "no component", req: extrun.Request{Program: extrun.Program{Path: "/usr/bin/git"}}, want: extrun.RefuseNoComponent},
		{name: "neither spec nor path", req: extrun.Request{Component: "projects"}, want: extrun.RefuseBadRequest},
		{name: "both spec and path", req: extrun.Request{Component: "projects", Program: extrun.Program{Spec: spec, Path: "/usr/bin/git"}}, want: extrun.RefuseBadRequest},
		{name: "negative limit", req: extrun.Request{Component: "projects", Program: extrun.Program{Path: "/usr/bin/git"}, Limits: extrun.Limits{Wall: -time.Second}}, want: extrun.RefuseBadLimits},
		{name: "bare name never looked up", req: extrun.Request{Component: "projects", Program: extrun.Program{Path: "git"}}, want: extrun.RefuseNotAbsolute},
		{name: "relative working dir", req: extrun.Request{Component: "projects", Program: extrun.Program{Path: "/usr/bin/git"}, Dir: "repo"}, want: extrun.RefuseNotAbsolute},
		{name: "missing program", req: extrun.Request{Component: "projects", Program: extrun.Program{Path: "/usr/bin/nope"}}, want: extrun.RefuseNotFound},
		{name: "spec that does not resolve", req: extrun.Request{Component: "projects", Program: extrun.Program{Spec: spec}}, resolve: toolresolve.VerdictForeignOnly, want: extrun.RefuseNotFound},
		{name: "symlink refused by default", req: extrun.Request{Component: "projects", Program: extrun.Program{Path: "/usr/local/bin/tool"}}, want: extrun.RefuseSymlink},
		{name: "symlinked companion refused by default", req: extrun.Request{Component: "projects", Program: extrun.Program{Path: "/opt/tool/bin/tool", Companions: []string{"/opt/tool/lib/link.so"}}}, want: extrun.RefuseSymlink},
		{name: "directory refused", req: extrun.Request{Component: "projects", Program: extrun.Program{Path: "/usr/bin"}}, want: extrun.RefuseNotRegular},
		{name: "binary digest mismatch", req: extrun.Request{Component: "projects", Program: extrun.Program{Path: "/usr/bin/git"}, Expect: &extrun.Digests{Binary: "d-other"}}, want: extrun.RefuseDigestMismatch},
		{name: "companion digest mismatch", req: extrun.Request{
			Component: "projects", Program: extrun.Program{Path: "/opt/tool/bin/tool", Companions: []string{"/opt/tool/lib/engine.so"}},
			Expect: &extrun.Digests{Companions: map[string]string{"/opt/tool/lib/engine.so": "d-swapped"}},
		}, want: extrun.RefuseDigestMismatch},
		{name: "secret env refused", req: extrun.Request{Component: "projects", Program: extrun.Program{Path: "/usr/bin/git"}, Env: extrun.EnvSpec{Inherit: []string{"OPENAI_API_KEY"}}}, want: extrun.RefuseEnv},
		{name: "isolation required but none wired", req: extrun.Request{Component: "projects", Program: extrun.Program{Path: "/usr/bin/git"}, RequireIsolation: true}, want: extrun.RefuseIsolationRequired},
		{name: "isolation that fails is never skipped", req: extrun.Request{Component: "projects", Program: extrun.Program{Path: "/usr/bin/git"}}, iso: fakeIsolation{fail: true}, want: extrun.RefuseIsolationFailed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ex := &extruntest.Executor{}
			r := extruntest.NewRunner("linux", files, ex, map[string]string{"OPENAI_API_KEY": "sk"})
			r.Isolation = tc.iso
			r.Resolve = func(integration.BinaryResolveSpec) toolresolve.Resolution {
				return toolresolve.Resolution{Verdict: tc.resolve}
			}
			res := r.Run(context.Background(), tc.req)
			if res.Outcome != extrun.OutcomeRefused || res.Reason != tc.want {
				t.Fatalf("got %s/%s (%s), want refused/%s", res.Outcome, res.Reason, res.Detail, tc.want)
			}
			if res.Detail == "" {
				t.Fatal("a refusal carries no detail")
			}
			if n := len(ex.Calls()); n != 0 {
				t.Fatalf("a refused run reached the executor %d times", n)
			}
		})
	}
}

func TestRunnerRunsTheCheckedPlan(t *testing.T) {
	t.Parallel()
	ex := &extruntest.Executor{
		Plat: &extrun.Platform{GOOS: "linux", Caps: map[extrun.Cap]extrun.CapState{
			extrun.CapWall: extrun.CapEnforced, extrun.CapStdout: extrun.CapEnforced, extrun.CapStderr: extrun.CapEnforced,
			extrun.CapMemory: extrun.CapBestEffort,
		}},
		Facts: func(extrun.Plan) extrun.ExecFacts {
			return extrun.ExecFacts{
				Stdout: []byte("out"), Duration: time.Second, PeakChildren: 2,
				Applied: map[extrun.Cap]extrun.CapApplied{extrun.CapMemory: {State: extrun.CapNotEnforced}},
			}
		},
	}
	r := extruntest.NewRunner("linux", files, ex, map[string]string{"LANG": "C.UTF-8", "HOME": "/home/dev"})
	r.Resolve = func(spec integration.BinaryResolveSpec) toolresolve.Resolution {
		return toolresolve.Resolution{Verdict: toolresolve.VerdictOKOffPath, Bin: "/usr/local/bin/tool"}
	}
	res := r.Run(context.Background(), extrun.Request{
		Component: "projects",
		Program: extrun.Program{
			Spec:         &integration.BinaryResolveSpec{Names: integration.BinaryNames{Unix: []string{"tool"}}},
			Companions:   []string{"/opt/tool/lib/link.so"},
			AllowSymlink: true,
		},
		Args:   []string{"scan", "--offline"},
		Expect: &extrun.Digests{Binary: "d-tool", Companions: map[string]string{"/opt/tool/lib/link.so": "d-engine"}},
		Env:    extrun.EnvSpec{Inherit: []string{"LANG"}, Set: []string{"HOME=/scratch"}, PathDirs: []string{"/usr/bin"}},
		Dir:    "/work",
		Limits: extrun.Limits{MemoryBytes: 1 << 30, Children: 4},
	})
	if res.Outcome != extrun.OutcomeOK {
		t.Fatalf("outcome %s/%s (%s)", res.Outcome, res.Reason, res.Detail)
	}
	calls := ex.Calls()
	if len(calls) != 1 {
		t.Fatalf("executor called %d times", len(calls))
	}
	want := extrun.Plan{
		Component: "projects",
		Path:      "/opt/tool/bin/tool", // the symlink's final target, never the link
		Args:      []string{"scan", "--offline"},
		Env:       []string{"HOME=/scratch", "LANG=C.UTF-8", "PATH=/usr/bin"},
		Dir:       "/work",
		Limits: extrun.Limits{
			Wall: extrun.DefaultWall, StdoutBytes: extrun.DefaultStdoutBytes,
			StderrBytes: extrun.DefaultStderrBytes, MemoryBytes: 1 << 30, Children: 4,
		},
		Program: "/opt/tool/bin/tool",
	}
	if !reflect.DeepEqual(calls[0], want) {
		t.Fatalf("plan = %+v\nwant  %+v", calls[0], want)
	}
	if res.Verdict != "ok_off_path" || res.Path != "/opt/tool/bin/tool" || res.Digests.Binary != "d-tool" ||
		res.Digests.Companions["/opt/tool/lib/link.so"] != "d-engine" {
		t.Fatalf("record = %+v", res)
	}
	if strings.Join(res.EnvNames, ",") != "HOME,LANG,PATH" {
		t.Fatalf("env names = %v", res.EnvNames)
	}
	states := map[extrun.Cap]extrun.CapState{}
	for _, c := range res.Caps {
		states[c.Cap] = c.State
	}
	if states[extrun.CapMemory] != extrun.CapNotEnforced || states[extrun.CapChildren] != extrun.CapNotEnforced || states[extrun.CapWall] != extrun.CapEnforced {
		t.Fatalf("caps = %+v", res.Caps)
	}
	if string(res.Stdout) != "out" || res.PeakChildren != 2 || res.Duration != time.Second {
		t.Fatalf("facts not carried: %+v", res)
	}
}

func TestRunnerIsolationWrapsThePlan(t *testing.T) {
	t.Parallel()
	ex := &extruntest.Executor{}
	r := extruntest.NewRunner("linux", files, ex, nil)
	r.Isolation = fakeIsolation{}
	res := r.Run(context.Background(), extrun.Request{Component: "projects", Program: extrun.Program{Path: "/usr/bin/git"}, Args: []string{"log"}, RequireIsolation: true})
	if res.Outcome != extrun.OutcomeOK || res.Isolation != "fake-bwrap" || res.Launcher != "/usr/bin/bwrap" || res.Path != "/usr/bin/git" {
		t.Fatalf("result = %+v", res)
	}
	got := ex.Calls()[0]
	if got.Path != "/usr/bin/bwrap" || got.Component != "projects" || strings.Join(got.Args, " ") != "--unshare-net -- /usr/bin/git log" {
		t.Fatalf("wrapped plan = %+v", got)
	}
}

func TestRunnerCarriesExecFacts(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		facts extrun.ExecFacts
		want  extrun.Outcome
	}{
		{"timeout", extrun.ExecFacts{KillReason: extrun.KillTimeout, Signaled: true, Signal: "killed"}, extrun.OutcomeTimeout},
		{"output cap", extrun.ExecFacts{KillReason: extrun.KillOutputCap, StdoutTruncated: true}, extrun.OutcomeOutputCap},
		{"start failure", extrun.ExecFacts{StartErr: "exec format error"}, extrun.OutcomeStartFailed},
		{"exit 2", extrun.ExecFacts{ExitCode: 2}, extrun.OutcomeExitNonZero},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ex := &extruntest.Executor{Facts: func(extrun.Plan) extrun.ExecFacts { return tc.facts }}
			r := extruntest.NewRunner("linux", files, ex, nil)
			res := r.Run(context.Background(), extrun.Request{Component: "projects", Program: extrun.Program{Path: "/usr/bin/git"}})
			if res.Outcome != tc.want {
				t.Fatalf("outcome %s, want %s", res.Outcome, tc.want)
			}
			if tc.facts.StartErr != "" && !strings.Contains(res.Detail, tc.facts.StartErr) {
				t.Fatalf("detail %q lost the start error", res.Detail)
			}
		})
	}
}

func TestProbeVersionCachesPerDigest(t *testing.T) {
	t.Parallel()
	fs := extruntest.Files{"/usr/bin/git": {Digest: "d1"}}
	ex := &extruntest.Executor{Facts: func(extrun.Plan) extrun.ExecFacts {
		return extrun.ExecFacts{Stdout: []byte("git version 2.43.0\n")}
	}}
	r := extruntest.NewRunner("linux", fs, ex, nil)
	req := extrun.Request{Component: "projects", Program: extrun.Program{Path: "/usr/bin/git"}}
	probe := extrun.VersionProbe{Args: []string{"--version"}}

	v1, res1 := r.ProbeVersion(context.Background(), req, probe)
	if v1.Version != "2.43.0" || v1.Cached || res1.Outcome != extrun.OutcomeOK || v1.Digest != "d1" {
		t.Fatalf("first probe = %+v %s", v1, res1.Outcome)
	}
	if got := ex.Calls()[0]; strings.Join(got.Args, " ") != "--version" || got.Limits.Wall != 10*time.Second || got.Limits.StdoutBytes != 64<<10 {
		t.Fatalf("probe plan = %+v", got)
	}
	v2, res2 := r.ProbeVersion(context.Background(), req, probe)
	if !v2.Cached || v2.Version != "2.43.0" || res2.Outcome != extrun.OutcomeCached || len(ex.Calls()) != 1 {
		t.Fatalf("second probe = %+v %s, calls %d", v2, res2.Outcome, len(ex.Calls()))
	}

	// The same path with new bytes is probed again.
	fs["/usr/bin/git"] = extruntest.File{Digest: "d2"}
	v3, _ := r.ProbeVersion(context.Background(), req, probe)
	if v3.Cached || v3.Digest != "d2" || len(ex.Calls()) != 2 {
		t.Fatalf("changed binary = %+v, calls %d", v3, len(ex.Calls()))
	}
}

func TestProbeVersionDoesNotCacheFailures(t *testing.T) {
	t.Parallel()
	ex := &extruntest.Executor{Facts: func(extrun.Plan) extrun.ExecFacts {
		return extrun.ExecFacts{ExitCode: 1, Stderr: []byte("tool 1.2.3: license expired\n")}
	}}
	r := extruntest.NewRunner("linux", extruntest.Files{"/usr/bin/tool": {}}, ex, nil)
	req := extrun.Request{Component: "projects", Program: extrun.Program{Path: "/usr/bin/tool"}}
	for i := 0; i < 2; i++ {
		v, res := r.ProbeVersion(context.Background(), req, extrun.VersionProbe{Args: []string{"-V"}})
		if v.Version != "1.2.3" || v.Cached || res.Outcome != extrun.OutcomeExitNonZero {
			t.Fatalf("probe %d = %+v %s", i, v, res.Outcome)
		}
	}
	if len(ex.Calls()) != 2 {
		t.Fatalf("a failed probe was cached: %d calls", len(ex.Calls()))
	}
}
