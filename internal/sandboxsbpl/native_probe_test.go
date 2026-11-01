package sandboxsbpl

import (
	"errors"
	"strings"
	"testing"
)

func TestNativeN6Table(t *testing.T) {
	cases := []struct {
		name string
		in   Native
		want NativeOutcome
		rule string
		env  string
		args string
	}{
		{"no Seatbelt of its own", Native{}, NativeKept, "N6-none", "", ""},
		{"vendor forced", Native{Seatbelt: true, DefaultOn: true, VendorForced: true, Switch: SwitchFlag, Value: "--sandbox danger-full-access", Args: []string{"--sandbox", "danger-full-access"}}, NativeRefuse, "N6-vendor-forced", "", ""},
		{"vendor forced although off by default", Native{Seatbelt: true, VendorForced: true}, NativeRefuse, "N6-vendor-forced", "", ""},
		{"off by default", Native{Seatbelt: true, Switch: SwitchGlobalSetting, Value: "sandbox.enabled: false"}, NativeUnjudged, "N6-off-by-default", "", ""},
		{"env switch", Native{Seatbelt: true, DefaultOn: true, Switch: SwitchEnv, Value: "AGENT_SANDBOX=off"}, NativeDisableEnv, "N6-env", "AGENT_SANDBOX=off", ""},
		{"env placeholder is not a value", Native{Seatbelt: true, DefaultOn: true, Switch: SwitchEnv, Value: "SANDBOX=<label>"}, NativeRefuse, "N6-no-per-run-switch", "", ""},
		{"flag switch (lane SBX-P3D)", Native{Seatbelt: true, DefaultOn: true, Switch: SwitchFlag, Value: "--sandbox danger-full-access", Args: []string{"--sandbox", "danger-full-access"}}, NativeDisableFlag, "N6-flag", "", "--sandbox,danger-full-access"},
		{"flag switch the boundary did not validate", Native{Seatbelt: true, DefaultOn: true, Switch: SwitchFlag, Value: "--x; rm -rf /"}, NativeRefuse, "N6-no-per-run-switch", "", ""},
		{"global setting only", Native{Seatbelt: true, DefaultOn: true, Switch: SwitchGlobalSetting}, NativeRefuse, "N6-no-per-run-switch", "", ""},
		{"no switch", Native{Seatbelt: true, DefaultOn: true}, NativeRefuse, "N6-no-per-run-switch", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := DecideNative(c.in)
			if d.Outcome != c.want || d.Rule != c.rule {
				t.Fatalf("got %s %s, want %s %s", d.Outcome, d.Rule, c.want, c.rule)
			}
			if got := strings.Join(d.Env, ","); got != c.env {
				t.Fatalf("env = %q, want %q", got, c.env)
			}
			if got := strings.Join(d.Args, ","); got != c.args {
				t.Fatalf("args = %q, want %q", got, c.args)
			}
		})
	}
}

func goodEnv() ProbeEnv {
	return ProbeEnv{
		GOOS: "darwin", Active: true,
		OSVersion: func() (string, error) { return "26.0.1", nil },
		StatExec:  func(string) (ExecFacts, error) { return ExecFacts{Regular: true, OwnerUID: 0, Perm: 0o755}, nil },
	}
}

func TestProbeLadder(t *testing.T) {
	cases := []struct {
		name    string
		mut     func(*ProbeEnv)
		verdict string
		rule    string
	}{
		{"available", func(*ProbeEnv) {}, VerdictAvailable, "P4 sandbox-exec"},
		{"linux", func(e *ProbeEnv) { e.GOOS = "linux" }, VerdictUnsupportedPlatform, "P1 platform"},
		{"windows", func(e *ProbeEnv) { e.GOOS = "windows" }, VerdictUnsupportedPlatform, "P1 platform"},
		{"inactive", func(e *ProbeEnv) { e.Active = false }, VerdictDisabledByConfig, "P2 active"},
		{"version unreadable", func(e *ProbeEnv) { e.OSVersion = func() (string, error) { return "", errors.New("no") } }, VerdictVersionUntested, "P3 macOS version"},
		{"version garbage", func(e *ProbeEnv) { e.OSVersion = func() (string, error) { return "twenty", nil } }, VerdictVersionUntested, "P3 macOS version"},
		{"below floor", func(e *ProbeEnv) { e.OSVersion = func() (string, error) { return "11.7", nil } }, VerdictOSTooOld, "P3 macOS version"},
		{"sandbox-exec missing", func(e *ProbeEnv) {
			e.StatExec = func(string) (ExecFacts, error) { return ExecFacts{}, errors.New("no such file") }
		}, VerdictBackendMissing, "P4 sandbox-exec"},
		{"sandbox-exec not root-owned", func(e *ProbeEnv) {
			e.StatExec = func(string) (ExecFacts, error) { return ExecFacts{Regular: true, OwnerUID: 501, Perm: 0o755}, nil }
		}, VerdictBackendUntrusted, "P4 sandbox-exec"},
		{"sandbox-exec group writable", func(e *ProbeEnv) {
			e.StatExec = func(string) (ExecFacts, error) { return ExecFacts{Regular: true, Perm: 0o775}, nil }
		}, VerdictBackendUntrusted, "P4 sandbox-exec"},
		{"sandbox-exec a symlink", func(e *ProbeEnv) {
			e.StatExec = func(string) (ExecFacts, error) { return ExecFacts{Regular: false, Perm: 0o755}, nil }
		}, VerdictBackendUntrusted, "P4 sandbox-exec"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			env := goodEnv()
			c.mut(&env)
			r := Probe(env)
			if r.Verdict.Code != c.verdict || r.Rule != c.rule {
				t.Fatalf("got %s at %s (%s), want %s at %s", r.Verdict.Code, r.Rule, r.Verdict.Reason, c.verdict, c.rule)
			}
		})
	}
}

// TestProbeTouchesNothingWhileInactive: an inactive driver reads neither the
// version nor the binary (the opt-in rule).
func TestProbeTouchesNothingWhileInactive(t *testing.T) {
	calls := 0
	env := ProbeEnv{
		GOOS:      "darwin",
		OSVersion: func() (string, error) { calls++; return "26.0", nil },
		StatExec:  func(string) (ExecFacts, error) { calls++; return ExecFacts{}, nil },
	}
	if r := Probe(env); r.Verdict.Code != VerdictDisabledByConfig || calls != 0 {
		t.Fatalf("verdict %s after %d calls", r.Verdict.Code, calls)
	}
}

func TestJudgeOSVersion(t *testing.T) {
	cases := []struct {
		v    string
		want VersionStatus
		note string
	}{
		{"11.7.10", VersionRefused, ""},
		{"12.0", VersionBeta, "outside"},
		{"14.0", VersionOK, ""},
		{"15.6.1", VersionOK, ""},
		{"26.1", VersionOK, ""},
		{"27.0", VersionBeta, FallbackDriver},
		{"x", VersionRefused, ""},
	}
	for _, c := range cases {
		got, note := JudgeOSVersion(c.v)
		if got != c.want || (c.note != "" && !strings.Contains(note, c.note)) || (c.note == "" && note != "") {
			t.Errorf("%s: %s %q, want %s with %q", c.v, got, note, c.want, c.note)
		}
	}
}

func TestSelfTest(t *testing.T) {
	good := SelfTestReport{WorkspaceWritable: true, TempWritable: true}
	r, err := ParseSelfTest(good.String())
	if err != nil || r != good {
		t.Fatalf("round trip: %+v %v", r, err)
	}
	if v := JudgeSelfTest(good, true); !v.OK() {
		t.Fatal(v)
	}
	leaks := []SelfTestReport{
		{ObserverDirReadable: true, WorkspaceWritable: true, TempWritable: true},
		{SocketParentReadable: true, WorkspaceWritable: true, TempWritable: true},
		{HomeListable: true, WorkspaceWritable: true, TempWritable: true},
		{ForbiddenConnect: true, WorkspaceWritable: true, TempWritable: true},
	}
	for _, l := range leaks {
		if v := JudgeSelfTest(l, true); v.Code != VerdictBuiltBelowPlan {
			t.Errorf("%+v judged %s", l, v.Code)
		}
	}
	if v := JudgeSelfTest(SelfTestReport{HomeListable: true, WorkspaceWritable: true, TempWritable: true}, false); !v.OK() {
		t.Error("a listable home in readonly mode is the plan, not a leak")
	}
	if v := JudgeSelfTest(SelfTestReport{TempWritable: true}, true); v.Code != VerdictSelfTestFailed {
		t.Error(v)
	}
	for _, bad := range []string{"", "obs=0", "obs=2 sockp=0 home=0 net=0 ws=1 tmp=1", "obs=0 obs=0 sockp=0 home=0 net=0 ws=1 tmp=1", "obs=0 sockp=0 home=0 net=0 ws=1 tmp=1 x=1"} {
		if _, err := ParseSelfTest(bad); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
}
