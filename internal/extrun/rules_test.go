package extrun

import (
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestBuildEnv(t *testing.T) {
	t.Parallel()
	daemon := map[string]string{
		"HOME": "/home/dev", "LANG": "C.UTF-8", "ANTHROPIC_API_KEY": "sk-x",
		"OBSERVER_LOC_EDITOR_TOKEN": "t", "HTTPS_PROXY": "http://u:p@proxy",
		"GITHUB_TOKEN": "g", "SystemRoot": `C:\Windows`,
		"DATABASE_URL": "postgres://u:p@db/x", "REDIS_URL": "redis://:p@cache", "STRIPE_APIKEY": "k",
		"SENTRY_DSN": "https://key@sentry.example/1", "TEST_DATABASE_URL": "postgres://u:p@db/t",
		"homepage_url": "https://example.com",
	}
	getenv := func(n string) (string, bool) { v, ok := daemon[n]; return v, ok }
	cases := []struct {
		name    string
		goos    string
		spec    EnvSpec
		want    []string
		wantErr string
	}{
		{name: "empty spec gives empty env", goos: "linux", want: []string{}},
		{name: "nothing inherited unless named", goos: "linux", spec: EnvSpec{Inherit: []string{"LANG"}}, want: []string{"LANG=C.UTF-8"}},
		{name: "named but unset is skipped", goos: "linux", spec: EnvSpec{Inherit: []string{"TZ"}}, want: []string{}},
		{
			name: "literal set and inherit sorted", goos: "linux", spec: EnvSpec{Set: []string{"NO_COLOR=1", "HOME=/scratch"}, Inherit: []string{"LANG"}},
			want: []string{"HOME=/scratch", "LANG=C.UTF-8", "NO_COLOR=1"},
		},
		{name: "path dirs become PATH", goos: "linux", spec: EnvSpec{PathDirs: []string{"/usr/bin", "/bin"}}, want: []string{"PATH=/usr/bin:/bin"}},
		{name: "windows path separator", goos: "windows", spec: EnvSpec{PathDirs: []string{`C:\Windows\System32`, `C:\tools`}}, want: []string{`PATH=C:\Windows\System32;C:\tools`}},
		{name: "relative path dir refused", goos: "linux", spec: EnvSpec{PathDirs: []string{"bin"}}, wantErr: "not one absolute directory"},
		{name: "path dir holding a separator refused", goos: "linux", spec: EnvSpec{PathDirs: []string{"/a:/b"}}, wantErr: "not one absolute directory"},
		{name: "PATH through Set refused", goos: "linux", spec: EnvSpec{Set: []string{"PATH=/bin"}}, wantErr: "PATH comes only from PathDirs"},
		{name: "PATH through Inherit refused", goos: "linux", spec: EnvSpec{Inherit: []string{"PATH"}}, wantErr: "PATH comes only from PathDirs"},
		{name: "loader injection refused in Set", goos: "linux", spec: EnvSpec{Set: []string{"LD_PRELOAD=/x.so"}}, wantErr: "dynamic loader injection"},
		{name: "loader injection refused lower-case", goos: "darwin", spec: EnvSpec{Set: []string{"dyld_insert_libraries=/x"}}, wantErr: "dynamic loader injection"},
		{name: "provider key may not be inherited", goos: "linux", spec: EnvSpec{Inherit: []string{"ANTHROPIC_API_KEY"}}, wantErr: "AI provider credentials"},
		{name: "provider key may be set as a literal", goos: "linux", spec: EnvSpec{Set: []string{"ANTHROPIC_API_KEY=sk-caller"}}, want: []string{"ANTHROPIC_API_KEY=sk-caller"}},
		{name: "daemon token may not be inherited", goos: "linux", spec: EnvSpec{Inherit: []string{"OBSERVER_LOC_EDITOR_TOKEN"}}, wantErr: "the daemon's own"},
		{name: "proxy may not be inherited", goos: "linux", spec: EnvSpec{Inherit: []string{"HTTPS_PROXY"}}, wantErr: "proxy settings"},
		{name: "forge token may not be inherited", goos: "linux", spec: EnvSpec{Inherit: []string{"GITHUB_TOKEN"}}, wantErr: "forge credentials"},
		{name: "credential suffix may not be inherited", goos: "linux", spec: EnvSpec{Inherit: []string{"MY_SERVICE_PASSWORD"}}, wantErr: "credential-shaped"},
		{name: "APIKEY without an underscore may not be inherited", goos: "linux", spec: EnvSpec{Inherit: []string{"STRIPE_APIKEY"}}, wantErr: "credential-shaped"},
		{name: "DATABASE_URL may not be inherited", goos: "linux", spec: EnvSpec{Inherit: []string{"DATABASE_URL"}}, wantErr: "connection URL"},
		{name: "a prefixed DATABASE_URL may not be inherited", goos: "linux", spec: EnvSpec{Inherit: []string{"TEST_DATABASE_URL"}}, wantErr: "connection URL"},
		{name: "REDIS_URL may not be inherited", goos: "linux", spec: EnvSpec{Inherit: []string{"REDIS_URL"}}, wantErr: "connection URL"},
		{name: "a DSN may not be inherited", goos: "linux", spec: EnvSpec{Inherit: []string{"SENTRY_DSN"}}, wantErr: "connection URL"},
		{name: "a connection URL may be set as a literal", goos: "linux", spec: EnvSpec{Set: []string{"DATABASE_URL=postgres://caller"}}, want: []string{"DATABASE_URL=postgres://caller"}},
		{name: "a plain URL name is still inheritable", goos: "linux", spec: EnvSpec{Inherit: []string{"homepage_url"}}, want: []string{"homepage_url=https://example.com"}},
		{name: "duplicate name refused", goos: "linux", spec: EnvSpec{Set: []string{"LANG=C"}, Inherit: []string{"LANG"}}, wantErr: "named twice"},
		{name: "windows names are case-insensitive", goos: "windows", spec: EnvSpec{Set: []string{"Path2=x", "PATH2=y"}}, wantErr: "named twice"},
		{name: "unix names are case-sensitive", goos: "linux", spec: EnvSpec{Set: []string{"Foo=x", "FOO=y"}}, want: []string{"FOO=y", "Foo=x"}},
		{name: "malformed set refused", goos: "linux", spec: EnvSpec{Set: []string{"NOEQUALS"}}, wantErr: "not NAME=VALUE"},
		{name: "empty name refused", goos: "linux", spec: EnvSpec{Set: []string{"=x"}}, wantErr: "not NAME=VALUE"},
		{name: "NUL value refused", goos: "linux", spec: EnvSpec{Set: []string{"A=x\x00y"}}, wantErr: "NUL"},
		{name: "windows essentials inherited by name", goos: "windows", spec: EnvSpec{Inherit: []string{"SystemRoot"}}, want: []string{`SystemRoot=C:\Windows`}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := BuildEnv(tc.spec, tc.goos, getenv)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want it to contain %q", err, tc.wantErr)
				}
				if got != nil {
					t.Fatalf("a refused build returned a partial env %v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("env = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestIsAbs(t *testing.T) {
	t.Parallel()
	cases := []struct {
		goos, p string
		want    bool
	}{
		{"linux", "/usr/bin/git", true},
		{"linux", "git", false},
		{"linux", "./git", false},
		{"linux", `C:\git.exe`, false},
		{"windows", `C:\Program Files\Git\bin\git.exe`, true},
		{"windows", `c:/tools/x.exe`, true},
		{"windows", `\\server\share\x.exe`, true},
		{"windows", `\\`, false},
		{"windows", `C:git.exe`, false},
		{"windows", `\git.exe`, false},
		{"windows", "git.exe", false},
	}
	for _, tc := range cases {
		if got := IsAbs(tc.goos, tc.p); got != tc.want {
			t.Errorf("IsAbs(%s, %q) = %v, want %v", tc.goos, tc.p, got, tc.want)
		}
	}
}

func TestResolveLimits(t *testing.T) {
	t.Parallel()
	got, ok := ResolveLimits(Limits{})
	want := Limits{Wall: DefaultWall, StdoutBytes: DefaultStdoutBytes, StderrBytes: DefaultStderrBytes}
	if !ok || got != want {
		t.Fatalf("zero limits = %+v %v, want %+v", got, ok, want)
	}
	set := Limits{Wall: time.Second, StdoutBytes: 10, StderrBytes: 20, MemoryBytes: 30, Children: 4}
	if got, ok := ResolveLimits(set); !ok || got != set {
		t.Fatalf("set limits changed: %+v", got)
	}
	for _, bad := range []Limits{{Wall: -1}, {StdoutBytes: -1}, {StderrBytes: -1}, {MemoryBytes: -1}, {Children: -1}, {CPU: -1}, {FileBytes: -1}} {
		if _, ok := ResolveLimits(bad); ok {
			t.Errorf("negative limits %+v accepted", bad)
		}
	}
}

func TestPlanCaps(t *testing.T) {
	t.Parallel()
	linuxLike := Platform{Caps: map[Cap]CapState{
		CapWall: CapEnforced, CapStdout: CapEnforced, CapStderr: CapEnforced,
		CapMemory: CapBestEffort, CapChildren: CapBestEffort,
	}}
	darwinLike := Platform{Caps: map[Cap]CapState{CapWall: CapEnforced, CapStdout: CapEnforced, CapStderr: CapEnforced}}
	l, _ := ResolveLimits(Limits{Wall: 3 * time.Second, MemoryBytes: 1 << 20, Children: 2})
	cases := []struct {
		name string
		l    Limits
		p    Platform
		want map[Cap]CapState
	}{
		{
			"linux-like holds memory and children best effort", l, linuxLike,
			map[Cap]CapState{CapWall: CapEnforced, CapStdout: CapEnforced, CapStderr: CapEnforced, CapMemory: CapBestEffort, CapChildren: CapBestEffort},
		},
		{
			"a cap the platform does not name is not enforced, never claimed", l, darwinLike,
			map[Cap]CapState{CapWall: CapEnforced, CapStdout: CapEnforced, CapStderr: CapEnforced, CapMemory: CapNotEnforced, CapChildren: CapNotEnforced},
		},
		{
			"an unrequested cap is off",
			Limits{Wall: time.Second, StdoutBytes: 1, StderrBytes: 1},
			linuxLike,
			map[Cap]CapState{CapWall: CapEnforced, CapStdout: CapEnforced, CapStderr: CapEnforced, CapMemory: CapOff, CapChildren: CapOff},
		},
		{
			"a sub-second wall is still requested",
			Limits{Wall: time.Millisecond, StdoutBytes: 1, StderrBytes: 1},
			darwinLike,
			map[Cap]CapState{CapWall: CapEnforced, CapStdout: CapEnforced, CapStderr: CapEnforced, CapMemory: CapOff, CapChildren: CapOff},
		},
		{
			"an empty platform enforces nothing", l,
			Platform{},
			map[Cap]CapState{CapWall: CapNotEnforced, CapStdout: CapNotEnforced, CapStderr: CapNotEnforced, CapMemory: CapNotEnforced, CapChildren: CapNotEnforced},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := PlanCaps(tc.l, tc.p)
			if len(got) != len(capTable) {
				t.Fatalf("got %d caps, want %d", len(got), len(capTable))
			}
			for i, c := range got {
				if c.Cap != capTable[i].cap {
					t.Errorf("cap %d is %s, want table order %s", i, c.Cap, capTable[i].cap)
				}
				want := tc.want[c.Cap]
				if want == "" {
					want = CapOff
				}
				if c.State != want {
					t.Errorf("%s = %s, want %s", c.Cap, c.State, want)
				}
			}
		})
	}
}

func TestCheckFile(t *testing.T) {
	t.Parallel()
	reg := FileFacts{Exists: true, Real: "/usr/bin/git", Regular: true}
	link := FileFacts{Exists: true, Symlink: true, Real: "/opt/node/lib/cli.js", Regular: true}
	cases := []struct {
		name    string
		goos    string
		path    string
		f       FileFacts
		allow   bool
		want    RefuseReason
		wantRun string
	}{
		{"regular absolute file runs", "linux", "/usr/bin/git", reg, false, RefuseNone, "/usr/bin/git"},
		{"bare name refused", "linux", "git", reg, false, RefuseNotAbsolute, ""},
		{"missing refused", "linux", "/usr/bin/nope", FileFacts{}, false, RefuseNotFound, ""},
		{"symlink refused by default", "linux", "/usr/local/bin/tool", link, false, RefuseSymlink, ""},
		{"symlink allowed runs its target", "linux", "/usr/local/bin/tool", link, true, RefuseNone, "/opt/node/lib/cli.js"},
		{"directory refused", "linux", "/usr/bin", FileFacts{Exists: true, Real: "/usr/bin"}, false, RefuseNotRegular, ""},
		{"dangling link refused", "linux", "/usr/local/bin/x", FileFacts{Exists: true, Symlink: true}, true, RefuseNotRegular, ""},
		{"windows batch file refused", "windows", `C:\npm\tool.cmd`, FileFacts{Exists: true, Real: `C:\npm\tool.cmd`, Regular: true}, false, RefuseScriptShim, ""},
		{"windows powershell refused", "windows", `C:\x\tool.PS1`, FileFacts{Exists: true, Real: `C:\x\tool.PS1`, Regular: true}, false, RefuseScriptShim, ""},
		{"windows exe runs", "windows", `C:\x\tool.exe`, FileFacts{Exists: true, Real: `C:\x\tool.exe`, Regular: true}, false, RefuseNone, `C:\x\tool.exe`},
		{"a .cmd name is fine off Windows", "linux", "/opt/x/tool.cmd", FileFacts{Exists: true, Real: "/opt/x/tool.cmd", Regular: true}, false, RefuseNone, "/opt/x/tool.cmd"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, detail, run := CheckFile(tc.goos, tc.path, tc.f, tc.allow)
			if got != tc.want || run != tc.wantRun {
				t.Fatalf("CheckFile = %q %q, want %q %q", got, run, tc.want, tc.wantRun)
			}
			if got != RefuseNone && detail == "" {
				t.Fatal("a refusal carries no detail")
			}
		})
	}
}

func TestCompareDigests(t *testing.T) {
	t.Parallel()
	got := Digests{Binary: "aa", Companions: map[string]string{"/x/a.dll": "11", "/x/b.dll": "22"}}
	cases := []struct {
		name   string
		expect *Digests
		want   []Mismatch
	}{
		{"nil expectation compares nothing", nil, nil},
		{"empty fields compare nothing", &Digests{}, nil},
		{"all match, hex case ignored", &Digests{Binary: "AA", Companions: map[string]string{"/x/a.dll": "11"}}, nil},
		{"binary mismatch", &Digests{Binary: "bb"}, []Mismatch{{Expected: "bb", Actual: "aa"}}},
		{
			"companion mismatch and missing companion, sorted", &Digests{Companions: map[string]string{"/x/z.dll": "99", "/x/b.dll": "23"}},
			[]Mismatch{{Path: "/x/b.dll", Expected: "23", Actual: "22"}, {Path: "/x/z.dll", Expected: "99", Actual: ""}},
		},
	}
	for _, tc := range cases {
		if m := CompareDigests(tc.expect, got); !reflect.DeepEqual(m, tc.want) {
			t.Errorf("%s: got %+v, want %+v", tc.name, m, tc.want)
		}
	}
}

func TestClassify(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		f    ExecFacts
		want Outcome
	}{
		{"start failure outranks all", ExecFacts{StartErr: "x", KillReason: KillTimeout}, OutcomeStartFailed},
		{"cancel", ExecFacts{KillReason: KillCanceled, Signaled: true}, OutcomeCanceled},
		{"timeout outranks the kill signal", ExecFacts{KillReason: KillTimeout, Signaled: true, Signal: "killed"}, OutcomeTimeout},
		{"output cap", ExecFacts{KillReason: KillOutputCap, Signaled: true}, OutcomeOutputCap},
		{"children cap", ExecFacts{KillReason: KillChildrenCap}, OutcomeChildrenCap},
		{"a signal the runner did not send", ExecFacts{Signaled: true, Signal: "segmentation fault", ExitCode: -1}, OutcomeSignaled},
		{"exit 0", ExecFacts{}, OutcomeOK},
		{"exit 3", ExecFacts{ExitCode: 3}, OutcomeExitNonZero},
	}
	for _, tc := range cases {
		if got := Classify(tc.f); got != tc.want {
			t.Errorf("%s: got %s, want %s", tc.name, got, tc.want)
		}
	}
}

func TestDeclaresProcess(t *testing.T) {
	t.Parallel()
	cases := []struct {
		declared []string
		path     string
		want     bool
	}{
		{[]string{"git (read-only log)"}, "/usr/bin/git", true},
		{[]string{"git (worktrees)", "AI agent CLIs"}, `C:\Program Files\Git\cmd\git.exe`, true},
		{[]string{"codex app-server, kiro-cli, amp, auggie (only for a Plans & limits account using that tool)"}, "/home/u/.local/bin/kiro-cli", true},
		{[]string{"codex app-server, kiro-cli, amp, auggie"}, "/usr/bin/auggie", true},
		{[]string{"ssh"}, "/usr/bin/ssh-keygen", false},
		{[]string{"ssh-keygen."}, "/usr/bin/ssh-keygen", true},
		{[]string{"vendor AI tool CLIs"}, "/usr/bin/claude", false},
		{[]string{"bwrap"}, "/usr/bin/BWRAP", true},
		{nil, "/usr/bin/git", false},
		{[]string{"git"}, "", false},
	}
	for _, tc := range cases {
		if got := DeclaresProcess(tc.declared, tc.path); got != tc.want {
			t.Errorf("DeclaresProcess(%q, %q) = %v, want %v", tc.declared, tc.path, got, tc.want)
		}
	}
}

func TestParseVersion(t *testing.T) {
	t.Parallel()
	custom := regexp.MustCompile(`build (\d+)`)
	cases := []struct {
		name     string
		out      string
		re       *regexp.Regexp
		want     string
		wantLine string
	}{
		{"git", "git version 2.43.0\n", nil, "2.43.0", "git version 2.43.0"},
		{"leading v dropped", "opengrep v1.6.0 (abc)\n", nil, "1.6.0", "opengrep v1.6.0 (abc)"},
		{"prerelease kept", "tool 1.19.0-rc.1+meta\n", nil, "1.19.0-rc.1+meta", "tool 1.19.0-rc.1+meta"},
		{"second line", "banner\nosv-scanner version: 2.0.1\n", nil, "2.0.1", "osv-scanner version: 2.0.1"},
		{"two-part version", "x 3.12\n", nil, "3.12", "x 3.12"},
		{"nothing", "no version here\n", nil, "", ""},
		{"custom pattern", "tool build 7731\n", custom, "7731", "tool build 7731"},
	}
	for _, tc := range cases {
		v, line := ParseVersion([]byte(tc.out), tc.re)
		if v != tc.want || line != tc.wantLine {
			t.Errorf("%s: got %q %q, want %q %q", tc.name, v, line, tc.want, tc.wantLine)
		}
	}
}

func TestCPUSeconds(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		in   time.Duration
		want int64
	}{
		{0, 0},
		{-time.Second, 0},
		{time.Millisecond, 1},
		{time.Second, 1},
		{1500 * time.Millisecond, 2},
		{90 * time.Second, 90},
	} {
		if got := CPUSeconds(tc.in); got != tc.want {
			t.Errorf("CPUSeconds(%v) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestMechanismState(t *testing.T) {
	t.Parallel()
	for mech, want := range map[string]CapState{
		MechCgroup:      CapEnforced,
		MechJob:         CapEnforced,
		MechTimer:       CapEnforced,
		MechPipe:        CapEnforced,
		MechRlimitFsize: CapEnforced,
		MechRlimitData:  CapBestEffort,
		MechRlimitCPU:   CapBestEffort,
		MechPoll:        CapBestEffort,
		MechJobCPU:      CapBestEffort,
		"":              CapNotEnforced,
		"rlimit_as":     CapNotEnforced,
	} {
		if got := MechanismState(mech); got != want {
			t.Errorf("MechanismState(%q) = %s, want %s", mech, got, want)
		}
	}
}

func TestPlanCapsUnits(t *testing.T) {
	t.Parallel()
	l := Limits{Wall: time.Second, StdoutBytes: 1, StderrBytes: 1, MemoryBytes: 1, Children: 64, CPU: time.Second, FileBytes: 1}
	units := map[Cap]string{}
	for _, c := range PlanCaps(l, Platform{}) {
		units[c.Cap] = c.Unit
	}
	want := map[Cap]string{
		CapWall: UnitSeconds, CapStdout: UnitBytes, CapStderr: UnitBytes, CapMemory: UnitBytes,
		CapChildren: UnitProcesses, CapCPU: UnitSeconds, CapFileSize: UnitBytes,
	}
	if !reflect.DeepEqual(units, want) {
		t.Fatalf("units = %v, want %v", units, want)
	}
	for _, c := range PlanCaps(l, Platform{ChildrenUnit: UnitTasks}) {
		if c.Cap == CapChildren && c.Unit != UnitTasks {
			t.Fatalf("children unit %q, want the platform's %q", c.Unit, UnitTasks)
		}
	}
}

func TestApplyApplied(t *testing.T) {
	t.Parallel()
	plan := func() []CapResult {
		return []CapResult{
			{Cap: CapMemory, Limit: 100, State: CapBestEffort, Unit: UnitBytes},
			{Cap: CapChildren, Limit: 64, State: CapBestEffort, Unit: UnitProcesses},
			{Cap: CapCPU, Limit: 2, State: CapBestEffort, Unit: UnitSeconds},
			{Cap: CapFileSize, Limit: 0, State: CapOff, Unit: UnitBytes},
		}
	}
	cases := []struct {
		name    string
		applied map[Cap]CapApplied
		want    []CapResult
	}{
		{"nothing reported keeps the plan", nil, plan()},
		{
			"a cgroup raises memory and children, with the cgroup's unit",
			map[Cap]CapApplied{CapMemory: {Mechanism: MechCgroup}, CapChildren: {Mechanism: MechCgroup, Unit: UnitTasks}},
			[]CapResult{
				{Cap: CapMemory, Limit: 100, State: CapEnforced, Unit: UnitBytes, Mechanism: MechCgroup},
				{Cap: CapChildren, Limit: 64, State: CapEnforced, Unit: UnitTasks, Mechanism: MechCgroup},
				{Cap: CapCPU, Limit: 2, State: CapBestEffort, Unit: UnitSeconds},
				{Cap: CapFileSize, Limit: 0, State: CapOff, Unit: UnitBytes},
			},
		},
		{
			"no mechanism (no trampoline) lowers to not enforced",
			map[Cap]CapApplied{CapCPU: {}},
			[]CapResult{
				{Cap: CapMemory, Limit: 100, State: CapBestEffort, Unit: UnitBytes},
				{Cap: CapChildren, Limit: 64, State: CapBestEffort, Unit: UnitProcesses},
				{Cap: CapCPU, Limit: 2, State: CapNotEnforced, Unit: UnitSeconds},
				{Cap: CapFileSize, Limit: 0, State: CapOff, Unit: UnitBytes},
			},
		},
		{
			"an off cap stays off whatever the executor says",
			map[Cap]CapApplied{CapFileSize: {Mechanism: MechRlimitFsize}},
			plan(),
		},
		{
			"a translated limit replaces the planned one",
			map[Cap]CapApplied{CapChildren: {Mechanism: MechJob, Unit: UnitProcesses, Limit: 65}},
			[]CapResult{
				{Cap: CapMemory, Limit: 100, State: CapBestEffort, Unit: UnitBytes},
				{Cap: CapChildren, Limit: 65, State: CapEnforced, Unit: UnitProcesses, Mechanism: MechJob},
				{Cap: CapCPU, Limit: 2, State: CapBestEffort, Unit: UnitSeconds},
				{Cap: CapFileSize, Limit: 0, State: CapOff, Unit: UnitBytes},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := applyApplied(plan(), tc.applied); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %+v\nwant %+v", got, tc.want)
			}
		})
	}
}

func TestDirOfAndJoinPath(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ goos, in, want string }{
		{"linux", "/usr/local/go/bin/go", "/usr/local/go/bin"},
		{"linux", "/go", "/"},
		{"linux", "go", ""},
		{"windows", `C:\Go\bin\go.exe`, `C:\Go\bin`},
		{"windows", `C:\go.exe`, `C:\`},
		{"windows", `C:/tools/go.exe`, `C:/tools`},
	} {
		if got := dirOf(tc.goos, tc.in); got != tc.want {
			t.Errorf("dirOf(%s, %q) = %q, want %q", tc.goos, tc.in, got, tc.want)
		}
	}
	if got := joinPath("linux", "/c/", "home"); got != "/c/home" {
		t.Errorf("joinPath linux = %q", got)
	}
	if got := joinPath("windows", `C:\c\`, "home"); got != `C:\c\home` {
		t.Errorf("joinPath windows = %q", got)
	}
}
