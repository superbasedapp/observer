package sandboxapple

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

const testDigest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func testPlan() RunPlan {
	return RunPlan{
		CLI: "/usr/local/bin/container", RunID: "RunLive_0123456789abcd", InstallID: "a1b2c3d4e5f60718",
		Name:  ContainerName("a1b2c3d4e5f60718", "RunLive_0123456789abcd"),
		Image: "ghcr.io/example/agent@sha256:" + testDigest, MemoryMiB: 4096, CPUs: 4, UID: 501, GID: 20,
		WorkDir: "/Users/dev/src/app",
		Mounts: []Mount{
			{Source: "/Users/dev/src/app", Target: "/Users/dev/src/app"},
			{Source: "/Users/dev/.claude", Target: "/Users/dev/.claude"},
			{Source: "/private/var/folders/xy/abc/T/obsbx/RunLive_0123456789abcd", Target: GuestSocketDir, ReadOnly: true},
		},
		Env:     []string{"HOME=/Users/dev", "OBSERVER_SANDBOX=1"},
		EnvFile: "/private/var/folders/xy/abc/T/obsbx-tmp/RunLive_0123456789abcd/env",
		Command: []string{GuestObserverPath, InitVerb, "--host-bin", "/opt/homebrew/bin/observer", "--uid", "501", "--gid", "20", "--", GuestObserverPath, "claude"},
	}
}

func TestRunArgv(t *testing.T) {
	argv, err := RunArgv(testPlan())
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(argv, " ")
	for _, want := range []string{
		"/usr/local/bin/container run -it --rm --progress none --name observer-a1b2c3d4e5f60718-",
		"--entrypoint /usr/local/bin/observer",
		"-l observer.run=RunLive_0123456789abcd -l observer.install=a1b2c3d4e5f60718",
		"--network none", "--memory 4096M", "--cpus 4", "-w /Users/dev/src/app", "--env-file /private/var/folders/xy/abc/T/obsbx-tmp/RunLive_0123456789abcd/env",
		"-e HOME=/Users/dev", "-v /Users/dev/src/app:/Users/dev/src/app",
		"-v /private/var/folders/xy/abc/T/obsbx/RunLive_0123456789abcd:/tmp/.observer-sandbox-net:ro",
		"ghcr.io/example/agent@sha256:" + testDigest + " sandbox-apple-init",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("argv lacks %q:\n%s", want, joined)
		}
	}
	if slices.Contains(argv, "machine") {
		t.Fatal("machine in a run argv")
	}
}

func TestRunArgvRefusals(t *testing.T) {
	cases := map[string]func(*RunPlan){
		"tag image":        func(p *RunPlan) { p.Image = "ghcr.io/example/agent:latest" },
		"relative cli":     func(p *RunPlan) { p.CLI = "container" },
		"bad run id":       func(p *RunPlan) { p.RunID = "a b" },
		"bad name":         func(p *RunPlan) { p.Name = "Observer_X" },
		"memory":           func(p *RunPlan) { p.MemoryMiB = 64 },
		"cpus":             func(p *RunPlan) { p.CPUs = 0 },
		"colon in mount":   func(p *RunPlan) { p.Mounts = append(p.Mounts, Mount{Source: "/a:b", Target: "/c"}) },
		"relative target":  func(p *RunPlan) { p.Mounts = append(p.Mounts, Mount{Source: "/a", Target: "c"}) },
		"root mount":       func(p *RunPlan) { p.Mounts = append(p.Mounts, Mount{Source: "/", Target: "/host"}) },
		"double target":    func(p *RunPlan) { p.Mounts = append(p.Mounts, Mount{Source: "/x", Target: GuestSocketDir}) },
		"bad env":          func(p *RunPlan) { p.Env = []string{"lower=1"} },
		"env newline":      func(p *RunPlan) { p.Env = []string{"A=1\nB=2"} },
		"empty command":    func(p *RunPlan) { p.Command = nil },
		"flag-shaped":      func(p *RunPlan) { p.Command = []string{"--privileged"} },
		"unclean work dir": func(p *RunPlan) { p.WorkDir = "/Users/dev/../x" },
		"negative uid":     func(p *RunPlan) { p.UID = -1 },
	}
	for name, mut := range cases {
		p := testPlan()
		mut(&p)
		if _, err := RunArgv(p); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestContainerMachineIsRefused is N10: `container machine` never runs,
// whatever position it takes before the image.
func TestContainerMachineIsRefused(t *testing.T) {
	for _, argv := range [][]string{
		{"/usr/local/bin/container", "machine", "start"},
		{"/usr/local/bin/container", "machines", "ls"},
		{"/usr/local/bin/container", "system", "machine"},
	} {
		if err := CheckArgv(argv); err == nil || !strings.Contains(err.Error(), "N10") {
			t.Errorf("%q: %v", argv, err)
		}
	}
	// After the image, "machine" is the container's own argument.
	argv, err := RunArgv(testPlan())
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckArgv(append(argv, "machine")); err != nil {
		t.Fatalf("an argument after the image was refused: %v", err)
	}
	noNet := []string{"/usr/local/bin/container", "run", "-it", "ghcr.io/x@sha256:" + testDigest}
	if err := CheckArgv(noNet); err == nil {
		t.Fatal("a run without --network none passed")
	}
	for _, a := range [][]string{ListArgv("/c"), InspectArgv("/c", "n"), RemoveArgv("/c", "n"), StatusArgv("/c"), VersionArgv("/c"), ImagesArgv("/c")} {
		if err := CheckArgv(a); err != nil {
			t.Errorf("%q: %v", a, err)
		}
	}
}

func TestContainerName(t *testing.T) {
	a := ContainerName("a1b2c3d4e5f60718", "Abc_def")
	b := ContainerName("a1b2c3d4e5f60718", "abc_def")
	if a == b {
		t.Fatal("two run ids differing in case share a name")
	}
	if !nameRE.MatchString(a) || len(a) > 63 {
		t.Fatalf("name %q", a)
	}
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name)) //nolint:gosec // G304: a fixed testdata path
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestContractList: the recorded `container ls --format json` shape.
func TestContractList(t *testing.T) {
	list, err := ParseList(readFixture(t, "ls.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 4 {
		t.Fatalf("%d containers", len(list))
	}
	c := list[0]
	if c.ID != "observer-a1b2c3d4e5f60718-1111111111111111" || c.Status != "running" || c.CPUs != 4 || c.MemoryBytes != 4<<30 || c.Labels[LabelRun] != "RunLive_0123456789abcd" {
		t.Fatalf("first %+v", c)
	}
	if web := list[3]; len(web.Networks) != 1 || web.Networks[0] != "default" {
		t.Fatalf("networks %+v", web.Networks)
	}
	for _, bad := range []string{`{"not":"a list"}`, `[{"status":"running","configuration":{}}]`, `not json`} {
		if _, err := ParseList([]byte(bad)); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
	if _, err := ParseList(make([]byte, maxListBytes+1)); err == nil {
		t.Error("an oversized output parsed")
	}
}

// TestOrphanSweep (MAC-17's unit half): only this install's containers
// whose run is gone are swept; another install's and foreign ones never.
func TestOrphanSweep(t *testing.T) {
	list, err := ParseList(readFixture(t, "ls.json"))
	if err != nil {
		t.Fatal(err)
	}
	live := func(run string) bool { return run == "RunLive_0123456789abcd" }
	got := Orphans(list, "a1b2c3d4e5f60718", live)
	if len(got) != 1 || got[0] != "observer-a1b2c3d4e5f60718-2222222222222222" {
		t.Fatalf("orphans %v", got)
	}
	if got := Orphans(list, "", live); len(got) != 0 {
		t.Fatalf("an empty install id swept %v", got)
	}
}

// TestContractInspectReadBack: the recorded inspect of a container built as
// planned passes; the weaker one (a network, a writable socket dir, an
// extra home mount) is built_below_plan.
func TestContractInspectReadBack(t *testing.T) {
	plan := testPlan()
	ok, err := ParseList(readFixture(t, "inspect.json"))
	if err != nil || len(ok) != 1 {
		t.Fatal(err)
	}
	if v := ReadBack(ok[0], plan); !v.OK() {
		t.Fatalf("the planned container refused: %v", v)
	}
	weak, err := ParseList(readFixture(t, "inspect_weaker.json"))
	if err != nil {
		t.Fatal(err)
	}
	v := ReadBack(weak[0], plan)
	if v.Code != VerdictBuiltBelowPlan {
		t.Fatalf("the weaker container passed: %v", v)
	}
	for _, want := range []string{"network default", "/tmp/.observer-sandbox-net is writable", "mounts /Users/dev,"} {
		if !strings.Contains(v.Reason, want) {
			t.Errorf("reason lacks %q: %s", want, v.Reason)
		}
	}
	other := ok[0]
	other.CPUs, other.MemoryBytes = 8, 1<<30
	other.Labels = map[string]string{LabelRun: "x", LabelInstall: "y"}
	if v := ReadBack(other, plan); v.OK() || !strings.Contains(v.Reason, "labels") || !strings.Contains(v.Reason, "CPUs") {
		t.Fatalf("limits and labels: %v", v)
	}
}

func TestContractImages(t *testing.T) {
	b := readFixture(t, "images.json")
	if ok, err := ImagePresent(b, "ghcr.io/example/agent@sha256:"+testDigest); err != nil || !ok {
		t.Fatalf("present: %v %v", ok, err)
	}
	if ok, _ := ImagePresent(b, "ghcr.io/example/agent@sha256:"+strings.Repeat("b", 64)); ok {
		t.Fatal("an absent digest matched")
	}
	if _, err := ImagePresent(b, "alpine:latest"); err == nil {
		t.Fatal("a tag was looked up")
	}
}

func TestGuestCommand(t *testing.T) {
	spec := InitSpec{
		HostBin: "/opt/homebrew/bin/observer", UID: 501, GID: 20, Relay: "RunLive_0123456789abcd",
		Mounts: []string{"/Users/dev/src/app", "/Users/dev/src/app/.git"}, ReadOnly: []string{"/Users/dev/src/app/.git/config"},
	}
	cmd, err := GuestCommand(spec, []string{GuestObserverPath, "sandbox-guest", "--"}, []string{"/opt/homebrew/bin/observer", "claude", "--resume"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		GuestObserverPath, InitVerb, "--host-bin", "/opt/homebrew/bin/observer", "--uid", "501", "--gid", "20",
		"--relay", "RunLive_0123456789abcd", "--mount", "/Users/dev/src/app", "--mount", "/Users/dev/src/app/.git", "--ro", "/Users/dev/src/app/.git/config",
		"--", GuestObserverPath, "sandbox-guest", "--", GuestObserverPath, "claude", "--resume",
	}
	if !slices.Equal(cmd, want) {
		t.Fatalf("%q", cmd)
	}
	ia, err := ParseInitArgs(cmd[2:])
	if err != nil || ia.HostBin != "/opt/homebrew/bin/observer" || ia.UID != 501 || ia.GID != 20 || ia.Command[0] != GuestObserverPath ||
		ia.Relay != spec.Relay || !slices.Equal(ia.Mounts, spec.Mounts) || !slices.Equal(ia.ReadOnly, spec.ReadOnly) {
		t.Fatalf("%+v %v", ia, err)
	}
	for _, bad := range [][]string{
		{"--host-bin", "rel", "--uid", "1", "--gid", "1", "--", "x"},
		{"--host-bin", "/a:b", "--uid", "1", "--gid", "1", "--", "x"},
		{"--host-bin", "/x", "--uid", "-1", "--gid", "1", "--", "x"},
		{"--host-bin", "/x", "--uid", "1", "--gid", "1", "--"},
		{"--host-bin", "/x", "--uid", "1", "--", "x"},
		{"--host-bin", "/x", "--uid", "1", "--gid", "1", "--uid", "2", "--", "x"},
		{"--host-bin", "/x", "--uid", "1", "--gid", "1", "--relay", "a b", "--", "x"},
		{"--host-bin", "/x", "--uid", "1", "--gid", "1", "--ro", "rel", "--", "x"},
		{"--host-bin", "/x", "--uid", "1", "--gid", "1", "--what", "/y", "--", "x"},
	} {
		if _, err := ParseInitArgs(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if _, err := GuestCommand(InitSpec{HostBin: "/o", UID: 1, GID: 1}, nil, nil); err == nil {
		t.Fatal("an empty inner launch was accepted")
	}
	if _, err := GuestCommand(InitSpec{HostBin: "/o", UID: 1, GID: 1, ReadOnly: []string{"/a:b"}}, nil, []string{"x"}); err == nil {
		t.Fatal("a checked path the argv cannot carry was accepted")
	}
}

func healthy() ProbeEnv {
	return ProbeEnv{
		GOOS: "darwin", Active: true,
		Arm64:      func() (bool, error) { return true, nil },
		OSVersion:  func() (string, error) { return "26.1", nil },
		Hypervisor: func() (bool, bool) { return true, true },
		LookCLI:    func() (string, error) { return "/usr/local/bin/container", nil },
		StatCLI:    func(string) (CLIFacts, error) { return CLIFacts{Regular: true, OwnerOK: true, Perm: 0o755}, nil },
		Version: func(string) (string, error) {
			return "container CLI version 1.6.0 (build: release, commit: 1a2b3c4)", nil
		},
		RunHelp:       func(string) (string, error) { return liveRunHelp, nil },
		SystemRunning: func(string) error { return nil },
		Image:         "ghcr.io/example/agent@sha256:" + testDigest,
		ImagePresent:  func(string, string) (bool, error) { return true, nil },
	}
}

func TestProbeLadder(t *testing.T) {
	cases := []struct {
		name    string
		mut     func(*ProbeEnv)
		verdict string
		rule    string
	}{
		{"available", func(*ProbeEnv) {}, VerdictAvailable, "A8 image"},
		{"linux", func(e *ProbeEnv) { e.GOOS = "linux" }, VerdictUnsupportedPlatform, "A1 platform"},
		{"inactive", func(e *ProbeEnv) { e.Active = false }, VerdictDisabledByConfig, "A2 active"},
		{"Intel Mac", func(e *ProbeEnv) { e.Arm64 = func() (bool, error) { return false, nil } }, VerdictArchUnsupported, "A3 Apple silicon"},
		{"arch unreadable", func(e *ProbeEnv) { e.Arm64 = func() (bool, error) { return false, errors.New("x") } }, VerdictArchUnsupported, "A3 Apple silicon"},
		{"macOS 15", func(e *ProbeEnv) { e.OSVersion = func() (string, error) { return "15.6.1", nil } }, VerdictOSTooOld, "A4 macOS 26"},
		{"version unreadable", func(e *ProbeEnv) { e.OSVersion = func() (string, error) { return "", nil } }, VerdictOSTooOld, "A4 macOS 26"},
		// A macOS VM without nested virtualisation: kern.hv_support is an
		// unknown oid (live check 2026-10-22), which counts as absent.
		{"hypervisor oid unknown", func(e *ProbeEnv) { e.Hypervisor = func() (bool, bool) { return false, false } }, VerdictNoHypervisor, "A4b hypervisor"},
		{"hypervisor off", func(e *ProbeEnv) { e.Hypervisor = func() (bool, bool) { return false, true } }, VerdictNoHypervisor, "A4b hypervisor"},
		{"hypervisor unreadable", func(e *ProbeEnv) { e.Hypervisor = nil }, VerdictNoHypervisor, "A4b hypervisor"},
		{"no CLI", func(e *ProbeEnv) { e.LookCLI = func() (string, error) { return "", errors.New("not found") } }, VerdictBackendMissing, "A5 container CLI"},
		{"writable CLI", func(e *ProbeEnv) {
			e.StatCLI = func(string) (CLIFacts, error) { return CLIFacts{Regular: true, OwnerOK: true, Perm: 0o777}, nil }
		}, VerdictBackendUntrusted, "A5 container CLI"},
		{"foreign CLI", func(e *ProbeEnv) {
			e.StatCLI = func(string) (CLIFacts, error) { return CLIFacts{Regular: true, Perm: 0o755}, nil }
		}, VerdictBackendUntrusted, "A5 container CLI"},
		{"old CLI", func(e *ProbeEnv) {
			e.Version = func(string) (string, error) { return "container CLI version 0.4.1", nil }
		}, VerdictVersionUntested, "A6 version"},
		{"garbage version", func(e *ProbeEnv) { e.Version = func(string) (string, error) { return "unknown", nil } }, VerdictVersionUntested, "A6 version"},
		{"system stopped", func(e *ProbeEnv) { e.SystemRunning = func(string) error { return errors.New("not running") } }, VerdictEngineUnreachable, "A7 system service"},
		{"no image set", func(e *ProbeEnv) { e.Image = "" }, VerdictImageMissing, "A8 image"},
		{"tag image", func(e *ProbeEnv) { e.Image = "ghcr.io/example/agent:latest" }, VerdictImageMissing, "A8 image"},
		{"image absent", func(e *ProbeEnv) { e.ImagePresent = func(string, string) (bool, error) { return false, nil } }, VerdictImageMissing, "A8 image"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			env := healthy()
			c.mut(&env)
			r := Probe(env)
			if r.Verdict.Code != c.verdict || r.Rule != c.rule {
				t.Fatalf("got %s at %s (%s), want %s at %s", r.Verdict.Code, r.Rule, r.Verdict.Reason, c.verdict, c.rule)
			}
		})
	}
	r := Probe(healthy())
	if r.CLI != "/usr/local/bin/container" || r.Version != "1.6.0" || r.OSVersion != "26.1" || r.Beta {
		t.Fatalf("established %+v", r)
	}
	env := healthy()
	env.Version = func(string) (string, error) { return "0.9.0", nil }
	if !Probe(env).Beta {
		t.Fatal("a version before the tested range is not beta")
	}
}

// TestProbeTouchesNothingWhileInactive: nothing runs below the active row.
func TestProbeTouchesNothingWhileInactive(t *testing.T) {
	calls := 0
	env := healthy()
	env.Active = false
	env.Arm64 = func() (bool, error) { calls++; return true, nil }
	env.LookCLI = func() (string, error) { calls++; return "/x", nil }
	env.Version = func(string) (string, error) { calls++; return "0.5.0", nil }
	if r := Probe(env); r.Verdict.Code != VerdictDisabledByConfig || calls != 0 {
		t.Fatalf("%s after %d calls", r.Verdict.Code, calls)
	}
}

func TestParseCLIVersion(t *testing.T) {
	for in, want := range map[string]string{
		"container CLI version 0.5.0 (build: release, commit: 1a2b3c4)": "0.5.0",
		"0.6.1":           "0.6.1",
		"v0.7":            "0.7",
		"container CLI":   "",
		"version 1.2.3.4": "",
	} {
		if got := ParseCLIVersion(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}

func TestContainerEnv(t *testing.T) {
	env := ContainerEnv([]string{"HOME=/Users/dev", "PATH=/opt/homebrew/bin", "DYLD_INSERT_LIBRARIES=/x", "NODE_OPTIONS=--require x", "SSH_AUTH_SOCK=/s", "ANTHROPIC_BASE_URL=http://127.0.0.1:8820", "=x"}, []string{"SSH_AUTH_SOCK"})
	if !slices.Equal(env, []string{"HOME=/Users/dev", "ANTHROPIC_BASE_URL=http://127.0.0.1:8820"}) {
		t.Fatalf("%q", env)
	}
	b, err := RenderEnvFile(append(env, "lower=dropped"))
	if err != nil || string(b) != "HOME=/Users/dev\nANTHROPIC_BASE_URL=http://127.0.0.1:8820\n" {
		t.Fatalf("%q %v", b, err)
	}
	if _, err := RenderEnvFile([]string{"A=1\nB=2"}); err == nil {
		t.Fatal("a newline value was written")
	}
}

// TestAwaitReadBackFailsClosed (F2 of the SBX-P5 merge): an inspect that
// never answers with exactly one parsable container within the window ends
// the run with built_below_plan; a matching one passes; a weaker one is
// refused by ReadBack.
func TestAwaitReadBackFailsClosed(t *testing.T) {
	plan := testPlan()
	good := readFixture(t, "inspect.json")
	weak := readFixture(t, "inspect_weaker.json")
	clock := func() ReadBackClock {
		now := time.Unix(1_800_000_000, 0)
		return ReadBackClock{Now: func() time.Time { return now }, Sleep: func(d time.Duration) { now = now.Add(d) }}
	}
	two := "[" + strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(string(good)), "["), "]") + "," + strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(string(good)), "["), "]") + "]"
	cases := []struct {
		name  string
		fetch func() ([]byte, error)
		code  string
		why   string
	}{
		{"an unknown JSON shape", func() ([]byte, error) { return []byte(`{"shape":"new"}`), nil }, VerdictBuiltBelowPlan, "could not be read back"},
		{"inspect keeps failing", func() ([]byte, error) { return nil, fmt.Errorf("not found") }, VerdictBuiltBelowPlan, "could not be read back"},
		{"two containers", func() ([]byte, error) { return []byte(two), nil }, VerdictBuiltBelowPlan, "2 containers"},
		{"empty list", func() ([]byte, error) { return []byte(`[]`), nil }, VerdictBuiltBelowPlan, "0 containers"},
		{"weaker container", func() ([]byte, error) { return weak, nil }, VerdictBuiltBelowPlan, "weaker than planned"},
		{"the planned container", func() ([]byte, error) { return good, nil }, VerdictAvailable, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := AwaitReadBack(c.fetch, plan, ReadBackWindow, clock())
			if v.Code != c.code || !strings.Contains(v.Reason, c.why) {
				t.Fatalf("verdict %+v, want %s (%q)", v, c.code, c.why)
			}
		})
	}
	// It keeps polling inside the window: a container that appears late
	// is judged, not refused.
	n := 0
	late := func() ([]byte, error) {
		if n++; n < 5 {
			return nil, fmt.Errorf("not yet")
		}
		return good, nil
	}
	if v := AwaitReadBack(late, plan, ReadBackWindow, clock()); !v.OK() {
		t.Fatalf("a late container was refused: %+v", v)
	}
}
