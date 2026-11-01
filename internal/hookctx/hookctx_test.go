package hookctx

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestNoForbiddenImports pins the seam as a neutral core leaf: no database,
// HTTP, fsnotify or exec, and nothing from this module except
// internal/policy, the pure guard core that owns the Event.Security type
// (it imports zero observer packages itself), so neither the security
// module nor the sandbox module can end up owning the seam.
func TestNoForbiddenImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{
			"database/sql",
			"net/http",
			"github.com/fsnotify/fsnotify",
			"os/exec",
		},
		Custom: func(_, p string) string {
			if p == "github.com/marmutapp/superbased-observer/internal/policy" {
				return ""
			}
			if strings.HasPrefix(p, "github.com/marmutapp/superbased-observer/") {
				return "hookctx is a leaf: it imports nothing from this module but internal/policy"
			}
			return ""
		},
		Reason: "hookctx is the neutral hook context seam",
	})
}

// countingSource fails the test when any of its I/O is used.
func countingSource(t *testing.T, calls *int) Source {
	t.Helper()
	bump := func() { *calls++ }
	return Source{
		ParentPID: func() int { bump(); return 1 },
		Ancestors: func(int) []int { bump(); return nil },
		Getenv:    func(string) string { bump(); return "" },
		Files: Files{
			ReadFile: func(string) ([]byte, error) { bump(); return nil, nil },
			Open:     func(string) (File, error) { bump(); return nil, nil },
			Stat:     func(string) (fs.FileInfo, error) { bump(); return nil, nil },
		},
	}
}

func fullRequest() Request {
	return Request{
		Tool: "claude-code", Event: "pre-tool", ProjectRoot: "/repo", SessionID: "s1",
		WriteCapable: true, QuickScan: &QuickScanRequest{ProjectRoot: "/repo", DirtySeen: 3},
	}
}

// TestNilProvidersDoNoWork: today's hook path. With no provider wired, the
// fill reads nothing, starts nothing, allocates nothing and records
// nothing, even for a request that would use every provider.
func TestNilProvidersDoNoWork(t *testing.T) {
	calls := 0
	for _, path := range []Path{PathHost, PathDaemon} {
		var c *Context
		if path == PathHost {
			c = Host(context.Background(), fullRequest(), countingSource(t, &calls), HostProviders{})
		} else {
			c = Daemon(context.Background(), fullRequest(), Channel{ParentPID: 7}, DaemonProviders{})
		}
		if c.Path() != path {
			t.Errorf("Path = %q, want %q", c.Path(), path)
		}
		if c.Security != nil || c.QuickScan != nil || c.DirtyRaised || len(c.Issues) != 0 {
			t.Errorf("%s: nil providers filled something: %+v", path, c)
		}
		ctx, req := context.Background(), fullRequest()
		if n := testing.AllocsPerRun(200, func() { c.Fill(ctx, req) }); n != 0 {
			t.Errorf("%s: Fill with nil providers allocates %.0f times per call; it must start no goroutine and do no work", path, n)
		}
	}
	if calls != 0 {
		t.Errorf("the host source was read %d times by the fill itself; process facts are read only when a handler asks", calls)
	}
}

// TestHostSourceFallsBackToOS: a zero host Source is the hook process's
// own operating system, exactly what the handlers read before the seam.
func TestHostSourceFallsBackToOS(t *testing.T) {
	t.Setenv("HOOKCTX_TEST_PROBE", "host-value")
	dir := t.TempDir()
	p := filepath.Join(dir, "payload.txt")
	if err := os.WriteFile(p, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]*Context{
		"Host":        Host(context.Background(), Request{}, Source{}, HostProviders{}),
		"HostDefault": HostDefault(),
		"From":        From(context.Background()),
	} {
		if c.Path() != PathHost {
			t.Errorf("%s: Path = %q", name, c.Path())
		}
		if got := c.ParentPID(); got != os.Getppid() {
			t.Errorf("%s: ParentPID = %d, os.Getppid = %d", name, got, os.Getppid())
		}
		if got := c.Getenv("HOOKCTX_TEST_PROBE"); got != "host-value" {
			t.Errorf("%s: Getenv = %q", name, got)
		}
		if b, err := c.ReadFile(p); err != nil || string(b) != "hello" {
			t.Errorf("%s: ReadFile = %q, %v", name, b, err)
		}
		f, err := c.Open(p)
		if err != nil {
			t.Fatalf("%s: Open: %v", name, err)
		}
		st, err := f.Stat()
		_ = f.Close()
		if err != nil || st.Size() != 5 {
			t.Errorf("%s: Open+Stat size = %v, %v", name, st, err)
		}
		if _, err := c.Open(filepath.Join(dir, "missing")); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s: Open(missing) = %v, want not-exist", name, err)
		}
		if st, err := c.Stat(p); err != nil || st.Size() != 5 {
			t.Errorf("%s: Stat = %v, %v", name, st, err)
		}
		if a := c.Ancestors(c.ParentPID()); a != nil {
			t.Errorf("%s: Ancestors without a walker = %v, want nil", name, a)
		}
	}
	// A caller's walker is kept.
	c := Host(context.Background(), Request{}, Source{Ancestors: func(p int) []int { return []int{p, 1} }}, HostProviders{})
	if got := c.Ancestors(42); !slices.Equal(got, []int{42, 1}) {
		t.Errorf("Ancestors = %v", got)
	}
}

// behaviour is one way a provider can answer.
type behaviour int

const (
	behaveOK behaviour = iota
	behaveErr
	behavePanic
	behaveOverrun
)

// TestFillProviderOutcomes walks every step through every provider
// behaviour on both paths: success fills the fact, and an error, a panic
// or an overrun leaves its honest unknown value plus one Issue, without
// blocking past the limit.
func TestFillProviderOutcomes(t *testing.T) {
	const limit = 30 * time.Millisecond
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	act := func(b behaviour) error {
		switch b {
		case behaveErr:
			return errors.New("provider failed")
		case behavePanic:
			panic("provider panicked")
		case behaveOverrun:
			<-release // ignores its context on purpose
		}
		return nil
	}
	cases := []struct {
		name      string
		step      Step
		b         behaviour
		wantSec   *Security
		wantScan  *QuickScanResult
		wantDirty bool
	}{
		{"security ok", StepSecurity, behaveOK, &Security{Posture: PostureClean}, nil, false},
		{"security error", StepSecurity, behaveErr, &Security{Posture: PostureUnknown}, nil, false},
		{"security panic", StepSecurity, behavePanic, &Security{Posture: PostureUnknown}, nil, false},
		{"security overrun", StepSecurity, behaveOverrun, &Security{Posture: PostureUnknown}, nil, false},
		{"quick scan ok", StepQuickScan, behaveOK, nil, &QuickScanResult{Verdict: QuickScanClean}, false},
		{"quick scan error", StepQuickScan, behaveErr, nil, &QuickScanResult{Verdict: QuickScanUnknown}, false},
		{"quick scan panic", StepQuickScan, behavePanic, nil, &QuickScanResult{Verdict: QuickScanUnknown}, false},
		{"quick scan overrun", StepQuickScan, behaveOverrun, nil, &QuickScanResult{Verdict: QuickScanUnknown}, false},
		{"dirty ok", StepDirty, behaveOK, nil, nil, true},
		{"dirty error", StepDirty, behaveErr, nil, nil, false},
		{"dirty panic", StepDirty, behavePanic, nil, nil, false},
		{"dirty overrun", StepDirty, behaveOverrun, nil, nil, false},
	}
	for _, path := range []Path{PathHost, PathDaemon} {
		for _, tc := range cases {
			t.Run(string(path)+"/"+tc.name, func(t *testing.T) {
				var sec SecuritySource
				var scan QuickScanner
				var dirty DirtyMarker
				switch tc.step {
				case StepSecurity:
					sec = func(context.Context, Request) (Security, error) {
						return Security{Posture: PostureClean}, act(tc.b)
					}
				case StepQuickScan:
					scan = func(context.Context, QuickScanRequest) (QuickScanResult, error) {
						return QuickScanResult{Verdict: QuickScanClean}, act(tc.b)
					}
				case StepDirty:
					dirty = func(context.Context, string) error { return act(tc.b) }
				}
				lim := Limits{Security: limit, Dirty: limit, QuickScan: limit}
				start := time.Now()
				var c *Context
				if path == PathHost {
					c = Host(context.Background(), fullRequest(), Source{}, HostProviders{Sidecar: sec, Dirty: dirty, QuickScan: scan, Limits: lim})
				} else {
					c = Daemon(context.Background(), fullRequest(), Channel{}, DaemonProviders{Memory: sec, Dirty: dirty, QuickScan: scan, Limits: lim})
				}
				if el := time.Since(start); el > 5*time.Second {
					t.Fatalf("Fill took %v; a provider must never hold the hook past its limit", el)
				}
				if !reflect.DeepEqual(c.Security, tc.wantSec) {
					t.Errorf("Security = %+v, want %+v", c.Security, tc.wantSec)
				}
				if !reflect.DeepEqual(c.QuickScan, tc.wantScan) {
					t.Errorf("QuickScan = %+v, want %+v", c.QuickScan, tc.wantScan)
				}
				if c.DirtyRaised != tc.wantDirty {
					t.Errorf("DirtyRaised = %v, want %v", c.DirtyRaised, tc.wantDirty)
				}
				wantIssues := 0
				if tc.b != behaveOK {
					wantIssues = 1
				}
				if len(c.Issues) != wantIssues {
					t.Fatalf("Issues = %+v, want %d", c.Issues, wantIssues)
				}
				if wantIssues == 1 {
					if c.Issues[0].Step != tc.step {
						t.Errorf("Issue step = %q, want %q", c.Issues[0].Step, tc.step)
					}
					if tc.b == behaveOverrun && !errors.Is(c.Issues[0].Err, context.DeadlineExceeded) {
						t.Errorf("overrun Issue = %v, want a deadline error", c.Issues[0].Err)
					}
				}
			})
		}
	}
}

// TestFillCallerDeadline: with no per-step limit, the caller's context
// (the hook watchdog in production) still bounds a provider.
func TestFillCallerDeadline(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	c := Host(ctx, fullRequest(), Source{}, HostProviders{Sidecar: func(context.Context, Request) (Security, error) {
		<-release
		return Security{Posture: PostureClean}, nil
	}})
	if c.Security == nil || c.Security.Posture != PostureUnknown || len(c.Issues) != 1 {
		t.Errorf("caller deadline: Security = %+v, Issues = %+v", c.Security, c.Issues)
	}
}

// TestFillOrderAndApplicability: the rows run in table order, and each
// applies only when its request field and provider are both present.
func TestFillOrderAndApplicability(t *testing.T) {
	cases := []struct {
		name string
		req  Request
		want []Step
	}{
		{"everything", fullRequest(), []Step{StepSecurity, StepQuickScan, StepDirty}},
		{"plain event", Request{Tool: "t", ProjectRoot: "/repo"}, []Step{StepSecurity}},
		{"write only", Request{ProjectRoot: "/repo", WriteCapable: true}, []Step{StepSecurity, StepDirty}},
		{"commit only", Request{ProjectRoot: "/repo", QuickScan: &QuickScanRequest{ProjectRoot: "/repo"}}, []Step{StepSecurity, StepQuickScan}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got []Step
			p := DaemonProviders{
				Memory: func(_ context.Context, r Request) (Security, error) {
					got = append(got, StepSecurity)
					return Security{Posture: PostureDirty}, nil
				},
				QuickScan: func(_ context.Context, r QuickScanRequest) (QuickScanResult, error) {
					got = append(got, StepQuickScan)
					return QuickScanResult{Verdict: QuickScanBlocking}, nil
				},
				Dirty: func(_ context.Context, root string) error {
					got = append(got, StepDirty)
					return nil
				},
			}
			Daemon(context.Background(), tc.req, Channel{}, p)
			if !slices.Equal(got, tc.want) {
				t.Errorf("steps = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestFillReplacesEarlierResults: a receiver that learns more calls Fill
// again, and the new fill replaces the old one.
func TestFillReplacesEarlierResults(t *testing.T) {
	fail := true
	p := HostProviders{Sidecar: func(context.Context, Request) (Security, error) {
		if fail {
			return Security{}, errors.New("no sidecar yet")
		}
		return Security{Posture: PostureClean}, nil
	}}
	c := Host(context.Background(), Request{ProjectRoot: "/repo"}, Source{}, p)
	if c.Security.Posture != PostureUnknown || len(c.Issues) != 1 {
		t.Fatalf("first fill = %+v %+v", c.Security, c.Issues)
	}
	fail = false
	c.Fill(context.Background(), Request{ProjectRoot: "/repo", WriteCapable: true})
	if c.Security.Posture != PostureClean || len(c.Issues) != 0 || c.DirtyRaised {
		t.Errorf("second fill = %+v %+v dirty=%v", c.Security, c.Issues, c.DirtyRaised)
	}
}

// TestDaemonPathReadsOnlyTheChannel is the daemon entry point against
// fakes (the relay does not exist yet): process facts and environment come
// from the channel, never the daemon's own process; files are refused
// unless the channel's confined reader serves them; Event.Security comes
// from the in-memory posture; the dirty marker is raised in process before
// Daemon returns; the quick scan runs in process.
func TestDaemonPathReadsOnlyTheChannel(t *testing.T) {
	t.Setenv("HOOKCTX_TEST_PROBE", "daemon-own-value")
	real := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(real, []byte("daemon file"), 0o600); err != nil {
		t.Fatal(err)
	}
	const ppid = 424242
	ch := Channel{
		RunID:     "run-1",
		ParentPID: ppid,
		Ancestors: []int{ppid, 4100},
		Env:       map[string]string{"HOOKCTX_TEST_PROBE": "frame-value"},
	}
	var memoryReq Request
	var dirtyRoot string
	var scanReq QuickScanRequest
	p := DaemonProviders{
		Memory: func(_ context.Context, r Request) (Security, error) {
			memoryReq = r
			return Security{Posture: PostureDirty}, nil
		},
		Dirty: func(_ context.Context, root string) error {
			dirtyRoot = root
			return nil
		},
		QuickScan: func(_ context.Context, r QuickScanRequest) (QuickScanResult, error) {
			scanReq = r
			return QuickScanResult{Verdict: QuickScanClean}, nil
		},
	}
	req := fullRequest()
	c := Daemon(context.Background(), req, ch, p)

	if c.Path() != PathDaemon {
		t.Errorf("Path = %q", c.Path())
	}
	if c.ParentPID() != ppid || c.ParentPID() == os.Getppid() {
		t.Errorf("ParentPID = %d, want the channel's %d", c.ParentPID(), ppid)
	}
	if got := c.Ancestors(ppid); !slices.Equal(got, []int{ppid, 4100}) {
		t.Errorf("Ancestors(channel pid) = %v", got)
	}
	if got := c.Ancestors(os.Getppid()); got != nil {
		t.Errorf("Ancestors(daemon's own parent) = %v, want nil", got)
	}
	if got := c.Getenv("HOOKCTX_TEST_PROBE"); got != "frame-value" {
		t.Errorf("Getenv = %q, want the frame's value", got)
	}
	if got := c.Getenv("HOME"); got != "" {
		t.Errorf("Getenv(HOME) = %q: the daemon's own environment leaked", got)
	}
	ch.Env["HOOKCTX_TEST_PROBE"] = "mutated"
	if got := c.Getenv("HOOKCTX_TEST_PROBE"); got != "frame-value" {
		t.Errorf("the context aliases the channel's map: %q", got)
	}
	if _, err := c.ReadFile(real); !IsRefused(err) {
		t.Errorf("ReadFile of a daemon-side file = %v, want refused", err)
	}
	if _, err := c.Open(real); !IsRefused(err) {
		t.Errorf("Open of a daemon-side file = %v, want refused", err)
	}
	if _, err := c.Stat(real); !IsRefused(err) {
		t.Errorf("Stat of a daemon-side file = %v, want refused", err)
	}

	if c.Security == nil || c.Security.Posture != PostureDirty || !reflect.DeepEqual(memoryReq, req) {
		t.Errorf("Security = %+v from request %+v", c.Security, memoryReq)
	}
	if !c.DirtyRaised || dirtyRoot != "/repo" {
		t.Errorf("dirty marker raised = %v for %q, want raised for /repo before Daemon returns", c.DirtyRaised, dirtyRoot)
	}
	if c.QuickScan == nil || c.QuickScan.Verdict != QuickScanClean || scanReq.DirtySeen != 3 {
		t.Errorf("QuickScan = %+v for %+v", c.QuickScan, scanReq)
	}
	if len(c.Issues) != 0 {
		t.Errorf("Issues = %+v", c.Issues)
	}

	// Structural: the daemon path has no sidecar reader to wire.
	if _, ok := reflect.TypeFor[DaemonProviders]().FieldByName("Sidecar"); ok {
		t.Error("DaemonProviders has a Sidecar field; the daemon path reads no sidecar")
	}
}

// TestDaemonEnvironIsTheChannelOnly: on the daemon path Environ lists only
// the frame's declared variables, sorted, never the daemon's own; the host
// path lists the process environment; and the install provider reads the
// context it runs under (PT-28).
func TestDaemonEnvironIsTheChannelOnly(t *testing.T) {
	t.Setenv("HOOKCTX_TEST_DAEMON_OWN", "leak")
	ch := Channel{Env: map[string]string{"NPM_CONFIG_REGISTRY": "https://x.example/", "A": "1"}}
	var seen []string
	p := DaemonProviders{Install: func(ctx context.Context, _ InstallRequest) (InstallResult, error) {
		seen = From(ctx).Environ()
		return InstallResult{}, nil
	}}
	c := Daemon(context.Background(), Request{}, ch, p)
	want := []string{"A=1", "NPM_CONFIG_REGISTRY=https://x.example/"}
	if got := c.Environ(); !slices.Equal(got, want) {
		t.Errorf("daemon Environ = %v, want %v", got, want)
	}
	ch.Env["B"] = "2"
	c.Environ()[0] = "mutated"
	if got := c.Environ(); !slices.Equal(got, want) {
		t.Errorf("daemon Environ aliases the channel or its own result: %v", got)
	}
	c.CheckInstall(context.Background(), InstallRequest{Event: &policy.Event{}})
	if !slices.Equal(seen, want) {
		t.Errorf("install provider read Environ %v, want the channel's %v", seen, want)
	}
	h := Host(context.Background(), Request{}, Source{}, HostProviders{})
	if !slices.Contains(h.Environ(), "HOOKCTX_TEST_DAEMON_OWN=leak") {
		t.Error("host Environ does not list the process environment")
	}
}

// TestDaemonConfinedFiles: a channel reader that serves the run's roots is
// used as given, and refuses what it does not serve.
func TestDaemonConfinedFiles(t *testing.T) {
	root := t.TempDir()
	inRun := filepath.Join(root, "transcript.jsonl")
	if err := os.WriteFile(inRun, []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}
	confined := func(p string) error {
		if !strings.HasPrefix(p, root+string(filepath.Separator)) {
			return ErrRefused
		}
		return nil
	}
	ch := Channel{Files: Files{
		ReadFile: func(p string) ([]byte, error) {
			if err := confined(p); err != nil {
				return nil, err
			}
			return os.ReadFile(p)
		},
	}}
	c := Daemon(context.Background(), Request{}, ch, DaemonProviders{})
	if b, err := c.ReadFile(inRun); err != nil || string(b) != "ok" {
		t.Errorf("ReadFile in run = %q, %v", b, err)
	}
	if _, err := c.ReadFile("/etc/hostname"); !IsRefused(err) {
		t.Errorf("ReadFile outside run = %v, want refused", err)
	}
	if _, err := c.Open(inRun); !IsRefused(err) {
		t.Errorf("Open with no channel opener = %v, want refused", err)
	}
}

// TestCarry: From returns the attached context, else a host default.
func TestCarry(t *testing.T) {
	c := Daemon(context.Background(), Request{}, Channel{ParentPID: 9}, DaemonProviders{})
	ctx := WithContext(context.Background(), c)
	if got := From(ctx); got != c {
		t.Errorf("From(attached) = %p, want %p", got, c)
	}
	if got, ok := Attached(ctx); !ok || got != c {
		t.Errorf("Attached = %p, %v", got, ok)
	}
	if _, ok := Attached(context.Background()); ok {
		t.Error("Attached on a bare context reported one")
	}
	if got := From(context.Background()); got.Path() != PathHost {
		t.Errorf("From(bare) path = %q", got.Path())
	}
	//nolint:staticcheck // a nil context is what a careless caller passes
	if _, ok := Attached(nil); ok {
		t.Error("Attached(nil) reported one")
	}
	//nolint:staticcheck // a nil parent must not panic
	if From(WithContext(nil, c)) != c {
		t.Error("WithContext(nil, c) lost c")
	}
}

// TestQuickScanOnlyWhen: a request's OnlyWhen reads the Security facts the
// same Fill just read; false skips the scan, true runs it, and with no
// Security facts at all the scan is skipped too.
func TestQuickScanOnlyWhen(t *testing.T) {
	ran := 0
	p := HostProviders{
		Sidecar: func(context.Context, Request) (Security, error) { return Security{Posture: PostureDirty}, nil },
		QuickScan: func(context.Context, QuickScanRequest) (QuickScanResult, error) {
			ran++
			return QuickScanResult{Verdict: QuickScanClean}, nil
		},
	}
	dirtyOnly := func(s Security) bool { return s.Posture == PostureDirty }
	c := Host(context.Background(), Request{ProjectRoot: "/r", QuickScan: &QuickScanRequest{ProjectRoot: "/r", OnlyWhen: dirtyOnly}}, Source{}, p)
	if ran != 1 || c.QuickScan == nil || c.QuickScan.Verdict != QuickScanClean {
		t.Fatalf("dirty: ran %d, %+v", ran, c.QuickScan)
	}
	p.Sidecar = func(context.Context, Request) (Security, error) { return Security{Posture: PostureClean}, nil }
	c = Host(context.Background(), Request{ProjectRoot: "/r", QuickScan: &QuickScanRequest{ProjectRoot: "/r", OnlyWhen: dirtyOnly}}, Source{}, p)
	if ran != 1 || c.QuickScan != nil || len(c.Issues) != 0 {
		t.Fatalf("clean: ran %d, %+v, issues %v", ran, c.QuickScan, c.Issues)
	}
	p.Sidecar = nil
	c = Host(context.Background(), Request{ProjectRoot: "/r", QuickScan: &QuickScanRequest{ProjectRoot: "/r", OnlyWhen: dirtyOnly}}, Source{}, p)
	if ran != 1 || c.QuickScan != nil {
		t.Fatalf("no security: ran %d, %+v", ran, c.QuickScan)
	}
}

// TestProcessSlot: Process is the host default until SetProcess records
// the invocation's context, and SetProcess(nil) clears it.
func TestProcessSlot(t *testing.T) {
	if Process().Path() != PathHost {
		t.Fatal("the default process context is not the host path")
	}
	d := Daemon(context.Background(), Request{}, Channel{RunID: "r", Env: map[string]string{"K": "v"}, Delivery: DeliveryCopy, CopyHostPath: "/copy"}, DaemonProviders{})
	SetProcess(d)
	defer SetProcess(nil)
	if Process().Path() != PathDaemon || Process().Getenv("K") != "v" {
		t.Fatal("Process did not return the recorded context")
	}
	if del, p := Process().WorkspaceDelivery(); del != DeliveryCopy || p != "/copy" {
		t.Fatalf("delivery %q %q", del, p)
	}
	SetProcess(nil)
	if Process().Path() != PathHost {
		t.Fatal("SetProcess(nil) did not clear the slot")
	}
}
