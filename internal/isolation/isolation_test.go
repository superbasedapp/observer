package isolation

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/extrun"
	"github.com/marmutapp/superbased-observer/internal/extrun/extruntest"
)

func testHost() Host {
	return Host{Bwrap: "/usr/bin/bwrap", Home: "/home/u", ObserverDir: "/home/u/.observer"}
}

func testDirs() extrun.OneShotDirs {
	return extrun.OneShotDirs{Project: "/home/u/src/p", Output: "/tmp/run/out", Cache: "/tmp/run/cache"}
}

func TestWrapRunsTheProgramInsideBwrap(t *testing.T) {
	o, err := New(testHost(), testDirs())
	if err != nil {
		t.Fatal(err)
	}
	in := extrun.Plan{Component: "security.code", Path: "/opt/s/bin/gosec", Args: []string{"-fmt", "sarif", "./..."}, Env: []string{"LANG=C"}}
	out, err := o.Wrap(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if out.Path != "/usr/bin/bwrap" || out.Dir != "/home/u/src/p" || out.Component != "security.code" || strings.Join(out.Env, ",") != "LANG=C" {
		t.Fatalf("wrapped plan = %+v", out)
	}
	n := len(out.Args)
	if strings.Join(out.Args[n-5:], " ") != "-- /opt/s/bin/gosec -fmt sarif ./..." {
		t.Fatalf("inner argv = %v", out.Args[n-5:])
	}
	joined := strings.Join(out.Args, " ")
	for _, want := range []string{"--unshare-net", "--ro-bind-try /opt/s/bin /opt/s/bin", "--ro-bind /home/u/src/p /home/u/src/p", "--bind /tmp/run/out /tmp/run/out", "--bind /tmp/run/cache /tmp/run/cache", "--chdir /home/u/src/p"} {
		if !strings.Contains(joined, want) {
			t.Errorf("argv lacks %q: %s", want, joined)
		}
	}
	if strings.Contains(joined, "--bind /home/u/.observer") || strings.Contains(joined, "--ro-bind /home/u/.observer") {
		t.Errorf("argv binds ~/.observer: %s", joined)
	}
}

// TestWrapKeepsASpacedProjectWhole: a project whose path holds a space is
// wrapped, not refused, and every flag that names it gets it as one argv
// element (operator ruling 2026-11-06).
func TestWrapKeepsASpacedProjectWhole(t *testing.T) {
	d := extrun.OneShotDirs{Project: "/mnt/d/programsx/future calculator", Output: "/tmp/run 1/out", Cache: "/tmp/run 1/cache"}
	o, err := New(testHost(), d)
	if err != nil {
		t.Fatal(err)
	}
	out, err := o.Wrap(context.Background(), extrun.Plan{Path: "/opt/s/bin/gosec", Args: []string{"./..."}})
	if err != nil {
		t.Fatal(err)
	}
	if out.Dir != d.Project {
		t.Fatalf("dir = %q, want %q", out.Dir, d.Project)
	}
	named := 0
	for i, a := range out.Args {
		if a == "--" {
			break
		}
		if strings.Contains(a, "future") {
			if a != d.Project {
				t.Fatalf("argv element %d = %q: the project path was split or altered", i, a)
			}
			named++
		}
	}
	if named != 3 { // --ro-bind <p> <p>, --chdir <p>
		t.Fatalf("the project is named %d times before --, want 3: %v", named, out.Args)
	}
}

func TestNewAndWrapRefuse(t *testing.T) {
	h := testHost()
	if _, err := New(Host{Home: h.Home, ObserverDir: h.ObserverDir}, testDirs()); !errors.Is(err, ErrNoBwrap) {
		t.Errorf("no bwrap: err = %v", err)
	}
	d := testDirs()
	d.Output = "/home/u/.observer/out"
	if _, err := New(h, d); err == nil || !strings.Contains(err.Error(), "observer dir") {
		t.Errorf("output under ~/.observer: err = %v", err)
	}
	o, err := New(h, testDirs())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := o.Wrap(context.Background(), extrun.Plan{Path: "gosec"}); err == nil {
		t.Error("relative program accepted")
	}
	if _, err := o.Wrap(context.Background(), extrun.Plan{Path: "/opt/s/gosec", Dir: "/elsewhere"}); err == nil {
		t.Error("a different working directory accepted")
	}
	if _, err := o.Wrap(context.Background(), extrun.Plan{Path: "/home/u/.observer/engines/gosec"}); err == nil {
		t.Error("a program under ~/.observer accepted (its directory would be bound)")
	}
}

// TestRunnerWrapsThroughTheFactory drives the shared runner with the
// factory's provider: the seam a consumer uses end to end. The executor
// receives bwrap, with the checked program inside it.
func TestRunnerWrapsThroughTheFactory(t *testing.T) {
	p, err := Factory(testHost())(testDirs())
	if err != nil {
		t.Fatal(err)
	}
	ex := &extruntest.Executor{}
	files := extruntest.Files{"/opt/s/bin/gosec": {}}
	r := extruntest.NewRunner("linux", files, ex, nil)
	r.Isolation = p
	res := r.Run(context.Background(), extrun.Request{Component: "isolation", Program: extrun.Program{Path: "/opt/s/bin/gosec"}, Args: []string{"./..."}, Dir: "/home/u/src/p", RequireIsolation: true})
	if res.Outcome != extrun.OutcomeOK || res.Isolation != ProviderName || res.Launcher != "/usr/bin/bwrap" {
		t.Fatalf("result = %+v", res)
	}
	got := ex.Calls()[0]
	if got.Path != "/usr/bin/bwrap" || got.Args[len(got.Args)-2] != "/opt/s/bin/gosec" {
		t.Fatalf("executor got %+v", got)
	}
}
