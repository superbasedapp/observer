package shellwrap

import (
	"strings"
	"testing"
)

// planShims renders the shims enable would write for id on goos.
func planShims(t *testing.T, goos, id, shimDir, obs string) []ShimFile {
	t.Helper()
	p, err := BuildPlan(PlanInput{
		Host: hostWith(goos), ShimDir: shimDir, ObserverPath: obs,
		Selection: Selection{Tools: []string{id}, Shells: ShellsFor(goos)[:1]},
	})
	if err != nil || len(p.Shims) == 0 {
		t.Fatalf("BuildPlan(%s): %+v %v", id, p, err)
	}
	return p.Shims
}

func onDisk(files []ShimFile) []OnDiskShim {
	out := make([]OnDiskShim, 0, len(files))
	for _, f := range files {
		tool, cmd, ver, _ := ParseMarkerLine(f.Content)
		out = append(out, OnDiskShim{FileName: f.FileName, Path: f.Path, ToolID: tool, Command: cmd, Version: ver, Content: f.Content})
	}
	return out
}

func TestEmbeddedObserverPathRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		goos, obs, dir string
	}{
		{"linux", "/home/u/it's here/observer", "/home/u/.observer/shims"},
		{"linux", "/usr/local/bin/observer", "/s"},
		{"darwin", "/opt/homebrew/Cellar/observer/1.2.3/bin/observer", "/Users/u/.observer/shims"},
		{"windows", `C:\Program Files\100%\observer.exe`, `C:\Users\u\.observer\shims`},
		{"windows", `\\srv\share\observer.exe`, `C:\s`},
	} {
		c := firstRouted(t, tc.goos)
		for _, s := range planShims(t, tc.goos, c.ID, tc.dir, tc.obs) {
			got, ok := EmbeddedObserverPath(s.Content)
			if !ok || got != tc.obs {
				t.Errorf("%s: EmbeddedObserverPath = %q %v, want %q", tc.goos, got, ok, tc.obs)
			}
		}
	}
	for name, content := range map[string]string{
		"unmarked":       "#!/bin/sh\nsbo_observer='/usr/bin/observer'\n",
		"hand-edited":    "#!/bin/sh\n# " + ShimMarker + " v1 tool=x command=x\nsbo_observer=/usr/bin/observer\n",
		"stray quote":    "#!/bin/sh\n# " + ShimMarker + " v1 tool=x command=x\nsbo_observer='/a'b'\n",
		"no observer":    "#!/bin/sh\n# " + ShimMarker + " v1 tool=x command=x\n",
		"cmd single pct": "@echo off\r\nrem " + ShimMarker + " v1 tool=x command=x\r\nif not exist \"C:\\100%\\o.exe\" (\r\n",
	} {
		if p, ok := EmbeddedObserverPath(content); ok {
			t.Errorf("%s: parsed %q, want refusal", name, p)
		}
	}
}

func TestPlanRefreshTable(t *testing.T) {
	const (
		dir    = "/home/u/.observer/shims"
		oldObs = "/old/prefix/bin/observer"
		newObs = "/new/prefix/bin/observer"
	)
	c := firstRouted(t, "linux")
	other := ""
	for _, o := range Candidates("linux") {
		if o.ID != c.ID && o.Kind == c.Kind {
			other = o.ID
			break
		}
	}
	oldShims := onDisk(planShims(t, "linux", c.ID, dir, oldObs))
	newShims := planShims(t, "linux", c.ID, dir, newObs)
	curShims := onDisk(newShims)
	first := oldShims[0]

	unmarked := first
	unmarked.Content = "#!/bin/sh\necho mine\n"
	renamed := first
	renamed.FileName = first.FileName + "-copy"
	edited := first
	edited.Content = strings.Replace(first.Content, "sbo_observer='"+oldObs+"'", "sbo_observer="+oldObs, 1)
	gone := first
	gone.ToolID = "no-such-tool"
	gone.Content = strings.Replace(first.Content, "tool="+c.ID, "tool=no-such-tool", 1)

	oldGone := func(p string) bool { return p != oldObs }
	allExist := func(string) bool { return true }

	cases := []struct {
		name     string
		enabled  bool
		selected []string
		resolve  func(string) string
		exists   func(string) bool
		runnable func(string) bool
		shims    []OnDiskShim
		want     []RefreshAction
		inactive bool
	}{
		{name: "not enabled plans nothing", enabled: false, selected: []string{c.ID}, shims: oldShims, inactive: true},
		{name: "paths equal", enabled: true, selected: []string{c.ID}, shims: curShims, want: repeat(RefreshCurrent, len(curShims))},
		{name: "different path that is gone", enabled: true, selected: []string{c.ID}, exists: oldGone, shims: oldShims, want: repeat(RefreshRewrite, len(oldShims))},
		// Another install (VS Code bundle / npm / PyPI) that still exists is
		// kept, so coexisting installs never flip the shims on each start.
		{name: "different path that still exists", enabled: true, selected: []string{c.ID}, exists: allExist, shims: oldShims, want: repeat(RefreshKept, len(oldShims))},
		{name: "nil existence check is conservative", enabled: true, selected: []string{c.ID}, shims: oldShims, want: repeat(RefreshKept, len(oldShims))},
		{
			name: "old path is a symlink to the running binary", enabled: true, selected: []string{c.ID},
			resolve: func(p string) string {
				if p == oldObs {
					return newObs
				}
				return p
			}, shims: oldShims, want: repeat(RefreshCurrent, len(oldShims)),
		},
		{name: "unmarked file", enabled: true, selected: []string{c.ID}, shims: []OnDiskShim{unmarked}, want: []RefreshAction{RefreshSkip}},
		{name: "tool not in the recorded choice", enabled: true, selected: []string{other}, shims: []OnDiskShim{first}, want: []RefreshAction{RefreshSkip}},
		{name: "file name does not match command", enabled: true, selected: []string{c.ID}, shims: []OnDiskShim{renamed}, want: []RefreshAction{RefreshSkip}},
		{name: "observer line hand-edited", enabled: true, selected: []string{c.ID}, shims: []OnDiskShim{edited}, want: []RefreshAction{RefreshSkip}},
		{name: "tool no longer wrappable", enabled: true, selected: []string{"no-such-tool"}, exists: oldGone, shims: []OnDiskShim{gone}, want: []RefreshAction{RefreshSkip}},
		// A recorded tool whose shim is gone is NOT recreated: deleting the
		// shim dir is the documented lock-out escape hatch.
		// The running binary was replaced/removed since it started
		// (os.Executable -> "<path> (deleted)"): never bake that in.
		{name: "running observer not runnable skips the rewrite", enabled: true, selected: []string{c.ID}, exists: oldGone, runnable: func(string) bool { return false }, shims: oldShims, want: repeat(RefreshSkip, len(oldShims))},
		{name: "running observer runnable rewrites", enabled: true, selected: []string{c.ID}, exists: oldGone, runnable: func(p string) bool { return p == newObs }, shims: oldShims, want: repeat(RefreshRewrite, len(oldShims))},
		{name: "not-runnable observer leaves current shims current", enabled: true, selected: []string{c.ID}, runnable: func(string) bool { return false }, shims: curShims, want: repeat(RefreshCurrent, len(curShims))},
		{name: "shim missing is never recreated", enabled: true, selected: []string{c.ID, other}, shims: nil, want: nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := PlanRefresh(RefreshInput{
				GOOS: "linux", Enabled: tc.enabled, Selected: tc.selected, ShimDir: dir,
				ObserverPath: newObs, ResolvedObserver: newObs, Resolve: tc.resolve, Exists: tc.exists,
				ObserverRunnable: tc.runnable, Shims: tc.shims,
			})
			if err != nil {
				t.Fatal(err)
			}
			if tc.inactive != (p.Inactive != "") || (tc.inactive && len(p.Shims) != 0) {
				t.Fatalf("inactive: %+v", p)
			}
			if len(p.Shims) != len(tc.want) {
				t.Fatalf("got %d decisions, want %d: %+v", len(p.Shims), len(tc.want), p.Shims)
			}
			for i, s := range p.Shims {
				if s.Action != tc.want[i] {
					t.Errorf("%s: action %s (%s), want %s", s.FileName, s.Action, s.Reason, tc.want[i])
				}
				if s.Reason == "" {
					t.Errorf("%s: no reason", s.FileName)
				}
				if s.Action != RefreshRewrite && s.Content != "" {
					t.Errorf("%s: content planned for a %s", s.FileName, s.Action)
				}
			}
		})
	}

	// A rewrite is byte-identical to what enable renders for the new path.
	p, _ := PlanRefresh(RefreshInput{
		GOOS: "linux", Enabled: true, Selected: []string{c.ID}, ShimDir: dir,
		ObserverPath: newObs, ResolvedObserver: newObs, Exists: oldGone, Shims: oldShims,
	})
	if len(p.Rewrites()) != len(oldShims) {
		t.Fatalf("rewrites: %+v", p.Shims)
	}
	for i, r := range p.Rewrites() {
		if r.Content != newShims[i].Content || r.OldObserverPath != oldObs || r.Before != oldShims[i].Content {
			t.Fatalf("rewrite %s differs from enable's render", r.FileName)
		}
	}
}

func TestPlanRefreshWindows(t *testing.T) {
	const dir = `C:\Users\u\.observer\shims`
	c := firstRouted(t, "windows")
	old := onDisk(planShims(t, "windows", c.ID, dir, `C:\Users\u\AppData\Roaming\npm\observer.exe`))
	// Same file, different case: NTFS says it is the running binary.
	p, err := PlanRefresh(RefreshInput{
		GOOS: "windows", Enabled: true, Selected: []string{c.ID}, ShimDir: dir,
		ObserverPath: `c:\users\U\appdata\roaming\npm\OBSERVER.exe`, Shims: old,
	})
	if err != nil || len(p.Rewrites()) != 0 {
		t.Fatalf("case-only difference must be current: %+v %v", p, err)
	}
	p, err = PlanRefresh(RefreshInput{
		GOOS: "windows", Enabled: true, Selected: []string{c.ID}, ShimDir: dir,
		ObserverPath: `D:\tools\observer.exe`, Exists: func(string) bool { return false }, Shims: old,
	})
	if err != nil || len(p.Rewrites()) != len(old) {
		t.Fatalf("moved: %+v %v", p, err)
	}
	for _, r := range p.Rewrites() {
		if !strings.HasPrefix(r.Content, "@echo off\r\n") || !strings.Contains(r.Content, `"D:\tools\observer.exe" `) {
			t.Fatalf("windows rewrite:\n%s", r.Content)
		}
	}
}

func TestPlanRefreshRefusesUnsafePaths(t *testing.T) {
	for _, in := range []RefreshInput{
		{GOOS: "linux", Enabled: true, ShimDir: "/s", ObserverPath: "/o/\"bad\""},
		{GOOS: "linux", Enabled: true, ShimDir: "/s\nx", ObserverPath: "/o"},
		{GOOS: "linux", Enabled: true, ShimDir: "/s", ObserverPath: ""},
	} {
		if _, err := PlanRefresh(in); err == nil {
			t.Errorf("%+v: want refusal", in)
		}
	}
	// Disabled short-circuits before any validation: nothing is considered.
	if p, err := PlanRefresh(RefreshInput{GOOS: "linux"}); err != nil || p.Inactive == "" {
		t.Fatalf("disabled: %+v %v", p, err)
	}
}

func repeat(a RefreshAction, n int) []RefreshAction {
	out := make([]RefreshAction, n)
	for i := range out {
		out[i] = a
	}
	return out
}
