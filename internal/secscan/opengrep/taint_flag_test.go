package opengrep

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/extrun/extruntest"
	"github.com/marmutapp/superbased-observer/internal/secrulepack"
)

// packWithTaint returns the embedded floor with taint_intrafile forced to
// on (set) or absent, whatever the shipped floor says, so the tests do not
// move when the floor's switch does.
func packWithTaint(t *testing.T, on bool) *secrulepack.Pack {
	t.Helper()
	floor, err := secrulepack.Floor()
	if err != nil {
		t.Fatal(err)
	}
	files := floor.Files()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(files[secrulepack.ManifestFile], &m); err != nil {
		t.Fatal(err)
	}
	delete(m, "taint_intrafile")
	if on {
		m["taint_intrafile"] = json.RawMessage("true")
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	files[secrulepack.ManifestFile] = b
	p, err := secrulepack.Parse(files)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return p
}

// TestArgsForPackFlagDecision is the flag decision's table: the pack's flag
// reaches every mode when, and only when, the pack declares it and the
// driver lists it, after FlagsAlways and before the job count.
func TestArgsForPackFlagDecision(t *testing.T) {
	modes := []Mode{ModeFull, ModeDiff, ModeSelfTest, ModeFiles}
	cases := []struct {
		name  string
		flags []string
		want  int
	}{
		{"a pack that declares nothing", nil, 0},
		{"an empty declaration", []string{}, 0},
		{"the taint switch", []string{secrulepack.FlagTaintIntrafile}, 1},
		{"a flag the driver does not list is dropped", []string{"https://example.com/rules"}, 0},
		{"the listed flag survives beside an unlisted one", []string{"--error", secrulepack.FlagTaintIntrafile}, 1},
	}
	for _, c := range cases {
		for _, m := range modes {
			args := ArgsForPack(m, "/p/rules", "/p/canary/x.py", "/o/opengrep.json", strings.Repeat("a", 40), []string{"a.py"}, 4, c.flags)
			n := 0
			for _, a := range args {
				if a == taintFlag {
					n++
				}
			}
			if n != c.want {
				t.Errorf("%s, mode %v: %d %s in %v, want %d", c.name, m, n, taintFlag, args, c.want)
			}
			if slices.Contains(args, "--error") || slices.Contains(args, "https://example.com/rules") {
				t.Errorf("%s, mode %v: an unlisted flag reached the engine: %v", c.name, m, args)
			}
			if i := slices.Index(args, taintFlag); i >= 0 {
				if j := slices.Index(args, "-j"); !(i > slices.Index(args, FlagsAlways[len(FlagsAlways)-1]) && i < j) {
					t.Errorf("%s, mode %v: the flag sits at %d, want after FlagsAlways and before -j (%d)", c.name, m, i, j)
				}
			}
		}
	}
	// ArgsFor is the no-pack-flag form: today's argument list exactly.
	if got, want := ArgsFor(ModeFull, "/r", "/c", "/j", "", nil, 4), ArgsForPack(ModeFull, "/r", "/c", "/j", "", nil, 4, nil); !slices.Equal(got, want) {
		t.Errorf("ArgsFor %v differs from ArgsForPack with no flags %v", got, want)
	}
}

// taintFlag is the engine's spelling, as `opengrep scan --help` lists it at
// v1.30.1; it is a literal here so the tests pin the constants to it.
const taintFlag = "--taint-intrafile"

// TestPackFlagsListTheTaintSwitch pins the one flag a pack may ask for.
func TestPackFlagsListTheTaintSwitch(t *testing.T) {
	if !slices.Equal(PackFlags, []string{taintFlag}) || secrulepack.FlagTaintIntrafile != taintFlag {
		t.Fatalf("PackFlags %v, secrulepack.FlagTaintIntrafile %q", PackFlags, secrulepack.FlagTaintIntrafile)
	}
	for _, f := range PackFlags {
		if slices.Contains(FlagsAlways, f) || slices.Contains(FlagsNever, f) {
			t.Errorf("%s is a pack flag and also in FlagsAlways or FlagsNever", f)
		}
	}
}

// TestDriverPassesTheTaintSwitchOnlyForADeclaringPack runs the driver with a
// pack that declares taint_intrafile and one that does not: the engine's
// scan carries the flag in the first run only, the version probe never does.
func TestDriverPassesTheTaintSwitchOnlyForADeclaringPack(t *testing.T) {
	for _, on := range []bool{false, true} {
		f := newFake(t)
		ex := &extruntest.Executor{}
		env := f.env(ex, &memState{})
		env.Pack = packWithTaint(t, on)
		if _, _, err := New(env).ScanFiles(context.Background(), full()); err != nil {
			t.Fatal(err)
		}
		scans := 0
		for _, c := range ex.Calls() {
			if len(c.Args) == 0 || c.Args[0] != "scan" {
				if slices.Contains(c.Args, taintFlag) {
					t.Errorf("taint_intrafile=%v: a non-scan run %v carries the flag", on, c.Args)
				}
				continue
			}
			scans++
			if got := slices.Contains(c.Args, taintFlag); got != on {
				t.Errorf("taint_intrafile=%v: flag present %v in %v", on, got, c.Args)
			}
		}
		if scans == 0 {
			t.Fatalf("taint_intrafile=%v: no scan run recorded", on)
		}
	}
}
