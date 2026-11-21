package sandboxopenshell

import (
	"strings"
	"testing"
)

// TestDescribeRunDirs (tracker F-032): one case per kind of run dir the
// reaper cannot remove, plus the cap. Only the name, the box name derived
// from it and the age are rendered.
func TestDescribeRunDirs(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		notes []RunDirNote
		want  []string
		never []string
	}{
		{"none", nil, nil, []string{"("}},
		{"plan-less", []RunDirNote{{Name: "r1", AgeSeconds: 3 * 3600, Planless: true}}, []string{"r1 (no plan file, 3 h old)"}, []string{"box"}},
		{"unreadable plan names its box", []RunDirNote{{Name: "r2", AgeSeconds: 3 * 86400}}, []string{"r2 (a plan this build cannot read, box " + SandboxName("r2") + ", 3 d old)"}, nil},
		{"seconds", []RunDirNote{{Name: "r3", AgeSeconds: 45, Planless: true}}, []string{"45 s old"}, nil},
		{"minutes", []RunDirNote{{Name: "r4", AgeSeconds: 600, Planless: true}}, []string{"10 min old"}, nil},
		{"a clock step back reads 0 s", []RunDirNote{{Name: "r5", AgeSeconds: -9, Planless: true}}, []string{"0 s old"}, nil},
		{"capped", []RunDirNote{{Name: "a"}, {Name: "b"}, {Name: "c"}, {Name: "d"}, {Name: "e"}, {Name: "f"}, {Name: "g"}}, []string{"e (", "and 2 more"}, []string{"f (", "g ("}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := DescribeRunDirs(tc.notes)
			if len(tc.want) == 0 && got != "" {
				t.Fatalf("got %q, want empty", got)
			}
			for _, w := range tc.want {
				if !strings.Contains(got, w) {
					t.Errorf("%q lacks %q", got, w)
				}
			}
			for _, n := range tc.never {
				if strings.Contains(got, n) {
					t.Errorf("%q has %q", got, n)
				}
			}
		})
	}
}

// TestG2ReasonNamesTheDirsThatHoldIt (tracker F-032): row G2's wait says
// how many runs keep the gateway, and names only the run dirs that hold it
// (a plan-less dir past the grace holds nothing and is left out), with the
// remedy; with none it names no dir.
func TestG2ReasonNamesTheDirsThatHoldIt(t *testing.T) {
	t.Parallel()
	f := readyFacts()
	f.Wanted, f.RecordedRuns, f.LiveRuns = false, 2, 1
	f.UnreadableRunDirs = []RunDirNote{
		{Name: "held-young", AgeSeconds: 30, Planless: true, Holds: true},
		{Name: "old-debris", AgeSeconds: 7200, Planless: true},
		{Name: "other-build", AgeSeconds: 86400 * 4, Holds: true},
	}
	d := DecideGateway(f)
	if d.Rule != "G2" || d.Action != GatewayWait || d.Verdict != "" {
		t.Fatalf("DecideGateway = %+v", d)
	}
	for _, w := range []string{"2 run(s) are recorded on it (1 live)", "held-young (no plan file, 30 s old)", "other-build (a plan this build cannot read, box " + SandboxName("other-build") + ", 4 d old)", RunDirsRemedy} {
		if !strings.Contains(d.Reason, w) {
			t.Errorf("reason %q lacks %q", d.Reason, w)
		}
	}
	if strings.Contains(d.Reason, "old-debris") {
		t.Errorf("a dir that holds nothing is named: %q", d.Reason)
	}
	f.UnreadableRunDirs = f.UnreadableRunDirs[1:2]
	if r := DecideGateway(f).Reason; strings.Contains(r, "reaper cannot remove") || !strings.Contains(r, "recorded on it") {
		t.Errorf("with no holding dir: %q", r)
	}
}
