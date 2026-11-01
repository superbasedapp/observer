package host

import (
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/extrun"
)

func TestPlanJob(t *testing.T) {
	t.Parallel()
	base := jobLimitKillOnJobClose | jobLimitDieOnUnhandledException
	cases := []struct {
		name string
		l    extrun.Limits
		want jobPlan
	}{
		{name: "no caps: kill on close and no crash dialog only", want: jobPlan{flags: base}},
		{name: "memory", l: extrun.Limits{MemoryBytes: 512 << 20}, want: jobPlan{flags: base | jobLimitJobMemory, memory: 512 << 20}},
		{
			name: "the process cap counts processes, the program included: the number as given",
			l:    extrun.Limits{Children: 64},
			want: jobPlan{flags: base | jobLimitActiveProcess, activeProcesses: 64},
		},
		{
			name: "CPU in 100 ns units, rounded up to whole seconds",
			l:    extrun.Limits{CPU: 1500 * time.Millisecond},
			want: jobPlan{flags: base | jobLimitJobTime, userTime100ns: 2 * 10_000_000},
		},
	}
	for _, tc := range cases {
		if got := planJob(tc.l); got != tc.want {
			t.Errorf("%s: got %+v, want %+v", tc.name, got, tc.want)
		}
	}
}

// TestPlanJobNeverBreaksAway: whatever the limits, a job never lets a child
// leave it (JSP-12: the breakaway start was refused because BREAKAWAY_OK was
// not set) and always kills on close.
func TestPlanJobNeverBreaksAway(t *testing.T) {
	t.Parallel()
	for _, l := range []extrun.Limits{{}, {MemoryBytes: 1, Children: 1, CPU: time.Second, FileBytes: 1}} {
		j := planJob(l)
		if j.flags&jobNeverFlags != 0 {
			t.Fatalf("limits %+v set a breakaway flag: %#x", l, j.flags)
		}
		if j.flags&jobLimitKillOnJobClose == 0 {
			t.Fatalf("limits %+v: no KILL_ON_JOB_CLOSE", l)
		}
	}
	// A row that tried to set one is overridden.
	bad := append(append([]jobRow(nil), jobTable...), jobRow{
		func(extrun.Limits) bool { return true },
		func(j *jobPlan, _ extrun.Limits) { j.flags |= jobLimitBreakawayOK | jobLimitSilentBreakawayOK },
	})
	if planJobFrom(bad, extrun.Limits{}).flags&jobNeverFlags != 0 {
		t.Fatal("a breakaway flag survived planJob")
	}
}

func TestJobApplied(t *testing.T) {
	t.Parallel()
	got := jobApplied(extrun.Limits{MemoryBytes: 1, Children: 64, CPU: time.Second, FileBytes: 1})
	want := map[extrun.Cap]extrun.CapApplied{
		extrun.CapMemory:   {Mechanism: extrun.MechJob},
		extrun.CapChildren: {Mechanism: extrun.MechJob, Unit: extrun.UnitProcesses},
		extrun.CapCPU:      {Mechanism: extrun.MechJobCPU},
		extrun.CapFileSize: {},
	}
	if len(got) != len(want) {
		t.Fatalf("got %+v", got)
	}
	for c, w := range want {
		if got[c] != w {
			t.Errorf("%s: %+v, want %+v", c, got[c], w)
		}
	}
	// As the run record shows them: the CPU cap is best effort (Windows
	// enforces it late), the file size cap is not enforced.
	if extrun.MechanismState(extrun.MechJobCPU) != extrun.CapBestEffort || extrun.MechanismState("") != extrun.CapNotEnforced {
		t.Fatal("job CPU must be best effort and a missing mechanism not enforced")
	}
}
