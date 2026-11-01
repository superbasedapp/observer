package host

import "github.com/marmutapp/superbased-observer/internal/extrun"

// The job-object limit flags the runner uses, mirrored from the Windows SDK
// (winnt.h) so the decision below is plain data, built and tested on every
// OS. jobplan_windows_test.go pins them to golang.org/x/sys/windows.
const (
	jobLimitJobTime                 uint32 = 0x00000004
	jobLimitActiveProcess           uint32 = 0x00000008
	jobLimitJobMemory               uint32 = 0x00000200
	jobLimitDieOnUnhandledException uint32 = 0x00000400
	jobLimitBreakawayOK             uint32 = 0x00000800
	jobLimitSilentBreakawayOK       uint32 = 0x00001000
	jobLimitKillOnJobClose          uint32 = 0x00002000
)

// jobNeverFlags are never set (JSP-12 laptop half): without BREAKAWAY_OK a
// child started with CREATE_BREAKAWAY_FROM_JOB is refused, so it cannot
// leave the job; SILENT_BREAKAWAY_OK would move every child out silently.
const jobNeverFlags = jobLimitBreakawayOK | jobLimitSilentBreakawayOK

// jobPlan is the job object of one run, as data.
type jobPlan struct {
	flags uint32
	// memory is the job's committed-memory limit in bytes.
	memory uint64
	// activeProcesses is the most processes in the job at once, the
	// program included.
	activeProcesses uint32
	// userTime100ns is the job's user-time limit in 100 ns units. Windows
	// enforces it late (JSP-12: a 1 s limit ended a spinner after 8 s), so
	// the wall cap stays the timeliness guarantee.
	userTime100ns int64
}

// jobRow is one row of the job table: when it applies and what it adds.
type jobRow struct {
	when  func(extrun.Limits) bool
	apply func(*jobPlan, extrun.Limits)
}

// jobTable is walked top-down. The first two rows always apply: the job
// kills everything when its last handle closes, and a crash dialog never
// holds a process alive.
var jobTable = []jobRow{
	{func(extrun.Limits) bool { return true }, func(j *jobPlan, _ extrun.Limits) { j.flags |= jobLimitKillOnJobClose }},
	{func(extrun.Limits) bool { return true }, func(j *jobPlan, _ extrun.Limits) { j.flags |= jobLimitDieOnUnhandledException }},
	{func(l extrun.Limits) bool { return l.MemoryBytes > 0 }, func(j *jobPlan, l extrun.Limits) {
		j.flags |= jobLimitJobMemory
		j.memory = uint64(l.MemoryBytes)
	}},
	{func(l extrun.Limits) bool { return l.Children > 0 }, func(j *jobPlan, l extrun.Limits) {
		j.flags |= jobLimitActiveProcess
		j.activeProcesses = uint32(l.Children)
	}},
	{func(l extrun.Limits) bool { return l.CPU > 0 }, func(j *jobPlan, l extrun.Limits) {
		j.flags |= jobLimitJobTime
		j.userTime100ns = extrun.CPUSeconds(l.CPU) * 10_000_000
	}},
}

// planJob builds the job of a run from its limits.
func planJob(l extrun.Limits) jobPlan { return planJobFrom(jobTable, l) }

// planJobFrom walks table for l. The never flags are cleared last, whatever
// a row did.
func planJobFrom(table []jobRow, l extrun.Limits) jobPlan {
	var j jobPlan
	for _, row := range table {
		if row.when(l) {
			row.apply(&j, l)
		}
	}
	j.flags &^= jobNeverFlags
	return j
}

// jobApplied reports, per requested cap, how a job holds it: memory and the
// process count by the job (processes, the program included), CPU by the
// job's user-time limit, which acts late (best effort).
func jobApplied(l extrun.Limits) map[extrun.Cap]extrun.CapApplied {
	out := map[extrun.Cap]extrun.CapApplied{}
	if l.MemoryBytes > 0 {
		out[extrun.CapMemory] = extrun.CapApplied{Mechanism: extrun.MechJob}
	}
	if l.Children > 0 {
		out[extrun.CapChildren] = extrun.CapApplied{Mechanism: extrun.MechJob, Unit: extrun.UnitProcesses}
	}
	if l.CPU > 0 {
		out[extrun.CapCPU] = extrun.CapApplied{Mechanism: extrun.MechJobCPU}
	}
	if l.FileBytes > 0 {
		out[extrun.CapFileSize] = extrun.CapApplied{}
	}
	return out
}
