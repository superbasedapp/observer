package seccustom

import (
	"fmt"
	"slices"
	"time"

	"github.com/marmutapp/superbased-observer/internal/extrun"
)

// Limits are a manifest's caps, each one of the fixed steps of its picker
// (section 8.6 "limits": pickers with fixed steps, never a typed number).
type Limits struct {
	WallSeconds int `json:"wall_seconds"`
	MemoryMiB   int `json:"memory_mib"`
	CPUSeconds  int `json:"cpu_seconds"`
	OutputMiB   int `json:"output_mib"`
	// ChildProcesses is the one child-process setting. The runner turns it
	// into the OS's own limit: tasks (processes and threads) under a
	// cgroup's pids.max on Linux, processes under a job object on Windows
	// (JSP-12 laptop half: pids.max 64 let 13 Go children start, the job's
	// 64 let 64). The picker labels its steps with ChildrenUnit.
	ChildProcesses int `json:"child_processes"`
	FileMiB        int `json:"file_mib"`
}

// LimitField names one limit picker.
type LimitField string

// The limit pickers.
const (
	LimitWall     LimitField = "wall_seconds"
	LimitMemory   LimitField = "memory_mib"
	LimitCPU      LimitField = "cpu_seconds"
	LimitOutput   LimitField = "output_mib"
	LimitChildren LimitField = "child_processes"
	LimitFile     LimitField = "file_mib"
)

// limitSteps is the step table of every limit picker. The child-process
// steps start at 64 because a Go driver uses several threads per process
// and Linux counts threads (revision 2.4 [JSP-12]: the smallest useful step
// is about 64, not 1); the measured caps of JSP-8 (memory 2 GB, wall 600 s,
// output 32 MB, children 64) are steps.
var limitSteps = map[LimitField][]int{
	LimitWall:     {60, 120, 300, 600, 1200},
	LimitMemory:   {512, 1024, 2048, 4096},
	LimitCPU:      {60, 120, 300, 600, 1200},
	LimitOutput:   {1, 4, 16, 32, 64},
	LimitChildren: {64, 128, 256, 512},
	LimitFile:     {16, 64, 256, 1024},
}

// LimitSteps returns the steps of one limit picker, smallest first.
func LimitSteps(f LimitField) []int { return append([]int(nil), limitSteps[f]...) }

// LimitFields returns the limit pickers in display order.
func LimitFields() []LimitField {
	return []LimitField{LimitWall, LimitMemory, LimitCPU, LimitOutput, LimitChildren, LimitFile}
}

// DefaultLimits are the steps a manifest that names no limits gets: the
// measured background caps of JSP-8.
var DefaultLimits = Limits{WallSeconds: 600, MemoryMiB: 2048, CPUSeconds: 600, OutputMiB: 32, ChildProcesses: 64, FileMiB: 256}

// value returns the setting of one picker.
func (l Limits) value(f LimitField) int {
	switch f {
	case LimitWall:
		return l.WallSeconds
	case LimitMemory:
		return l.MemoryMiB
	case LimitCPU:
		return l.CPUSeconds
	case LimitOutput:
		return l.OutputMiB
	case LimitChildren:
		return l.ChildProcesses
	case LimitFile:
		return l.FileMiB
	}
	return 0
}

// validate refuses a setting that is not one of its picker's steps.
func (l Limits) validate() error {
	for _, f := range LimitFields() {
		if v := l.value(f); !slices.Contains(limitSteps[f], v) {
			return fmt.Errorf("limits.%s = %d is not one of the steps %v", f, v, limitSteps[f])
		}
	}
	return nil
}

// ChildrenUnit is the unit the child-process picker's steps are labelled
// with on goos (revision 2.5 [JSP-12 laptop half]): "processes" where a job
// object counts processes (Windows), "tasks" where a cgroup counts
// processes and threads (Linux), "processes" where the runner polls the
// process group (macOS).
func ChildrenUnit(goos string) string {
	switch goos {
	case "linux":
		return extrun.UnitTasks
	default:
		return extrun.UnitProcesses
	}
}

// RunLimits turns the manifest's steps into the runner's caps. The one
// child-process setting becomes extrun.Limits.Children, which the runner
// holds as pids.max (tasks) on Linux and as the job's active-process limit
// (processes) on Windows.
func (l Limits) RunLimits() extrun.Limits {
	return extrun.Limits{
		Wall:        time.Duration(l.WallSeconds) * time.Second,
		StdoutBytes: int64(l.OutputMiB) << 20,
		StderrBytes: 1 << 20,
		MemoryBytes: int64(l.MemoryMiB) << 20,
		Children:    l.ChildProcesses,
		CPU:         time.Duration(l.CPUSeconds) * time.Second,
		FileBytes:   int64(l.FileMiB) << 20,
	}
}
