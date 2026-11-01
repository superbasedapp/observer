//go:build windows

package host

import (
	"testing"

	"golang.org/x/sys/windows"
)

// TestJobFlagMirror pins the mirrored flags to the SDK values.
func TestJobFlagMirror(t *testing.T) {
	t.Parallel()
	for name, pair := range map[string][2]uint32{
		"JOB_TIME":          {jobLimitJobTime, windows.JOB_OBJECT_LIMIT_JOB_TIME},
		"ACTIVE_PROCESS":    {jobLimitActiveProcess, windows.JOB_OBJECT_LIMIT_ACTIVE_PROCESS},
		"JOB_MEMORY":        {jobLimitJobMemory, windows.JOB_OBJECT_LIMIT_JOB_MEMORY},
		"DIE_ON_UNHANDLED":  {jobLimitDieOnUnhandledException, windows.JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION},
		"BREAKAWAY_OK":      {jobLimitBreakawayOK, windows.JOB_OBJECT_LIMIT_BREAKAWAY_OK},
		"SILENT_BREAKAWAY":  {jobLimitSilentBreakawayOK, windows.JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK},
		"KILL_ON_JOB_CLOSE": {jobLimitKillOnJobClose, windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE},
	} {
		if pair[0] != pair[1] {
			t.Errorf("%s: mirrored %#x, SDK %#x", name, pair[0], pair[1])
		}
	}
}
