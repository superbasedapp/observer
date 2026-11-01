package sandboxapple

import (
	"fmt"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/sandbox"
)

// guestcheck.go is the in-guest check: before the agent starts, the in-image
// init reads its own mount table (/proc/self/mountinfo, injected here as
// bytes) and refuses the run with built_below_plan unless every planned
// mount is a mount point and every planned read-only path is a read-only
// one. It exists because `container inspect` is no witness for this row:
// Apple container 1.6.0 dropped the .git pin from the guest while inspect
// still listed it (live 2026-10-23, D-A3). The cmd layer adds a second,
// functional witness for the read-only paths (access(2) must answer EROFS).
// The parser and the judge are internal/sandbox/guestmounts.go's, shared
// with the microVM row (lane SBX-P4); these are thin wrappers.

// MountEntry is one line of a mountinfo table.
type MountEntry = sandbox.MountEntry

// ParseMountInfo reads /proc/self/mountinfo (sandbox.ParseGuestMountInfo).
func ParseMountInfo(b []byte) ([]MountEntry, error) {
	t, err := sandbox.ParseGuestMountInfo(b)
	if err != nil {
		return nil, fmt.Errorf("sandboxapple.ParseMountInfo: %w", err)
	}
	return t, nil
}

// CheckGuestMounts judges the guest's own mount table against the plan
// (sandbox.GuestMountShortfalls): anything short is built_below_plan,
// naming every shortfall.
func CheckGuestMounts(table []MountEntry, mounts, ro []string) Verdict {
	if bad := sandbox.GuestMountShortfalls(table, mounts, ro); len(bad) > 0 {
		return refuse(VerdictBuiltBelowPlan, "the box read its own mounts back weaker than planned: "+strings.Join(bad, "; ")+"; the agent was not started")
	}
	return pass()
}
