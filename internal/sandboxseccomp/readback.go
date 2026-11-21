package sandboxseccomp

import (
	"fmt"
	"strconv"
	"strings"
)

// Status is the seccomp state of one process as /proc/<pid>/status reports
// it: the Seccomp mode (0 none, 1 strict, 2 filter) and, on kernels 5.9
// and later, the Seccomp_filters count.
type Status struct {
	// Mode is the Seccomp line's value ("" when the line is missing).
	Mode string
	// Filters is the Seccomp_filters count; HasFilters is false on a kernel
	// without the line.
	Filters    int
	HasFilters bool
}

// modeFilter is the Seccomp line's value for SECCOMP_MODE_FILTER.
const modeFilter = "2"

// ParseStatus reads the two seccomp lines from a /proc/<pid>/status text.
func ParseStatus(text string) Status {
	var s Status
	for _, line := range strings.Split(text, "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch k {
		case "Seccomp":
			s.Mode = v
		case "Seccomp_filters":
			if n, err := strconv.Atoi(v); err == nil && n >= 0 {
				s.Filters, s.HasFilters = n, true
			}
		}
	}
	return s
}

// The read-back's refusal states, named in the launch's refusal line.
const (
	// StateNotFiltered: the process runs with no seccomp filter.
	StateNotFiltered = "seccomp_not_filtered"
	// StateOnlyInherited: the process carries only the filters its parent
	// (the host helper) already had, so Observer's own is not there.
	StateOnlyInherited = "seccomp_only_inherited"
	// StateUnmeasurable: the host helper already runs under a filter and the
	// kernel reports no filter count, so Observer's own cannot be told from
	// the inherited one.
	StateUnmeasurable = "seccomp_unmeasurable"
)

// readBackRow is one row of the read-back table, walked top down: the
// first row whose condition holds decides; no row holding is a match.
type readBackRow struct {
	state string
	when  func(self, child Status) bool
}

// readBackRows is the read-back table.
var readBackRows = []readBackRow{
	{StateNotFiltered, func(_, c Status) bool { return c.Mode != modeFilter }},
	{StateNotFiltered, func(_, c Status) bool { return c.HasFilters && c.Filters < 1 }},
	{StateUnmeasurable, func(s, c Status) bool { return s.Mode == modeFilter && (!s.HasFilters || !c.HasFilters) }},
	{StateOnlyInherited, func(s, c Status) bool { return s.Mode == modeFilter && c.Filters <= s.Filters }},
}

// preflightRows is the pre-launch table (audit N2-A6, lane FU4): states the
// host helper's own status already decides, before anything starts. A host
// that matches a row can never pass the read-back, so the launch is refused
// before the agent runs instead of after it started (the bwrap read-back
// happens once the box is released). Walked top down; no row holding means
// the read-back can measure.
var preflightRows = []struct {
	state string
	when  func(self Status) bool
}{
	// The helper already runs under a filter (a systemd SystemCallFilter, a
	// container's profile) on a kernel without the Seccomp_filters line:
	// Observer's own filter cannot be told from the inherited one.
	{StateUnmeasurable, func(s Status) bool { return s.Mode == modeFilter && !s.HasFilters }},
}

// Preflight judges the host helper's own status before a launch: nil when
// the read-back can tell Observer's filter apart, else an error naming the
// state. The caller refuses the launch before it starts anything.
func Preflight(self Status) error {
	for _, r := range preflightRows {
		if r.when(self) {
			return fmt.Errorf("%s: the host helper already runs under a seccomp filter (Seccomp %q) and this kernel reports no Seccomp_filters count, so Observer's own filter could never be read back; refused before the launch", r.state, self.Mode)
		}
	}
	return nil
}

// ReadBack judges a launched process's status against the host helper's
// own: nil when the process carries a filter the helper does not, else an
// error naming the state. The caller refuses the run on any error (fail
// closed: a requested filter that cannot be proven is not there).
func ReadBack(self, child Status) error {
	for _, r := range readBackRows {
		if r.when(self, child) {
			return fmt.Errorf("%s: the process shows Seccomp %q with %d filter(s) (host helper: %q, %d)", r.state, child.Mode, child.Filters, self.Mode, self.Filters)
		}
	}
	return nil
}
