package sandboxsbpl

import (
	"fmt"
	"strings"
)

// selftest.go judges the launch self-test (the Seatbelt row's read-back,
// sandbox plan v2 section 4.4, review R2-3): before the agent starts, the
// host helper runs `observer sandbox-seatbelt-selftest` under the very
// profile and parameters the agent will get. Inside, the self-test tries
// what the profile must refuse and what it must allow, and prints one line
// of results; the helper parses it here and starts the agent only on a
// pass. A profile that let a forbidden access through is built_below_plan.

// SelfTestReport is what the self-test observed inside the profile.
type SelfTestReport struct {
	// ObserverDirReadable: listing the observer directory worked (must not).
	ObserverDirReadable bool
	// SocketParentReadable: listing the socket parent worked (must not).
	SocketParentReadable bool
	// HomeListable: listing the home worked in tmpfs mode (must not).
	HomeListable bool
	// ForbiddenConnect: a connect to a loopback port the tier does not
	// allow got past the profile (any answer but "operation not
	// permitted"; must not).
	ForbiddenConnect bool
	// WorkspaceWritable: creating and removing a file in the workspace
	// worked (must).
	WorkspaceWritable bool
	// TempWritable: the same in the run's TMPDIR (must).
	TempWritable bool
}

// selfTestFields is the wire order of the report line.
var selfTestFields = []string{"obs", "sockp", "home", "net", "ws", "tmp"}

// String renders the report line ("obs=0 sockp=0 home=0 net=0 ws=1 tmp=1").
func (r SelfTestReport) String() string {
	vals := []bool{r.ObserverDirReadable, r.SocketParentReadable, r.HomeListable, r.ForbiddenConnect, r.WorkspaceWritable, r.TempWritable}
	parts := make([]string, len(vals))
	for i, v := range vals {
		b := "0"
		if v {
			b = "1"
		}
		parts[i] = selfTestFields[i] + "=" + b
	}
	return strings.Join(parts, " ")
}

// ParseSelfTest reads a report line; every field must be present once.
func ParseSelfTest(line string) (SelfTestReport, error) {
	got := map[string]bool{}
	for _, f := range strings.Fields(strings.TrimSpace(line)) {
		k, v, ok := strings.Cut(f, "=")
		if !ok || (v != "0" && v != "1") {
			return SelfTestReport{}, fmt.Errorf("self-test field %q", f)
		}
		if _, dup := got[k]; dup {
			return SelfTestReport{}, fmt.Errorf("self-test field %q twice", k)
		}
		got[k] = v == "1"
	}
	for _, k := range selfTestFields {
		if _, ok := got[k]; !ok {
			return SelfTestReport{}, fmt.Errorf("self-test field %q missing", k)
		}
	}
	if len(got) != len(selfTestFields) {
		return SelfTestReport{}, fmt.Errorf("self-test has unknown fields")
	}
	return SelfTestReport{
		ObserverDirReadable: got["obs"], SocketParentReadable: got["sockp"], HomeListable: got["home"],
		ForbiddenConnect: got["net"], WorkspaceWritable: got["ws"], TempWritable: got["tmp"],
	}, nil
}

// JudgeSelfTest decides the report. homeBlinded is true in tmpfs home mode.
func JudgeSelfTest(r SelfTestReport, homeBlinded bool) Verdict {
	var leaks []string
	if r.ObserverDirReadable {
		leaks = append(leaks, "the observer directory was readable")
	}
	if r.SocketParentReadable {
		leaks = append(leaks, "other runs' socket directories were readable")
	}
	if homeBlinded && r.HomeListable {
		leaks = append(leaks, "the home directory could be listed")
	}
	if r.ForbiddenConnect {
		leaks = append(leaks, "a loopback port outside the tier was reachable")
	}
	if len(leaks) > 0 {
		return refuse(VerdictBuiltBelowPlan, "the Seatbelt profile was weaker than planned: "+strings.Join(leaks, "; ")+"; the agent was not started")
	}
	if !r.WorkspaceWritable || !r.TempWritable {
		return refuse(VerdictSelfTestFailed, "the Seatbelt profile refused the workspace or the run's TMPDIR, so the agent could not work; the agent was not started")
	}
	return pass()
}
