package sandboxopenshell

import (
	"strconv"
	"strings"
)

// RunDirNote is one run dir under the install's state dir whose plan this
// build cannot read (tracker F-032, the O5 sweep's L5 class): a launch
// killed before it wrote its plan, or a plan from another build or refused
// for its owner or size. The reaper never removes such a dir and nothing
// deletes it, so it is named to the user instead. Only the dir's name (the
// run id) and its age are carried: nothing read from inside it is shown
// (the scan that finds such a dir does try to parse its plan file).
type RunDirNote struct {
	// Name is the dir's name, the run id.
	Name string
	// AgeSeconds is how long ago the dir last changed.
	AgeSeconds int64
	// Planless: the dir has no plan file at all, so its run never had a
	// box (the plan is written before the helper creates one).
	Planless bool
	// Holds: the dir counts as a recorded run, so it keeps a gateway from
	// stopping (a dir whose plan exists but cannot be read always does; a
	// plan-less one only while a helper holds it or it is young).
	Holds bool
}

// runDirNoteMax is how many dirs a sentence names before "and N more".
const runDirNoteMax = 5

// DescribeRunDirs names the dirs with their ages, for example
// "run-a (no plan file, 3 h old), run-b (a plan this build cannot read, box
// sbo-..., 2 d old)". It returns "" for none. Names are only ever run ids
// (the caller lists only dirs whose name is a valid run id), and the box
// name is derived from the run id, never taken from the plan.
func DescribeRunDirs(notes []RunDirNote) string {
	var parts []string
	for i, n := range notes {
		if i == runDirNoteMax {
			parts = append(parts, "and "+strconv.Itoa(len(notes)-runDirNoteMax)+" more")
			break
		}
		kind := "a plan this build cannot read, box " + SandboxName(n.Name)
		if n.Planless {
			kind = "no plan file"
		}
		parts = append(parts, n.Name+" ("+kind+", "+describeAge(n.AgeSeconds)+" old)")
	}
	return strings.Join(parts, ", ")
}

// describeAge renders an age in seconds as a coarse plain-language length.
func describeAge(s int64) string {
	switch {
	case s < 0:
		return "0 s"
	case s < 120:
		return strconv.FormatInt(s, 10) + " s"
	case s < 2*3600:
		return strconv.FormatInt(s/60, 10) + " min"
	case s < 2*86400:
		return strconv.FormatInt(s/3600, 10) + " h"
	}
	return strconv.FormatInt(s/86400, 10) + " d"
}

// RunDirsRemedy is the one sentence that says what to do about run dirs
// the reaper cannot remove, shared by the G2 wait reason and the probe's
// note (so `observer sandbox status` and `observer doctor` say the same).
const RunDirsRemedy = "the reaper never removes such a dir and Observer deletes nothing; a dir with no plan file that is more than a few minutes old never had a box and can be removed, and a dir whose plan this build cannot read can be removed once `openshell sandbox list` no longer names its box"

// holdingRunDirs is the notes that keep a gateway recorded.
func holdingRunDirs(notes []RunDirNote) []RunDirNote {
	var out []RunDirNote
	for _, n := range notes {
		if n.Holds {
			out = append(out, n)
		}
	}
	return out
}

// notWantedWaitReason is row G2's reason: why a gateway that is no longer
// wanted keeps running, naming the run dirs that hold it which the reaper
// can never remove (tracker F-032), with what to do about them.
func notWantedWaitReason(f GatewayFacts) string {
	out := "the private gateway is no longer wanted and keeps running while " + strconv.Itoa(f.RecordedRuns) + " run(s) are recorded on it (" + strconv.Itoa(f.LiveRuns) + " live); it stops once the reaper has removed them"
	if held := holdingRunDirs(f.UnreadableRunDirs); len(held) > 0 {
		out += "; these run dirs keep it running and the reaper cannot remove them: " + DescribeRunDirs(held) + "; " + RunDirsRemedy
	}
	return out
}
