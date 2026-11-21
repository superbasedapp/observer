package sandboxopenshell

import (
	"regexp"
	"strings"
)

// Outcome is what a CLI answer says about a sandbox.
type Outcome string

// The closed Outcome vocabulary. Unknown is never Gone: a reaper that
// cannot classify an answer keeps looking (lane O0 finding O0-A1).
const (
	OutcomePresent Outcome = "present"
	OutcomeGone    Outcome = "gone"
	OutcomeUnknown Outcome = "unknown"
)

// frameRE matches whitespace and the frame characters miette draws around
// an error (it wraps long lines), so a wrapped text matches once flattened.
// The set is lane O0's helper's (o0helper.py is_sandbox_not_found).
var frameRE = regexp.MustCompile(`[\s\x{2502}\x{00d7}\x{256d}\x{2570}\x{2500}]+`)

// flatten collapses whitespace and miette's frame characters to one space.
func flatten(s string) string { return frameRE.ReplaceAllString(s, " ") }

// ClassifyGet classifies the answer of `openshell sandbox get NAME` at the
// OpenShell version v: exit 0 is present; a non-zero exit whose stderr
// carries v's exact not-found text (after flattening) is gone; anything
// else, and any answer from a version not in the tested table, is unknown.
func ClassifyGet(v Version, exitCode int, stderr string) Outcome {
	if exitCode == 0 {
		return OutcomePresent
	}
	row, ok := testedRow(v)
	if !ok || row.NotFoundText == "" {
		return OutcomeUnknown
	}
	if strings.Contains(flatten(stderr), row.NotFoundText) {
		return OutcomeGone
	}
	return OutcomeUnknown
}
