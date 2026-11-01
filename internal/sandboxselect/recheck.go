package sandboxselect

import (
	"fmt"
	"regexp"
	"strings"

	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// recheck.go is the post-build re-check parser for bwrap (section 4.4,
// acceptance mutation proof 7): the host helper reads the namespace links
// of the sandboxed process and of itself (`/proc/<pid>/ns/<name>`, each a
// "name:[inode]" link) and hands both here. The parser is strict: a
// missing, truncated or reshaped line yields built_below_plan, never the
// planned value.

// VerdictBuiltBelowPlan is the re-check's refusal.
const VerdictBuiltBelowPlan = "built_below_plan"

// PlannedBwrap is what the plan asked bwrap to build.
type PlannedBwrap struct {
	// PrivateNet: the tier unshares the network (every tier but host).
	PrivateNet bool
}

// RecheckResult is what was built.
type RecheckResult struct {
	OK      bool
	Verdict string
	Reason  string
	// Class is the class the build supports (process when the pid and
	// mount namespaces are private, none otherwise).
	Class vocab.IsoClass
	// PrivateNet: the network namespace differs from the host's.
	PrivateNet bool
}

var nsLink = regexp.MustCompile(`^([a-z_]+):\[([0-9]+)\]$`)

// requiredNS are the namespaces every bwrap plan creates.
var requiredNS = []string{"mnt", "pid", "net"}

// ParseNSLinks reads lines of "<name>:[<inode>]". An empty, malformed or
// duplicate line is an error.
func ParseNSLinks(lines []string) (map[string]string, error) {
	out := map[string]string{}
	for _, raw := range lines {
		l := strings.TrimSpace(raw)
		m := nsLink.FindStringSubmatch(l)
		if m == nil {
			return nil, fmt.Errorf("unparsed namespace link %q", raw)
		}
		if _, dup := out[m[1]]; dup {
			return nil, fmt.Errorf("namespace %q twice", m[1])
		}
		out[m[1]] = m[2]
	}
	return out, nil
}

// RecheckBwrap compares the sandboxed process's namespaces with the host
// helper's own. The mount and pid namespaces must differ; the network
// namespace must differ when the plan asked for a private one.
func RecheckBwrap(plan PlannedBwrap, hostLines, childLines []string) RecheckResult {
	fail := func(why string) RecheckResult {
		return RecheckResult{Verdict: VerdictBuiltBelowPlan, Reason: why, Class: vocab.ClassNone}
	}
	host, err := ParseNSLinks(hostLines)
	if err != nil {
		return fail("host namespaces: " + err.Error())
	}
	child, err := ParseNSLinks(childLines)
	if err != nil {
		return fail("sandbox namespaces: " + err.Error())
	}
	for _, ns := range requiredNS {
		if host[ns] == "" || child[ns] == "" {
			return fail("namespace " + ns + " not reported")
		}
	}
	if child["mnt"] == host["mnt"] || child["pid"] == host["pid"] {
		return fail("the sandbox shares the host's mount or pid namespace")
	}
	private := child["net"] != host["net"]
	if plan.PrivateNet && !private {
		return fail("the plan asked for a private network namespace and the sandbox shares the host's")
	}
	return RecheckResult{OK: true, Class: vocab.ClassProcess, PrivateNet: private}
}
