package main

import (
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// sdkR165Verbs are the `observer sdk` leaf commands R-165 must deny an agent:
// each changes which SDK key this machine holds, and so where an app's data
// may go (Plane A W2-7, lane sdk-use-key).
var sdkR165Verbs = map[string]string{
	"sdk sign-in":  "mints the member's SDK key, which lets apps send data off this machine",
	"sdk sign-out": "revokes the member's SDK key on the organization (--all: on every machine)",
	"sdk use-key":  "installs an SDK key an admin issued, which lets apps send data off this machine",
}

// sdkR165VerbExceptions are the `observer sdk` leaves R-165 lets through.
var sdkR165VerbExceptions = map[string]string{
	"sdk status": "read",
}

// TestEverySDKVerbIsR165OrExcepted walks every leaf of `observer sdk`: each
// is an R-165 denial or a reasoned exception, so a new SDK key verb cannot
// land without a decision (the obs verbs' walk, TestEveryObsVerbIsR165OrExcepted,
// is the precedent).
func TestEverySDKVerbIsR165OrExcepted(t *testing.T) {
	e, err := policy.New(policy.Config{Mode: policy.ModeEnforce, Home: "/home/u"})
	if err != nil {
		t.Fatalf("policy.New: %v", err)
	}
	verdict := func(line string) policy.Verdict {
		return e.Evaluate(policy.Event{Kind: policy.KindShellExec, Target: line, Cwd: "/home/u/p", ProjectRoot: "/home/u/p", SessionID: "s", Now: time.Now()})
	}
	seen := map[string]bool{}
	var walk func(c *cobra.Command, path string)
	walk = func(c *cobra.Command, path string) {
		path = strings.TrimSpace(path + " " + c.Name())
		if c.RunE != nil || c.Run != nil {
			seen[path] = true
			_, deny := sdkR165Verbs[path]
			_, exc := sdkR165VerbExceptions[path]
			switch {
			case deny && exc:
				t.Errorf("%q is in both tables", path)
			case !deny && !exc:
				t.Errorf("`observer %s` is neither an R-165 verb row (sdkR165Verbs plus a row in internal/policy/rules_selfapproval.go) nor a reasoned exception (sdkR165VerbExceptions)", path)
			case deny:
				if v := verdict("observer " + path); v.RuleID != "R-165" || v.Decision != policy.DecisionDeny {
					t.Errorf("`observer %s` %s, but R-165 does not deny it (got %s/%s)", path, sdkR165Verbs[path], v.RuleID, v.Decision)
				}
			default:
				if v := verdict("observer " + path); v.RuleID == "R-165" {
					t.Errorf("`observer %s` is a read, but R-165 matches it", path)
				}
			}
		}
		for _, s := range c.Commands() {
			walk(s, path)
		}
	}
	walk(newSDKCmd(), "")
	for _, tbl := range []map[string]string{sdkR165Verbs, sdkR165VerbExceptions} {
		for p := range tbl {
			if !seen[p] {
				t.Errorf("table names `observer %s`, which is not an sdk verb (stale row)", p)
			}
		}
	}
}
