package secrules

import (
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// fakeAWSKeyID is shaped like an AWS key id and visibly fake. It is not an
// ...EXAMPLE value on purpose: secdetect never fires on an AWS-shaped key
// ending in EXAMPLE (knownExample), and these tests need a hit.
const fakeAWSKeyID = "AKIA" + "FAKEFIXTURE0TEST" // split: GitHub push protection on the public mirror

// writeEvent builds a write event and stamps Event.Security the way the
// hook context seam does, through PreWriteSecurity.
func writeEvent(target string, edits ...policy.ProposedEdit) policy.Event {
	ev := policy.Event{
		Kind: policy.KindFileAccess, ActionType: "write_file", Target: target,
		ProjectRoot: "/r", Cwd: "/r", Edits: edits, Now: time.Unix(1, 0),
		Caps: policy.Capabilities{PreExecution: true, CanBlock: true, CanAsk: true},
	}
	hits, incomplete := PreWriteSecurity(&ev)
	ev.Security = &policy.Security{Posture: policy.SecurityPostureClean, Hits: hits, ScanIncomplete: incomplete}
	return ev
}

func TestSecretRuleS721(t *testing.T) {
	key := policy.ProposedEdit{Kind: policy.EditWhole, New: "x = 1\nk = \"" + fakeAWSKeyID + "\"\n"}
	cases := []struct {
		name    string
		ev      policy.Event
		mode    policy.Mode
		want    policy.Decision
		matched bool
	}{
		{"observe flags", writeEvent("/r/cfg/prod.py", key), policy.ModeObserve, policy.DecisionFlag, true},
		{"enforce denies", writeEvent("/r/cfg/prod.py", key), policy.ModeEnforce, policy.DecisionDeny, true},
		{"fixture asks under enforce", writeEvent("/r/internal/x/testdata/k.py", key), policy.ModeEnforce, policy.DecisionAsk, true},
		{"edit replace", writeEvent("/r/a.py", policy.ProposedEdit{Kind: policy.EditReplace, Old: "x", New: "k = \"" + fakeAWSKeyID + "\""}), policy.ModeEnforce, policy.DecisionDeny, true},
		{"removed text is not added", writeEvent("/r/a.py", policy.ProposedEdit{Kind: policy.EditReplace, Old: "k = \"" + fakeAWSKeyID + "\"", New: "k = os.environ['K']"}), policy.ModeEnforce, policy.DecisionAllow, false},
		{"clean write", writeEvent("/r/a.py", policy.ProposedEdit{Kind: policy.EditWhole, New: "print(1)\n"}), policy.ModeEnforce, policy.DecisionAllow, false},
		{"no edits (watcher path)", writeEvent("/r/a.py"), policy.ModeEnforce, policy.DecisionAllow, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			eng, err := policy.New(policy.Config{Mode: tc.mode, Home: "/home/u", ExtraRules: SecretRules()})
			if err != nil {
				t.Fatal(err)
			}
			v := eng.Evaluate(tc.ev)
			if (v.RuleID == "S-721") != tc.matched {
				t.Fatalf("verdict = %+v, matched want %v", v, tc.matched)
			}
			if tc.matched && v.Decision != tc.want {
				t.Fatalf("decision = %v, want %v", v.Decision, tc.want)
			}
			if tc.matched {
				if strings.Contains(v.Reason, fakeAWSKeyID) {
					t.Fatal("the secret value reached the verdict reason")
				}
				if !strings.Contains(v.Reason, `"`) || !strings.Contains(v.Reason, "AWS") {
					t.Fatalf("reason lacks the templated location: %q", v.Reason)
				}
			}
		})
	}
}

// TestPreWriteSecurityCapsBeforeCopy (P-003, SEC-C2 milestone 1g): a huge
// edit is cut to the in-hook cap before it is copied; a secret inside the
// cap is still found and what was cut is reported as scan_incomplete.
func TestPreWriteSecurityCapsBeforeCopy(t *testing.T) {
	big := "k = \"" + fakeAWSKeyID + "\"\n" + strings.Repeat("x = 1\n", 1<<20)
	ev := policy.Event{
		Kind: policy.KindFileAccess, ActionType: "write_file", Target: "/r/a.py", ProjectRoot: "/r",
		Edits: []policy.ProposedEdit{{Kind: policy.EditWhole, New: big}, {Kind: policy.EditWhole, New: "y = 2\n"}},
	}
	hits, incomplete := PreWriteSecurity(&ev)
	if len(hits) != 1 || !incomplete {
		t.Fatalf("hits %+v incomplete %v, want one hit and incomplete", hits, incomplete)
	}
	small := policy.Event{
		Kind: policy.KindFileAccess, ActionType: "write_file", Target: "/r/a.py", ProjectRoot: "/r",
		Edits: []policy.ProposedEdit{{Kind: policy.EditWhole, New: "y = 2\n"}},
	}
	if _, inc := PreWriteSecurity(&small); inc {
		t.Fatal("a small edit reads incomplete")
	}
}
