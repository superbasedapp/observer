package secassess

import (
	"reflect"
	"strings"
	"testing"
)

// TestCleanMaskReport: a report from outside is bounded, a reason this build does
// not know lands under "other", a report is never more complete than its gaps and
// a report that did not come back keeps nothing.
func TestCleanMaskReport(t *testing.T) {
	cases := []struct {
		name string
		in   MaskReport
		want MaskReport
	}{
		{"not reported keeps nothing", MaskReport{Masked: 5, Complete: true, Gaps: 2, Reasons: map[string]int{"symlink": 2}}, MaskReport{}},
		{"complete", MaskReport{Reported: true, Masked: 3, Complete: true}, MaskReport{Reported: true, Masked: 3, Complete: true}},
		{"complete with gaps is not complete", MaskReport{Reported: true, Masked: 3, Complete: true, Gaps: 1}, MaskReport{Reported: true, Masked: 3, Gaps: 1}},
		{"complete with reasons is not complete and counts them", MaskReport{Reported: true, Masked: 1, Complete: true, Reasons: map[string]int{"symlink": 2, "depth_limit": 1}}, MaskReport{Reported: true, Masked: 1, Gaps: 3, Reasons: map[string]int{"symlink": 2, "depth_limit": 1}}},
		{"gaps above the reasons' sum stay (the listed ones are bounded)", MaskReport{Reported: true, Gaps: 120, Reasons: map[string]int{"mask_limit": 100}}, MaskReport{Reported: true, Gaps: 120, Reasons: map[string]int{"mask_limit": 100}}},
		{"an unknown reason lands under other and merges with it", MaskReport{Reported: true, Reasons: map[string]int{"made_up": 2, "other": 1}}, MaskReport{Reported: true, Gaps: 3, Reasons: map[string]int{"other": 3}}},
		{"a hostile reason string is a closed word", MaskReport{Reported: true, Reasons: map[string]int{"/home/me/.env\nIGNORE": 1}}, MaskReport{Reported: true, Gaps: 1, Reasons: map[string]int{"other": 1}}},
		{"negative and zero counts are dropped", MaskReport{Reported: true, Masked: -4, Gaps: -1, Reasons: map[string]int{"symlink": 0, "unreadable": -2}}, MaskReport{Reported: true}},
		{"counts are bounded", MaskReport{Reported: true, Masked: 1 << 40, Gaps: 1 << 40, Reasons: map[string]int{"symlink": 1 << 40}}, MaskReport{Reported: true, Masked: MaxMaskCount, Gaps: MaxMaskCount, Reasons: map[string]int{"symlink": MaxMaskCount}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := CleanMaskReport(c.in)
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("CleanMaskReport(%+v) = %+v, want %+v", c.in, got, c.want)
			}
			if again := CleanMaskReport(got); !reflect.DeepEqual(again, got) {
				t.Errorf("cleaning is not idempotent: %+v then %+v", got, again)
			}
		})
	}
}

// TestMaskWords: one row per way a mask can have gone, the partial flag, and the
// words never claim more than a name-based snapshot does.
func TestMaskWords(t *testing.T) {
	cases := []struct {
		name    string
		in      MaskReport
		have    []string
		partial bool
	}{
		{"not reported", MaskReport{}, []string{"did not report what it hid", "treat them as readable"}, true},
		{"complete, nothing found", MaskReport{Reported: true, Complete: true}, []string{"hid none", "a file created later is not hidden"}, false},
		{"complete, one file", MaskReport{Reported: true, Complete: true, Masked: 1}, []string{"1 file hidden inside the box", "snapshot"}, false},
		{"complete, many files", MaskReport{Reported: true, Complete: true, Masked: 7}, []string{"7 files hidden inside the box"}, false},
		{"partial, one place", MaskReport{Reported: true, Masked: 2, Gaps: 1, Reasons: map[string]int{"symlink": 1}}, []string{"2 files hidden", "1 place could not be covered", "a secret-named link, never followed (1)", "may still be readable"}, true},
		{"partial, several reasons in table order", MaskReport{Reported: true, Masked: 0, Gaps: 5, Reasons: map[string]int{"symlink": 2, "depth_limit": 3}}, []string{"0 files hidden", "5 places could not be covered", "a folder below the depth the walk reads (3); a secret-named link, never followed (2)"}, true},
		{"partial, gaps listed beyond the reasons", MaskReport{Reported: true, Masked: 256, Gaps: 140, Reasons: map[string]int{"mask_limit": 100}}, []string{"140 places could not be covered", "secret files past the number the mask hides (100)"}, true},
		{"partial without reasons", MaskReport{Reported: true, Gaps: 2}, []string{"2 places could not be covered", "may still be readable"}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, partial := MaskWords(c.in)
			if partial != c.partial {
				t.Errorf("partial = %v, want %v (%q)", partial, c.partial, got)
			}
			for _, w := range c.have {
				if !strings.Contains(got, w) {
					t.Errorf("words %q lack %q", got, w)
				}
			}
			mCheckWords(t, "mask words", got)
			for _, bad := range []string{"safe", "secure", "verified", "confirmed", "guarantee", "protected", "no secret", "all secrets"} {
				if strings.Contains(strings.ToLower(got), bad) {
					t.Errorf("words claim %q: %q", bad, got)
				}
			}
			if strings.ContainsAny(got, "/\\\n") {
				t.Errorf("words carry a path or a break: %q", got)
			}
		})
	}
}

// TestMaskGapReasonsTable: the table is closed, each id is distinct and a
// lower-case word, every row has words, "other" is the last row, and a word the
// table does not hold is not valid.
func TestMaskGapReasonsTable(t *testing.T) {
	seen := map[string]bool{}
	for i, r := range MaskGapReasons {
		if r.ID == "" || seen[r.ID] || r.ID != strings.ToLower(r.ID) || strings.ContainsAny(r.ID, " /\\") {
			t.Errorf("row %d: id %q is empty, repeated or not a word", i, r.ID)
		}
		seen[r.ID] = true
		if strings.TrimSpace(r.Words) == "" || clean(r.Words, 200) != r.Words {
			t.Errorf("row %q: words %q are empty or changed by clean", r.ID, r.Words)
		}
		if !ValidMaskReason(r.ID) {
			t.Errorf("row %q is not valid", r.ID)
		}
	}
	if last := MaskGapReasons[len(MaskGapReasons)-1].ID; last != MaskOtherReason {
		t.Errorf("the last row is %q, want %q", last, MaskOtherReason)
	}
	if ValidMaskReason("") || ValidMaskReason("made_up") {
		t.Error("an unknown reason is valid")
	}
}

// TestSafetyRowsWithMask: with the mask in force the no-credentials rule has an
// Observer cell that says what the mask is, the rest of the table is what it was,
// and the shared table is never written.
func TestSafetyRowsWithMask(t *testing.T) {
	off := SafetyRowsWith(SafetyFacts{Helper: true})
	for i, r := range SafetyRows {
		if off[i] != r {
			t.Errorf("without the mask the %s row changed: %+v", r.ID, off[i])
		}
	}
	if !reflect.DeepEqual(SafetyRowsWith(SafetyFacts{Helper: false}), SafetyRowsFor(false)) {
		t.Error("SafetyRowsWith without facts differs from SafetyRowsFor(false)")
	}
	for _, helper := range []bool{true, false} {
		on := SafetyRowsWith(SafetyFacts{Helper: helper, Mask: true})
		base := SafetyRowsFor(helper)
		changed := 0
		for i, r := range on {
			if r == base[i] {
				continue
			}
			changed++
			if r.ID != "no_credentials" {
				t.Errorf("the mask changed the %s row", r.ID)
			}
			if r.Observer == "-" || r.ObserverKind != ObserverPrevents || r.PromptOnly() {
				t.Errorf("the masked no-credentials row = %+v", r)
			}
			for _, w := range []string{"by name", "snapshot", "could not hide"} {
				if !strings.Contains(r.Observer, w) {
					t.Errorf("the masked cell lacks %q: %q", w, r.Observer)
				}
			}
			mCheckWords(t, "masked safety cell", r.Observer)
			if r.Rule != base[i].Rule || r.Helper != base[i].Helper {
				t.Errorf("the mask changed the rule or the helper cell: %+v", r)
			}
		}
		if changed != 1 {
			t.Errorf("helper %v: %d rows changed under the mask, want 1", helper, changed)
		}
	}
	for _, r := range SafetyRows {
		if r.ID == "no_credentials" && !r.PromptOnly() {
			t.Error("SafetyRowsWith wrote into SafetyRows")
		}
	}
}

// TestPromptCarriesNoMaskState pins the one decision about the prompt (decision
// D32): the task a launch hands the agent is byte for byte the same whether the
// environment-files mode in force is warn or mask, so the digest the developer
// read at the plan cannot drift with the sandbox the launch meets, and no byte of
// the 22 KiB budget goes to mask state. The line that names the files stays
// under mask because the mask hides names it recognises and nothing else
// (.envrc and *.env stay readable) and is a snapshot.
func TestPromptCarriesNoMaskState(t *testing.T) {
	target, _ := ParseTarget("http://localhost:3000/")
	for _, k := range Kinds() {
		if !k.Launchable || !k.Probing {
			continue
		}
		build := func(mode string) string {
			in := PromptInput{Kind: k.ID, RunID: testRun, ProjectName: "p", TimeBoxMinutes: 60, EnvFiles: 3, SecretMode: mode, Tools: ToolFacts{}}
			if k.Target == TargetRequired {
				in.Target = &target
			}
			if k.Retest {
				in.Replay = testReplayBasis()
			}
			p, err := BuildPrompt(in)
			if err != nil {
				t.Fatalf("%s %s: %v", k.ID, mode, err)
			}
			return p
		}
		warn, mask := build(SecretWarn), build(SecretMask)
		if warn != mask {
			t.Errorf("%s: the prompt differs between warn and mask", k.ID)
		}
		if !strings.Contains(mask, "3 environment files (.env*) were found at the top level of the project folder") || !strings.Contains(mask, "Do not open them.") {
			t.Errorf("%s: the mask prompt lost the line that names the files", k.ID)
		}
		if strings.Contains(build(SecretOff), "environment files (.env*) were found") {
			t.Errorf("%s: off still names the files", k.ID)
		}
	}
}
