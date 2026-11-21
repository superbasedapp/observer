package secassess

import (
	"strings"
	"testing"
)

// TestSelfCheckBinaryRows: one case per row of the table that decides how the
// self-check line spells its command word, in the order the rows are asked, plus
// the paths that pass every row.
func TestSelfCheckBinaryRows(t *testing.T) {
	const dev = "/home/marmu/sbo-scratch/tr-grants/bin/observer"
	longDir := "/" + strings.Repeat("d", MaxSelfCheckBinBytes-len("/observer")) // one byte over once "/observer" is added
	atBound := "/" + strings.Repeat("d", MaxSelfCheckBinBytes-len("/observer")-1) + "/observer"
	cases := []struct {
		name string
		in   BinaryFacts
		bin  string // the command word
		row  string // the refusing row ("" when the path is used)
	}{
		{"B1 no path", BinaryFacts{}, "observer", "B1"},
		{"B1 no path, sandboxed", BinaryFacts{Backend: "bwrap"}, "observer", "B1"},
		{"B2 replaced under the running daemon", BinaryFacts{Path: dev + " (deleted)"}, "observer", "B2"},
		{"B3 a Windows path", BinaryFacts{Path: `C:\Users\u\bin\observer.exe`}, "observer", "B3"},
		{"B3 a relative path", BinaryFacts{Path: "bin/observer"}, "observer", "B3"},
		{"B3 a space", BinaryFacts{Path: "/home/u/My Tools/observer"}, "observer", "B3"},
		{"B3 a quote", BinaryFacts{Path: "/home/u/it's/observer"}, "observer", "B3"},
		{"B3 a dollar sign", BinaryFacts{Path: "/home/$USER/observer"}, "observer", "B3"},
		{"B3 a dot dot folder", BinaryFacts{Path: "/home/u/../bin/observer"}, "observer", "B3"},
		{"B3 an empty folder", BinaryFacts{Path: "/home//u/observer"}, "observer", "B3"},
		{"B3 a trailing slash", BinaryFacts{Path: "/home/u/observer/"}, "observer", "B3"},
		{"B3 over the byte bound", BinaryFacts{Path: longDir + "/observer"}, "observer", "B3"},
		{"B3 the root", BinaryFacts{Path: "/"}, "observer", "B3"},
		{"B4 another file name", BinaryFacts{Path: "/home/u/bin/observer-dev"}, "observer", "B4"},
		{"B4 a test binary", BinaryFacts{Path: "/tmp/go-build123/b001/observer.test"}, "observer", "B4"},
		{"B5 a sandbox with its own copy", BinaryFacts{Path: dev, Backend: "apple-container"}, "observer", "B5"},
		{"B5 an unknown backend", BinaryFacts{Path: dev, Backend: "somewhere"}, "observer", "B5"},
		{"the path, on the host", BinaryFacts{Path: dev}, dev, ""},
		{"the path, in bubblewrap", BinaryFacts{Path: dev, Backend: "bwrap"}, dev, ""},
		{"the path, installed", BinaryFacts{Path: "/usr/local/bin/observer"}, "/usr/local/bin/observer", ""},
		{"the path, with the punctuation a package folder holds", BinaryFacts{Path: "/home/u/.local/lib/node_modules/@superbased/observer-linux-x64/bin/observer"}, "/home/u/.local/lib/node_modules/@superbased/observer-linux-x64/bin/observer", ""},
		{"the path, at the byte bound", BinaryFacts{Path: atBound}, atBound, ""},
	}
	if len(atBound) != MaxSelfCheckBinBytes {
		t.Fatalf("the fixture's longest path is %d bytes, not %d", len(atBound), MaxSelfCheckBinBytes)
	}
	seen := map[string]bool{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bin, row := SelfCheckBinary(tc.in)
			if bin != tc.bin || row != tc.row {
				t.Errorf("SelfCheckBinary(%+v) = %q, %q; want %q, %q", tc.in, bin, row, tc.bin, tc.row)
			}
		})
		if tc.row != "" {
			seen[tc.row] = true
		}
	}
	// Every row has a case (the cases are written so that only that row, once
	// the earlier ones have let the path through, refuses it).
	for _, r := range selfCheckBinRows {
		if !seen[r.ID] {
			t.Errorf("row %s has no case", r.ID)
		}
	}
}

// TestHostBinaryBackendsAreGrounded: a backend in the table that holds the
// daemon's binary at its host path names where that is grounded, and the table
// holds each backend once; a backend the table lacks is refused (row B5).
func TestHostBinaryBackendsAreGrounded(t *testing.T) {
	seen := map[string]bool{}
	for _, b := range hostBinaryBackends {
		if b.ID == "" || strings.TrimSpace(b.Ground) == "" || seen[b.ID] {
			t.Errorf("row %+v: no id, no ground, or a repeat", b)
		}
		seen[b.ID] = true
		if !bindsHostBinary(b.ID) {
			t.Errorf("%s is in the table and not read from it", b.ID)
		}
	}
	// Every backend a run that runs only in a sandbox may use (rule E9's table)
	// is one that holds the binary at its host path, or the line is dead there.
	for _, id := range LoopbackBackendIDs() {
		if !bindsHostBinary(id) {
			t.Errorf("%s is a backend a confined assessment runs in, and no row says its box holds the daemon's binary at its host path: the self-check line would name a path the box lacks", id)
		}
	}
}

// TestSelfCheckLineNamesThePath: the task's self-check line starts with the
// command word the rows chose, in every kind that has a result model, and a kind
// without one has no line.
func TestSelfCheckLineNamesThePath(t *testing.T) {
	const dev = "/home/marmu/sbo-scratch/tr-grants/bin/observer"
	target, _ := ParseTarget("http://localhost:3000/")
	cases := []struct {
		name string
		in   PromptInput
		want string // the line's command, "" for no line
	}{
		{"threat model, a path", PromptInput{Kind: ThreatModel, SelfCheck: true, Binary: BinaryFacts{Path: dev}}, dev + " security assess check .observer/assessments/" + testRun + "/assessment.json"},
		{"pen test, a path in bubblewrap", PromptInput{Kind: PentestLocal, Target: &target, SelfCheck: true, Binary: BinaryFacts{Path: dev, Backend: "bwrap"}}, dev + " security assess check .observer/assessments/" + testRun + "/assessment.json"},
		{"red team, a path", PromptInput{Kind: RedTeamLocal, Target: &target, SelfCheck: true, Binary: BinaryFacts{Path: dev, Backend: "bwrap"}}, dev + " security assess check .observer/assessments/" + testRun + "/assessment.json"},
		{"retest, a path", PromptInput{Kind: PentestRetest, Target: &target, SelfCheck: true, Replay: testReplayBasis(), Binary: BinaryFacts{Path: dev, Backend: "bwrap"}}, dev + " security assess check .observer/assessments/" + testRun + "/assessment.json"},
		{"pen test, the path was replaced", PromptInput{Kind: PentestLocal, Target: &target, SelfCheck: true, Binary: BinaryFacts{Path: dev + " (deleted)", Backend: "bwrap"}}, "observer security assess check .observer/assessments/" + testRun + "/assessment.json"},
		{"pen test, no path known", PromptInput{Kind: PentestLocal, Target: &target, SelfCheck: true}, "observer security assess check .observer/assessments/" + testRun + "/assessment.json"},
		{"pen test, self-check off", PromptInput{Kind: PentestLocal, Target: &target, Binary: BinaryFacts{Path: dev}}, ""},
		{"a kind with no result model", PromptInput{Kind: CSPMReadonly, SelfCheck: true, Binary: BinaryFacts{Path: dev}}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.in.RunID, tc.in.ProjectName = testRun, "my-app"
			p, err := BuildPrompt(tc.in)
			if err != nil {
				t.Fatal(err)
			}
			if tc.want == "" {
				if strings.Contains(p, "SELF-CHECK") || strings.Contains(p, " security assess check ") {
					t.Errorf("a self-check line is in the task")
				}
				return
			}
			line := "SELF-CHECK: before you finish, run `" + tc.want + "` and fix what it names."
			if !strings.Contains(p, line) {
				t.Errorf("the task lacks %q", line)
			}
			if strings.Count(p, " security assess check ") != 1 {
				t.Errorf("the check is named %d times", strings.Count(p, " security assess check "))
			}
		})
	}
}
