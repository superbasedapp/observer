package secassess

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
)

func TestParseStatusZ(t *testing.T) {
	cases := []struct {
		name string
		out  string
		want []TreeEntry
	}{
		{"empty", "", nil},
		{"modified and untracked", " M a.go\x00?? b.txt\x00", []TreeEntry{{Status: " M", Path: "a.go"}, {Status: "??", Path: "b.txt"}}},
		{"sorted by path", "?? z\x00 M a\x00", []TreeEntry{{Status: " M", Path: "a"}, {Status: "??", Path: "z"}}},
		{"rename drops the original path", "R  new.go\x00old.go\x00 M a.go\x00", []TreeEntry{{Status: " M", Path: "a.go"}, {Status: "R ", Path: "new.go"}}},
		{"copy drops the original path", "C  copy.go\x00orig.go\x00", []TreeEntry{{Status: "C ", Path: "copy.go"}}},
		{"staged and worktree", "MM both.go\x00A  added.go\x00D  gone.go\x00", []TreeEntry{{Status: "A ", Path: "added.go"}, {Status: "MM", Path: "both.go"}, {Status: "D ", Path: "gone.go"}}},
		{"path with spaces", "?? a b c.txt\x00", []TreeEntry{{Status: "??", Path: "a b c.txt"}}},
		{"junk fields are skipped", "x\x00\x00 M ok.go\x00", []TreeEntry{{Status: " M", Path: "ok.go"}}},
		{"missing separator is skipped", "XYa.go\x00", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, trunc := ParseStatusZ([]byte(c.out))
			if trunc || len(got) != len(c.want) {
				t.Fatalf("got %v trunc %v, want %v", got, trunc, c.want)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Fatalf("entry %d = %+v, want %+v", i, got[i], c.want[i])
				}
			}
		})
	}
}

func TestParseStatusZCap(t *testing.T) {
	var b strings.Builder
	for i := 0; i < MaxTreeEntries+5; i++ {
		b.WriteString("?? f")
		b.WriteString(strings.Repeat("x", i%7))
		b.WriteString(string(rune('a' + i%26)))
		b.WriteString(strings.Repeat("y", i/26))
		b.WriteString("\x00")
	}
	got, trunc := ParseStatusZ([]byte(b.String()))
	if len(got) != MaxTreeEntries || !trunc {
		t.Fatalf("%d entries, truncated %v", len(got), trunc)
	}
	at := strings.Repeat("?? p\x00", MaxTreeEntries)
	if got, trunc := ParseStatusZ([]byte(at)); len(got) != MaxTreeEntries || trunc {
		t.Fatalf("on the cap: %d entries, truncated %v", len(got), trunc)
	}
}

func TestTreeStatusArgs(t *testing.T) {
	// A strict policy lists every untracked file on its own, so an edit inside a
	// new directory can be fingerprinted; the other policies let git collapse a
	// directory because untracked files do not count for them.
	cases := []struct {
		policy    TreePolicy
		untracked string
	}{
		{TreeStrict, "--untracked-files=all"},
		{TreeUntrackedReported, "--untracked-files=normal"},
	}
	for _, c := range cases {
		t.Run(string(c.policy), func(t *testing.T) {
			args := TreeStatusArgs(c.policy)
			joined := strings.Join(args, " ")
			for _, want := range []string{"--porcelain=v1", "-z", c.untracked, ":(exclude).observer/assessments"} {
				if !strings.Contains(joined, want) {
					t.Errorf("args %q lack %q", joined, want)
				}
			}
			if args[0] != "status" {
				t.Fatalf("args = %v", args)
			}
		})
	}
}

func TestPolicyCounts(t *testing.T) {
	tracked, untracked := TreeEntry{Status: " M", Path: "a"}, TreeEntry{Status: "??", Path: "b"}
	cases := []struct {
		policy TreePolicy
		entry  TreeEntry
		want   bool
	}{
		{TreeStrict, tracked, true},
		{TreeStrict, untracked, true},
		{TreeUntrackedReported, tracked, true},
		{TreeUntrackedReported, untracked, false},
	}
	for _, c := range cases {
		if got := c.policy.Counts(c.entry); got != c.want {
			t.Errorf("%s.Counts(%s) = %v, want %v", c.policy, c.entry.Status, got, c.want)
		}
	}
}

func snap(entries ...TreeEntry) TreeSnapshot {
	return TreeSnapshot{OK: true, Head: "h1", Branch: "main", StashCount: 0, RefsDigest: "r1", Entries: entries}
}

// Two distinct stored fingerprints (FpLen hex characters).
const (
	fpA = "0123456789abcdef0123"
	fpB = "fedcba9876543210fedc"
)

func TestAuditTree(t *testing.T) {
	mod := TreeEntry{Status: " M", Path: "a.go"}
	mod2 := TreeEntry{Status: " M", Path: "b.go"}
	untr := TreeEntry{Status: "??", Path: "cache/x.pyc"}
	modA, modB := TreeEntry{Status: " M", Path: "a.go", Fp: fpA}, TreeEntry{Status: " M", Path: "a.go", Fp: fpB}
	untrA, untrB := TreeEntry{Status: "??", Path: "cache/x.pyc", Fp: fpA}, TreeEntry{Status: "??", Path: "cache/x.pyc", Fp: fpB}
	gone := TreeEntry{Status: " D", Path: "gone.go", Fp: FpAbsent}
	with := func(s TreeSnapshot, f func(*TreeSnapshot)) TreeSnapshot { f(&s); return s }

	cases := []struct {
		name          string
		before, after TreeSnapshot
		policy        TreePolicy
		want          AuditVerdict
		reason        string
	}{
		{"identical, strict", snap(modA), snap(modA), TreeStrict, AuditNoChange, ""},
		{"identical, untracked reported", snap(modA), snap(modA), TreeUntrackedReported, AuditNoChange, ""},
		{"head moved", snap(), with(snap(), func(s *TreeSnapshot) { s.Head = "h2" }), TreeStrict, AuditChanged, ""},
		{"head moved, untracked reported", snap(), with(snap(), func(s *TreeSnapshot) { s.Head = "h2" }), TreeUntrackedReported, AuditChanged, ""},
		{"branch switched", snap(), with(snap(), func(s *TreeSnapshot) { s.Branch = "other" }), TreeUntrackedReported, AuditChanged, ""},
		{"stash added", snap(), with(snap(), func(s *TreeSnapshot) { s.StashCount = 1 }), TreeStrict, AuditChanged, ""},
		{"ref added", snap(), with(snap(), func(s *TreeSnapshot) { s.RefsDigest = "r2" }), TreeUntrackedReported, AuditChanged, ""},
		{"tracked file edited", snap(), snap(mod), TreeStrict, AuditChanged, ""},
		{"tracked file edited, untracked reported", snap(), snap(mod), TreeUntrackedReported, AuditChanged, ""},
		{"tracked edit reverted", snap(mod), snap(), TreeUntrackedReported, AuditChanged, ""},
		{"a different tracked file", snap(mod), snap(mod2), TreeUntrackedReported, AuditChanged, ""},
		{"status of a tracked file changed", snap(mod), snap(TreeEntry{Status: "M ", Path: "a.go"}), TreeUntrackedReported, AuditChanged, ""},
		{"untracked file added, strict", snap(), snap(untr), TreeStrict, AuditChanged, ""},
		{"untracked file added, reported only", snap(), snap(untr), TreeUntrackedReported, AuditNoChange, ""},
		{"untracked file removed, strict", snap(untr), snap(), TreeStrict, AuditChanged, ""},
		{"untracked file removed, reported only", snap(untr), snap(), TreeUntrackedReported, AuditNoChange, ""},
		{"not audited ignores everything", snap(), with(snap(), func(s *TreeSnapshot) { s.Head = "h2" }), TreeNotAudited, AuditNotAudited, ""},
		{"not audited ignores failure", TreeSnapshot{}, TreeSnapshot{}, TreeNotAudited, AuditNotAudited, ""},
		{"before failed", TreeSnapshot{}, snap(), TreeStrict, AuditUnchecked, "before_failed"},
		{"after failed", snap(), TreeSnapshot{}, TreeUntrackedReported, AuditUnchecked, "after_failed"},
		{"both failed", TreeSnapshot{}, TreeSnapshot{}, TreeStrict, AuditUnchecked, "before_failed"},
		{"truncated with no visible change", with(snap(mod), func(s *TreeSnapshot) { s.Truncated = true }), snap(mod), TreeStrict, AuditPartial, ReasonTruncated},
		{"truncated after", snap(mod), with(snap(mod), func(s *TreeSnapshot) { s.Truncated = true }), TreeUntrackedReported, AuditPartial, ReasonTruncated},
		{"truncated but a change is visible", with(snap(), func(s *TreeSnapshot) { s.Truncated = true }), snap(mod), TreeStrict, AuditChanged, ""},

		// The content fingerprint (review finding M3): a file that was already
		// dirty and is edited again keeps its status line.
		{"dirty tracked file edited again, strict", snap(modA), snap(modB), TreeStrict, AuditChanged, ""},
		{"dirty tracked file edited again, untracked reported", snap(modA), snap(modB), TreeUntrackedReported, AuditChanged, ""},
		{"dirty tracked file untouched", snap(modA), snap(modA), TreeStrict, AuditNoChange, ""},
		{"dirty tracked file untouched, untracked reported", snap(modA), snap(modA), TreeUntrackedReported, AuditNoChange, ""},
		{"untracked file edited, strict", snap(untrA), snap(untrB), TreeStrict, AuditChanged, ""},
		{"untracked file edited, reported only", snap(untrA), snap(untrB), TreeUntrackedReported, AuditNoChange, ""},
		{"untracked file untouched, strict", snap(untrA), snap(untrA), TreeStrict, AuditNoChange, ""},
		{"deleted file stays deleted", snap(gone), snap(gone), TreeStrict, AuditNoChange, ""},
		{"deleted file recreated with content", snap(gone), snap(TreeEntry{Status: " M", Path: "gone.go", Fp: fpB}), TreeStrict, AuditChanged, ""},

		// Coverage: a path that was not fingerprinted is never read as unchanged.
		{"tracked file with no fingerprint at either end", snap(mod), snap(mod), TreeStrict, AuditPartial, ReasonNotFingerprinted},
		{"tracked file with no fingerprint, untracked reported", snap(mod), snap(mod), TreeUntrackedReported, AuditPartial, ReasonNotFingerprinted},
		{"untracked file with no fingerprint, strict", snap(untr), snap(untr), TreeStrict, AuditPartial, ReasonNotFingerprinted},
		{"untracked file with no fingerprint, reported only", snap(untr), snap(untr), TreeUntrackedReported, AuditNoChange, ""},
		{"old record: no fingerprint before, one after", snap(mod), snap(modA), TreeStrict, AuditPartial, ReasonNotFingerprinted},
		{"no fingerprint after, one before", snap(modA), snap(mod), TreeStrict, AuditPartial, ReasonNotFingerprinted},
		{"one path fingerprinted, one not", snap(modA, mod2), snap(modA, mod2), TreeStrict, AuditPartial, ReasonNotFingerprinted},
		{"a change is seen although a fingerprint is missing", snap(mod), snap(mod, mod2), TreeStrict, AuditChanged, ""},
		{"a fingerprint change is seen although another is missing", snap(modA, mod2), snap(modB, mod2), TreeStrict, AuditChanged, ""},
		{"truncated and fingerprints equal", with(snap(modA), func(s *TreeSnapshot) { s.Truncated = true }), snap(modA), TreeStrict, AuditPartial, ReasonTruncated},
		{"truncated takes the reason before a missing fingerprint", with(snap(mod), func(s *TreeSnapshot) { s.Truncated = true }), snap(mod), TreeStrict, AuditPartial, ReasonTruncated},
		{"truncated but an edit is seen", with(snap(modA), func(s *TreeSnapshot) { s.Truncated = true }), snap(modB), TreeStrict, AuditChanged, ""},
		{"not audited ignores fingerprints", snap(modA), snap(modB), TreeNotAudited, AuditNotAudited, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := AuditTree(c.before, c.after, c.policy)
			if got.Verdict != c.want || got.Reason != c.reason {
				t.Fatalf("verdict %s reason %q, want %s %q", got.Verdict, got.Reason, c.want, c.reason)
			}
		})
	}
}

func TestAuditTreeReportsWhatChanged(t *testing.T) {
	before := snap(TreeEntry{Status: " M", Path: "a.go"}, TreeEntry{Status: "??", Path: "old.tmp"})
	after := snap(TreeEntry{Status: " M", Path: "a.go"}, TreeEntry{Status: " M", Path: "b.go"}, TreeEntry{Status: "??", Path: "new.tmp"})
	after.Head = "h2"
	got := AuditTree(before, after, TreeStrict)
	if !got.HeadChanged || got.BranchChanged || got.StashChanged || got.RefsChanged {
		t.Fatalf("audit = %+v", got)
	}
	if strings.Join(got.TrackedChanged, ",") != "b.go" || strings.Join(got.UntrackedAdded, ",") != "new.tmp" || strings.Join(got.UntrackedGone, ",") != "old.tmp" {
		t.Fatalf("audit = %+v", got)
	}
}

// TestAuditTreeReportsEditedPaths: a path present at both ends whose content
// fingerprint differs is listed like any other change, tracked or untracked,
// and a path that was not fingerprinted is counted, never listed as changed.
func TestAuditTreeReportsEditedPaths(t *testing.T) {
	before := snap(
		TreeEntry{Status: " M", Path: "src/auth.py", Fp: fpA},
		TreeEntry{Status: " M", Path: "src/same.py", Fp: fpA},
		TreeEntry{Status: " M", Path: "src/blind.py"},
		TreeEntry{Status: "??", Path: "notes/draft.md", Fp: fpA},
	)
	after := snap(
		TreeEntry{Status: " M", Path: "src/auth.py", Fp: fpB},
		TreeEntry{Status: " M", Path: "src/same.py", Fp: fpA},
		TreeEntry{Status: " M", Path: "src/blind.py", Fp: fpA},
		TreeEntry{Status: "??", Path: "notes/draft.md", Fp: fpB},
	)
	got := AuditTree(before, after, TreeStrict)
	if got.Verdict != AuditChanged || got.Reason != "" {
		t.Fatalf("audit = %+v", got)
	}
	if strings.Join(got.TrackedChanged, ",") != "src/auth.py" || strings.Join(got.UntrackedEdited, ",") != "notes/draft.md" {
		t.Fatalf("lists = tracked %v, untracked edited %v", got.TrackedChanged, got.UntrackedEdited)
	}
	if len(got.UntrackedAdded) != 0 || len(got.UntrackedGone) != 0 || got.Uncompared != 1 {
		t.Fatalf("audit = %+v", got)
	}
	// An untracked edit is reported but is not a change under the reported-only policy.
	rep := AuditTree(snap(TreeEntry{Status: "??", Path: "x", Fp: fpA}), snap(TreeEntry{Status: "??", Path: "x", Fp: fpB}), TreeUntrackedReported)
	if rep.Verdict != AuditNoChange || strings.Join(rep.UntrackedEdited, ",") != "x" {
		t.Fatalf("reported-only audit = %+v", rep)
	}
}

// TestAuditTreeReviewScenario is the proof of finding M3: the developer starts
// a threat model with a dirty file, the agent edits it again, and the status
// line is the same at both ends. Before fingerprints this read no_change.
func TestAuditTreeReviewScenario(t *testing.T) {
	entry := func(fp string) TreeEntry { return TreeEntry{Status: " M", Path: "src/auth.py", Fp: fp} }
	if got := AuditTree(snap(entry(fpA)), snap(entry(fpB)), TreeStrict); got.Verdict != AuditChanged {
		t.Fatalf("a re-edited dirty file read %s", got.Verdict)
	}
	// The same snapshot compared with itself, as the old code compared them.
	if got := AuditTree(snap(entry("")), snap(entry("")), TreeStrict); got.Verdict == AuditNoChange {
		t.Fatalf("an unfingerprinted dirty file read no_change")
	}
}

// TestTreeSnapshotOldRecordStillDecodes: a snapshot stored before fingerprints
// existed has no "f" key, decodes with empty fingerprints and compares by status
// and path; a fingerprint on only one side reads as partly checked.
func TestTreeSnapshotOldRecordStillDecodes(t *testing.T) {
	old := `{"ok":true,"head":"h1","branch":"main","refs":"r1","entries":[{"s":" M","p":"a.go"},{"s":"??","p":"b.txt"}]}`
	var s TreeSnapshot
	if err := json.Unmarshal([]byte(old), &s); err != nil || len(s.Entries) != 2 || s.Entries[0].Fp != "" {
		t.Fatalf("decoded %+v, %v", s, err)
	}
	now := snap(TreeEntry{Status: " M", Path: "a.go", Fp: fpA}, TreeEntry{Status: "??", Path: "b.txt", Fp: fpA})
	got := AuditTree(s, now, TreeStrict)
	if got.Verdict != AuditPartial || got.Reason != ReasonNotFingerprinted || got.Uncompared != 2 {
		t.Fatalf("audit = %+v", got)
	}
	// A new path is still a change when the old snapshot has no fingerprints.
	now.Entries = append(now.Entries, TreeEntry{Status: "??", Path: "c.txt", Fp: fpA})
	if got := AuditTree(s, now, TreeStrict); got.Verdict != AuditChanged {
		t.Fatalf("audit = %+v", got)
	}
	// The fingerprint key is short and absent when empty.
	b, _ := json.Marshal(TreeEntry{Status: " M", Path: "a.go"})
	if strings.Contains(string(b), `"f"`) {
		t.Fatalf("an empty fingerprint was written: %s", b)
	}
	b, _ = json.Marshal(TreeEntry{Status: " M", Path: "a.go", Fp: fpA})
	if !strings.Contains(string(b), `"f":"`+fpA+`"`) {
		t.Fatalf("the fingerprint was not written: %s", b)
	}
}

func TestAuditTreePathListsAreCapped(t *testing.T) {
	var es []TreeEntry
	for i := 0; i < maxAuditPaths+7; i++ {
		es = append(es, TreeEntry{Status: " M", Path: "f" + strings.Repeat("x", i)})
	}
	got := AuditTree(snap(), snap(es...), TreeStrict)
	if len(got.TrackedChanged) != maxAuditPaths || got.TrackedMore != 7 {
		t.Fatalf("%d listed, %d more", len(got.TrackedChanged), got.TrackedMore)
	}
}

func TestAuditTreeIsUnaffectedByTheModuleDirectory(t *testing.T) {
	// The snapshot excludes the module's own directory by pathspec, so a run
	// that only wrote its result files shows no change; this pins the pathspec.
	if !strings.HasSuffix(TreeExclude, ResultRoot) {
		t.Fatalf("TreeExclude = %q", TreeExclude)
	}
	if got := AuditTree(snap(), snap(), TreeStrict); got.Verdict != AuditNoChange {
		t.Fatalf("verdict = %s", got.Verdict)
	}
}

func TestAuditWords(t *testing.T) {
	for _, v := range []AuditVerdict{AuditNoChange, AuditChanged, AuditPartial, AuditUnchecked, AuditNotAudited, AuditOff} {
		w := AuditWords(v)
		if w == "" {
			t.Errorf("%s has no words", v)
		}
		for _, bad := range []string{"crossed", "clean", "verified", "confirmed"} {
			if strings.Contains(strings.ToLower(w), bad) {
				t.Errorf("%s: %q contains %q", v, w, bad)
			}
		}
	}
	if AuditWords("") != "" || AuditWords("nope") != "" {
		t.Error("an unknown verdict has words")
	}
	// Incomplete coverage never reads as no change, and says what happened.
	partial := AuditWords(AuditPartial)
	if strings.Contains(strings.ToLower(partial), "no git change") || !strings.Contains(partial, "could not be compared") {
		t.Errorf("AuditWords(partial) = %q", partial)
	}
	if AuditPartial != "partly_checked" {
		t.Errorf("the verdict code is %q", AuditPartial)
	}
}

// TestAuditLimits: the sentence the card shows names what the check does not
// see, and the numbers in it are the constants the check uses.
func TestAuditLimits(t *testing.T) {
	for _, must := range []string{".env", "databases", "caches", "node_modules", "same window", "content", "not compared"} {
		if !strings.Contains(AuditLimits, must) {
			t.Errorf("AuditLimits lacks %q", must)
		}
	}
	for _, c := range []struct {
		name string
		text string
	}{
		{"MaxTreeEntries", strconv.Itoa(MaxTreeEntries) + " paths"},
		{"FpMaxFileBytes", strconv.Itoa(FpMaxFileBytes>>20) + " MiB"},
	} {
		if !strings.Contains(AuditLimits, c.text) {
			t.Errorf("AuditLimits does not state %s as %q", c.name, c.text)
		}
	}
	for _, bad := range []string{"clean", "verified", "confirmed"} {
		if strings.Contains(strings.ToLower(AuditLimits), bad) {
			t.Errorf("AuditLimits contains %q", bad)
		}
	}
}

func TestFitTreeRecord(t *testing.T) {
	big := func(n int) *TreeSnapshot {
		s := &TreeSnapshot{OK: true, Head: strings.Repeat("a", 40), RefsDigest: "0123456789abcdef"}
		for i := 0; i < n; i++ {
			s.Entries = append(s.Entries, TreeEntry{Status: " M", Path: "internal/some/long/path/segment/file" + strings.Repeat("x", 40) + ".go"})
		}
		return s
	}
	t.Run("a record under the cap is written as it is", func(t *testing.T) {
		rec := TreeRecord{Before: big(3)}
		b, err := FitTreeRecord(rec, 64<<10)
		if err != nil || len(b) > 64<<10 || strings.Contains(string(b), `"truncated"`) {
			t.Fatalf("%d bytes, %v, %s", len(b), err, b)
		}
	})
	t.Run("entries are dropped from the longer snapshot and it is marked truncated", func(t *testing.T) {
		before, after := big(40), big(500)
		rec := TreeRecord{Before: before, After: after}
		b, err := FitTreeRecord(rec, 16<<10)
		if err != nil || len(b) > 16<<10 {
			t.Fatalf("%d bytes, %v", len(b), err)
		}
		var got TreeRecord
		if err := json.Unmarshal(b, &got); err != nil {
			t.Fatalf("the result is not JSON: %v", err)
		}
		if !got.After.Truncated || len(got.After.Entries) >= 500 {
			t.Fatalf("after = %d entries, truncated %v", len(got.After.Entries), got.After.Truncated)
		}
		if got.After.Head == "" || got.Before.Head == "" {
			t.Fatalf("the scalars were dropped: %+v", got)
		}
		// The caller's snapshots are not changed.
		if len(after.Entries) != 500 || after.Truncated || len(before.Entries) != 40 {
			t.Fatalf("the caller's snapshots were modified: %d %v %d", len(after.Entries), after.Truncated, len(before.Entries))
		}
	})
	t.Run("a record whose scalars alone do not fit is refused", func(t *testing.T) {
		if _, err := FitTreeRecord(TreeRecord{Before: big(0)}, 10); err == nil {
			t.Fatal("a 10-byte cap accepted a snapshot")
		}
	})
}

// TestFitTreeRecordFingerprints: a full 400-entry snapshot with fingerprints
// fits the side-data cap whole (the launch record holds one snapshot), and a
// record that does not fit loses fingerprints before it loses paths.
func TestFitTreeRecordFingerprints(t *testing.T) {
	const sideCap = 64 << 10 // secassesssvc.MaxSideTree
	full := func(fp bool) *TreeSnapshot {
		s := &TreeSnapshot{OK: true, Head: strings.Repeat("a", 40), RefsDigest: "0123456789abcdef"}
		for i := 0; i < MaxTreeEntries; i++ {
			e := TreeEntry{Status: " M", Path: "internal/some/module/path/file" + strconv.Itoa(1000+i) + "_handler.go"}
			if fp {
				e.Fp = fpA
			}
			s.Entries = append(s.Entries, e)
		}
		return s
	}
	t.Run("a full launch snapshot keeps every path and fingerprint", func(t *testing.T) {
		b, err := FitTreeRecord(TreeRecord{Before: full(true)}, sideCap)
		if err != nil || len(b) > sideCap {
			t.Fatalf("%d bytes, %v", len(b), err)
		}
		var got TreeRecord
		if err := json.Unmarshal(b, &got); err != nil {
			t.Fatal(err)
		}
		if len(got.Before.Entries) != MaxTreeEntries || got.Before.Truncated || got.Before.Entries[0].Fp != fpA || got.Before.Entries[MaxTreeEntries-1].Fp != fpA {
			t.Fatalf("before = %d entries, truncated %v", len(got.Before.Entries), got.Before.Truncated)
		}
	})
	t.Run("two full snapshots drop fingerprints before paths", func(t *testing.T) {
		before, after := full(true), full(true)
		b, err := FitTreeRecord(TreeRecord{Before: before, After: after}, sideCap)
		if err != nil || len(b) > sideCap {
			t.Fatalf("%d bytes, %v", len(b), err)
		}
		var got TreeRecord
		if err := json.Unmarshal(b, &got); err != nil {
			t.Fatal(err)
		}
		// 800 entries do not fit with fingerprints; whichever snapshot was shrunk
		// lost its fingerprints, and it lost entries only if that was not enough.
		shrunk := 0
		for _, s := range []*TreeSnapshot{got.Before, got.After} {
			if hasFingerprints(s.Entries) {
				if len(s.Entries) != MaxTreeEntries || s.Truncated {
					t.Fatalf("a snapshot kept its fingerprints but lost paths: %d, truncated %v", len(s.Entries), s.Truncated)
				}
				continue
			}
			shrunk++
			if !s.Truncated && len(s.Entries) != MaxTreeEntries {
				t.Fatalf("paths were lost without the snapshot saying so: %d", len(s.Entries))
			}
		}
		if shrunk == 0 {
			t.Fatalf("nothing was shrunk although the record exceeded the cap")
		}
		// The caller's snapshots are not changed.
		if before.Entries[0].Fp != fpA || after.Entries[0].Fp != fpA || before.Truncated || after.Truncated {
			t.Fatalf("the caller's snapshots were modified")
		}
		// A shrunk snapshot never compares as no change against a fingerprinted one.
		live := full(true)
		for _, stored := range []*TreeSnapshot{got.Before, got.After} {
			wasShrunk := !hasFingerprints(stored.Entries) || stored.Truncated
			if verdict := AuditTree(*stored, *live, TreeStrict).Verdict; wasShrunk && verdict == AuditNoChange {
				t.Fatalf("a shrunk snapshot compared as no change")
			}
		}
	})
	t.Run("a snapshot too large even without fingerprints loses paths and says so", func(t *testing.T) {
		long := full(true)
		for i := range long.Entries {
			long.Entries[i].Path = strings.Repeat("d/", 90) + long.Entries[i].Path
		}
		b, err := FitTreeRecord(TreeRecord{Before: long}, sideCap)
		if err != nil || len(b) > sideCap {
			t.Fatalf("%d bytes, %v", len(b), err)
		}
		var got TreeRecord
		if err := json.Unmarshal(b, &got); err != nil {
			t.Fatal(err)
		}
		if !got.Before.Truncated || len(got.Before.Entries) >= MaxTreeEntries || hasFingerprints(got.Before.Entries) {
			t.Fatalf("before = %d entries, truncated %v, fingerprints %v", len(got.Before.Entries), got.Before.Truncated, hasFingerprints(got.Before.Entries))
		}
	})
}
