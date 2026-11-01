package secchange

import (
	"strings"
	"testing"
	"time"
)

func TestAddTrailer(t *testing.T) {
	const v = "claude-code:claude-opus-5-5"
	cases := []struct{ name, in, want string }{
		{"subject only", "feat: x\n", "feat: x\n\nAssisted-by: " + v + "\n"},
		{"subject and body", "feat: x\n\nbody line\n", "feat: x\n\nbody line\n\nAssisted-by: " + v + "\n"},
		{"existing trailers", "feat: x\n\nbody\n\nSigned-off-by: a <a@b>\n", "feat: x\n\nbody\n\nSigned-off-by: a <a@b>\nAssisted-by: " + v + "\n"},
		{
			"before git's comments", "feat: x\n\n# Please enter the commit message\n# Lines starting with '#'\n",
			"feat: x\n\nAssisted-by: " + v + "\n\n# Please enter the commit message\n# Lines starting with '#'\n",
		},
		{"already there", "feat: x\n\nAssisted-by: " + v + "\n", "feat: x\n\nAssisted-by: " + v + "\n"},
		{"empty message stays empty", "\n# comment\n", "\n# comment\n"},
		{"a subject that looks like a trailer is not a trailer block", "fix: thing\n", "fix: thing\n\nAssisted-by: " + v + "\n"},
		// Audit finding F8: under `git commit -v` the trailer goes above the
		// scissors line, never into the diff git cuts away.
		{
			"above the scissors line",
			"feat: x\n\n# Please enter the commit message\n# ------------------------ >8 ------------------------\n# Do not modify or remove the line above.\ndiff --git a/x b/x\n+Assisted-by: " + v + "\n",
			"feat: x\n\nAssisted-by: " + v + "\n\n# Please enter the commit message\n# ------------------------ >8 ------------------------\n# Do not modify or remove the line above.\ndiff --git a/x b/x\n+Assisted-by: " + v + "\n",
		},
	}
	for _, c := range cases {
		if got := AddTrailer(c.in, v, '#'); got != c.want {
			t.Errorf("%s:\n got %q\nwant %q", c.name, got, c.want)
		}
	}
	if got := AddTrailer("feat\n", "", '#'); got != "feat\n" {
		t.Errorf("empty value changed the message: %q", got)
	}
	// core.commentChar=';': ';' lines are git's comments, '#' is message text.
	in := "feat: x\n\n#1 is the issue\n\n; Please enter the commit message\n; ------------------------ >8 ------------------------\n+x\n"
	want := "feat: x\n\n#1 is the issue\n\nAssisted-by: " + v + "\n\n; Please enter the commit message\n; ------------------------ >8 ------------------------\n+x\n"
	if got := AddTrailer(in, v, ';'); got != want {
		t.Errorf("comment char ';':\n got %q\nwant %q", got, want)
	}
}

func TestCommentChar(t *testing.T) {
	cases := []struct {
		setting, msg string
		want         byte
	}{
		{"", "x\n# c\n", '#'},
		{";", "x\n", ';'},
		{"%%", "x\n", '%'},
		{"auto", "x\n; ------------------------ >8 ------------------------\n", ';'},
		{"auto", "x\n\n@ Please enter the commit message for your changes.\n", '@'},
		{"auto", "x\n", '#'},
	}
	for _, c := range cases {
		if got := CommentChar(c.setting, c.msg); got != c.want {
			t.Errorf("%q %q: %q, want %q", c.setting, c.msg, got, c.want)
		}
	}
}

func TestTrailerValue(t *testing.T) {
	cases := []struct{ agent, model, want string }{
		{"claude-code", "claude-opus-5-5", "claude-code:claude-opus-5-5"},
		{"codex", "", "codex"},
		{"codex", "a model", "codex"},
		{"bad agent", "m", ""},
	}
	for _, c := range cases {
		if got := TrailerValue(c.agent, c.model); got != c.want {
			t.Errorf("%q %q: %q, want %q", c.agent, c.model, got, c.want)
		}
	}
}

func TestDecideTrailerTable(t *testing.T) {
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	fresh := &PendingCommit{RootHash: "r1", Agent: "claude-code", At: now.Add(-20 * time.Second).Format(time.RFC3339), Head: "h1", IndexFP: "i1"}
	stale := &PendingCommit{RootHash: "r1", Agent: "claude-code", At: now.Add(-31 * time.Second).Format(time.RFC3339), Head: "h1", IndexFP: "i1"}
	other := &PendingCommit{RootHash: "r2", Agent: "claude-code", At: fresh.At, Head: "h1", IndexFP: "i1"}
	unbound := &PendingCommit{RootHash: "r1", Agent: "claude-code", At: fresh.At}
	base := TrailerFacts{Selected: true, Consent: true, Pending: fresh, RootHash: "r1", Now: now, Head: "h1", IndexFP: "i1"}
	cases := []struct {
		name   string
		mut    func(f *TrailerFacts)
		add    bool
		reason string
	}{
		{"agent commit", func(*TrailerFacts) {}, true, "agent_commit"},
		{"amend by the agent", func(f *TrailerFacts) { f.Source = "commit" }, true, "agent_commit"},
		{"provenance off", func(f *TrailerFacts) { f.Selected = false }, false, "provenance_off"},
		{"no consent", func(f *TrailerFacts) { f.Consent = false }, false, "no_consent"},
		{"merge", func(f *TrailerFacts) { f.Source = "merge" }, false, "merge_or_squash"},
		{"squash", func(f *TrailerFacts) { f.Source = "squash" }, false, "merge_or_squash"},
		{"a person's commit: no marker", func(f *TrailerFacts) { f.Pending = nil }, false, "not_an_agent_commit"},
		{"marker for another repository", func(f *TrailerFacts) { f.Pending = other }, false, "not_an_agent_commit"},
		{"stale marker (over 30 seconds)", func(f *TrailerFacts) { f.Pending = stale }, false, "marker_stale"},
		{"marker from an older build (no HEAD and index)", func(f *TrailerFacts) { f.Pending = unbound }, false, "marker_unbound"},
		{"a person's later commit on another HEAD", func(f *TrailerFacts) { f.Head = "h2" }, false, "marker_other_head"},
		{"a person's commit from another index", func(f *TrailerFacts) { f.IndexFP = "i2" }, false, "marker_other_tree"},
		{"the index could not be read", func(f *TrailerFacts) { f.IndexFP = "" }, false, "marker_other_tree"},
	}
	for _, c := range cases {
		f := base
		c.mut(&f)
		if add, reason := DecideTrailer(f); add != c.add || reason != c.reason {
			t.Errorf("%s: %v %s, want %v %s", c.name, add, reason, c.add, c.reason)
		}
	}
}

func TestTrailerBlockInstallRemove(t *testing.T) {
	block := TrailerBlock("/usr/bin/observer")
	fresh, err := InstallTrailerBlock("", block)
	if err != nil || !HasTrailerBlock(fresh) || !strings.HasPrefix(fresh, "#!/bin/sh\n") {
		t.Fatalf("fresh: %q %v", fresh, err)
	}
	if rest, empty := RemoveTrailerBlock(fresh); !empty || HasTrailerBlock(rest) {
		t.Fatalf("remove fresh: %q %v", rest, empty)
	}
	existing := "#!/bin/bash\necho mine\n"
	with, err := InstallTrailerBlock(existing, block)
	if err != nil {
		t.Fatal(err)
	}
	if again, _ := InstallTrailerBlock(with, block); again != with {
		t.Fatal("a second install changed the hook")
	}
	if rest, empty := RemoveTrailerBlock(with); empty || rest != existing {
		t.Fatalf("remove is not byte-exact: %q", rest)
	}
	if _, err := InstallTrailerBlock("#!/usr/bin/env python3\nprint(1)\n", block); err == nil {
		t.Fatal("a python hook was edited")
	}
	if !strings.Contains(block, "|| :") {
		t.Fatal("the block must never fail the commit")
	}
}

func TestNoteLines(t *testing.T) {
	note := []byte("{\"a\":1}\n\n{\"b\":2}\n")
	if !NoteHas(note, []byte(`{"b":2}`)) || NoteHas(note, []byte(`{"c":3}`)) {
		t.Fatal("NoteHas")
	}
	if len(NoteEnvelopes(note)) != 2 {
		t.Fatal("NoteEnvelopes")
	}
}

// TestStagedWithinPlan pins the planned-staging rule of the trailer marker
// (lane SEC-F2B, decision log P-078 ruling 2), one case per shape.
func TestStagedWithinPlan(t *testing.T) {
	pre := map[string]string{"a.go": "1", "b/c.go": "2", "d.go": "3"}
	with := func(kv ...string) map[string]string {
		m := map[string]string{}
		for k, v := range pre {
			m[k] = v
		}
		for i := 0; i+1 < len(kv); i += 2 {
			if kv[i+1] == "" {
				delete(m, kv[i])
			} else {
				m[kv[i]] = kv[i+1]
			}
		}
		return m
	}
	whole := []PlannedScope{{}}
	tracked := []PlannedScope{{TrackedOnly: true}}
	cases := []struct {
		name    string
		now     map[string]string
		planned []PlannedScope
		want    bool
	}{
		{"unchanged", with(), nil, true},
		{"add X", with("x.go", "9"), []PlannedScope{{Prefix: "x.go"}}, true},
		{"add X stages Y too", with("x.go", "9", "y.go", "8"), []PlannedScope{{Prefix: "x.go"}}, false},
		{"directory scope", with("b/c.go", "7", "b/n.go", "6"), []PlannedScope{{Prefix: "b"}}, true},
		{"prefix is not a directory", with("bb.go", "7"), []PlannedScope{{Prefix: "b"}}, false},
		{"add -A", with("new.go", "5", "a.go", "4"), whole, true},
		{"commit -a tracked", with("a.go", "4", "d.go", ""), tracked, true},
		{"commit -a never adds untracked", with("new.go", "5"), tracked, false},
		{"rm outside plan", with("d.go", ""), []PlannedScope{{Prefix: "a.go"}}, false},
		{"unread index", nil, whole, false},
	}
	for _, c := range cases {
		if got := StagedWithinPlan(pre, c.now, c.planned); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
	// An empty or absent pre-command listing never allows (lane SEC-P4,
	// SEC-F2B audit finding 8): StagedWithinPlan(nil, {}, nil) was true.
	for name, p := range map[string]map[string]string{"absent": nil, "empty": {}} {
		for _, now := range []map[string]string{{}, {"x.go": "9"}} {
			if StagedWithinPlan(p, now, whole) || StagedWithinPlan(p, now, nil) {
				t.Errorf("%s pre-command listing allowed now=%v", name, now)
			}
		}
	}
}

func TestIndexListing(t *testing.T) {
	ls := []byte("100644 aaaa 0\ta.go\x00100644 bbbb 1\tc.go\x00100644 cccc 2\tc.go\x00")
	m, ok := IndexListing(ls)
	if !ok || len(m) != 2 || m["a.go"] == "" || m["c.go"] == "" {
		t.Fatalf("listing %v %v", m, ok)
	}
	if _, ok := IndexListing([]byte("garbage\x00")); ok {
		t.Fatal("unreadable output accepted")
	}
	if m, ok := IndexListing(nil); !ok || len(m) != 0 {
		t.Fatal("an empty index is readable")
	}
}

// TestDecideTrailerPlanned: a marker carrying a plan admits an index that
// moved inside it; without one the index must match exactly.
func TestDecideTrailerPlanned(t *testing.T) {
	now := time.Now()
	pre := map[string]string{"a.go": "1"}
	moved := map[string]string{"a.go": "1", "x.go": "2"}
	base := TrailerFacts{Selected: true, Consent: true, RootHash: "r", Now: now, Head: "h", IndexFP: "new", Index: moved}
	p := &PendingCommit{RootHash: "r", At: now.UTC().Format(time.RFC3339), Head: "h", IndexFP: "old", Index: pre, Planned: []PlannedScope{{Prefix: "x.go"}}}
	f := base
	f.Pending = p
	if add, why := DecideTrailer(f); !add {
		t.Fatalf("planned add refused: %s", why)
	}
	q := *p
	q.Planned = nil
	f.Pending = &q
	if add, why := DecideTrailer(f); add || why != "marker_other_tree" {
		t.Fatalf("unplanned change: %v %s", add, why)
	}
}
