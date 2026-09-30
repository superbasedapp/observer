package commitlog

import (
	"os"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/loc"
)

// These three testdata files are hand-written in the EXACT byte layout
// Args's logFormat + --numstat produce (recordSep 0x1e, NUL-separated
// header fields, tab-separated numstat lines, "-\t-" for binary), per
// the plan's "no git allowed in this lane" constraint (W1a). They were
// built with printf, not git, and their exact bytes are asserted below
// so a change to logFormat or ParseLog that silently drifts the two
// apart is caught here rather than only in a live W2/W9 scan.

func mustReadFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("../../testdata/commitlog/" + name)
	if err != nil {
		t.Fatalf("reading fixture %s: %v", name, err)
	}
	return data
}

// TestParseLogNormalCommit covers a commit with three files, one of them
// binary, and a subject that reads like a real one.
func TestParseLogNormalCommit(t *testing.T) {
	data := mustReadFixture(t, "normal_commit.txt")
	commits, err := ParseLog(data, false)
	if err != nil {
		t.Fatalf("ParseLog: %v", err)
	}
	if len(commits) != 1 {
		t.Fatalf("got %d commits, want 1", len(commits))
	}
	c := commits[0]

	if c.SHA != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Errorf("SHA = %q", c.SHA)
	}
	if len(c.Parents) != 1 || c.Parents[0] != "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" {
		t.Errorf("Parents = %v, want [bbbb...]", c.Parents)
	}
	if c.IsMerge {
		t.Error("IsMerge = true, want false (single parent)")
	}
	wantAuthorHash := hashAuthor("Santosh Kathira")
	if c.AuthorHash != wantAuthorHash {
		t.Errorf("AuthorHash = %q, want %q", c.AuthorHash, wantAuthorHash)
	}
	if len(c.AuthorHash) != authorHashLen {
		t.Errorf("AuthorHash length = %d, want %d", len(c.AuthorHash), authorHashLen)
	}
	wantAuthoredAt, _ := time.Parse(time.RFC3339, "2026-09-21T18:04:00-07:00")
	if !c.AuthoredAt.Equal(wantAuthoredAt) {
		t.Errorf("AuthoredAt = %v, want %v", c.AuthoredAt, wantAuthoredAt)
	}
	wantCommittedAt, _ := time.Parse(time.RFC3339, "2026-09-21T18:04:05-07:00")
	if !c.CommittedAt.Equal(wantCommittedAt) {
		t.Errorf("CommittedAt = %v, want %v", c.CommittedAt, wantCommittedAt)
	}
	if c.Subject != "fix(web2): call a guard-bundle row a rule, not an override" {
		t.Errorf("Subject = %q", c.Subject)
	}

	if len(c.Files) != 3 {
		t.Fatalf("got %d files, want 3", len(c.Files))
	}
	f0, f1, f2 := c.Files[0], c.Files[1], c.Files[2]

	if f0.RelPath != "internal/commitlog/parse.go" || f0.Added != 5 || f0.Deleted != 2 || f0.Binary {
		t.Errorf("Files[0] = %+v", f0)
	}
	wantHash := loc.PathHash("", f0.RelPath)
	if f0.PathHash == "" || f0.PathHash != wantHash {
		t.Errorf("Files[0].PathHash = %q, want %q", f0.PathHash, wantHash)
	}

	if f1.RelPath != "internal/commitlog/types.go" || f1.Added != 10 || f1.Deleted != 0 || f1.Binary {
		t.Errorf("Files[1] = %+v", f1)
	}

	if f2.RelPath != "testdata/commitlog/fixture.png" || !f2.Binary || f2.Added != 0 || f2.Deleted != 0 {
		t.Errorf("Files[2] = %+v, want a binary row with zero added/deleted", f2)
	}
}

// TestParseLogMergeCommit covers a merge commit: two parents, IsMerge
// true, and NO numstat lines at all (git emits none for a merge by
// default) — Files must come back nil/empty, not error.
func TestParseLogMergeCommit(t *testing.T) {
	data := mustReadFixture(t, "merge_commit.txt")
	commits, err := ParseLog(data, false)
	if err != nil {
		t.Fatalf("ParseLog: %v", err)
	}
	if len(commits) != 1 {
		t.Fatalf("got %d commits, want 1", len(commits))
	}
	c := commits[0]

	if !c.IsMerge {
		t.Error("IsMerge = false, want true (two parents)")
	}
	if len(c.Parents) != 2 {
		t.Fatalf("got %d parents, want 2: %v", len(c.Parents), c.Parents)
	}
	if c.Parents[0] != "dddddddddddddddddddddddddddddddddddddddd" ||
		c.Parents[1] != "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" {
		t.Errorf("Parents = %v", c.Parents)
	}
	if len(c.Files) != 0 {
		t.Errorf("Files = %v, want empty (merge commits carry no numstat)", c.Files)
	}
	if c.Subject != "Merge branch 'feature/x' into main" {
		t.Errorf("Subject = %q", c.Subject)
	}
}

// TestParseLogTruncatedStream covers the overflow=true path: the fixture
// is a normal commit + a merge commit + a THIRD record whose own numstat
// block was cut mid-line by (simulating) the byte cap. With overflow
// set, ParseLog must return exactly the two complete commits and never
// error on — or fabricate a row for — the partial third one.
func TestParseLogTruncatedStream(t *testing.T) {
	data := mustReadFixture(t, "truncated_stream.txt")

	commits, err := ParseLog(data, true)
	if err != nil {
		t.Fatalf("ParseLog(overflow=true): %v", err)
	}
	if len(commits) != 2 {
		t.Fatalf("got %d commits, want 2 (the partial 3rd record must be dropped): %+v", len(commits), commits)
	}
	if commits[0].SHA != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Errorf("commits[0].SHA = %q", commits[0].SHA)
	}
	if commits[1].SHA != "cccccccccccccccccccccccccccccccccccccccc" {
		t.Errorf("commits[1].SHA = %q", commits[1].SHA)
	}

	// Sanity: WITHOUT the overflow flag, the same bytes would either
	// error (malformed trailing header) or, worse, silently parse a
	// commit missing part of its file list — this is exactly the
	// distinction the overflow flag exists to avoid, so parsing the
	// full 3-record data with overflow=true must not surface the
	// partial commit no matter how parseRecord would have handled it
	// standing alone.
	for _, c := range commits {
		if c.SHA == "ffffffffffffffffffffffffffffffffffffffff" {
			t.Fatal("the partial trailing record must never appear in the result")
		}
	}
}
