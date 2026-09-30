package commitlog

import (
	"reflect"
	"testing"
	"time"
)

// TestReflogArgs pins the exact argv ReflogArgs builds for each max/skip
// combination.
func TestReflogArgs(t *testing.T) {
	base := []string{"reflog", "show", "--no-color", "--date=unix", "--format=tformat:" + reflogFormat}

	tests := []struct {
		name string
		max  int
		skip int
		want []string
	}{
		{
			name: "no max, no skip",
			want: append(append([]string{}, base...), "HEAD", "--"),
		},
		{
			name: "max only",
			max:  50,
			want: append(append(append([]string{}, base...), "-n", "50"), "HEAD", "--"),
		},
		{
			name: "skip only",
			skip: 100,
			want: append(append(append([]string{}, base...), "--skip=100"), "HEAD", "--"),
		},
		{
			name: "max and skip together",
			max:  50,
			skip: 100,
			want: append(append(append([]string{}, base...), "-n", "50", "--skip=100"), "HEAD", "--"),
		},
		{
			name: "max <= 0 is unbounded",
			max:  0,
			want: append(append([]string{}, base...), "HEAD", "--"),
		},
		{
			name: "negative skip is also omitted",
			skip: -1,
			want: append(append([]string{}, base...), "HEAD", "--"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ReflogArgs(tt.max, tt.skip)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ReflogArgs(%d, %d) =\n  %v\nwant\n  %v", tt.max, tt.skip, got, tt.want)
			}
		})
	}
}

// reflogRecord builds one raw reflog record (without the leading
// separator, added by the caller) the same shape ReflogArgs' format
// produces.
func reflogRecord(sha, gd, gs string) string {
	return sha + "\x00" + gd + "\x00" + gs + "\n"
}

func TestParseReflog(t *testing.T) {
	sha1a := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	sha1b := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	sha256a := "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

	t.Run("newest first order preserved", func(t *testing.T) {
		data := "\x1e" + reflogRecord(sha1a, "HEAD@{1700000000}", "commit: first") +
			"\x1e" + reflogRecord(sha1b, "HEAD@{1600000000}", "checkout: moving from a to b")
		got := ParseReflog([]byte(data))
		want := []ReflogEntry{
			{SHA: sha1a, MovedAt: time.Unix(1700000000, 0).UTC(), Kind: "commit"},
			{SHA: sha1b, MovedAt: time.Unix(1600000000, 0).UTC(), Kind: "checkout"},
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("ParseReflog() =\n  %#v\nwant\n  %#v", got, want)
		}
	})

	t.Run("sha256 accepted", func(t *testing.T) {
		data := "\x1e" + reflogRecord(sha256a, "HEAD@{1700000000}", "commit: sha256 repo")
		got := ParseReflog([]byte(data))
		if len(got) != 1 || got[0].SHA != sha256a {
			t.Fatalf("ParseReflog() = %#v, want one entry with the 64-hex SHA", got)
		}
	})

	t.Run("malformed sha drops the record", func(t *testing.T) {
		data := "\x1e" + reflogRecord("not-a-sha", "HEAD@{1700000000}", "commit: bad sha") +
			"\x1e" + reflogRecord(sha1a, "HEAD@{1700000000}", "commit: good")
		got := ParseReflog([]byte(data))
		if len(got) != 1 || got[0].SHA != sha1a {
			t.Fatalf("ParseReflog() = %#v, want only the well-formed SHA to survive", got)
		}
	})

	t.Run("uppercase hex sha is rejected", func(t *testing.T) {
		upper := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		data := "\x1e" + reflogRecord(upper, "HEAD@{1700000000}", "commit: upper")
		if got := ParseReflog([]byte(data)); len(got) != 0 {
			t.Fatalf("ParseReflog() = %#v, want uppercase SHA dropped", got)
		}
	})

	t.Run("unparsable selector drops the record", func(t *testing.T) {
		data := "\x1e" + reflogRecord(sha1a, "HEAD@{not-a-number}", "commit: bad date") +
			"\x1e" + reflogRecord(sha1b, "not-shaped-right", "commit: bad shape") +
			"\x1e" + reflogRecord(sha1a, "HEAD@{1700000000}", "commit: good")
		got := ParseReflog([]byte(data))
		if len(got) != 1 || got[0].SHA != sha1a || got[0].MovedAt.Unix() != 1700000000 {
			t.Fatalf("ParseReflog() = %#v, want only the well-formed selector to survive", got)
		}
	})

	t.Run("trailing partial record dropped", func(t *testing.T) {
		full := "\x1e" + reflogRecord(sha1a, "HEAD@{1700000000}", "commit: full")
		partial := "\x1e" + sha1b + "\x00" + "HEAD@{160" // cut mid-record, no gs field at all
		data := full + partial
		got := ParseReflog([]byte(data))
		if len(got) != 1 || got[0].SHA != sha1a {
			t.Fatalf("ParseReflog() = %#v, want the partial trailing record dropped", got)
		}
	})

	t.Run("empty input yields no entries", func(t *testing.T) {
		if got := ParseReflog(nil); len(got) != 0 {
			t.Fatalf("ParseReflog(nil) = %#v, want empty", got)
		}
	})
}

// TestReflogKind exercises every row of reflogKinds plus the "other"
// fallback and the "am" vs "amend" word-boundary edge.
func TestReflogKind(t *testing.T) {
	tests := []struct {
		name    string
		subject string
		want    string
	}{
		{"amend", "commit (amend): fix typo", "amend"},
		{"merge commit", "commit (merge): Merge branch 'x'", "merge"},
		{"initial commit", "commit (initial): first commit", "commit"},
		{"plain commit", "commit: add feature", "commit"},
		{"checkout", "checkout: moving from main to feature", "checkout"},
		{"merge", "merge feature: Fast-forward", "merge"},
		{"rebase paren", "rebase (pick): apply patch", "rebase"},
		{"rebase finished", "rebase finished: returning to refs/heads/main", "rebase"},
		{"reset", "reset: moving to HEAD~1", "reset"},
		{"pull", "pull: Fast-forward", "pull"},
		{"pull with remote", "pull origin main: Fast-forward", "pull"},
		{"cherry-pick", "cherry-pick: apply commit abc123", "cherry-pick"},
		{"revert maps to commit", "revert: revert commit abc123", "commit"},
		{"clone", "clone: from https://example.com/repo.git", "clone"},
		{"am maps to commit", "am: apply mailbox patch", "commit"},
		{"am with flag", "am --patch: apply", "commit"},
		{"am exact", "am", "commit"},
		{"amend-shaped subject not preceded by commit falls to other", "amend: this is not an am entry", "other"},
		{"amorphous falls to other", "amorphous change", "other"},
		{"unknown subject", "some totally unrecognized subject", "other"},
		{"empty subject", "", "other"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ReflogKind(tt.subject); got != tt.want {
				t.Errorf("ReflogKind(%q) = %q, want %q", tt.subject, got, tt.want)
			}
		})
	}
}
