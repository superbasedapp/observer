package commitlog

import (
	"reflect"
	"strings"
	"testing"
)

func TestStatusArgs(t *testing.T) {
	tests := []struct {
		name     string
		pathspec string
		want     []string
	}{
		{
			name: "no pathspec covers the whole work tree",
			want: []string{"status", "--porcelain=v2", "-z", "--untracked-files=all", "--ignored=matching", "--"},
		},
		{
			name:     "pathspec scopes the status",
			pathspec: "internal/commitlog",
			want: []string{
				"status", "--porcelain=v2", "-z", "--untracked-files=all", "--ignored=matching", "--",
				"internal/commitlog",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := StatusArgs(tt.pathspec)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("StatusArgs(%q) = %v, want %v", tt.pathspec, got, tt.want)
			}
		})
	}
}

func TestParseStatus(t *testing.T) {
	sha := "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"

	tests := []struct {
		name    string
		records []string // joined with NUL to build the raw -z stream
		want    []PathState
	}{
		{
			name: "ordinary modified entry",
			records: []string{
				"# branch.head main",
				"1 M. N... 100644 100644 100644 " + sha + " " + sha + " foo.txt",
			},
			want: []PathState{{RelPath: "foo.txt", State: StatusModified}},
		},
		{
			name: "ordinary deleted entry (D in Y)",
			records: []string{
				"1 .D N... 100644 100644 000000 " + sha + " " + sha + " gone.txt",
			},
			want: []PathState{{RelPath: "gone.txt", State: StatusDeleted}},
		},
		{
			name: "ordinary added entry (A in X)",
			records: []string{
				"1 A. N... 000000 100644 100644 " + sha + " " + sha + " new.txt",
			},
			want: []PathState{{RelPath: "new.txt", State: StatusAdded}},
		},
		{
			name: "rename record reports the origin as renamed_away",
			records: []string{
				"2 R. N... 100644 100644 100644 " + sha + " " + sha + " R100 new/path.txt",
				"old/path.txt",
				"? untracked-after-rename.txt",
			},
			want: []PathState{
				{RelPath: "new/path.txt", State: StatusRenamed},
				{RelPath: "old/path.txt", State: StatusRenamedAway},
				{RelPath: "untracked-after-rename.txt", State: StatusUntracked},
			},
		},
		{
			name: "copy record (C in X) classifies renamed; its origin is untouched",
			records: []string{
				"2 C. N... 100644 100644 100644 " + sha + " " + sha + " C100 copied.txt",
				"source.txt",
			},
			want: []PathState{{RelPath: "copied.txt", State: StatusRenamed}},
		},
		{
			name: "a staged rename then deleted from the work tree stays a (never committed) rename",
			records: []string{
				"2 RD N... 100644 100644 000000 " + sha + " " + sha + " R100 deleted-after-rename.txt",
				"origin.txt",
			},
			want: []PathState{
				{RelPath: "deleted-after-rename.txt", State: StatusRenamed},
				{RelPath: "origin.txt", State: StatusRenamedAway},
			},
		},
		{
			name: "staged add then deleted from the work tree (AD) is added, never committed",
			records: []string{
				"1 AD N... 000000 100644 000000 " + sha + " " + sha + " added-then-gone.txt",
			},
			want: []PathState{{RelPath: "added-then-gone.txt", State: StatusAdded}},
		},
		{
			name: "staged delete (D in X) is deleted",
			records: []string{
				"1 D. N... 100644 000000 000000 " + sha + " " + sha + " staged-gone.txt",
			},
			want: []PathState{{RelPath: "staged-gone.txt", State: StatusDeleted}},
		},
		{
			name: "unmerged entry always classifies unmerged",
			records: []string{
				"u UU N... 100644 100644 100644 100644 " + sha + " " + sha + " " + sha + " conflict.txt",
			},
			want: []PathState{{RelPath: "conflict.txt", State: StatusUnmerged}},
		},
		{
			name: "untracked entry",
			records: []string{
				"? scratch.txt",
			},
			want: []PathState{{RelPath: "scratch.txt", State: StatusUntracked}},
		},
		{
			name: "ignored entry",
			records: []string{
				"! build/output.o",
			},
			want: []PathState{{RelPath: "build/output.o", State: StatusIgnored}},
		},
		{
			name: "header-only stream yields nothing",
			records: []string{
				"# branch.head main",
				"# branch.oid " + sha,
			},
			want: nil,
		},
		{
			name: "malformed ordinary record (too few fields) is skipped",
			records: []string{
				"1 M. N... 100644 foo.txt",
			},
			want: nil,
		},
		{
			name:    "empty input yields no entries",
			records: nil,
			want:    nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := strings.Join(tt.records, "\x00")
			if len(tt.records) > 0 {
				data += "\x00" // trailing NUL, as `-z` always emits
			}
			got := ParseStatus([]byte(data))
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseStatus(%q) =\n  %#v\nwant\n  %#v", data, got, tt.want)
			}
		})
	}
}
