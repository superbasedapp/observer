package commitlog

import (
	"reflect"
	"testing"
)

func TestLsTreeArgs(t *testing.T) {
	tests := []struct {
		name     string
		sha      string
		pathspec string
		want     []string
	}{
		{
			name: "no pathspec lists the whole tree",
			sha:  "HEAD",
			want: []string{"ls-tree", "-r", "-z", "HEAD", "--"},
		},
		{
			name:     "pathspec scopes to a subtree",
			sha:      "abc123",
			pathspec: "internal/commitlog",
			want:     []string{"ls-tree", "-r", "-z", "abc123", "--", "internal/commitlog"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := LsTreeArgs(tt.sha, tt.pathspec)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("LsTreeArgs(%q, %q) = %v, want %v", tt.sha, tt.pathspec, got, tt.want)
			}
		})
	}
}

func TestParseLsTree(t *testing.T) {
	tests := []struct {
		name string
		data string
		want []TreeEntry
	}{
		{
			name: "blob and gitlink kept, tree skipped",
			data: "100644 blob e69de29bb2d1d6434b8b29ae775ad8c2e48c5391\tREADME.md\x00" +
				"160000 commit aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\tvendor/lib\x00" +
				"040000 tree bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\tsubdir\x00",
			want: []TreeEntry{
				{Mode: "100644", Type: "blob", OID: "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391", RelPath: "README.md"},
				{Mode: "160000", Type: "commit", OID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", RelPath: "vendor/lib"},
			},
		},
		{
			name: "nested path with slashes preserved",
			data: "100755 blob cccccccccccccccccccccccccccccccccccccccc\tinternal/commitlog/lstree.go\x00",
			want: []TreeEntry{
				{Mode: "100755", Type: "blob", OID: "cccccccccccccccccccccccccccccccccccccccc", RelPath: "internal/commitlog/lstree.go"},
			},
		},
		{
			name: "record with no tab is malformed and skipped",
			data: "100644 blob e69de29bb2d1d6434b8b29ae775ad8c2e48c5391 README.md\x00",
			want: nil,
		},
		{
			name: "header with too few fields is skipped",
			data: "100644 blob\tREADME.md\x00",
			want: nil,
		},
		{
			name: "empty input yields no entries",
			data: "",
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseLsTree([]byte(tt.data))
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseLsTree(%q) =\n  %#v\nwant\n  %#v", tt.data, got, tt.want)
			}
		})
	}
}
