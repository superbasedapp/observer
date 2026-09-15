package update

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// loadEntries reads one committed archive entry-list golden. The lists
// are DATA, not real archives, which is exactly what lets the safety
// rules be tested for both archive shapes without writing a byte to a
// filesystem — and without a test that could only be run by unpacking
// something hostile.
func loadEntries(t *testing.T, name string) []Entry {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name+".json"))
	if err != nil {
		t.Fatalf("load %s: %v", name, err)
	}
	var entries []Entry
	if err := json.Unmarshal(b, &entries); err != nil {
		t.Fatalf("decode %s: %v", name, err)
	}
	return entries
}

// TestSelectMember is the archive-safety table, run over BOTH archive
// shapes (§3.1 "Archive shapes are not uniform, and the extractor must
// know it").
func TestSelectMember(t *testing.T) {
	cases := []struct {
		name string
		// golden is the committed entry list.
		golden string
		// artifact is the manifest row the entries are judged against.
		artifact Artifact
		// wantErr is the sentinel expected, nil for the happy paths.
		wantErr error
		// wantMember is the selected member name on success.
		wantMember string
		// wantAliases is how many alias entries were skipped.
		wantAliases int
	}{
		{
			name:   "tar.gz: the member is selected and the symlink alias is skipped",
			golden: "archive-tar-valid", artifact: linuxArtifact(),
			wantMember: "observer", wantAliases: 1,
		},
		{
			name:   "zip: the member is selected and the copied alias is skipped",
			golden: "archive-zip-valid", artifact: windowsArtifact(),
			wantMember: "observer.exe", wantAliases: 1,
		},
		{
			name:   "tar.gz: a nested layout works, and its ancestor directory is structural",
			golden: "archive-tar-nested-valid",
			artifact: func() Artifact {
				a := linuxArtifact()
				a.Member = "observer-v1.33.0-linux-x64/observer"
				a.AliasMembers = []string{"observer-v1.33.0-linux-x64/superbased"}
				return a
			}(),
			wantMember: "observer-v1.33.0-linux-x64/observer", wantAliases: 1,
		},
		{
			name:   "tar.gz: an unlisted extra member FAILS (it is not skipped)",
			golden: "archive-tar-unlisted-member", artifact: linuxArtifact(),
			wantErr: ErrUnlistedMember,
		},
		{
			name:   "tar.gz: a symlink escaping the extraction root is refused",
			golden: "archive-tar-escaping-symlink", artifact: linuxArtifact(),
			wantErr: ErrEscapingSymlink,
		},
		{
			name:   "tar.gz: a member name with .. is refused",
			golden: "archive-tar-traversal-member", artifact: linuxArtifact(),
			wantErr: ErrPathTraversal,
		},
		{
			name:   "tar.gz: a member that is itself a symlink is refused",
			golden: "archive-tar-member-is-symlink", artifact: linuxArtifact(),
			wantErr: ErrMemberNotRegular,
		},
		{
			name:   "zip: an absolute-path member is refused",
			golden: "archive-zip-absolute-path", artifact: windowsArtifact(),
			wantErr: ErrAbsolutePath,
		},
		{
			name:   "zip: a symlink alias is refused (the pipeline ships a copy)",
			golden: "archive-zip-symlink-alias", artifact: windowsArtifact(),
			wantErr: ErrSymlinkInZip,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sel, err := SelectMember(tc.artifact, loadEntries(t, tc.golden))
			if tc.wantErr != nil {
				if err == nil {
					t.Fatalf("expected %v, got nil (member %q)", tc.wantErr, sel.Member.Name)
				}
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("error = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if sel.Member.Name != tc.wantMember {
				t.Errorf("member = %q, want %q", sel.Member.Name, tc.wantMember)
			}
			if len(sel.Aliases) != tc.wantAliases {
				t.Errorf("skipped %d aliases, want %d", len(sel.Aliases), tc.wantAliases)
			}
		})
	}
}

// TestSelectMemberInlineRules covers the safety rules whose input shape
// does not deserve a committed file: duplicates, exotic kinds, missing
// members and the three absolute-path spellings.
func TestSelectMemberInlineRules(t *testing.T) {
	tar := linuxArtifact()
	cases := []struct {
		name     string
		artifact Artifact
		entries  []Entry
		wantErr  error
	}{
		{
			name: "the member is missing entirely", artifact: tar,
			entries: []Entry{{Name: "superbased", Kind: EntrySymlink, LinkTarget: "observer"}},
			wantErr: ErrMemberMissing,
		},
		{
			name: "a duplicate entry name is refused", artifact: tar,
			entries: []Entry{
				{Name: "observer", Kind: EntryFile},
				{Name: "./observer", Kind: EntryFile},
				{Name: "superbased", Kind: EntrySymlink, LinkTarget: "observer"},
			},
			wantErr: ErrDuplicateEntry,
		},
		{
			name: "a hardlink or device node is refused", artifact: tar,
			entries: []Entry{
				{Name: "observer", Kind: EntryFile},
				{Name: "superbased", Kind: EntryOther},
			},
			wantErr: ErrUnsupportedEntryKind,
		},
		{
			name: "a unix-absolute entry is refused", artifact: tar,
			entries: []Entry{{Name: "/etc/passwd", Kind: EntryFile}},
			wantErr: ErrAbsolutePath,
		},
		{
			name: "a backslash-rooted entry is refused", artifact: tar,
			entries: []Entry{{Name: `\evil`, Kind: EntryFile}},
			wantErr: ErrAbsolutePath,
		},
		{
			name:     "a backslash traversal is refused (backslashes are separators, not characters)",
			artifact: tar,
			entries:  []Entry{{Name: `..\..\evil`, Kind: EntryFile}},
			wantErr:  ErrPathTraversal,
		},
		{
			name:     "an alias symlink pointing somewhere other than the member is refused",
			artifact: tar,
			entries: []Entry{
				{Name: "observer", Kind: EntryFile},
				{Name: "superbased", Kind: EntrySymlink, LinkTarget: "observer-old"},
			},
			wantErr: ErrEscapingSymlink,
		},
		{
			name: "an alias symlink with an absolute target is refused", artifact: tar,
			entries: []Entry{
				{Name: "observer", Kind: EntryFile},
				{Name: "superbased", Kind: EntrySymlink, LinkTarget: "/bin/sh"},
			},
			wantErr: ErrEscapingSymlink,
		},
		{
			name: "an unlisted directory is refused", artifact: tar,
			entries: []Entry{
				{Name: "observer", Kind: EntryFile},
				{Name: "superbased", Kind: EntrySymlink, LinkTarget: "observer"},
				{Name: "docs", Kind: EntryDir},
			},
			wantErr: ErrUnlistedMember,
		},
		{
			name: "a manifest whose own member is absolute is refused before any entry is read",
			artifact: func() Artifact {
				a := linuxArtifact()
				a.Member = "/usr/bin/observer"
				return a
			}(),
			entries: []Entry{{Name: "observer", Kind: EntryFile}},
			wantErr: ErrAbsolutePath,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := SelectMember(tc.artifact, tc.entries)
			if err == nil {
				t.Fatalf("expected %v, got nil", tc.wantErr)
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("error = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

// TestIsAbsArchivePath pins the host-independence of the absolute-path
// check: a tar written on one OS is routinely extracted on another, so
// all three spellings are absolute regardless of GOOS.
func TestIsAbsArchivePath(t *testing.T) {
	for _, s := range []string{"/etc/passwd", `\windows`, `C:\Windows`, "c:/windows"} {
		if !IsAbsArchivePath(s) {
			t.Errorf("IsAbsArchivePath(%q) = false", s)
		}
	}
	for _, s := range []string{"observer", "./observer", "bin/observer", "", "c-drive/x"} {
		if IsAbsArchivePath(s) {
			t.Errorf("IsAbsArchivePath(%q) = true", s)
		}
	}
}
