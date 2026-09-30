package commitlog

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/loc"
)

// TestPathHashJoinsWithStoreHash pins plan R3's central claim: a commit
// file's RelPath — already project-relative, exactly as git reports it —
// hashes to the SAME file_changes.file_path_hash an AI edit of the same
// file would produce, whether you hash the git-relative path directly
// against an empty root, or hash the full absolute path against the
// project's real root. internal/loc.RelativeProjectPath leaves an
// already-relative path unchanged when root=="" (its root-strip block
// only runs when root != ""), which is exactly what makes this hold.
//
// This is the join key internal/projectroi's commit-to-edit attribution
// (R4) depends on — if it ever stops holding, commits and AI edits would
// silently stop linking.
func TestPathHashJoinsWithStoreHash(t *testing.T) {
	tests := []struct {
		name string
		root string
		full string
		rel  string // the git-relative path, i.e. what a CommitFile.RelPath would be
	}{
		{
			name: "unix-style repo root",
			root: "/home/marmutapp/superbased-observer",
			full: "/home/marmutapp/superbased-observer/internal/guard/hook.go",
			rel:  "internal/guard/hook.go",
		},
		{
			name: "windows-style root and backslash full path",
			root: `C:\work\repo`,
			full: `C:\work\repo\a\b.go`,
			rel:  "a/b.go",
		},
		{
			name: "root with a trailing slash",
			root: "/repo/",
			full: "/repo/src/main.go",
			rel:  "src/main.go",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Confirm the relative form matches what a commit scan would
			// see as CommitFile.RelPath, so the equality below is
			// actually testing the join key and not just two random
			// hashes that happen to match.
			if gotRel := loc.RelativeProjectPath(tt.root, tt.full); gotRel != tt.rel {
				t.Fatalf("loc.RelativeProjectPath(%q, %q) = %q, want %q", tt.root, tt.full, gotRel, tt.rel)
			}

			// The store's join key for the same file: the full path,
			// hashed against the project's real root.
			storeHash := loc.PathHash(tt.root, tt.full)

			// commitlog's join key: the git-relative path (RelPath),
			// hashed with an empty root — exactly what parse.go's
			// parseNumstat does for every CommitFile.
			commitHash := loc.PathHash("", tt.rel)

			if storeHash != commitHash {
				t.Errorf("loc.PathHash(%q, %q) = %q != loc.PathHash(\"\", %q) = %q — commit files would never join file_changes",
					tt.root, tt.full, storeHash, tt.rel, commitHash)
			}
		})
	}
}
