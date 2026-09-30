package loc

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// TestRelativeProjectPath pins the hashing normalization (plan §2, moved
// here from internal/store/loc.go by the projects-page-roi-and-commit-
// alignment plan §2 R3 / §4 W1a). The AI side and the editor side MUST
// agree on it, or a human save and the agent edit it echoes could never
// join — and now internal/commitlog must agree too, or a git commit's
// file list could never join file_changes.
func TestRelativeProjectPath(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		root string
		path string
		want string
	}{
		{"absolute under root", "/repo", "/repo/src/a.go", "src/a.go"},
		{"trailing slash on root", "/repo/", "/repo/src/a.go", "src/a.go"},
		{"already relative", "/repo", "src/a.go", "src/a.go"},
		{"dot-slash relative", "/repo", "./src/a.go", "src/a.go"},
		{"windows separators", `C:\proj`, `C:\proj\src\a.go`, "src/a.go"},
		{"windows drive-letter case", `c:\proj`, `C:\proj\src\a.go`, "src/a.go"},
		{"not under root stays distinct", "/repo", "/other/x.go", "other/x.go"},
		{"external pseudo path", "/repo", "[external]/x.go", "[external]/x.go"},
		{"empty path", "/repo", "", ""},
		{"empty root", "", "/abs/a.go", "abs/a.go"},
		// A prefix that only LOOKS like the root must not be stripped:
		// /repo-two is not inside /repo.
		{"prefix is not a path boundary", "/repo", "/repo-two/a.go", "repo-two/a.go"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := RelativeProjectPath(tt.root, tt.path); got != tt.want {
				t.Errorf("RelativeProjectPath(%q, %q) = %q, want %q",
					tt.root, tt.path, got, tt.want)
			}
		})
	}
}

// TestPathHash pins PathHash's contract: it is the sha256 hex digest of
// RelativeProjectPath, and an empty relative path yields an empty hash
// (never sha256("")), so "no path" and "path hashed to nothing" stay
// distinguishable.
func TestPathHash(t *testing.T) {
	t.Parallel()
	want := func(rel string) string {
		sum := sha256.Sum256([]byte(rel))
		return hex.EncodeToString(sum[:])
	}

	tests := []struct {
		name string
		root string
		path string
		want string
	}{
		{"absolute under root", "/repo", "/repo/src/a.go", want("src/a.go")},
		{"already relative", "/repo", "src/a.go", want("src/a.go")},
		{"windows separators", `C:\proj`, `C:\proj\src\a.go`, want("src/a.go")},
		{"empty path yields empty hash", "/repo", "", ""},
		{"empty root", "", "src/a.go", want("src/a.go")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := PathHash(tt.root, tt.path); got != tt.want {
				t.Errorf("PathHash(%q, %q) = %q, want %q", tt.root, tt.path, got, tt.want)
			}
		})
	}

	// PathHash must equal the two-step form store.loc.go used to compute
	// (sha256Hex(RelativeProjectPath(root, path))) — this IS that
	// composition, pinned so a future edit can't silently fork them.
	if got, twoStep := PathHash("/repo", "/repo/src/a.go"), want(RelativeProjectPath("/repo", "/repo/src/a.go")); got != twoStep {
		t.Errorf("PathHash diverges from sha256Hex(RelativeProjectPath(...)): got %q want %q", got, twoStep)
	}
}
