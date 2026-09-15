package index

import "testing"

// TestIsAutoIndexBlocked pins the pathological-root guard: home/drive/root
// containers are blocked from auto-indexing (the /mnt/c/Users/<user> 384K-file
// bloat), while real project roots and deep subfolders are allowed.
func TestIsAutoIndexBlocked(t *testing.T) {
	cases := []struct {
		root string
		want bool
	}{
		{"/", true},
		{"/mnt/c", true},
		{"/mnt/d", true},
		{"/mnt/c/Users/auzy_", true}, // Windows home container
		{"/home/someuser", true},     // linux home container
		{"/Users/alice", true},       // macOS home container
		{"/tmp", true},               // system temp container
		{"/tmp/", true},              // trailing slash cleaned
		{"/var/tmp", true},           // secondary temp container
		{"/dev/shm", true},           // tmpfs scratch
		{"/home/marmutapp/superbased-observer", false},      // real repo
		{"/mnt/c/Users/auzy_/OneDrive/Desktop/proj", false}, // deep subfolder
		{"/tmp/work/proj", false},
		{"/mnt/c/programsx/regulation", false},

		// User-content containers (Desktop/Downloads/Documents), incl.
		// OneDrive-redirected, across WSL-mount and native home shapes.
		{"/mnt/c/Users/auzy_/OneDrive/Desktop", true}, // the live adopted root
		{"/mnt/c/Users/auzy_/Desktop", true},          // WSL-mount, no OneDrive
		{"/mnt/c/Users/auzy_/Downloads", true},        // WSL-mount, Downloads
		{"/mnt/c/Users/auzy_/Documents", true},        // WSL-mount, Documents
		{"/mnt/c/Users/auzy_/desktop", true},          // case-insensitive
		{"/Users/alice/Desktop", true},                // native macOS home
		{"/Users/alice/OneDrive/Desktop", true},       // native macOS + OneDrive
		{"/home/someuser/Desktop", true},              // native Linux home
		{"/home/someuser/OneDrive/Downloads", true},   // native Linux + OneDrive
		{"C:/Users/auzy_/OneDrive/Desktop", true},     // native Windows shape (post ToSlash)

		// Nested real projects stay indexable — only the container itself
		// is blocked.
		{"/mnt/c/Users/auzy_/Desktop/myproject", false},
		{"/mnt/c/Users/auzy_/Downloads/myproject", false},
		{"/home/someuser/Desktop/myproject", false},
		{"/Users/alice/OneDrive/Desktop/myproject", false},
		// A subdirectory that merely happens to share the name, with no
		// Users/home/OneDrive marker above it, is a real project dir, not
		// a content container — must not be blocked.
		{"/home/marmutapp/superbased-observer/Desktop", false},
	}
	for _, c := range cases {
		if got := isAutoIndexBlocked(c.root); got != c.want {
			t.Errorf("isAutoIndexBlocked(%q) = %v, want %v", c.root, got, c.want)
		}
	}
}

// TestIsIgnored pins the [codeintel].ignore_paths boundary match: a root is
// ignored when it equals or is nested under an ignore entry, but a sibling
// that only shares a string prefix ("/a/bc" vs "/a/b") is NOT.
func TestIsIgnored(t *testing.T) {
	ignore := []string{"/a/b", "/mnt/c/Users/auzy_", ""}
	cases := []struct {
		root string
		want bool
	}{
		{"/a/b", true},                        // exact
		{"/a/b/c", true},                      // nested
		{"/a/b/c/d/e.go", true},               // deep nested
		{"/a/bc", false},                      // sibling, prefix-only — must NOT match
		{"/a", false},                         // parent of an ignore entry
		{"/other", false},                     // unrelated
		{"/mnt/c/Users/auzy_/OneDrive", true}, // nested under a listed root
		{"/a/b/", true},                       // trailing slash cleaned
	}
	for _, c := range cases {
		if got := IsIgnored(c.root, ignore); got != c.want {
			t.Errorf("IsIgnored(%q) = %v, want %v", c.root, got, c.want)
		}
	}
	// A blank/empty ignore entry never swallows the tree.
	if IsIgnored("/anything", []string{""}) {
		t.Error("blank ignore entry matched everything")
	}
	if IsIgnored("/anything", nil) {
		t.Error("nil ignore list matched")
	}
}
