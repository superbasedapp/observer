package keystore

import (
	"os"
	"path/filepath"
	"testing"
)

// TestNamespaceSymlinkSpellingOfTheDefaultHome (WINFIX2 audit finding 6): a
// HOME that is a symbolic link spelling of the account's home is the
// account's own Observer home, so its keychain names stay the unsuffixed,
// byte-identical ones a real install already has. Before, only case,
// separators and a trailing slash were folded: the link spelling got a tag
// and the install switched to an empty namespace, losing its bearer.
func TestNamespaceSymlinkSpellingOfTheDefaultHome(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real-home")
	if err := os.MkdirAll(filepath.Join(real, ".observer"), 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link-home")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("this host cannot make a symbolic link here: %v", err)
	}
	for _, c := range []struct{ name, env string }{
		{"the link itself", filepath.Join(link, ".observer")},
		{"the link with a trailing separator", filepath.Join(link, ".observer") + string(filepath.Separator)},
	} {
		withHomes(t, c.env, filepath.Join(real, ".observer"))
		if got := Namespace("sbo-change-record-v1"); got != "sbo-change-record-v1" {
			t.Errorf("%s: Namespace = %q, want the unsuffixed name", c.name, got)
		}
	}
	// A home whose .observer is not made yet (a first start).
	withHomes(t, filepath.Join(link, ".observer-fresh"), filepath.Join(real, ".observer-fresh"))
	if got := Namespace("sbo-change-record-v1"); got != "sbo-change-record-v1" {
		t.Errorf("a first start through the link: Namespace = %q, want the unsuffixed name", got)
	}
	// A different folder behind a link is still another home.
	other := filepath.Join(root, "other-home")
	if err := os.MkdirAll(other, 0o700); err != nil {
		t.Fatal(err)
	}
	withHomes(t, filepath.Join(other, ".observer"), filepath.Join(real, ".observer"))
	if HomeTag() == "" {
		t.Fatal("another folder was taken for the account's home")
	}
}

// TestCanonicalPathResolvesTheExistingPart: the deepest part of a path that
// exists is resolved and the rest kept, so a home whose .observer is not
// made yet already has its final tag.
func TestCanonicalPathResolvesTheExistingPart(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "r")
	if err := os.MkdirAll(real, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "l")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("this host cannot make a symbolic link here: %v", err)
	}
	want := canonicalPath(filepath.Join(real, "a", "b"))
	if got := canonicalPath(filepath.Join(link, "a", "b")); got != want {
		t.Fatalf("canonicalPath = %q, want %q", got, want)
	}
	if got := canonicalPath(filepath.Join(real, "a", "b")); filepath.Base(got) != "b" || filepath.Base(filepath.Dir(got)) != "a" {
		t.Fatalf("the missing tail was not kept: %q", got)
	}
}
