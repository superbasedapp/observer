//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
)

func TestSecretMaskKind(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		mode fs.FileMode
		want sandbox.MaskEntryKind
	}{
		{"regular file", 0, sandbox.MaskEntryFile},
		{"folder", fs.ModeDir, sandbox.MaskEntryDir},
		{"symbolic link", fs.ModeSymlink, sandbox.MaskEntrySymlink},
		{"link wins over a folder bit", fs.ModeSymlink | fs.ModeDir, sandbox.MaskEntrySymlink},
		{"named pipe", fs.ModeNamedPipe, sandbox.MaskEntryOther},
		{"socket", fs.ModeSocket, sandbox.MaskEntryOther},
		{"device", fs.ModeDevice, sandbox.MaskEntryOther},
		{"char device", fs.ModeDevice | fs.ModeCharDevice, sandbox.MaskEntryOther},
	}
	for _, tc := range tests {
		if got := secretMaskKind(tc.mode); got != tc.want {
			t.Errorf("%s: secretMaskKind(%v) = %v, want %v", tc.name, tc.mode, got, tc.want)
		}
	}
}

func TestOSSecretMaskReadDir(t *testing.T) {
	root := t.TempDir()
	for _, n := range []string{".env", "a.txt", "b.txt", "c.txt", "d.txt"} {
		if err := os.WriteFile(filepath.Join(root, n), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(root, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}

	got, more, err := osSecretMaskReadDir(root, 100)
	if err != nil || more {
		t.Fatalf("read all: more=%v err=%v", more, err)
	}
	kinds := map[string]sandbox.MaskEntryKind{}
	for _, e := range got {
		kinds[e.Name] = e.Kind
	}
	if len(kinds) != 6 || kinds[".env"] != sandbox.MaskEntryFile || kinds["sub"] != sandbox.MaskEntryDir {
		t.Fatalf("entries = %v", kinds)
	}

	// The cap: max entries returned, and more=true says the folder holds more.
	got, more, err = osSecretMaskReadDir(root, 4)
	if err != nil || !more || len(got) != 4 {
		t.Fatalf("capped read: %d entries, more=%v, err=%v, want 4, true, nil", len(got), more, err)
	}
	// Exactly max entries is not "more".
	if got, more, err = osSecretMaskReadDir(root, 6); err != nil || more || len(got) != 6 {
		t.Fatalf("exact-fit read: %d entries, more=%v, err=%v, want 6, false, nil", len(got), more, err)
	}
	// An empty folder is a clean empty read (io.EOF is not an error).
	empty := filepath.Join(root, "sub")
	if got, more, err = osSecretMaskReadDir(empty, 10); err != nil || more || len(got) != 0 {
		t.Fatalf("empty folder: %v %v %v", got, more, err)
	}
	// A folder that is not there is an error the walk reports.
	if _, _, err = osSecretMaskReadDir(filepath.Join(root, "missing"), 10); err == nil {
		t.Fatal("a missing folder must be an error")
	}
}

// symlinkOrSkip makes a symbolic link, skipping the test on a host that
// cannot (Windows without developer mode).
func symlinkOrSkip(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symbolic links are not available here: %v", err)
	}
}

func TestOSSecretMaskReadDirDoesNotFollowLinks(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(real, ".env"), []byte("SECRET"), 0o600); err != nil {
		t.Fatal(err)
	}
	symlinkOrSkip(t, real, filepath.Join(root, "linkdir"))
	symlinkOrSkip(t, filepath.Join(real, ".env"), filepath.Join(root, ".env"))

	got, _, err := osSecretMaskReadDir(root, 100)
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]sandbox.MaskEntryKind{}
	for _, e := range got {
		kinds[e.Name] = e.Kind
	}
	if kinds["linkdir"] != sandbox.MaskEntrySymlink || kinds[".env"] != sandbox.MaskEntrySymlink || kinds["real"] != sandbox.MaskEntryDir {
		t.Fatalf("links must be classified as links, not followed: %v", kinds)
	}
	// A folder that is itself a link is refused as a listing target.
	if _, _, err := osSecretMaskReadDir(filepath.Join(root, "linkdir"), 10); err == nil {
		t.Fatal("listing a symbolic link must be refused")
	}
}

// TestDiscoverOverARealTree runs the planner's walk through the real
// listing: secrets found at depth, the committed example and the skipped
// folders left alone, and (where the host can make one) a link to a folder
// holding a secret never entered, so the secret is masked once, at its own
// path.
func TestDiscoverOverARealTree(t *testing.T) {
	root := t.TempDir()
	put := func(rel string) {
		t.Helper()
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, rel := range []string{
		".env", ".env.example", "README.md",
		"svc/api/.env.production", "svc/api/main.go", "svc/tls/server.key", "svc/tls/ca.pem",
		".git/config", ".git/secret.pem", "node_modules/pkg/.env",
		"real/.npmrc",
	} {
		put(rel)
	}
	// A link to a folder that holds a secret: never entered. Where links are
	// not available (Windows without developer mode) the rest still runs.
	if err := os.Symlink(filepath.Join(root, "real"), filepath.Join(root, "linkdir")); err != nil {
		t.Logf("no symbolic link in this run: %v", err)
	}

	rep := sandbox.DiscoverWorkspaceSecrets(root, osSecretMaskReadDir, sandbox.SecretMaskLimits{}, nil)
	j := func(rel string) string { return filepath.Join(root, filepath.FromSlash(rel)) }
	want := []string{j(".env"), j("real/.npmrc"), j("svc/api/.env.production"), j("svc/tls/ca.pem"), j("svc/tls/server.key")}
	got := slices.Clone(rep.Masked)
	slices.Sort(got)
	slices.Sort(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Masked = %v\n want %v", got, want)
	}
	if !rep.Complete() {
		t.Fatalf("report = %+v, want complete (the link is not secret-named and is not entered)", rep)
	}
}

func TestSecretMaskRefusal(t *testing.T) {
	t.Parallel()
	for _, id := range sandboxbackend.IDs() {
		err := secretMaskRefusal(id)
		if (id == sandboxbackend.BackendBwrap) != (err == nil) {
			t.Errorf("%s: secretMaskRefusal = %v, want nil only for bwrap", id, err)
		}
	}
	if err := secretMaskRefusal("no-such-backend"); err == nil {
		t.Error("an unknown backend id must be refused, never assumed able")
	}
}

func TestSecretMaskOutcome(t *testing.T) {
	t.Parallel()
	if got := secretMaskOutcome(sandbox.SecretMaskReport{}); got != nil {
		t.Fatalf("a report of a plan that did not ask for the mask must flatten to nil, got %+v", got)
	}
	rep := sandbox.SecretMaskReport{
		Enabled: true, Root: "/ws", Masked: []string{"/ws/.env", "/ws/a.key"},
		Gaps:        []sandbox.SecretMaskGap{{Path: "/ws/deep", Reason: sandbox.MaskGapDepth}},
		GapsDropped: 3,
	}
	want := &termsvc.SecretMaskOutcome{
		Masked: 2, Complete: false, GapsDropped: 3,
		Gaps: []termsvc.SecretMaskGap{{Path: "/ws/deep", Reason: "depth_limit"}},
	}
	if got := secretMaskOutcome(rep); !reflect.DeepEqual(got, want) {
		t.Fatalf("outcome = %+v, want %+v", got, want)
	}
	done := secretMaskOutcome(sandbox.SecretMaskReport{Enabled: true, Masked: []string{"/ws/.env"}})
	if done == nil || !done.Complete || done.Masked != 1 {
		t.Fatalf("a clean report = %+v, want complete with one file", done)
	}
}

func TestSandboxSecretMaskOption(t *testing.T) {
	t.Parallel()
	if sandboxSecretMaskOption(false) != nil {
		t.Fatal("a launch that did not ask for the mask must plan none")
	}
	o := sandboxSecretMaskOption(true)
	if o == nil || o.ReadDir == nil {
		t.Fatalf("option = %+v, want the real listing injected", o)
	}
}
