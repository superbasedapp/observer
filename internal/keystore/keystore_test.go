package keystore

import (
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const testService = "sbo-keystore-test-v1"

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// noKeychain makes Open see an unusable keychain without touching the real
// OS keychain.
func noKeychain(t *testing.T) {
	t.Helper()
	prev := keychainProbe
	keychainProbe = func(string, string) bool { return false }
	t.Cleanup(func() { keychainProbe = prev })
}

func TestValidName(t *testing.T) {
	cases := []struct {
		name string
		ok   bool
	}{
		{"acct-1/key", false},
		{`acct\key`, false},
		{"", false},
		{".", false},
		{"..", false},
		{"../x", false},
		{"a b", false},
		{"plans:acct-01:key", true},
		{"sbo-api-token@cloud.superbased.app", true},
		{"coordination-lock", true},
		{"x_y.z", true},
		{strings.Repeat("a", 201), false},
		{strings.Repeat("a", 200), true},
	}
	for _, c := range cases {
		if got := ValidName(c.name); got != c.ok {
			t.Errorf("ValidName(%q) = %v, want %v", c.name, got, c.ok)
		}
	}
}

// storeCases runs the shared Store contract against each backend.
func storeCases(t *testing.T) map[string]Store {
	t.Helper()
	return map[string]Store{
		"file":   NewFileStore(testService, filepath.Join(t.TempDir(), "cred")),
		"memory": &MemStore{},
	}
}

func TestStoreContract(t *testing.T) {
	for name, s := range storeCases(t) {
		t.Run(name, func(t *testing.T) {
			if name == "file" && !FileFallbackSecure() {
				t.Skip("the 0600 file fallback is unix-only; Windows fails closed instead (FileFallbackSecure)")
			}
			if _, err := s.Get("k1"); !errors.Is(err, ErrNotFound) {
				t.Fatalf("Get empty = %v, want ErrNotFound", err)
			}
			if err := s.Set("k1", "v1"); err != nil {
				t.Fatalf("Set: %v", err)
			}
			if got, err := s.Get("k1"); err != nil || got != "v1" {
				t.Fatalf("Get = %q,%v", got, err)
			}
			if err := s.Set("k1", "v2"); err != nil {
				t.Fatalf("Set replace: %v", err)
			}
			if got, _ := s.Get("k1"); got != "v2" {
				t.Fatalf("Get after replace = %q", got)
			}
			if err := s.Delete("k1"); err != nil {
				t.Fatalf("Delete: %v", err)
			}
			if err := s.Delete("k1"); err != nil {
				t.Fatalf("Delete absent: %v", err)
			}
			if _, err := s.Get("k1"); !errors.Is(err, ErrNotFound) {
				t.Fatalf("Get after delete = %v", err)
			}
			if err := s.Set("../escape", "x"); !errors.Is(err, ErrInvalidName) {
				t.Fatalf("Set invalid name = %v, want ErrInvalidName", err)
			}
			if _, err := s.Get("a/b"); !errors.Is(err, ErrInvalidName) {
				t.Fatalf("Get invalid name = %v, want ErrInvalidName", err)
			}
			if err := s.Set("big", strings.Repeat("x", MaxValueBytes+1)); !errors.Is(err, ErrValueTooLarge) {
				t.Fatalf("Set oversized = %v, want ErrValueTooLarge", err)
			}
			if s.Backend() == "" || s.SecurityDiagnostic() == "" {
				t.Fatal("non-keychain backends must name themselves and report a diagnostic")
			}
		})
	}
}

func TestFileBackendModeAndNaming(t *testing.T) {
	if !FileFallbackSecure() {
		t.Skip("the 0600 file fallback is unix-only; Windows fails closed instead (keystore.FileFallbackSecure)")
	}
	dir := filepath.Join(t.TempDir(), "cred")
	b := FileBackend{Dir: dir, Service: testService}
	if err := b.Write("rec", []byte("secret")); err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(dir, testService+".rec")
	fi, err := os.Stat(want)
	if err != nil {
		t.Fatalf("file not at %s: %v", want, err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm() != FileMode {
		t.Errorf("mode = %#o, want 0600", fi.Mode().Perm())
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp.") {
			t.Errorf("leftover temp file %s", e.Name())
		}
	}
}

func TestFileBackendRefusals(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX symlink and mode semantics")
	}
	cases := []struct {
		name  string
		setup func(t *testing.T, b FileBackend) string // returns an outside file to check
		op    func(b FileBackend) error
	}{
		{
			name: "symlink refused on read",
			setup: func(t *testing.T, b FileBackend) string {
				out := filepath.Join(t.TempDir(), "attacker")
				mustWrite(t, out, "attacker", 0o600)
				mustSymlink(t, out, b.Path("rec"))
				return ""
			},
			op: func(b FileBackend) error { _, err := b.Read("rec"); return err },
		},
		{
			name: "symlink refused on write",
			setup: func(t *testing.T, b FileBackend) string {
				out := filepath.Join(t.TempDir(), "target")
				mustWrite(t, out, "old", 0o600)
				mustSymlink(t, out, b.Path("rec"))
				return out
			},
			op: func(b FileBackend) error { return b.Write("rec", []byte("new")) },
		},
		{
			name: "permissive file refused",
			setup: func(t *testing.T, b FileBackend) string {
				mustWrite(t, b.Path("rec"), "v", 0o644)
				return ""
			},
			op: func(b FileBackend) error { _, err := b.Read("rec"); return err },
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := FileBackend{Dir: filepath.Join(t.TempDir(), "cred"), Service: testService}
			if err := b.EnsureDir(); err != nil {
				t.Fatal(err)
			}
			outside := c.setup(t, b)
			if err := c.op(b); err == nil {
				t.Fatal("operation succeeded; must refuse")
			}
			if outside != "" {
				if got, _ := os.ReadFile(outside); string(got) != "old" {
					t.Fatalf("write leaked through the symlink: %q", got)
				}
			}
		})
	}
}

func TestFileBackendPermissiveDirRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mode bits")
	}
	dir := filepath.Join(t.TempDir(), "loose")
	if err := os.MkdirAll(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	b := FileBackend{Dir: dir, Service: testService}
	if err := b.Write("rec", []byte("x")); err == nil {
		t.Fatal("write into a 0777 dir; must refuse")
	}
}

func TestFailClosed(t *testing.T) {
	s := FailClosed()
	if s.Backend() != "unavailable" || !strings.Contains(s.SecurityDiagnostic(), "fail-closed") {
		t.Fatalf("backend %q diag %q", s.Backend(), s.SecurityDiagnostic())
	}
	if err := s.Set("k", "v"); !errors.Is(err, ErrInsecureFallbackUnavailable) {
		t.Fatalf("Set = %v", err)
	}
	if _, err := s.Get("k"); !errors.Is(err, ErrInsecureFallbackUnavailable) {
		t.Fatalf("Get = %v", err)
	}
	if err := s.Delete("k"); err != nil {
		t.Fatalf("Delete = %v", err)
	}
}

func TestOpenWithoutKeychain(t *testing.T) {
	noKeychain(t)
	dir := filepath.Join(t.TempDir(), "cred")
	s := Open(testService, dir, quietLogger())
	if !FileFallbackSecure() {
		if s.Backend() != "unavailable" {
			t.Fatalf("Backend = %q, want unavailable on an unverified platform", s.Backend())
		}
		return
	}
	if s.Backend() != "file" {
		t.Fatalf("Backend = %q, want file", s.Backend())
	}
	if err := s.Set("k", "v"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".keychain-unavailable")); err != nil {
		t.Fatalf("sentinel not written: %v", err)
	}
	// A second Open reuses the same file store.
	if got, err := Open(testService, dir, quietLogger()).Get("k"); err != nil || got != "v" {
		t.Fatalf("reopen Get = %q,%v", got, err)
	}
}

func TestFileFallbackSecureMatchesPlatform(t *testing.T) {
	if got, want := FileFallbackSecure(), runtime.GOOS != "windows"; got != want {
		t.Fatalf("FileFallbackSecure = %v, want %v on %s", got, want, runtime.GOOS)
	}
}

func TestWithLockRunsFn(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cred")
	ran := false
	if err := WithLock(dir, testService, func() error { ran = true; return nil }); err != nil {
		t.Fatal(err)
	}
	if !ran {
		t.Fatal("fn not run")
	}
	want := errors.New("boom")
	if err := WithLock(dir, testService, func() error { return want }); !errors.Is(err, want) {
		t.Fatalf("WithLock err = %v", err)
	}
}

func TestMemStoreNames(t *testing.T) {
	var s MemStore
	_ = s.Set("b", "1")
	_ = s.Set("a", "2")
	if got := strings.Join(s.Names(), ","); got != "a,b" {
		t.Fatalf("Names = %s", got)
	}
}

func mustWrite(t *testing.T, path, v string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(v), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func mustSymlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}
