package testwriteguard

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRefusal pins Check's rule table, one case per row: a real foreign mount
// (any case, either slash), a path outside the temp dir, and an empty path
// are refused; a path under the temp dir is allowed.
func TestRefusal(t *testing.T) {
	tmp := t.TempDir()
	cases := []struct {
		name, path, temp string
		wantRefused      bool
		wantReason       string
	}{
		{"under the temp dir", filepath.Join(tmp, "home", ".qwen", "settings.json"), tmp, false, ""},
		{"the temp root itself", tmp, tmp, false, ""},
		{"empty", "", tmp, true, "empty"},
		{"real WSL view of the Windows users dir", "/mnt/c/Users/operator/.qwen/settings.json", tmp, true, "foreign-OS mount"},
		{"DrvFs case folding", "/mnt/C/users/operator/.factory/hooks.json", tmp, true, "foreign-OS mount"},
		{"UNC wsl.localhost", `\\wsl.localhost\Ubuntu\home\u\.claude\settings.json`, tmp, true, "foreign-OS mount"},
		{"UNC wsl$", `\\wsl$\Ubuntu\home\u\.claude\settings.json`, tmp, true, "foreign-OS mount"},
		{"outside the temp dir", filepath.Join(string(filepath.Separator)+"etc", "observer-test", "settings.json"), tmp, true, "outside the test temp directory"},
		{"dot-dot escape", filepath.Join(tmp, "..", "escaped.json"), tmp, true, "outside the test temp directory"},
		{"sibling with a shared name prefix", tmp + "-sibling" + string(os.PathSeparator) + "x.json", tmp, true, "outside the test temp directory"},
		{"no temp root", filepath.Join(tmp, "x.json"), "", true, "outside the test temp directory"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := refusal(c.path, c.temp)
			if (got != "") != c.wantRefused {
				t.Fatalf("refusal(%q) = %q, refused want %v", c.path, got, c.wantRefused)
			}
			if c.wantRefused && !strings.Contains(got, c.wantReason) {
				t.Errorf("refusal(%q) = %q, want it to mention %q", c.path, got, c.wantReason)
			}
		})
	}
}

// TestCheckErrorAndRecord: a refusal is an *fs.PathError for the path and
// op, wraps ErrRefused, and is recorded; an allowed write and any write in a
// production binary are neither. Not parallel: it drains the process-wide
// record.
func TestCheckErrorAndRecord(t *testing.T) {
	_ = TakeViolationsForTest()
	t.Cleanup(func() { _ = TakeViolationsForTest() })
	tmp := t.TempDir()
	outside := filepath.Join(filepath.VolumeName(tmp)+string(os.PathSeparator), "observer-test-write-guard-never-created", "settings.json")

	if err := check(true, tmp, "write", filepath.Join(tmp, "ok.json")); err != nil {
		t.Fatalf("temp path refused: %v", err)
	}
	if err := check(false, tmp, "write", outside); err != nil {
		t.Fatalf("production binary refused: %v", err)
	}
	if v := Violations(); len(v) != 0 {
		t.Fatalf("violations after allowed writes = %v", v)
	}
	err := check(true, tmp, "remove", outside)
	if !errors.Is(err, ErrRefused) {
		t.Fatalf("check(outside) = %v, want ErrRefused", err)
	}
	var pe *fs.PathError
	if !errors.As(err, &pe) || pe.Path != outside || pe.Op != "remove" {
		t.Errorf("error %#v is not a remove PathError for %s", err, outside)
	}
	if !strings.Contains(err.Error(), "incident 2026-10-20") || !strings.Contains(err.Error(), "incident 2026-10-21") {
		t.Errorf("error %q does not name both incidents", err)
	}
	v := TakeViolationsForTest()
	if len(v) != 1 || !strings.HasPrefix(v[0], outside) {
		t.Fatalf("violations = %v, want the one refused path", v)
	}
	if v := Violations(); len(v) != 0 {
		t.Fatalf("TakeViolationsForTest left %v", v)
	}
}

// TestCheckIsLiveInThisBinary pins that the real entry point sees a test
// binary: a path outside the temp directory is refused here.
func TestCheckIsLiveInThisBinary(t *testing.T) {
	t.Cleanup(func() { _ = TakeViolationsForTest() })
	if err := Check("write", filepath.Join(t.TempDir(), "ok.json")); err != nil {
		t.Errorf("temp-dir path refused: %v", err)
	}
	outside := filepath.Join(filepath.VolumeName(os.TempDir())+string(os.PathSeparator), "observer-test-write-guard-never-created")
	if err := Check("remove", outside); !errors.Is(err, ErrRefused) {
		t.Errorf("Check(%s) = %v, want ErrRefused", outside, err)
	}
}
