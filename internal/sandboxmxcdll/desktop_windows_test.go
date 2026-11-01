//go:build windows

package sandboxmxcdll

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRunDesktopIsTheRunsOnly: a run's desktop holds a protected DACL with
// the user and the box entry only (ALL APPLICATION PACKAGES until Narrow,
// then the box's SID alone), a second desktop of the same name is refused,
// and a process StartOnDesktop starts runs on it with its exit code
// returned (Windows 11 Pro rerun 2026-10-25, D1).
func TestRunDesktopIsTheRunsOnly(t *testing.T) {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	name := "observer-test-" + hex.EncodeToString(b)
	d, err := CreateRunDesktop(name)
	if err != nil {
		t.Fatalf("CreateRunDesktop: %v", err)
	}
	defer d.Close()
	if !strings.HasSuffix(d.Path, `\`+name) {
		t.Fatalf("Path = %q", d.Path)
	}
	if _, err := CreateRunDesktop(name); err == nil {
		t.Fatal("a second desktop of the same name was created")
	}
	sddl, err := d.SDDL()
	if err != nil {
		t.Fatalf("SDDL: %v", err)
	}
	if !strings.HasPrefix(sddl, "D:P") || !strings.Contains(strings.ToUpper(sddl), ";;;AC)") || strings.Count(sddl, "(A;") != 2 {
		t.Fatalf("before the box SID: %s", sddl)
	}
	const box = "S-1-15-2-1-2-3-4-5-6-7"
	if err := d.Narrow(box); err != nil {
		t.Fatalf("Narrow: %v", err)
	}
	if sddl, _ = d.SDDL(); !strings.Contains(sddl, box) || strings.Contains(strings.ToUpper(sddl), ";;;AC)") || strings.Count(sddl, "(A;") != 2 {
		t.Fatalf("after Narrow: %s", sddl)
	}
	if err := d.Narrow("S-1-1-0"); err == nil {
		t.Fatal("Narrow accepted a SID that is not an AppContainer SID")
	}
	cmd := filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe")
	p, err := StartOnDesktop(cmd, []string{"/d", "/c", "exit 3"}, os.TempDir(), []string{"SYSTEMROOT=" + os.Getenv("SystemRoot")}, d.Path, nil, nil, nil)
	if err != nil {
		t.Fatalf("StartOnDesktop: %v", err)
	}
	if code, err := p.Wait(); err != nil || code != 3 {
		t.Fatalf("exit = %d, %v; want 3", code, err)
	}
}
