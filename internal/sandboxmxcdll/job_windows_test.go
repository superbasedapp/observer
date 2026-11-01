//go:build windows

package sandboxmxcdll

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func testRunDesktop(t *testing.T) *RunDesktop {
	t.Helper()
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	d, err := CreateRunDesktop("observer-jobtest-" + hex.EncodeToString(b))
	if err != nil {
		t.Fatalf("CreateRunDesktop: %v", err)
	}
	t.Cleanup(d.Close)
	return d
}

// TestStartOnDesktopJobEndsTheTreeWithTheHelper (WINFIX2 audit finding 9):
// the process StartOnDesktop starts, and a child it starts, are in a
// kill-on-close job only the helper holds, so when the helper's handle
// closes (what a killed helper's exit does) both end. Before the fix
// wxc-exec was in no job of the helper's, and a killed helper left the box
// running.
func TestStartOnDesktopJobEndsTheTreeWithTheHelper(t *testing.T) {
	d := testRunDesktop(t)
	sys := os.Getenv("SystemRoot")
	cmd := filepath.Join(sys, "System32", "cmd.exe")
	ping := filepath.Join(sys, "System32", "PING.EXE")
	p, err := StartOnDesktop(cmd, []string{"/d", "/c", ping + " -n 60 127.0.0.1"}, os.TempDir(), []string{"SYSTEMROOT=" + sys}, d.Path, nil, nil, nil)
	if err != nil {
		t.Fatalf("StartOnDesktop: %v", err)
	}
	var pids []uint32
	for i := 0; i < 200 && len(pids) < 2; i++ {
		pids, _ = p.JobPIDs()
		time.Sleep(25 * time.Millisecond)
	}
	if len(pids) < 2 {
		t.Fatalf("the job holds %v, want cmd.exe and its child", pids)
	}
	var hs []windows.Handle
	for _, pid := range pids {
		h, err := windows.OpenProcess(windows.SYNCHRONIZE, false, pid)
		if err != nil {
			t.Fatalf("OpenProcess %d: %v", pid, err)
		}
		hs = append(hs, h)
	}
	defer func() {
		for _, h := range hs {
			_ = windows.CloseHandle(h)
		}
	}()
	p.closeJob()
	for i, h := range hs {
		if ev, err := windows.WaitForSingleObject(h, 10_000); err != nil || ev != windows.WAIT_OBJECT_0 {
			t.Fatalf("process %d outlived the helper's job (%d, %v)", pids[i], ev, err)
		}
	}
	_, _ = p.Wait()
}

// TestStartedKillEndsTheRun: Kill ends the run's job with the given code
// (how the helper ends a run whose desktop was not narrowed, finding 2).
func TestStartedKillEndsTheRun(t *testing.T) {
	d := testRunDesktop(t)
	sys := os.Getenv("SystemRoot")
	p, err := StartOnDesktop(filepath.Join(sys, "System32", "PING.EXE"), []string{"-n", "60", "127.0.0.1"}, os.TempDir(), []string{"SYSTEMROOT=" + sys}, d.Path, nil, nil, nil)
	if err != nil {
		t.Fatalf("StartOnDesktop: %v", err)
	}
	if err := p.Kill(125); err != nil {
		t.Fatalf("Kill: %v", err)
	}
	code, err := p.Wait()
	if err != nil || code != 125 {
		t.Fatalf("exit = %d, %v; want 125", code, err)
	}
	if err := p.Kill(1); err != nil {
		t.Fatalf("Kill after Wait: %v", err)
	}
}
