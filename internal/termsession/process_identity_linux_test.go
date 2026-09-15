//go:build linux

package termsession

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeProcessIdentityFixture(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

type processIdentitySpawnerFunc func(Spec) (PTY, error)

func (f processIdentitySpawnerFunc) Spawn(spec Spec) (PTY, error) { return f(spec) }

func processIdentityStat(pid int, state, start string) string {
	fields := strings.Fields("S 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1234")
	fields[0] = state
	fields[19] = start
	return fmt.Sprintf("%d (name with (parentheses)) %s", pid, strings.Join(fields, " "))
}

func TestProcessStartIdentityInProcRejectsBirthMismatchAndUnavailableMetadata(t *testing.T) {
	const pid = 4242
	root := t.TempDir()
	statPath := filepath.Join(root, "4242", "stat")
	bootPath := filepath.Join(root, "sys", "kernel", "random", "boot_id")
	writeProcessIdentityFixture(t, statPath, processIdentityStat(pid, "S", "1234"))
	writeProcessIdentityFixture(t, bootPath, "fixture-boot\n")

	if got := processStartIdentityInProc(root, pid); got != "linux:fixture-boot:1234" {
		t.Fatalf("initial identity = %q", got)
	}
	writeProcessIdentityFixture(t, statPath, processIdentityStat(pid, "S", "9999"))
	if got := processStartIdentityInProc(root, pid); got != "linux:fixture-boot:9999" {
		t.Fatalf("reused identity = %q", got)
	}

	for _, tc := range []struct {
		name string
		pid  int
		stat string
		boot string
	}{
		{name: "invalid pid", pid: 1, stat: processIdentityStat(1, "S", "1234"), boot: "fixture-boot"},
		{name: "zombie", pid: pid, stat: processIdentityStat(pid, "Z", "1234"), boot: "fixture-boot"},
		{name: "zero birth", pid: pid, stat: processIdentityStat(pid, "S", "0"), boot: "fixture-boot"},
		{name: "malformed birth", pid: pid, stat: processIdentityStat(pid, "S", "bad"), boot: "fixture-boot"},
		{name: "invalid boot", pid: pid, stat: processIdentityStat(pid, "S", "1234"), boot: "bad:boot"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeProcessIdentityFixture(t, filepath.Join(dir, fmt.Sprint(tc.pid), "stat"), tc.stat)
			writeProcessIdentityFixture(t, filepath.Join(dir, "sys", "kernel", "random", "boot_id"), tc.boot)
			if got := processStartIdentityInProc(dir, tc.pid); got != "" {
				t.Fatalf("identity = %q, want unavailable", got)
			}
		})
	}
}

func TestProcessIdentityForHandleRevalidatesCapturedBirth(t *testing.T) {
	self := os.Getpid()
	if processStartIdentity(self) == "" {
		t.Skip("current Linux process identity is unavailable")
	}
	sp := &pidSpawner{pids: []int{self, 0}}
	m := newTestManager(t, sp, time.Now)

	handle, err := m.Create(validSpec())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	pid, birth, ok := m.ProcessIdentityForHandle(handle)
	if !ok || pid != self || birth != processStartIdentity(self) {
		t.Fatalf("ProcessIdentityForHandle = (%d,%q,%v)", pid, birth, ok)
	}

	if _, _, ok := m.ProcessIdentityForHandle("unknown"); ok {
		t.Fatal("unknown handle reported process identity")
	}

	m.mu.Lock()
	s := m.sessions[handle]
	s.startIdentity = birth + ":reused"
	m.mu.Unlock()
	if _, _, ok := m.ProcessIdentityForHandle(handle); ok {
		t.Fatal("birth mismatch reported process identity")
	}
	m.mu.Lock()
	s.startIdentity = birth
	m.mu.Unlock()

	sp.lastPTY().exit(0)
	waitFor(t, "session marked exited", func() bool {
		_, _, live := m.ProcessIdentityForHandle(handle)
		return !live
	})
	if _, _, ok := m.ProcessIdentityForHandle(handle); ok {
		t.Fatal("exited handle reported process identity")
	}

	withoutPID, err := m.Create(validSpec())
	if err != nil {
		t.Fatalf("Create without pid: %v", err)
	}
	if _, _, ok := m.ProcessIdentityForHandle(withoutPID); ok {
		t.Fatal("pid-less backend reported process identity")
	}
}

func TestCreateCapturesProcessBirthBeforeExitWait(t *testing.T) {
	self := os.Getpid()
	want := processStartIdentity(self)
	if want == "" {
		t.Skip("current Linux process identity is unavailable")
	}
	preExited := &pidPTY{fakePTY: newFakePTY(), pid: self}
	preExited.exit(0)
	// Supply the already-completed PTY directly so Wait returns as soon as its
	// goroutine starts. The birth must already be stored on the Session.
	spawner := processIdentitySpawnerFunc(func(Spec) (PTY, error) { return preExited, nil })
	m := NewManager(Options{Spawner: spawner, ReapInterval: time.Hour, ExitLinger: time.Hour, Now: time.Now})
	t.Cleanup(m.Shutdown)
	handle, err := m.Create(validSpec())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	m.mu.Lock()
	captured := m.sessions[handle].startIdentity
	m.mu.Unlock()
	if captured != want {
		t.Fatalf("captured birth = %q, want %q", captured, want)
	}
}
