package termsession

import (
	"testing"
	"time"
)

// TestSpecSSHArgv pins the SpecSSH argv contract
// (docs/plans/ssh-remote-profiles-plan-2026-08-27.md §2): the server-derived
// SSHArgv is returned verbatim, and — unlike SpecShell — a WrapArgv isolation
// prefix is deliberately IGNORED, because bwrap would blind the known_hosts /
// key file / agent socket ssh needs.
func TestSpecSSHArgv(t *testing.T) {
	t.Parallel()
	ssh := []string{"ssh", "-tt", "-o", "StrictHostKeyChecking=ask", "h.example.com"}

	t.Run("returned verbatim", func(t *testing.T) {
		t.Parallel()
		got := Spec{Kind: SpecSSH, SSHArgv: ssh}.argv()
		if len(got) != len(ssh) {
			t.Fatalf("argv = %q, want %q", got, ssh)
		}
		for i := range got {
			if got[i] != ssh[i] {
				t.Fatalf("argv[%d] = %q, want %q", i, got[i], ssh[i])
			}
		}
	})

	t.Run("WrapArgv is ignored", func(t *testing.T) {
		t.Parallel()
		got := Spec{Kind: SpecSSH, SSHArgv: ssh, WrapArgv: []string{"bwrap", "--unshare-all", "--"}}.argv()
		if got[0] != "ssh" {
			t.Fatalf("a sandbox wrapper leaked into an SSH launch: %q", got)
		}
		if len(got) != len(ssh) {
			t.Fatalf("argv length changed under WrapArgv: %q", got)
		}
	})

	t.Run("ignores agent fields", func(t *testing.T) {
		t.Parallel()
		got := Spec{
			Kind: SpecSSH, SSHArgv: ssh,
			BinPath: "/usr/bin/observer", Subcommand: "claude", SessionID: "s1",
			ExtraArgs: []string{"--resume", "s1"},
		}.argv()
		if len(got) != len(ssh) {
			t.Fatalf("agent fields leaked into the SSH argv: %q", got)
		}
	})

	t.Run("copy-on-return", func(t *testing.T) {
		t.Parallel()
		src := []string{"ssh", "h"}
		got := Spec{Kind: SpecSSH, SSHArgv: src}.argv()
		got[1] = "mutated"
		if src[1] != "h" {
			t.Fatal("argv() returned an alias of the caller's slice")
		}
	})
}

// TestManagerCreateRejectsEmptySSHArgv pins the fail-closed validation: a
// SpecSSH with no argv must never reach a spawn.
func TestManagerCreateRejectsEmptySSHArgv(t *testing.T) {
	t.Parallel()
	for _, spec := range []Spec{
		{Kind: SpecSSH},
		{Kind: SpecSSH, SSHArgv: []string{}},
		{Kind: SpecSSH, SSHArgv: []string{""}},
	} {
		m := NewManager(Options{Spawner: &fakeSpawner{}, ReapInterval: time.Hour, MaxConcurrent: 4, RingBytes: 1 << 16, Now: time.Now})
		t.Cleanup(m.Shutdown)
		if _, err := m.Create(spec); err == nil {
			t.Fatalf("Create accepted a SpecSSH with argv %q", spec.SSHArgv)
		}
	}
}
