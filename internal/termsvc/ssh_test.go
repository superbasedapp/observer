package termsvc

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sshprofile"
	"github.com/marmutapp/superbased-observer/internal/termrun"
)

// sshPolicy is an enabled policy with one profile, the baseline each gate test
// removes exactly one thing from.
func sshPolicy() Policy {
	return Policy{
		AllowSSH: true,
		SSHProfiles: []sshprofile.Profile{
			{Name: "demo-box", Label: "Client demo", Host: "demo.example.com", User: "ubuntu", Port: 2222},
		},
	}
}

// TestLaunchSSH_Success pins the happy path AND the honest zero values an SSH
// run records: no source session, no project-root hash (the shell's cwd is on
// another machine), and the reserved pseudo-tool name.
func TestLaunchSSH_Success(t *testing.T) {
	t.Parallel()
	rec := newFakeRecorder()
	l := &fakeLauncher{handle: "H"}
	svc := newService(t, sshPolicy(), rec, l, nil)

	res, err := svc.LaunchSSH(context.Background(), SSHRequest{Profile: "demo-box", Rows: 40, Cols: 120})
	if err != nil {
		t.Fatalf("LaunchSSH: %v", err)
	}
	if res.Handle != "H" || res.RunID == "" {
		t.Fatalf("LaunchResult = %+v", res)
	}
	if len(rec.runs) != 1 {
		t.Fatalf("recorded %d runs, want 1", len(rec.runs))
	}
	run := rec.runs[0]
	if run.Kind != termrun.KindSSH {
		t.Errorf("run kind = %q, want %q", run.Kind, termrun.KindSSH)
	}
	if run.Tool != SSHTool {
		t.Errorf("run tool = %q, want %q", run.Tool, SSHTool)
	}
	if run.SourceSessionID != "" {
		t.Errorf("SSH run carries a source session %q — it has none", run.SourceSessionID)
	}
	if run.ProjectRootHash != "" {
		t.Errorf("SSH run carries a project-root hash %q — its cwd is on another machine", run.ProjectRootHash)
	}

	req := l.lastReq
	if req.Kind != termrun.KindSSH {
		t.Errorf("LaunchRequest kind = %q", req.Kind)
	}
	if req.Rows != 40 || req.Cols != 120 {
		t.Errorf("PTY geometry dropped: %+v", req)
	}
	if req.Dir != "" || req.Subcommand != "" || req.IsShell || len(req.WrapArgv) > 0 {
		t.Errorf("SSH launch carried local-launch fields: %+v", req)
	}
	if len(req.SSHArgv) == 0 {
		t.Fatal("LaunchRequest.SSHArgv is empty")
	}
	if req.SSHArgv[0] != "ssh" {
		t.Errorf("argv[0] = %q, want ssh", req.SSHArgv[0])
	}
	if got := req.SSHArgv[len(req.SSHArgv)-1]; got != "demo.example.com" {
		t.Errorf("host is not the last argv token: %q", req.SSHArgv)
	}
	joined := strings.Join(req.SSHArgv, " ")
	if !strings.Contains(joined, "StrictHostKeyChecking=ask") {
		t.Errorf("composed argv lost the host-key policy: %q", req.SSHArgv)
	}
	if !strings.Contains(joined, "-p 2222") || !strings.Contains(joined, "-l ubuntu") {
		t.Errorf("composed argv dropped profile fields: %q", req.SSHArgv)
	}
}

// TestLaunchSSH_FailsClosed is the authorization surface. Every row must refuse
// BEFORE a run is minted or a process spawned — a launch that is going to be
// denied must not leave a dangling terminal_run row behind.
func TestLaunchSSH_FailsClosed(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		policy  func() Policy
		req     SSHRequest
		wantErr error
		why     string
	}{
		{
			name:    "feature disabled",
			policy:  func() Policy { p := sshPolicy(); p.AllowSSH = false; return p },
			req:     SSHRequest{Profile: "demo-box"},
			wantErr: ErrSSHLaunchDisabled,
			why:     "[terminal.ssh].enabled is the master opt-in",
		},
		{
			name:    "no profiles configured is deny-all",
			policy:  func() Policy { return Policy{AllowSSH: true} },
			req:     SSHRequest{Profile: "demo-box"},
			wantErr: ErrSSHProfileUnknown,
			why:     "an empty allow-list must not mean 'anything goes'",
		},
		{
			name:    "unknown profile name",
			policy:  sshPolicy,
			req:     SSHRequest{Profile: "not-configured"},
			wantErr: ErrSSHProfileUnknown,
			why:     "THE gate — a destination the operator never wrote cannot be reached",
		},
		{
			name:    "empty profile name",
			policy:  sshPolicy,
			req:     SSHRequest{},
			wantErr: ErrSSHProfileUnknown,
			why:     "an empty name must not match the first profile",
		},
		{
			name:    "name lookup is exact, not prefix",
			policy:  sshPolicy,
			req:     SSHRequest{Profile: "demo"},
			wantErr: ErrSSHProfileUnknown,
			why:     "a prefix match would let a client reach a neighbouring profile",
		},
		{
			name: "configured profile that fails validation",
			policy: func() Policy {
				return Policy{AllowSSH: true, SSHProfiles: []sshprofile.Profile{
					// A config that slipped past load-time validation (hand-edited
					// while the daemon ran). Re-validation at launch must catch it.
					{Name: "bad", Host: "-oProxyCommand=touch /tmp/pwn"},
				}}
			},
			req:     SSHRequest{Profile: "bad"},
			wantErr: ErrSSHProfileInvalid,
			why:     "re-validate at launch, never trust the load-time check alone",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rec := newFakeRecorder()
			l := &fakeLauncher{handle: "H"}
			svc := newService(t, tc.policy(), rec, l, nil)

			_, err := svc.LaunchSSH(context.Background(), tc.req)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v (%s)", err, tc.wantErr, tc.why)
			}
			if l.calls != 0 {
				t.Errorf("a denied launch still spawned a process (%d calls)", l.calls)
			}
			if len(rec.runs) != 0 {
				t.Errorf("a denied launch minted %d run rows", len(rec.runs))
			}
		})
	}
}

// TestLaunchSSH_RevalidatesKeyPathAtLaunch pins the ValidateProjectRoot-shaped
// discipline: a key file that existed at config load but is gone by launch time
// fails the launch loudly, rather than producing an opaque ssh error in the PTY.
func TestLaunchSSH_RevalidatesKeyPathAtLaunch(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	key := filepath.Join(dir, "id_demo")
	if err := os.WriteFile(key, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	policy := Policy{AllowSSH: true, SSHProfiles: []sshprofile.Profile{
		{Name: "k", Host: "h.example.com", KeyPath: key},
	}}
	rec := newFakeRecorder()
	l := &fakeLauncher{handle: "H"}
	svc := newService(t, policy, rec, l, nil)

	if _, err := svc.LaunchSSH(context.Background(), SSHRequest{Profile: "k"}); err != nil {
		t.Fatalf("launch with a present key: %v", err)
	}
	if got := strings.Join(l.lastReq.SSHArgv, " "); !strings.Contains(got, "-i "+key) || !strings.Contains(got, "IdentitiesOnly=yes") {
		t.Fatalf("key flags missing from argv: %q", l.lastReq.SSHArgv)
	}

	if err := os.Remove(key); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	_, err := svc.LaunchSSH(context.Background(), SSHRequest{Profile: "k"})
	if !errors.Is(err, ErrSSHProfileInvalid) {
		t.Fatalf("launch after the key vanished = %v, want ErrSSHProfileInvalid", err)
	}
}

// TestLaunchSSH_NoLauncher pins the nil-seam refusal, matching LaunchFresh.
func TestLaunchSSH_NoLauncher(t *testing.T) {
	t.Parallel()
	svc := New(Options{Policy: sshPolicy(), Recorder: newFakeRecorder()})
	if _, err := svc.LaunchSSH(context.Background(), SSHRequest{Profile: "demo-box"}); !errors.Is(err, ErrNoLauncher) {
		t.Fatalf("err = %v, want ErrNoLauncher", err)
	}
}

// TestSSHProfileList pins the picker READ seam: it reports the same
// enabled-state and list the launch gate consults (one owner), and hands back a
// COPY so a caller cannot mutate the policy's allow-list.
func TestSSHProfileList(t *testing.T) {
	t.Parallel()
	svc := newService(t, sshPolicy(), newFakeRecorder(), &fakeLauncher{handle: "H"}, nil)

	enabled, profiles := svc.SSHProfileList()
	if !enabled || len(profiles) != 1 || profiles[0].Name != "demo-box" {
		t.Fatalf("SSHProfileList = %v, %+v", enabled, profiles)
	}
	// Mutating the returned slice must not reach the policy — otherwise a
	// picker read could rewrite the authorization list.
	profiles[0].Host = "evil.example.com"
	_, again := svc.SSHProfileList()
	if again[0].Host != "demo.example.com" {
		t.Fatalf("SSHProfileList returned an alias of the policy: %+v", again[0])
	}

	off := newService(t, Policy{}, newFakeRecorder(), &fakeLauncher{handle: "H"}, nil)
	if enabled, ps := off.SSHProfileList(); enabled || len(ps) != 0 {
		t.Fatalf("disabled service reported %v, %+v", enabled, ps)
	}
}

// TestLaunchSSH_LeavesOtherLaunchPathsAlone pins the additive-not-invasive
// property: an SSH-enabled policy that denies fresh/shell launches still denies
// them, and an SSH-disabled policy does not disturb a working shell launch.
func TestLaunchSSH_LeavesOtherLaunchPathsAlone(t *testing.T) {
	t.Parallel()
	p := sshPolicy() // AllowFresh and AllowShell both false
	svc := newService(t, p, newFakeRecorder(), &fakeLauncher{handle: "H"}, nil)
	if _, err := svc.LaunchFresh(context.Background(), FreshRequest{Tool: "claude-code"}); !errors.Is(err, ErrFreshLaunchDisabled) {
		t.Errorf("enabling SSH also enabled fresh launch: %v", err)
	}
	if _, err := svc.LaunchFresh(context.Background(), FreshRequest{Shell: true}); !errors.Is(err, ErrShellLaunchDisabled) {
		t.Errorf("enabling SSH also enabled the local shell: %v", err)
	}

	shellOnly := Policy{AllowShell: true}
	svc2 := newService(t, shellOnly, newFakeRecorder(), &fakeLauncher{handle: "H"}, nil)
	if _, err := svc2.LaunchFresh(context.Background(), FreshRequest{Shell: true}); err != nil {
		t.Errorf("a shell launch broke: %v", err)
	}
	if _, err := svc2.LaunchSSH(context.Background(), SSHRequest{Profile: "demo-box"}); !errors.Is(err, ErrSSHLaunchDisabled) {
		t.Errorf("allow_shell implied SSH: %v", err)
	}
}
