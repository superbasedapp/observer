package termsvc

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// TestTerminalGateJudgesEveryEntry (OSH-R-003): the org's terminals
// decision (Options.TerminalGate) is asked by every PTY launch entry, with
// the launch's own sandbox answer, and a refusal comes back before a run is
// recorded or a process spawned. Before the fix only the dashboard's HTTP
// handlers asked, so an attach launch (and any entry a handler forgot)
// started a terminal the org had disabled.
func TestTerminalGateJudgesEveryEntry(t *testing.T) {
	root := t.TempDir()
	pol := Policy{AllowFresh: true, AllowShell: true, AllowedTools: []string{"claude-code"}, AllowedProjectRoots: []string{root}}
	cases := []struct {
		name        string
		launch      func(*Service) error
		wantSandbox bool
	}{
		{"fresh", func(s *Service) error {
			_, err := s.LaunchFresh(context.Background(), FreshRequest{Tool: "claude-code", Subcommand: "claude", ProjectRoot: root})
			return err
		}, false},
		{"fresh sandboxed", func(s *Service) error {
			_, err := s.LaunchFresh(context.Background(), FreshRequest{Tool: "claude-code", Subcommand: "claude", ProjectRoot: root, Sandbox: true})
			return err
		}, true},
		{"shell", func(s *Service) error {
			_, err := s.LaunchFresh(context.Background(), FreshRequest{Shell: true, ProjectRoot: root, Sandbox: true})
			return err
		}, false},
		{"handoff", func(s *Service) error {
			_, err := s.LaunchHandoff(context.Background(), HandoffRequest{Tool: "claude-code", Subcommand: "claude", SessionID: "s1"})
			return err
		}, false},
		{"resume", func(s *Service) error {
			_, err := s.LaunchResume(context.Background(), ResumeRequest{Tool: "claude-code", Subcommand: "claude", ProjectRoot: root, SourceSessionID: "s1", ExtraArgs: []string{"--resume", "s1"}})
			return err
		}, false},
		{"attach", func(s *Service) error {
			_, err := s.LaunchAttachable(context.Background(), AttachRequest{Tool: "claude-code", Subcommand: "claude", Dir: root})
			return err
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := newFakeRecorder()
			l := &fakeLauncher{handle: "H1"}
			var asked []bool
			svc := New(Options{Policy: pol, Recorder: rec, Launcher: l, TerminalGate: func(sb bool) (bool, string) {
				asked = append(asked, sb)
				return false, "disabled by organization policy"
			}})
			err := tc.launch(svc)
			if !errors.Is(err, ErrTerminalNotAllowed) || !strings.Contains(err.Error(), "disabled by organization policy") {
				t.Fatalf("err = %v, want the org terminals refusal", err)
			}
			if len(asked) != 1 || asked[0] != tc.wantSandbox {
				t.Fatalf("gate asked %v, want once with sandbox=%v", asked, tc.wantSandbox)
			}
			if rec.recordCalls != 0 || l.calls != 0 {
				t.Fatalf("a refused launch recorded %d runs and spawned %d processes", rec.recordCalls, l.calls)
			}
		})
	}

	// An allowing gate changes nothing: the attach launch spawns.
	rec := newFakeRecorder()
	l := &fakeLauncher{handle: "H1"}
	svc := New(Options{Policy: pol, Recorder: rec, Launcher: l, TerminalGate: func(bool) (bool, string) { return true, "" }})
	if _, err := svc.LaunchAttachable(context.Background(), AttachRequest{Tool: "claude-code", Subcommand: "claude", Dir: root}); err != nil || l.calls != 1 {
		t.Fatalf("allowed attach: %v, %d spawns", err, l.calls)
	}
}
