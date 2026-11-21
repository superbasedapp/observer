//go:build !sbo_omit_terminals

package main

import (
	"context"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/termrun"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
)

// backendSandboxer is a Sandboxer that builds nothing and reports the isolation
// stack the test chose.
type backendSandboxer struct {
	dir   string
	stack []string
}

func (s backendSandboxer) Prepare(context.Context, termsvc.PrepareRequest) (termsvc.PrepareResult, error) {
	return termsvc.PrepareResult{Dir: s.dir, WrapArgv: []string{"box", "--"}, Isolation: termrun.Isolation{Class: "process", Stack: s.stack}}, nil
}

// TestCreateFreshDetailedReportsTheBackend: the dashboard's detailed launch
// names the sandbox backend that built the box (the isolation stack's outermost
// layer), and names none for a launch that was not sandboxed. A caller that
// records which backend a run used (the assessments module) reads it here,
// because an Automatic choice is resolved only by the launcher.
func TestCreateFreshDetailedReportsTheBackend(t *testing.T) {
	root := t.TempDir()
	for _, tc := range []struct {
		name    string
		sandbox bool
		stack   []string
		want    string
	}{
		{"sandboxed", true, []string{"bwrap"}, "bwrap"},
		{"sandboxed with a stack of two", true, []string{"lima", "bwrap"}, "lima"},
		{"sandboxed, no stack reported", true, nil, ""},
		{"not sandboxed", false, []string{"bwrap"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc := termsvc.New(termsvc.Options{
				Policy:    termsvc.Policy{AllowFresh: true, AllowedTools: []string{"claude-code"}, AllowedProjectRoots: []string{root}},
				Recorder:  assembledRecorder{},
				Launcher:  &recordingLauncher{},
				Sandboxer: backendSandboxer{dir: root, stack: tc.stack},
			})
			a := &launchManagerAdapter{svc: svc}
			res, err := a.CreateFreshDetailed(dashapi.FreshLaunchSpec{
				Tool: "claude-code", Subcommand: "claude", ProjectRoot: root, Sandbox: tc.sandbox, WorkspaceSource: "live",
			})
			if err != nil {
				t.Fatalf("CreateFreshDetailed: %v", err)
			}
			if res.Handle == "" || res.Backend != tc.want {
				t.Errorf("handle %q backend %q, want a handle and %q", res.Handle, res.Backend, tc.want)
			}
		})
	}
}
