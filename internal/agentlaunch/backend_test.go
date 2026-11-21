package agentlaunch

import (
	"errors"
	"strings"
	"testing"
)

func probe() Probe {
	return Probe{
		Available: true,
		Backends: []BackendRow{
			{ID: "bwrap", Maturity: "shipped", Available: true, Verification: "live"},
			{ID: "oci-runc", Maturity: "preview", Available: true, Verification: "doc"},
			{ID: "gvisor", Maturity: "preview", Available: false, Verification: "doc", Verdict: "backend_missing", Reason: "runsc not found"},
			{ID: "codespaces", Maturity: MaturityPlanned},
		},
		Sources: []SourceRow{
			{ID: WorkspaceLive, Available: true},
			{ID: WorkspaceCloneLocal, Available: true},
			{ID: WorkspaceCloneRemote, Available: false, Reason: "allow_remote_clone is not set"},
		},
		Tools: map[string]ToolRow{
			"claude-code": {Available: true},
			"codex":       {Available: false, Reason: "state dirs not grounded"},
		},
	}
}

func norm(t *testing.T, r Request) Normalized {
	t.Helper()
	n, err := Normalize(r)
	if err != nil {
		t.Fatalf("normalize %+v: %v", r, err)
	}
	return n
}

// TestChooseRows walks the backend choice table, one case per row, plus
// the refusal shapes: a requested sandbox that cannot be built always
// refuses (never an unsandboxed launch) and auto never takes a beta row.
func TestChooseRows(t *testing.T) {
	cases := []struct {
		name    string
		req     Request
		probe   func(*Probe)
		want    Choice
		refuse  string // substring of the refusal; "" = accepted
		refuseF string // refusal field
	}{
		{name: "C1 unsandboxed ignores the probe", req: Request{Tool: "claude", Project: "/p"}, probe: func(p *Probe) { *p = Probe{} }, want: Choice{}},
		{name: "C2 explicit shipped row", req: Request{Tool: "claude", Project: "/p", Sandbox: "bwrap"}, want: Choice{Sandboxed: true, Backend: "bwrap"}},
		{name: "C2 explicit beta row is allowed", req: Request{Tool: "claude", Project: "/p", Sandbox: "oci-runc"}, want: Choice{Sandboxed: true, Backend: "oci-runc"}},
		{name: "C2 unknown row", req: Request{Tool: "claude", Project: "/p", Sandbox: "e2b"}, refuse: "unknown sandbox backend", refuseF: "sandbox"},
		{name: "C2 planned row", req: Request{Tool: "claude", Project: "/p", Sandbox: "codespaces"}, refuse: "not offered yet", refuseF: "sandbox"},
		{name: "C2 unavailable row names verdict", req: Request{Tool: "claude", Project: "/p", Sandbox: "gvisor"}, refuse: "backend_missing", refuseF: "sandbox"},
		{name: "C3 auto with nothing available", req: Request{Tool: "claude", Project: "/p", Sandbox: "auto"}, probe: func(p *Probe) {
			p.Available, p.Verdict, p.Reason = false, "userns_denied", "kernel.unprivileged_userns_clone=0"
		}, refuse: "userns_denied", refuseF: "sandbox"},
		{name: "C4 auto takes the live row", req: Request{Tool: "claude", Project: "/p", Sandbox: "auto"}, want: Choice{Sandboxed: true, Auto: true}},
		{name: "C4 auto skips a beta-only host", req: Request{Tool: "claude", Project: "/p", Sandbox: "auto"}, probe: func(p *Probe) {
			p.Backends = []BackendRow{
				{ID: "bwrap", Maturity: "shipped", Available: false, Verification: "live", Verdict: "backend_missing"},
				{ID: "oci-runc", Maturity: "preview", Available: true, Verification: "doc"},
			}
		}, refuse: "never picks a beta backend", refuseF: "sandbox"},
		{name: "C4 auto with only planned rows", req: Request{Tool: "claude", Project: "/p", Sandbox: "auto"}, probe: func(p *Probe) {
			p.Backends = []BackendRow{{ID: "codespaces", Maturity: MaturityPlanned, Available: true, Verification: "live"}}
		}, refuse: "no non-beta", refuseF: "sandbox"},
		{name: "C5 unavailable source", req: Request{Tool: "claude", Project: "/p", Sandbox: "auto", Workspace: WorkspaceCloneRemote, Remote: "https://e/r.git"}, refuse: "allow_remote_clone", refuseF: "workspace"},
		{name: "C5 source not offered", req: Request{Tool: "claude", Project: "/p", Sandbox: "bwrap", Workspace: WorkspaceWorktree}, refuse: "not offered", refuseF: "workspace"},
		{name: "C5 clone-local accepted", req: Request{Tool: "claude", Project: "/p", Sandbox: "bwrap", Workspace: WorkspaceCloneLocal, Branch: "main"}, want: Choice{Sandboxed: true, Backend: "bwrap"}},
		{name: "C6 tool without sandbox row", req: Request{Tool: "codex", Project: "/p", Sandbox: "bwrap"}, refuse: "state dirs not grounded", refuseF: "tool"},
		{name: "C6 tool missing from probe", req: Request{Tool: "claude", Project: "/p", Sandbox: "bwrap"}, probe: func(p *Probe) { p.Tools = nil }, refuse: "no grounded sandbox row", refuseF: "tool"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := probe()
			if tc.probe != nil {
				tc.probe(&p)
			}
			c, err := Choose(norm(t, tc.req), p)
			if tc.refuse != "" {
				if err == nil {
					t.Fatalf("want refusal %q, got choice %+v", tc.refuse, c)
				}
				if CodeOf(err) != CodeSandboxUnavailable || !strings.Contains(err.Error(), tc.refuse) {
					t.Fatalf("refusal = %v (code %s), want %q", err, CodeOf(err), tc.refuse)
				}
				var e *Error
				if !errors.As(err, &e) || e.Field != tc.refuseF {
					t.Fatalf("refusal %v: want field %q", err, tc.refuseF)
				}
				if c != (Choice{}) {
					t.Fatalf("a refusal must return the zero choice, got %+v", c)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected refusal: %v", err)
			}
			if c != tc.want {
				t.Fatalf("choice = %+v, want %+v", c, tc.want)
			}
		})
	}
}
