package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/govern"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/routeprov"
)

func leaveTestClaudeURL(t *testing.T, home string) (string, bool) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(home, ".claude", "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	var s struct {
		Env map[string]any `json:"env"`
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatal(err)
	}
	v, ok := s.Env["ANTHROPIC_BASE_URL"].(string)
	return v, ok
}

// TestLeaveRemovesOnlyEnrolmentWrittenRoutes runs the real chain on both
// rails' shared code: the enrolment's --wire-clients step
// (wireAIClients with RouteWriter=enrolment, hooks and MCP skipped) writes
// the Claude Code route, the dashboard overview's Leave plan names what
// Leave will do, and the shared Leave (performUnenrol, which
// `observer unenroll` also runs) removes the route only when enrolment
// wrote it.
func TestLeaveRemovesOnlyEnrolmentWrittenRoutes(t *testing.T) {
	requireComponents(t, "integration.proxy-route")
	requireActiveAdapters(t, "claude-code")
	requireAdapter(t, "claude-code")
	const port = 18644
	cases := []struct {
		name string
		// userRoute pre-sets ANTHROPIC_BASE_URL before enrolment, as a
		// developer who set it themselves would have.
		userRoute   bool
		wantAction  string
		wantMessage string
		wantKept    bool
	}{
		{
			name: "enrolment wrote the route", wantAction: "remove",
			wantMessage: "Removes ANTHROPIC_BASE_URL from",
		},
		{
			name: "you set the route yourself", userRoute: true, wantAction: "keep",
			wantMessage: "Your Claude Code proxy setting will be kept because you set it yourself.", wantKept: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := context.Background()
			org := newEnrolFakeOrg(t, orgcontract.TenancyIndividual, []string{govern.AuthorityDashboardVisibility})
			d, _, _ := testEnrolDashboard(t)
			home := os.Getenv("HOME")
			settings := filepath.Join(home, ".claude", "settings.json")
			seed := `{"permissions":{"allow":["Read"]}}`
			if c.userRoute {
				seed = `{"env":{"ANTHROPIC_BASE_URL":"http://127.0.0.1:18644"}}`
			}
			if err := os.MkdirAll(filepath.Dir(settings), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(settings, []byte(seed), 0o600); err != nil {
				t.Fatal(err)
			}

			if _, err := d.Enrol(ctx, dashapi.EnrolRequest{Method: "code", OrgURL: org.url, Token: idpTestEnrolCode}); err != nil {
				t.Fatalf("Enrol: %v", err)
			}
			// The CLI enrolment's --wire-clients step, as org.go calls it.
			if _, _, _, _, err := wireAIClients(WireAIClientsOptions{
				RouteWriter:    routeprov.WriterEnrolment,
				ProxyPort:      port,
				HomeDir:        home,
				OnlyClaudeCode: true,
				SkipHooks:      true,
				SkipMCP:        true,
				SkipExtension:  true,
			}); err != nil {
				t.Fatalf("wireAIClients: %v", err)
			}
			before, ok := leaveTestClaudeURL(t, home)
			if !ok || before != "http://127.0.0.1:18644" {
				t.Fatalf("route after wiring = %q (%v)", before, ok)
			}

			// The confirm dialog's plan.
			ov, err := d.Overview(ctx)
			if err != nil {
				t.Fatal(err)
			}
			var plan *dashapi.EnrolLeaveRoute
			for i := range ov.LeavePlan {
				if ov.LeavePlan[i].Tool == "claude-code" {
					plan = &ov.LeavePlan[i]
				}
			}
			if plan == nil || plan.Action != c.wantAction || !strings.HasPrefix(plan.Message, c.wantMessage) {
				t.Fatalf("leave plan = %+v, want %s %q", ov.LeavePlan, c.wantAction, c.wantMessage)
			}

			lv, err := d.Leave(ctx, dashapi.SwitchOptions{})
			if err != nil || !lv.WasEnrolled {
				t.Fatalf("Leave = (%+v, %v)", lv, err)
			}
			after, stillSet := leaveTestClaudeURL(t, home)
			var notes []string
			for _, n := range lv.Notes {
				notes = append(notes, n.Text)
			}
			joined := strings.Join(notes, "\n")
			if c.wantKept {
				if !stillSet || after != before || !strings.Contains(joined, c.wantMessage) {
					t.Fatalf("route must be kept and said so: set=%v %q\n%s", stillSet, after, joined)
				}
				return
			}
			if stillSet || !strings.Contains(joined, "Removed ANTHROPIC_BASE_URL from "+settings) {
				t.Fatalf("route must be removed and said so: set=%v %q\n%s", stillSet, after, joined)
			}
			raw, _ := os.ReadFile(settings)
			if !strings.Contains(string(raw), `"Read"`) {
				t.Fatalf("other settings must survive:\n%s", raw)
			}
		})
	}
}
