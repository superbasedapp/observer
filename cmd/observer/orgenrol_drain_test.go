package main

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/orgenrol"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// R3-78 (operator ruling D-22): switching organizations, or leaving, first
// sends the rows still waiting for the current organization; when that fails
// nothing changes unless the person chose to drop them.

// seedDrainTail captures n actions after enrolment: the tail a switch or a
// leave must not drop silently.
func seedDrainTail(t *testing.T, st *store.Store, n int) {
	t.Helper()
	ctx := context.Background()
	pid, err := st.UpsertProject(ctx, "/tmp/drainproj", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSession(ctx, models.Session{
		ID: "drain-s1", ProjectID: pid, Tool: models.ToolClaudeCode, Model: "claude", StartedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	acts := make([]models.Action, n)
	for i := range acts {
		acts[i] = models.Action{
			SessionID: "drain-s1", ProjectID: pid, Timestamp: time.Now().UTC(),
			ActionType: models.ActionReadFile, Target: "a.go", Success: true,
			Tool: models.ToolClaudeCode, SourceFile: "f.jsonl", SourceEventID: "d" + strconv.Itoa(i),
		}
	}
	if _, err := st.InsertActions(ctx, acts); err != nil {
		t.Fatal(err)
	}
}

func TestDrainWording(t *testing.T) {
	rep := orgclient.DrainReport{
		Attempted: true, OrgID: "org-1", OrgName: "Acme", OrgServerURL: "https://a.example",
		Pending: 7, Remaining: 7, Reason: "the organization server could not be reached (x)",
	}
	for _, tc := range []struct {
		name string
		got  string
		want []string
	}{
		{
			name: "cli switch refusal",
			got:  unsentRefusalText(rep, false, cliDrainSurface),
			want: []string{"Not switched: 7 rows captured for Acme", "could not be reached", "still enrolled in Acme", "--drop-unsent", "observer org backfill --all --confirm"},
		},
		{
			name: "dashboard switch refusal",
			got:  unsentRefusalText(rep, false, dashDrainSurface),
			want: []string{"Not switched: 7 rows", "choose Switch anyway"},
		},
		{
			name: "cli leave refusal",
			got:  unsentRefusalText(rep, true, cliDrainSurface),
			want: []string{"Did not leave: 7 rows captured for Acme", "add --drop-unsent to leave anyway"},
		},
		{
			name: "dashboard leave refusal",
			got:  unsentRefusalText(rep, true, dashDrainSurface),
			want: []string{"Did not leave", "choose Leave anyway"},
		},
	} {
		for _, w := range tc.want {
			if !strings.Contains(tc.got, w) {
				t.Errorf("%s: %q does not contain %q", tc.name, tc.got, w)
			}
		}
	}

	notes := []struct {
		name     string
		rep      orgclient.DrainReport
		leave    bool
		drop     bool
		want     string
		wantWarn bool
	}{
		{name: "nothing to drain", rep: orgclient.DrainReport{}},
		{name: "nothing was waiting", rep: orgclient.DrainReport{Attempted: true, Complete: true, OrgName: "Acme"}},
		{
			name: "sent before switching", rep: orgclient.DrainReport{Attempted: true, Complete: true, Sent: 12, OrgName: "Acme"},
			want: "Sent 12 pending rows to Acme before switching.",
		},
		{
			name: "sent before leaving", leave: true, rep: orgclient.DrainReport{Attempted: true, Complete: true, Sent: 3, OrgName: "Acme"},
			want: "Sent 3 pending rows to Acme before leaving.",
		},
		{
			name: "dropped on request", drop: true, rep: func() orgclient.DrainReport { r := rep; r.Dropped = true; return r }(),
			want: "Switched anyway: 7 rows captured for Acme were not sent", wantWarn: true,
		},
		{
			name: "left on request", leave: true, drop: true, rep: func() orgclient.DrainReport { r := rep; r.Dropped = true; return r }(),
			want: "Left anyway: 7 rows", wantWarn: true,
		},
		{
			name: "same server other org", rep: func() orgclient.DrainReport { r := rep; r.Dropped = true; return r }(),
			want: "known only once the enrolment code is used", wantWarn: true,
		},
	}
	for _, tc := range notes {
		got, warn := drainNote(tc.rep, tc.leave, tc.drop)
		if tc.want == "" {
			if got != "" {
				t.Errorf("%s: note = %q, want none", tc.name, got)
			}
			continue
		}
		if !strings.Contains(got, tc.want) || warn != tc.wantWarn {
			t.Errorf("%s: note = %q (warn %v), want it to contain %q (warn %v)", tc.name, got, warn, tc.want, tc.wantWarn)
		}
	}
}

func TestSwitchDrainOptionsPushOff(t *testing.T) {
	var on, off config.Config
	on.OrgClient.Enabled = true
	if o := switchDrainOptions(&on, true); o.PushOffReason != "" || !o.DropUnsent {
		t.Errorf("enabled: %+v", o)
	}
	if o := switchDrainOptions(&off, false); !strings.Contains(o.PushOffReason, "enabled = false") {
		t.Errorf("disabled: %+v", o)
	}
}

// TestEnrolDashboardSwitchRefusesThenSwitchAnyway is the dashboard's confirm
// path: enrolled with org A, whose server refuses the push, an enrolment with
// org B is refused (unsent_rows, the code unspent, still enrolled with A);
// the same request with DropUnsent ("Switch anyway") switches and says what
// was left behind.
func TestEnrolDashboardSwitchRefusesThenSwitchAnyway(t *testing.T) {
	ctx := context.Background()
	orgA := newEnrolFakeOrg(t, orgcontract.TenancyIndividual, nil)
	orgA.pushStatus = http.StatusUnauthorized
	orgB := newEnrolFakeOrg(t, orgcontract.TenancyIndividual, nil)
	d, st, _ := testEnrolDashboard(t)

	if _, err := d.Enrol(ctx, dashapi.EnrolRequest{Method: "code", OrgURL: orgA.url, Token: idpTestEnrolCode}); err != nil {
		t.Fatalf("enrol A: %v", err)
	}
	seedDrainTail(t, st, 5)

	req := dashapi.EnrolRequest{Method: "code", OrgURL: orgB.url, Token: idpTestEnrolCode}
	_, err := d.Enrol(ctx, req)
	wantFailure(t, err, orgenrol.CodeUnsentRows)
	f, _ := orgenrol.AsFailure(err)
	for _, w := range []string{"Not switched: 6 rows", "refused this machine's credential", "choose Switch anyway"} {
		if !strings.Contains(f.Message, w) {
			t.Errorf("refusal %q does not contain %q", f.Message, w)
		}
	}
	if orgA.pushCalls == 0 {
		t.Error("the old org was never asked to take its rows")
	}
	if orgB.enrolCalls != 0 {
		t.Errorf("the new org's enrol endpoint was called %d times: the code was spent on a refused switch", orgB.enrolCalls)
	}
	if enr, _ := st.LoadEnrolment(ctx); enr == nil || enr.OrgServerURL != orgA.url {
		t.Fatalf("enrolment after the refusal = %+v, want still org A", enr)
	}

	req.DropUnsent = true
	out, err := d.Enrol(ctx, req)
	if err != nil {
		t.Fatalf("Switch anyway: %v", err)
	}
	if out.OrgServerURL != orgB.url {
		t.Fatalf("switched to %q, want org B", out.OrgServerURL)
	}
	var note string
	for _, n := range out.Notes {
		if strings.HasPrefix(n.Text, "Switched anyway") {
			if n.Level != "warn" {
				t.Errorf("dropped note level = %q, want warn", n.Level)
			}
			note = n.Text
		}
	}
	if !strings.Contains(note, "6 rows captured for") || !strings.Contains(note, "were not sent") {
		t.Fatalf("outcome notes do not report the dropped rows: %+v", out.Notes)
	}
}

// TestEnrolDashboardLeaveRefusesThenLeaveAnyway: the same rule for a leave.
func TestEnrolDashboardLeaveRefusesThenLeaveAnyway(t *testing.T) {
	ctx := context.Background()
	org := newEnrolFakeOrg(t, orgcontract.TenancyIndividual, nil)
	org.pushStatus = http.StatusUnauthorized
	d, st, _ := testEnrolDashboard(t)
	if _, err := d.Enrol(ctx, dashapi.EnrolRequest{Method: "code", OrgURL: org.url, Token: idpTestEnrolCode}); err != nil {
		t.Fatalf("enrol: %v", err)
	}
	seedDrainTail(t, st, 3)

	_, err := d.Leave(ctx, dashapi.SwitchOptions{})
	wantFailure(t, err, orgenrol.CodeUnsentRows)
	if f, _ := orgenrol.AsFailure(err); !strings.Contains(f.Message, "Did not leave: 4 rows") || !strings.Contains(f.Message, "choose Leave anyway") {
		t.Errorf("leave refusal = %q", f.Message)
	}
	if enr, _ := st.LoadEnrolment(ctx); enr == nil {
		t.Fatal("a refused leave removed the enrolment")
	}

	lv, err := d.Leave(ctx, dashapi.SwitchOptions{DropUnsent: true})
	if err != nil || !lv.WasEnrolled {
		t.Fatalf("Leave anyway = (%+v, %v)", lv, err)
	}
	var saw bool
	for _, n := range lv.Notes {
		saw = saw || (strings.Contains(n.Text, "Left anyway: 4 rows") && n.Level == "warn")
	}
	if !saw {
		t.Fatalf("leave notes do not report the dropped rows: %+v", lv.Notes)
	}
	if enr, _ := st.LoadEnrolment(ctx); enr != nil {
		t.Fatal("Leave anyway left the enrolment row")
	}
}
