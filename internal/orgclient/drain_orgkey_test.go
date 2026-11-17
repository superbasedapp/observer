package orgclient

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// M8.2 (plan 07): the switch drain under the per-session authority key
// (sessions.authority_org_key, M8.1). The org servers here record WHICH
// sessions and actions each one received, so a test proves A got only A's
// rows and B never got A's.

// recOrg is a fake org server that records the session ids and action source
// event ids of every accepted push.
type recOrg struct {
	orgID  string
	refuse bool

	mu       sync.Mutex
	sessions map[string]bool
	actions  map[string]bool
	srv      *httptest.Server
}

func newRecOrg(t *testing.T, orgID string) *recOrg {
	t.Helper()
	o := &recOrg{orgID: orgID, sessions: map[string]bool{}, actions: map[string]bool{}}
	o.srv = httptest.NewServer(http.HandlerFunc(o.serve))
	t.Cleanup(o.srv.Close)
	return o
}

func (o *recOrg) setRefuse(v bool) {
	o.mu.Lock()
	o.refuse = v
	o.mu.Unlock()
}

func (o *recOrg) serve(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/api/agent/enroll":
		writeTestJSON(w, http.StatusOK, orgcontract.EnrollResponse{
			Bearer: "bearer-" + o.orgID, OrgID: o.orgID, OrgName: "Org " + o.orgID,
			UserID: "u-1", UserEmail: "dev@example.com",
		})
	case "/api/agent/push":
		o.mu.Lock()
		refuse := o.refuse
		o.mu.Unlock()
		if refuse {
			writeTestJSON(w, http.StatusUnauthorized, map[string]string{"error": "revoked"})
			return
		}
		wire, _ := io.ReadAll(r.Body)
		env := decodeEnvelopeNoT(wire)
		o.mu.Lock()
		for _, s := range env.Sessions {
			o.sessions[s.ID] = true
		}
		for _, a := range env.Actions {
			o.actions[a.SessionID+"/"+a.SourceEventID] = true
		}
		o.mu.Unlock()
		n := len(env.Sessions) + len(env.Actions) + len(env.APITurns) + len(env.TokenUsage)
		writeTestJSON(w, http.StatusOK, orgcontract.PushResponse{AcceptedRows: int64(n), NextCursor: env.CursorTo})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// gotActions returns the sorted action keys ("session/event") received.
func (o *recOrg) gotActions() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	out := make([]string, 0, len(o.actions))
	for k := range o.actions {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (o *recOrg) hasSession(id string) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.sessions[id]
}

// captureActions records session sid (creating it on first use) with n
// actions whose event ids are prefix0..prefix(n-1), as the watcher would.
func captureActions(t *testing.T, s *store.Store, sid, prefix string, n int) {
	t.Helper()
	ctx := context.Background()
	pid, err := s.UpsertProject(ctx, "/tmp/proj", "git@example.com:acme/app.git")
	if err != nil {
		t.Fatalf("UpsertProject: %v", err)
	}
	if err := s.UpsertSession(ctx, models.Session{
		ID: sid, ProjectID: pid, Tool: models.ToolClaudeCode, Model: "claude", StartedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("UpsertSession %s: %v", sid, err)
	}
	acts := make([]models.Action, n)
	for i := range acts {
		acts[i] = models.Action{
			SessionID: sid, ProjectID: pid, Timestamp: time.Now().UTC(),
			ActionType: models.ActionReadFile, Target: "a.go", Success: true,
			Tool: models.ToolClaudeCode, SourceFile: "f.jsonl", SourceEventID: prefix + strconv.Itoa(i),
		}
	}
	if _, err := s.InsertActions(ctx, acts); err != nil {
		t.Fatalf("InsertActions: %v", err)
	}
}

func wantKeys(sid, prefix string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = sid + "/" + prefix + strconv.Itoa(i)
	}
	sort.Strings(out)
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestSwitchDrain_OrgKeyAttribution drives enrol A, capture, switch to B,
// capture, push, for each switch policy.
func TestSwitchDrain_OrgKeyAttribution(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		// aRefuses makes A reject pushes, so the drain cannot finish.
		aRefuses bool
		opts     DrainOptions
		// wantRefused: the switch is refused with UnsentRowsError.
		wantRefused bool
		// wantAGot: A's received actions after the switch attempt.
		wantAGot []string
	}{
		{
			name:     "drain sends only A's rows then B gets only B's",
			wantAGot: wantKeys("sa", "a", 3),
		},
		{
			name:     "drop-unsent leaves A's rows behind and B never gets them",
			aRefuses: true, opts: DrainOptions{DropUnsent: true},
		},
		{
			name:     "refusal reports the size and keeps A",
			aRefuses: true, wantRefused: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			s := newAgentStore(t)
			c := newTestClient(t, s, &memBearerStore{})
			c.drainRetryDelay = time.Millisecond
			a := newRecOrg(t, "org-a")
			b := newRecOrg(t, "org-b")
			if _, _, err := c.Enroll(ctx, a.srv.URL, "tok.secret"); err != nil {
				t.Fatalf("Enroll A: %v", err)
			}
			captureActions(t, s, "sa", "a", 3)
			before := pending(t, c)
			a.setRefuse(tc.aRefuses)

			_, _, rep, err := c.EnrollWithOptions(ctx, b.srv.URL, "tok.secret", EnrollOptions{Drain: tc.opts})
			if tc.wantRefused {
				var ue *UnsentRowsError
				if !errors.As(err, &ue) {
					t.Fatalf("err = %v, want UnsentRowsError", err)
				}
				if ue.Report.Remaining != before || before == 0 {
					t.Errorf("refusal size = %d, want %d (>0)", ue.Report.Remaining, before)
				}
				if cur, _ := s.LoadEnrolment(ctx); cur == nil || cur.OrgID != "org-a" {
					t.Errorf("enrolment = %+v, want still org-a", cur)
				}
				if got := b.gotActions(); len(got) != 0 {
					t.Errorf("B received %v after a refused switch", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("switch: %v", err)
			}
			if tc.opts.DropUnsent && (!rep.Dropped || rep.Remaining != before) {
				t.Errorf("report = %+v, want Dropped with %d remaining", rep, before)
			}
			if got := a.gotActions(); !equalStrings(got, tc.wantAGot) {
				t.Errorf("A received %v, want %v", got, tc.wantAGot)
			}

			// B-era capture, then B push cycles.
			captureActions(t, s, "sb", "b", 2)
			if _, err := c.PushOnce(ctx); err != nil {
				t.Fatalf("PushOnce to B: %v", err)
			}
			if got, want := b.gotActions(), wantKeys("sb", "b", 2); !equalStrings(got, want) {
				t.Errorf("B received %v, want only %v", got, want)
			}
			if b.hasSession("sa") {
				t.Error("B received session sa, which belongs to A")
			}
			if _, err := c.PushOnce(ctx); err != nil {
				t.Fatalf("second PushOnce: %v", err)
			}
			if got, want := b.gotActions(), wantKeys("sb", "b", 2); !equalStrings(got, want) {
				t.Errorf("B received %v after a second push, want only %v", got, want)
			}
		})
	}
}

// TestSwitchDrain_SessionOpenAcrossEnrolment: a session captured before A
// (personal) that keeps running is A's once A's push selects it (operator
// ruling 2026-11-13); its later actions never reach B after a switch, and a
// personal session that never ran again is nobody's.
func TestSwitchDrain_SessionOpenAcrossEnrolment(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := newAgentStore(t)
	c := newTestClient(t, s, &memBearerStore{})
	c.drainRetryDelay = time.Millisecond
	a := newRecOrg(t, "org-a")
	b := newRecOrg(t, "org-b")

	captureActions(t, s, "open", "p", 2) // personal, running at enrolment
	captureActions(t, s, "old", "p", 2)  // personal history, never runs again
	if _, _, err := c.Enroll(ctx, a.srv.URL, "tok.secret"); err != nil {
		t.Fatalf("Enroll A: %v", err)
	}
	captureActions(t, s, "open", "q", 2) // continues after enrolment

	if _, _, _, err := c.EnrollWithOptions(ctx, b.srv.URL, "tok.secret", EnrollOptions{}); err != nil {
		t.Fatalf("switch to B: %v", err)
	}
	if got, want := a.gotActions(), wantKeys("open", "q", 2); !equalStrings(got, want) {
		t.Errorf("A received %v, want the post-enrolment actions %v", got, want)
	}
	if a.hasSession("old") {
		t.Error("A received the pre-enrolment session that never ran again")
	}

	captureActions(t, s, "open", "r", 2) // still running after the switch
	captureActions(t, s, "sb", "b", 1)
	if _, err := c.PushOnce(ctx); err != nil {
		t.Fatalf("PushOnce to B: %v", err)
	}
	if got, want := b.gotActions(), wantKeys("sb", "b", 1); !equalStrings(got, want) {
		t.Errorf("B received %v, want only %v (A's open session and personal history stay out)", got, want)
	}
	if b.hasSession("open") || b.hasSession("old") {
		t.Error("B received a session that belongs to A or to nobody")
	}
}
