package orgclient

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// fakeOrg is an org server for the switch-drain tests (R3-78): it answers
// enrolment with its own org id and push with the mode it is set to. It counts
// every request per path so a test can prove which server was contacted.
type fakeOrg struct {
	orgID string
	// push is "accept", "refuse" (401), "fail" (503) or "hang".
	push string

	mu      sync.Mutex
	pushes  int
	pushed  int // rows carried by accepted pushes
	enrols  int
	srv     *httptest.Server
	release chan struct{}
}

func newFakeOrg(t *testing.T, orgID, push string) *fakeOrg {
	t.Helper()
	f := &fakeOrg{orgID: orgID, push: push, release: make(chan struct{})}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(func() {
		close(f.release)
		f.srv.Close()
	})
	return f
}

func (f *fakeOrg) serve(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/api/agent/enroll":
		f.mu.Lock()
		f.enrols++
		f.mu.Unlock()
		writeTestJSON(w, http.StatusOK, orgcontract.EnrollResponse{
			Bearer: "bearer-" + f.orgID, OrgID: f.orgID, OrgName: "Org " + f.orgID,
			UserID: "u-1", UserEmail: "dev@example.com",
		})
	case "/api/agent/push":
		f.mu.Lock()
		f.pushes++
		mode := f.push
		f.mu.Unlock()
		switch mode {
		case "accept":
			wire, _ := io.ReadAll(r.Body)
			env := decodeEnvelopeNoT(wire)
			n := len(env.Sessions) + len(env.Actions) + len(env.APITurns) + len(env.TokenUsage)
			f.mu.Lock()
			f.pushed += n
			f.mu.Unlock()
			writeTestJSON(w, http.StatusOK, orgcontract.PushResponse{AcceptedRows: int64(n), NextCursor: env.CursorTo})
		case "refuse":
			writeTestJSON(w, http.StatusUnauthorized, map[string]string{"error": "revoked"})
		case "hang":
			select {
			case <-r.Context().Done():
			case <-f.release:
			}
		default:
			writeTestJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "down"})
		}
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (f *fakeOrg) counts() (pushes, pushed, enrols int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.pushes, f.pushed, f.enrols
}

// decodeEnvelopeNoT is decodeEnvelope without a *testing.T (the handler runs
// on the server's goroutine); a decode failure yields an empty envelope.
func decodeEnvelopeNoT(gz []byte) orgcontract.PushEnvelope {
	var env orgcontract.PushEnvelope
	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		return env
	}
	raw, err := io.ReadAll(zr)
	if err == nil {
		_ = json.Unmarshal(raw, &env)
	}
	return env
}

// enrolledIn enrols the test store in org (through its own fake server) and
// then seeds n actions captured AFTER enrolment: the tail a switch must not
// drop.
func enrolledIn(t *testing.T, c *Client, s *store.Store, org *fakeOrg, n int) {
	t.Helper()
	if _, _, err := c.Enroll(context.Background(), org.srv.URL, "tok.secret"); err != nil {
		t.Fatalf("first Enroll: %v", err)
	}
	seedActivity(t, s, n)
}

func pending(t *testing.T, c *Client) int64 {
	t.Helper()
	n, err := c.pendingRows(context.Background())
	if err != nil {
		t.Fatalf("pendingRows: %v", err)
	}
	return n
}

func TestEnrollSwitch_DrainsOldOrgFirst(t *testing.T) {
	cases := []struct {
		name string
		// oldPush is the old org's push behaviour; closed shuts it down first.
		oldPush string
		closed  bool
		opts    DrainOptions
		// wantSwitch: the new enrolment was written.
		wantSwitch  bool
		wantRefused bool
		wantDropped bool
		wantReason  string
		// wantNewEnrol: the new server's enrol endpoint was called (the code
		// was spent).
		wantNewEnrol bool
	}{
		{
			name: "drain succeeds then switch", oldPush: "accept",
			wantSwitch: true, wantNewEnrol: true,
		},
		{
			name: "old org unreachable refuses", oldPush: "accept", closed: true,
			wantRefused: true, wantReason: "could not be reached",
		},
		{
			name: "old org unreachable with drop-unsent switches", oldPush: "accept", closed: true,
			opts:       DrainOptions{DropUnsent: true},
			wantSwitch: true, wantDropped: true, wantNewEnrol: true, wantReason: "could not be reached",
		},
		{
			name: "old org refuses the credential", oldPush: "refuse",
			wantRefused: true, wantReason: "refused this machine's credential",
		},
		{
			name: "old org failing (5xx) refuses after retries", oldPush: "fail",
			wantRefused: true, wantReason: "did not accept the push",
		},
		{
			name: "budget exhausted refuses", oldPush: "hang",
			opts:        DrainOptions{Budget: 150 * time.Millisecond},
			wantRefused: true, wantReason: "time allowed",
		},
		{
			name: "push off refuses without a push", oldPush: "accept",
			opts:        DrainOptions{PushOffReason: "org push is turned off"},
			wantRefused: true, wantReason: "org push is turned off",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newAgentStore(t)
			bs := &memBearerStore{}
			c := newTestClient(t, s, bs)
			c.drainRetryDelay = 5 * time.Millisecond
			oldOrg := newFakeOrg(t, "org-a", tc.oldPush)
			newOrg := newFakeOrg(t, "org-b", "accept")
			enrolledIn(t, c, s, oldOrg, 4)
			before := pending(t, c)
			if before == 0 {
				t.Fatal("no pending rows seeded")
			}
			if tc.closed {
				oldOrg.srv.Close()
			}

			enr, _, rep, err := c.EnrollWithOptions(context.Background(), newOrg.srv.URL, "tok.secret",
				EnrollOptions{Drain: tc.opts})

			_, pushed, _ := oldOrg.counts()
			_, _, newEnrols := newOrg.counts()
			if (newEnrols > 0) != tc.wantNewEnrol {
				t.Errorf("new org enrol calls = %d, want called=%v", newEnrols, tc.wantNewEnrol)
			}
			cur, _ := s.LoadEnrolment(context.Background())
			switch {
			case tc.wantRefused:
				var ue *UnsentRowsError
				if !errors.Is(err, ErrUnsentRows) || !errors.As(err, &ue) {
					t.Fatalf("err = %v, want ErrUnsentRows", err)
				}
				if ue.Report.Remaining != before || ue.Report.Pending != before {
					t.Errorf("report pending/remaining = %d/%d, want %d", ue.Report.Pending, ue.Report.Remaining, before)
				}
				if !strings.Contains(ue.Report.Reason, tc.wantReason) {
					t.Errorf("reason = %q, want it to contain %q", ue.Report.Reason, tc.wantReason)
				}
				if cur == nil || cur.OrgID != "org-a" {
					t.Errorf("enrolment after a refusal = %+v, want still org-a", cur)
				}
				if bs.bearer != "bearer-org-a" {
					t.Errorf("bearer after a refusal = %q, want the old one", bs.bearer)
				}
				if got := pending(t, c); got != before {
					t.Errorf("pending after a refusal = %d, want %d (cursor untouched)", got, before)
				}
				if tc.opts.PushOffReason != "" {
					if p, _, _ := oldOrg.counts(); p != 0 {
						t.Errorf("push off: old org saw %d pushes, want 0", p)
					}
				}
			case tc.wantSwitch:
				if err != nil {
					t.Fatalf("EnrollWithOptions: %v", err)
				}
				if enr == nil || enr.OrgID != "org-b" || cur == nil || cur.OrgID != "org-b" {
					t.Fatalf("enrolment = %+v / %+v, want org-b", enr, cur)
				}
				if rep.Dropped != tc.wantDropped {
					t.Errorf("Dropped = %v, want %v", rep.Dropped, tc.wantDropped)
				}
				if tc.wantDropped {
					if rep.Remaining != before || !strings.Contains(rep.Reason, tc.wantReason) {
						t.Errorf("dropped report = %+v, want remaining %d and reason %q", rep, before, tc.wantReason)
					}
				} else {
					if !rep.Complete || rep.Sent == 0 || pushed == 0 {
						t.Errorf("drain report = %+v (old org got %d rows), want complete with rows sent", rep, pushed)
					}
					if rep.OrgID != "org-a" {
						t.Errorf("drain report org = %q, want org-a", rep.OrgID)
					}
				}
				// The new enrolment's cursor is reseeded either way: the old
				// org's rows never go to the new one.
				if got := pending(t, c); got != 0 {
					t.Errorf("pending after the switch = %d, want 0", got)
				}
			}
		})
	}
}

// TestEnrollSameOrgReenrolUnchanged pins that a re-enrolment with the same
// server and org drains nothing (no push) and reseeds the cursor as before.
func TestEnrollSameOrgReenrolUnchanged(t *testing.T) {
	s := newAgentStore(t)
	c := newTestClient(t, s, &memBearerStore{})
	org := newFakeOrg(t, "org-a", "accept")
	enrolledIn(t, c, s, org, 3)
	_, _, rep, err := c.EnrollWithOptions(context.Background(), org.srv.URL+"/", "tok.secret", EnrollOptions{})
	if err != nil {
		t.Fatalf("re-enrol: %v", err)
	}
	if rep.Attempted {
		t.Errorf("same-org re-enrol attempted a drain: %+v", rep)
	}
	if p, _, _ := org.counts(); p != 0 {
		t.Errorf("same-org re-enrol pushed %d times, want 0", p)
	}
	if got := pending(t, c); got != 0 {
		t.Errorf("pending after re-enrol = %d, want 0 (reseeded)", got)
	}
}

// TestEnrollSameServerDifferentOrg covers the one case decided after the code
// is spent: the same server answering for another organization. The drain is
// tried with the old credentials; when it fails the switch still goes ahead
// and the report says what was left.
func TestEnrollSameServerDifferentOrg(t *testing.T) {
	for _, tc := range []struct {
		name        string
		push        string
		wantDropped bool
	}{
		{name: "drain succeeds", push: "accept"},
		{name: "drain fails, switch proceeds", push: "refuse", wantDropped: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newAgentStore(t)
			bs := &memBearerStore{}
			c := newTestClient(t, s, bs)
			c.drainRetryDelay = 5 * time.Millisecond
			org := newFakeOrg(t, "org-a", tc.push)
			enrolledIn(t, c, s, org, 3)
			before := pending(t, c)
			org.mu.Lock()
			org.orgID = "org-z" // the server now answers for another org
			org.mu.Unlock()
			enr, _, rep, err := c.EnrollWithOptions(context.Background(), org.srv.URL, "tok.secret", EnrollOptions{})
			if err != nil {
				t.Fatalf("EnrollWithOptions: %v", err)
			}
			if enr.OrgID != "org-z" {
				t.Fatalf("enrolled in %q, want org-z", enr.OrgID)
			}
			if !rep.Attempted || rep.OrgID != "org-a" {
				t.Errorf("drain report = %+v, want an attempted drain to org-a", rep)
			}
			if rep.Dropped != tc.wantDropped {
				t.Errorf("Dropped = %v, want %v (report %+v)", rep.Dropped, tc.wantDropped, rep)
			}
			if tc.wantDropped && rep.Remaining != before {
				t.Errorf("Remaining = %d, want %d", rep.Remaining, before)
			}
			if !tc.wantDropped && !rep.Complete {
				t.Errorf("drain not complete: %+v", rep)
			}
		})
	}
}

func TestDrainBeforeLeave(t *testing.T) {
	for _, tc := range []struct {
		name        string
		push        string
		drop        bool
		wantErr     bool
		wantDropped bool
	}{
		{name: "drain succeeds", push: "accept"},
		{name: "refused without drop", push: "refuse", wantErr: true},
		{name: "drop proceeds", push: "refuse", drop: true, wantDropped: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newAgentStore(t)
			c := newTestClient(t, s, &memBearerStore{})
			c.drainRetryDelay = 5 * time.Millisecond
			org := newFakeOrg(t, "org-a", tc.push)
			enrolledIn(t, c, s, org, 2)
			rep, err := c.DrainBeforeLeave(context.Background(), DrainOptions{DropUnsent: tc.drop})
			if gotErr := errors.Is(err, ErrUnsentRows); gotErr != tc.wantErr {
				t.Fatalf("err = %v, want ErrUnsentRows=%v", err, tc.wantErr)
			}
			if rep.Dropped != tc.wantDropped {
				t.Errorf("Dropped = %v, want %v", rep.Dropped, tc.wantDropped)
			}
			if !tc.wantErr && !tc.wantDropped && (!rep.Complete || pending(t, c) != 0) {
				t.Errorf("drain = %+v, pending %d; want complete and nothing pending", rep, pending(t, c))
			}
		})
	}
}

// TestDrainNotEnrolledIsNoop: nothing to drain, no refusal.
func TestDrainNotEnrolledIsNoop(t *testing.T) {
	c := newTestClient(t, newAgentStore(t), &memBearerStore{})
	rep, err := c.DrainBeforeLeave(context.Background(), DrainOptions{})
	if err != nil || rep.Attempted || !rep.Complete {
		t.Fatalf("DrainBeforeLeave on a fresh node = %+v, %v", rep, err)
	}
}

// TestDrainCycleCap: a tail that needs more cycles than allowed stops and
// reports what is left, which (without drop-unsent) refuses the switch.
func TestDrainCycleCap(t *testing.T) {
	s := newAgentStore(t)
	bs := &memBearerStore{}
	// A small batch budget, so the tail needs several cycles.
	c := New(config.OrgClientConfig{
		Enabled: true, PushIntervalSeconds: config.DefaultPushIntervalSeconds,
		MaxPushBytes: 4096, KeychainID: config.DefaultKeychainID,
	}, s, bs, "test-version", http.DefaultClient, quietLogger())
	org := newFakeOrg(t, "org-a", "accept")
	enrolledIn(t, c, s, org, 60)
	rep, err := c.DrainPending(context.Background(), DrainOptions{MaxCycles: 1})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Complete || rep.Remaining == 0 || rep.Cycles != 1 || !strings.Contains(rep.Reason, "more than 1 push cycles") {
		t.Fatalf("capped drain = %+v, want incomplete after 1 cycle with rows left", rep)
	}
	// Uncapped, the same tail drains completely.
	rep, err = c.DrainPending(context.Background(), DrainOptions{})
	if err != nil || !rep.Complete || pending(t, c) != 0 {
		t.Fatalf("uncapped drain = %+v, %v (pending %d)", rep, err, pending(t, c))
	}
}

func TestClassifyDrainErr(t *testing.T) {
	for _, tc := range []struct {
		err       error
		rule      string
		retryable bool
	}{
		{context.DeadlineExceeded, "budget", false},
		{fmt.Errorf("x: %w", ErrAuthFailed), "auth", false},
		{fmt.Errorf("x: %w", ErrAgentTooOld), "too-old", false},
		{fmt.Errorf("x: %w", ErrBatchTooLarge), "too-large", false},
		{ErrNotEnrolled, "not-enrolled", false},
		{&httpStatusError{op: "x", status: 503}, "other", true},
		{errors.New("boom"), "other", true},
	} {
		got := classifyDrainErr(tc.err)
		if got.name != tc.rule || got.retryable != tc.retryable {
			t.Errorf("classifyDrainErr(%v) = %s/%v, want %s/%v", tc.err, got.name, got.retryable, tc.rule, tc.retryable)
		}
		if got.reason(tc.err) == "" {
			t.Errorf("rule %s has an empty reason", got.name)
		}
	}
}
