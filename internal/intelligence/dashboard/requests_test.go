package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/accessgrant"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// fakeRequests is a RequestService that records what it was asked to send.
type fakeRequests struct {
	enrolled  bool
	offline   bool
	sent      []orgcontract.AccessRequestCreate
	queued    []orgcontract.AccessRequestCreate
	withdrawn []int64
	// held are the grants in force on the fake node (AlreadyGranted).
	held []accessgrant.Held
}

func (f *fakeRequests) Status(context.Context) (orgclient.EnrolmentState, error) {
	return orgclient.EnrolmentState{Enrolled: f.enrolled, OrgName: "Acme"}, nil
}

func (f *fakeRequests) ListMyOrgRequests(context.Context) ([]orgclient.OrgRequest, error) {
	if f.offline {
		return nil, errors.New("dial tcp: connection refused")
	}
	return []orgclient.OrgRequest{{ID: 4, Kind: "other", Message: "need curl", Status: "open", RequestType: accessgrant.TypeGuardExemption}}, nil
}

func (f *fakeRequests) PrepareAccessRequest(_ context.Context, in orgcontract.AccessRequestCreate, optIn bool) (orgcontract.AccessRequestCreate, error) {
	if in.Context != nil {
		shaped := accessgrant.ShapeContext(*in.Context, false, optIn)
		in.Context = &shaped
	}
	return in, nil
}

func (f *fakeRequests) SendOrQueueAccessRequest(_ context.Context, p orgcontract.AccessRequestCreate) (orgclient.OrgRequest, int64, error) {
	if f.offline {
		f.queued = append(f.queued, p)
		return orgclient.OrgRequest{}, int64(len(f.queued)), nil
	}
	f.sent = append(f.sent, p)
	return orgclient.OrgRequest{ID: 9, Status: "open"}, 0, nil
}

func (f *fakeRequests) WithdrawOrgRequest(_ context.Context, id int64) error {
	f.withdrawn = append(f.withdrawn, id)
	if id == 77 {
		return orgclient.ErrRequestNotOpen
	}
	return nil
}

func (f *fakeRequests) AccessGrantsView(context.Context) (store.AccessGrantsView, bool, error) {
	return store.AccessGrantsView{Version: 3, Grants: []store.AccessGrantView{{
		Grant: orgcontract.AccessGrantWire{ID: 12, Type: accessgrant.TypeGuardExemption, RuleID: "R-171", ExpiresAtNs: time.Now().Add(time.Hour).UnixNano()}, Honoured: true,
	}}}, true, nil
}

func (f *fakeRequests) QueuedAccessRequests(context.Context) ([]store.OutboxRequest, error) {
	return []store.OutboxRequest{}, nil
}

func (f *fakeRequests) CancelQueuedAccessRequest(context.Context, int64) (bool, error) {
	return true, nil
}

func (f *fakeRequests) RequestContextShipsRaw(context.Context) bool { return false }

// AlreadyGranted answers from f.held, the grants in force on the fake node.
func (f *fakeRequests) AlreadyGranted(_ context.Context, n accessgrant.Normalized) (accessgrant.Held, bool) {
	return accessgrant.CoveredBy(accessgrant.AskFromRequest(n, time.Now()), f.held)
}

func (f *fakeRequests) RequestableBudgets() []orgclient.RequestableBudget {
	return []orgclient.RequestableBudget{{BudgetID: "b-u1", Scope: "member:u1", Period: "calendar_month", CapTokens: 1_000_000}}
}

func doRequests(t *testing.T, s *Server, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, armLocalWrite(r))
	return rr
}

func TestRequestsPageSoloNodeSaysEnrolFirst(t *testing.T) {
	s, _ := newTestServer(t)
	rr := doRequests(t, s, http.MethodGet, "/api/requests", "")
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"available":false`) {
		t.Fatalf("solo GET: %d %s", rr.Code, rr.Body)
	}
	if rr := doRequests(t, s, http.MethodPost, "/api/requests", `{"request":{"message":"x"}}`); rr.Code != http.StatusConflict {
		t.Fatalf("solo POST: %d %s", rr.Code, rr.Body)
	}
}

func TestRequestsPageListsPreviewsSendsAndQueues(t *testing.T) {
	s, _ := newTestServer(t)
	fake := &fakeRequests{enrolled: true}
	s.opts.Requests = fake

	rr := doRequests(t, s, http.MethodGet, "/api/requests", "")
	var page requestsPageResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if !page.Enrolled || len(page.Requests) != 1 || len(page.Grants.Grants) != 1 || len(page.Types) == 0 {
		t.Fatalf("page: %+v", page)
	}
	// The budget picker's options come from the node's budget rail.
	if len(page.Budgets) != 1 || page.Budgets[0].BudgetID != "b-u1" {
		t.Fatalf("budgets: %+v", page.Budgets)
	}

	body := `{"request":{"request_type":"guard_exemption","message":"deploy needs curl","payload":{"rule_id":"R-171","breadth":"rule"},
		"context":{"rule_id":"R-171","target_excerpt":"curl -T x"},"requested_duration_s":3600},"opt_in_excerpt":false}`
	rr = doRequests(t, s, http.MethodPost, "/api/requests/preview", body)
	var pv requestPreview
	if err := json.Unmarshal(rr.Body.Bytes(), &pv); err != nil || rr.Code != http.StatusOK {
		t.Fatalf("preview: %d %s", rr.Code, rr.Body)
	}
	if strings.Contains(pv.JSON, "curl -T") || len(pv.Problems) != 0 {
		t.Fatalf("preview leaked the excerpt without opt-in or has problems: %s %+v", pv.JSON, pv.Problems)
	}

	if rr := doRequests(t, s, http.MethodPost, "/api/requests", body); rr.Code != http.StatusCreated || len(fake.sent) != 1 {
		t.Fatalf("send: %d %s", rr.Code, rr.Body)
	}
	if fake.sent[0].Context.TargetExcerpt != "" {
		t.Fatal("the sent request differs from the preview: excerpt shipped without opt-in")
	}

	// A request the local pre-check refuses never leaves the machine.
	bad := `{"request":{"request_type":"guard_exemption","message":"x","payload":{"breadth":"rule"}}}`
	if rr := doRequests(t, s, http.MethodPost, "/api/requests", bad); rr.Code != http.StatusBadRequest || len(fake.sent) != 1 {
		t.Fatalf("invalid: %d %s", rr.Code, rr.Body)
	}

	fake.offline = true
	if rr := doRequests(t, s, http.MethodPost, "/api/requests", body); rr.Code != http.StatusAccepted || len(fake.queued) != 1 {
		t.Fatalf("offline: %d %s", rr.Code, rr.Body)
	}
	rr = doRequests(t, s, http.MethodGet, "/api/requests", "")
	if !strings.Contains(rr.Body.String(), "could not be reached") {
		t.Fatalf("offline list: %s", rr.Body)
	}

	if rr := doRequests(t, s, http.MethodPost, "/api/requests/4/withdraw", ""); rr.Code != http.StatusNoContent {
		t.Fatalf("withdraw: %d", rr.Code)
	}
	if rr := doRequests(t, s, http.MethodPost, "/api/requests/77/withdraw", ""); rr.Code != http.StatusConflict {
		t.Fatalf("withdraw closed: %d", rr.Code)
	}
}

// TestRequestsAlreadyGrantedIsNotSent pins the node half of the 2026-11-13
// operator report (the same rule requested and granted three times): a
// request a grant in force on this machine already covers is shown as such
// in the preview and never leaves the machine; a request the grant does not
// cover still goes.
func TestRequestsAlreadyGrantedIsNotSent(t *testing.T) {
	const body = `{"request":{"request_type":"guard_exemption","message":"again","payload":%s,"requested_duration_s":2592000}}`
	held := []accessgrant.Held{{
		ID: 11, Type: accessgrant.TypeGuardExemption, Effect: orgcontract.AccessGrantEffectExempt,
		SubjectKind: orgcontract.AccessGrantSubjectMember, RuleID: "S-793", ProjectRootHash: "p1",
	}}
	cases := []struct {
		name    string
		payload string
		covered bool
	}{
		{"the same rule and project again", `{"rule_id":"S-793","project_root_hash":"p1","breadth":"rule"}`, true},
		{"one exact command under the rule-wide grant", `{"rule_id":"S-793","project_root_hash":"p1","operand_hash":"op","command_class":"/shell_exec","breadth":"exact"}`, true},
		{"another project", `{"rule_id":"S-793","project_root_hash":"p2","breadth":"rule"}`, false},
		{"another rule", `{"rule_id":"S-794","project_root_hash":"p1","breadth":"rule"}`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, _ := newTestServer(t)
			fake := &fakeRequests{enrolled: true, held: held}
			s.opts.Requests = fake
			req := fmt.Sprintf(body, c.payload)
			rr := doRequests(t, s, http.MethodPost, "/api/requests/preview", req)
			var pv requestPreview
			if err := json.Unmarshal(rr.Body.Bytes(), &pv); err != nil || rr.Code != http.StatusOK {
				t.Fatalf("preview: %d %s", rr.Code, rr.Body)
			}
			named := len(pv.Problems) == 1 && pv.Problems[0].Code == accessgrant.CodeAlreadyGranted && strings.Contains(pv.Problems[0].Message, "G-11")
			if named != c.covered || (!c.covered && len(pv.Problems) != 0) {
				t.Fatalf("preview problems = %+v, want covered=%v", pv.Problems, c.covered)
			}
			rr = doRequests(t, s, http.MethodPost, "/api/requests", req)
			wantCode, wantSent := http.StatusCreated, 1
			if c.covered {
				wantCode, wantSent = http.StatusBadRequest, 0
			}
			if rr.Code != wantCode || len(fake.sent) != wantSent {
				t.Fatalf("send: %d (sent %d) %s", rr.Code, len(fake.sent), rr.Body)
			}
			if c.covered && !strings.Contains(rr.Body.String(), "G-11 already covers this") {
				t.Fatalf("the refusal does not name the grant: %s", rr.Body)
			}
		})
	}
}
