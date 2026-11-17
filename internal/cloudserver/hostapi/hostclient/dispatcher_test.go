package hostclient_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/hostapi"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/hostapi/hostclient"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
	pc "github.com/marmutapp/superbased-observer/internal/platformcontract"
)

func zeroJitter() float64 { return 0 }

func newDispatcher(t *testing.T, ms *memStore, tr hostclient.Transport, res hostclient.CreateResolver) *hostclient.Dispatcher {
	t.Helper()
	d, err := hostclient.NewDispatcher(hostclient.DispatcherConfig{
		Store: ms, Transport: tr, Hosts: directory(t, hostAt("https://10.0.0.1:8443")),
		Resolver: res, Now: fixedNow, Jitter: zeroJitter,
	})
	if err != nil {
		t.Fatalf("NewDispatcher: %v", err)
	}
	return d
}

func answerJSON(t *testing.T, v any) hostapi.Answer {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return hostapi.Answer{Kind: hostapi.AnswerVerified, Body: b}
}

func provisioning(orgID string) store.OrgReconcileView {
	return store.OrgReconcileView{OrgID: orgID, DisplayName: "Acme", Status: string(pc.StateProvisioning)}
}

// TestDispatchCreatePlacesSendsAndAdopts: an unplaced org's create is placed
// on the directory's host, sent with the owner identity resolved at send
// time, acked, and the org adopts the host's answer.
func TestDispatchCreatePlacesSendsAndAdopts(t *testing.T) {
	t.Parallel()
	ms := newMemStore()
	ms.addOrg(provisioning(orgA))
	ms.enqueue(must(t)(hostapi.CreateTenantIntent(orgA, "Acme")))
	tr := &scripted{answer: func(h hostclient.Host, r hostapi.Request) hostapi.Answer {
		if h.ID != "host-1" || r.Path != pc.PathTenants {
			return hostapi.Answer{Kind: hostapi.AnswerTransport, Reason: "wrong"}
		}
		return answerJSON(t, pc.CreateTenantResponse{TenantID: orgA, Outcome: pc.CreateReady, State: pc.StateActive, LifecycleGen: 1})
	}}
	st, err := newDispatcher(t, ms, tr, resolver{}).DispatchOnce(context.Background())
	if err != nil || st.Claimed != 1 || st.Acked != 1 {
		t.Fatalf("DispatchOnce = %+v, %v", st, err)
	}
	row := ms.row(orgA)
	if row.state != "acked" || row.hostState != "active" || row.hostGen != 1 {
		t.Fatalf("row = %+v", row)
	}
	if v := ms.orgs[orgA]; v.HostID != "host-1" || v.Status != "active" || v.LifecycleGen != 1 {
		t.Fatalf("org = %+v, want placed on host-1 and adopted active/1", v)
	}
	var req pc.CreateTenantRequest
	if err := json.Unmarshal(tr.requests()[0].Body, &req); err != nil || req.OwnerSub != "user_owner" || req.IdempotencyKey != orgA {
		t.Fatalf("create request = %+v, %v", req, err)
	}
}

// TestDispatchRetryReusesTheIdempotencyKey: a retried intent is a new
// request carrying the same idempotency key, after the backoff.
func TestDispatchRetryReusesTheIdempotencyKey(t *testing.T) {
	t.Parallel()
	ms := newMemStore()
	ms.addOrg(store.OrgReconcileView{OrgID: orgA, Status: "active", HostID: "host-1"})
	in := must(t)(hostapi.DeactivateMemberIntent(orgA, "user_x"))
	ms.enqueue(in)
	calls := 0
	tr := &scripted{answer: func(hostclient.Host, hostapi.Request) hostapi.Answer {
		calls++
		if calls == 1 {
			return hostapi.Answer{Kind: hostapi.AnswerTransport, Reason: "timeout"}
		}
		return answerJSON(t, pc.DeactivateMemberResponse{Deactivated: true})
	}}
	d := newDispatcher(t, ms, tr, resolver{})
	if st, err := d.DispatchOnce(context.Background()); err != nil || st.Retried != 1 {
		t.Fatalf("first pass = %+v, %v", st, err)
	}
	row := ms.row(in.IdempotencyKey)
	if row.state != "pending" || row.errClass != "transport:timeout" || !row.nextAt.Equal(testNow.Add(hostapi.Backoff(1, 0))) {
		t.Fatalf("after a transport failure row = %+v", row)
	}
	// Not due yet: nothing is claimed.
	if st, _ := d.DispatchOnce(context.Background()); st.Claimed != 0 {
		t.Fatalf("a backing-off row was claimed: %+v", st)
	}
	ms.due(in.IdempotencyKey)
	if st, err := d.DispatchOnce(context.Background()); err != nil || st.Acked != 1 {
		t.Fatalf("second pass = %+v, %v", st, err)
	}
	reqs := tr.requests()
	if len(reqs) != 2 {
		t.Fatalf("%d requests, want 2", len(reqs))
	}
	var a, b pc.DeactivateMemberRequest
	_ = json.Unmarshal(reqs[0].Body, &a)
	_ = json.Unmarshal(reqs[1].Body, &b)
	if a.IdempotencyKey == "" || a.IdempotencyKey != b.IdempotencyKey || a.IdempotencyKey != in.IdempotencyKey {
		t.Fatalf("idempotency keys %q then %q, want the row key %q twice", a.IdempotencyKey, b.IdempotencyKey, in.IdempotencyKey)
	}
	if ms.row(in.IdempotencyKey).Attempts != 2 {
		t.Fatalf("attempts = %d, want 2", ms.row(in.IdempotencyKey).Attempts)
	}
}

// TestDispatchOutcomes: each kind of attempt lands on the row as the retry
// table says, through the dispatcher's own failure paths (placement,
// unknown host, resolver, build) and the host's answers.
func TestDispatchOutcomes(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		org    store.OrgReconcileView
		intent func(t *testing.T) hostapi.Intent
		res    hostclient.CreateResolver
		answer hostapi.Answer
		state  string
		class  string
	}{
		{
			name: "unplaced non-create waits", org: store.OrgReconcileView{OrgID: orgA, Status: "active"},
			intent: func(t *testing.T) hostapi.Intent { return must(t)(hostapi.EvictIntent(orgA, 1)) },
			state:  "pending", class: "not_sent:unplaced",
		},
		{
			name: "unknown host", org: store.OrgReconcileView{OrgID: orgA, Status: "active", HostID: "host-9"},
			intent: func(t *testing.T) hostapi.Intent { return must(t)(hostapi.EvictIntent(orgA, 1)) },
			state:  "pending", class: "not_sent:unknown_host",
		},
		{
			name: "resolver not ready", org: provisioning(orgA), res: resolver{err: errBoom},
			intent: func(t *testing.T) hostapi.Intent { return must(t)(hostapi.CreateTenantIntent(orgA, "Acme")) },
			state:  "pending", class: "not_sent:resolve",
		},
		{
			name: "typed resolver refusal names its reason", org: provisioning(orgA),
			res:    resolver{err: fmt.Errorf("wrapped: %w", &hostclient.ResolveError{Reason: "owner_identity_unavailable"})},
			intent: func(t *testing.T) hostapi.Intent { return must(t)(hostapi.CreateTenantIntent(orgA, "Acme")) },
			state:  "pending", class: "not_sent:resolve:owner_identity_unavailable",
		},
		{
			name: "a malformed typed reason is not echoed", org: provisioning(orgA),
			res:    resolver{err: &hostclient.ResolveError{Reason: "Owner Email!"}},
			intent: func(t *testing.T) hostapi.Intent { return must(t)(hostapi.CreateTenantIntent(orgA, "Acme")) },
			state:  "pending", class: "not_sent:resolve",
		},
		{
			name: "payload for another tenant parks", org: store.OrgReconcileView{OrgID: orgA, Status: "active", HostID: "host-1"},
			intent: func(t *testing.T) hostapi.Intent {
				in := must(t)(hostapi.EvictIntent(orgA, 1))
				in.Payload = []byte(`{"tenant_id":"` + orgB + `"}`)
				return in
			},
			state: "failed", class: "bad_intent",
		},
		{
			name: "replayed retries as a new request", org: store.OrgReconcileView{OrgID: orgA, Status: "active", HostID: "host-1"},
			intent: func(t *testing.T) hostapi.Intent { return must(t)(hostapi.EvictIntent(orgA, 1)) },
			answer: answerJSON(t, pc.ErrorResponse{Code: pc.CodeReplayed}),
			state:  "pending", class: "refused:replayed",
		},
		{
			name: "unknown tenant parks", org: store.OrgReconcileView{OrgID: orgA, Status: "active", HostID: "host-1"},
			intent: func(t *testing.T) hostapi.Intent { return must(t)(hostapi.EvictIntent(orgA, 1)) },
			answer: answerJSON(t, pc.ErrorResponse{Code: pc.CodeUnknownTenant}),
			state:  "failed", class: "refused:unknown_tenant",
		},
		{
			name: "unverified success never acks", org: store.OrgReconcileView{OrgID: orgA, Status: "active", HostID: "host-1"},
			intent: func(t *testing.T) hostapi.Intent { return must(t)(hostapi.EvictIntent(orgA, 1)) },
			answer: hostapi.Answer{Kind: hostapi.AnswerUnverified, Reason: "signature", Body: []byte(`{"evicted":true}`)},
			state:  "pending", class: "unverified:signature",
		},
		{
			name: "stale state intent is a success", org: store.OrgReconcileView{OrgID: orgA, Status: "active", HostID: "host-1"},
			intent: func(t *testing.T) hostapi.Intent { return must(t)(hostapi.SetStateIntent(orgA, pc.StateSuspended, 2)) },
			answer: answerJSON(t, pc.SetStateResponse{State: pc.StateActive, LifecycleGen: 5, Applied: false}),
			state:  "acked",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ms := newMemStore()
			ms.addOrg(tc.org)
			in := tc.intent(t)
			ms.enqueue(in)
			res := tc.res
			if res == nil {
				res = resolver{}
			}
			tr := &scripted{answer: func(hostclient.Host, hostapi.Request) hostapi.Answer { return tc.answer }}
			if _, err := newDispatcher(t, ms, tr, res).DispatchOnce(context.Background()); err != nil {
				t.Fatalf("DispatchOnce: %v", err)
			}
			row := ms.row(in.IdempotencyKey)
			if row.state != tc.state || row.errClass != tc.class {
				t.Fatalf("row state %q class %q, want %q %q", row.state, row.errClass, tc.state, tc.class)
			}
			if tc.state == "pending" && !row.nextAt.After(testNow) {
				t.Fatalf("a retried row is due at %s, not after now", row.nextAt)
			}
		})
	}
}

// TestDispatchPerOrgOrder: a later intent of an org waits for the earlier
// one; another org's intent is not held up.
func TestDispatchPerOrgOrder(t *testing.T) {
	t.Parallel()
	ms := newMemStore()
	ms.addOrg(store.OrgReconcileView{OrgID: orgA, Status: "active", HostID: "host-1"})
	ms.addOrg(store.OrgReconcileView{OrgID: orgB, Status: "active", HostID: "host-1"})
	first := must(t)(hostapi.SetStateIntent(orgA, pc.StateSuspended, 2))
	second := must(t)(hostapi.EvictIntent(orgA, 2))
	other := must(t)(hostapi.EvictIntent(orgB, 1))
	ms.enqueue(first)
	ms.enqueue(second)
	ms.enqueue(other)
	tr := &scripted{answer: func(_ hostclient.Host, r hostapi.Request) hostapi.Answer {
		if r.Path == pc.PathTenantState(orgA) {
			return hostapi.Answer{Kind: hostapi.AnswerTransport, Reason: "timeout"}
		}
		return answerJSON(t, pc.EvictResponse{Evicted: true})
	}}
	st, err := newDispatcher(t, ms, tr, resolver{}).DispatchOnce(context.Background())
	if err != nil || st.Claimed != 2 {
		t.Fatalf("DispatchOnce = %+v, %v; want orgA's first intent and orgB's", st, err)
	}
	if ms.row(second.IdempotencyKey).Attempts != 0 || ms.row(other.IdempotencyKey).state != "acked" {
		t.Fatalf("second = %+v other = %+v", ms.row(second.IdempotencyKey), ms.row(other.IdempotencyKey))
	}
}

// TestDispatchLeaseLostAndRecordErrors: an outcome whose lease was taken over
// is dropped and counted; any other record failure is returned.
func TestDispatchLeaseLostAndRecordErrors(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		err      error
		wantLost int
		wantErr  bool
	}{
		{store.ErrOrgOutboxLeaseLost, 1, false},
		{errBoom, 0, true},
	} {
		ms := newMemStore()
		ms.addOrg(store.OrgReconcileView{OrgID: orgA, Status: "active", HostID: "host-1"})
		ms.enqueue(must(t)(hostapi.EvictIntent(orgA, 1)))
		ms.recordErr = tc.err
		tr := &scripted{answer: func(hostclient.Host, hostapi.Request) hostapi.Answer {
			return answerJSON(t, pc.EvictResponse{})
		}}
		st, err := newDispatcher(t, ms, tr, resolver{}).DispatchOnce(context.Background())
		if st.LeaseLost != tc.wantLost || (err != nil) != tc.wantErr || (tc.wantErr && !errors.Is(err, errBoom)) {
			t.Errorf("record error %v: stats %+v err %v", tc.err, st, err)
		}
	}
}

// TestNewDispatcherLeaseMustOutlastRequest: a lease shorter than twice the
// transport's timeout is refused, so a slow send cannot race a second worker.
func TestNewDispatcherLeaseMustOutlastRequest(t *testing.T) {
	t.Parallel()
	tlsc := newPKI(t)
	s, err := hostclient.NewSender(hostclient.SenderConfig{
		TLS: tlsConfigWith(tlsc), Signer: hostclient.Ed25519Signer("cp-1", requestKey), Timeout: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg := hostclient.DispatcherConfig{
		Store: newMemStore(), Transport: s, Hosts: directory(t, hostAt("https://10.0.0.1:8443")),
		Resolver: resolver{}, LeaseTTL: 90 * time.Second,
	}
	if _, err := hostclient.NewDispatcher(cfg); err == nil {
		t.Fatal("a 90s lease over a 60s request timeout was accepted")
	}
	cfg.LeaseTTL = 2 * time.Minute
	if _, err := hostclient.NewDispatcher(cfg); err != nil {
		t.Fatalf("a 2m lease was refused: %v", err)
	}
	if _, err := hostclient.NewDispatcher(hostclient.DispatcherConfig{}); err == nil {
		t.Fatal("an empty config was accepted")
	}
}
