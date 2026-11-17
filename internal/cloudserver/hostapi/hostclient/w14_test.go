package hostclient_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/hostapi"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/hostapi/hostclient"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
	pc "github.com/marmutapp/superbased-observer/internal/platformcontract"
)

// w14_test.go covers the wave 14 tenant-cloud additions to the client: the
// capacity_waitlist answer, the post-create hook (the launch document,
// W14-D1a) and the usage pull in the reconciler (M6.0 Q11).

// TestDispatchWaitlistedCreateStaysOpen: a signed capacity_waitlist refusal
// keeps the create open (pending), records the class the console reads as
// "waitlisted", waits at least WaitlistMinDelay, runs no post-create hook,
// and a later attempt that the host admits acks it and runs the hook.
func TestDispatchWaitlistedCreateStaysOpen(t *testing.T) {
	t.Parallel()
	ms := newMemStore()
	ms.addOrg(provisioning(orgA))
	ms.enqueue(must(t)(hostapi.CreateTenantIntent(orgA, "Acme")))
	admit := false
	tr := &scripted{answer: func(hostclient.Host, hostapi.Request) hostapi.Answer {
		if !admit {
			return answerJSON(t, pc.ErrorResponse{Code: pc.CodeCapacityWaitlist})
		}
		return answerJSON(t, pc.CreateTenantResponse{TenantID: orgA, Outcome: pc.CreateReady, State: pc.StateActive, LifecycleGen: 1})
	}}
	var hooked []string
	d, err := hostclient.NewDispatcher(hostclient.DispatcherConfig{
		Store: ms, Transport: tr, Hosts: directory(t, hostAt("https://10.0.0.1:8443")),
		Resolver: resolver{}, Now: fixedNow, Jitter: zeroJitter,
		AfterCreate: func(_ context.Context, org string) error { hooked = append(hooked, org); return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if st, err := d.DispatchOnce(context.Background()); err != nil || st.Retried != 1 || st.Parked != 0 {
		t.Fatalf("waitlisted pass = %+v, %v", st, err)
	}
	row := ms.row(orgA)
	if row.state != "pending" || row.errClass != "refused:"+string(pc.CodeCapacityWaitlist) {
		t.Fatalf("waitlisted row = %+v", row)
	}
	if got := row.nextAt.Sub(testNow); got < hostapi.WaitlistMinDelay {
		t.Fatalf("waitlisted row is due again after %s, want at least %s", got, hostapi.WaitlistMinDelay)
	}
	if len(hooked) != 0 || ms.orgs[orgA].Status != "provisioning" {
		t.Fatalf("a waitlisted create ran the hook (%v) or moved the org (%+v)", hooked, ms.orgs[orgA])
	}
	admit = true
	ms.due(orgA)
	if st, err := d.DispatchOnce(context.Background()); err != nil || st.Acked != 1 {
		t.Fatalf("admitted pass = %+v, %v", st, err)
	}
	if len(hooked) != 1 || hooked[0] != orgA || ms.orgs[orgA].Status != "active" {
		t.Fatalf("after the admit: hooked %v, org %+v", hooked, ms.orgs[orgA])
	}
}

// TestDispatchAfterCreateOnlyForCreates: the hook runs for an acked create
// only (not for another verb's ack), and its failure is reported without
// undoing the ack.
func TestDispatchAfterCreateOnlyForCreates(t *testing.T) {
	t.Parallel()
	ms := newMemStore()
	ms.addOrg(provisioning(orgA))
	ms.addOrg(store.OrgReconcileView{OrgID: orgB, Status: "active", HostID: "host-1"})
	ms.enqueue(must(t)(hostapi.CreateTenantIntent(orgA, "Acme")))
	ms.enqueue(must(t)(hostapi.EvictIntent(orgB, 3)))
	tr := &scripted{answer: func(_ hostclient.Host, r hostapi.Request) hostapi.Answer {
		if r.Path == pc.PathTenants {
			return answerJSON(t, pc.CreateTenantResponse{TenantID: orgA, Outcome: pc.CreateReady, State: pc.StateActive, LifecycleGen: 1})
		}
		return answerJSON(t, pc.EvictResponse{Evicted: true})
	}}
	var mu sync.Mutex
	var hooked []string
	d, err := hostclient.NewDispatcher(hostclient.DispatcherConfig{
		Store: ms, Transport: tr, Hosts: directory(t, hostAt("https://10.0.0.1:8443")),
		Resolver: resolver{}, Now: fixedNow, Jitter: zeroJitter,
		AfterCreate: func(_ context.Context, org string) error {
			mu.Lock()
			defer mu.Unlock()
			hooked = append(hooked, org)
			return errBoom
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	st, err := d.DispatchOnce(context.Background())
	if !errors.Is(err, errBoom) || st.Acked != 2 {
		t.Fatalf("pass = %+v, %v; want both acked and the hook's error reported", st, err)
	}
	if len(hooked) != 1 || hooked[0] != orgA {
		t.Fatalf("hook ran for %v, want only the create's org", hooked)
	}
	if ms.row(orgA).state != "acked" {
		t.Fatalf("a failing hook undid the ack: %+v", ms.row(orgA))
	}
}

// memUsage is the UsageStore fake.
type memUsage struct {
	mu   sync.Mutex
	rows map[string]pc.TenantUsage // org|day -> usage
	dig  map[string]string
	err  error
}

func (m *memUsage) RecordOrgUsageDay(_ context.Context, org, day string, u pc.TenantUsage, digest string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	m.rows[org+"|"+day] = u
	m.dig[org+"|"+day] = digest
	return nil
}

// TestReconcilePullsUsage: each host that serves an org is asked for each
// receipt day; only verified answers for that day are read; an entry is
// stored only for an org placed on the host that reported it, once; an
// unanswered host is counted, not an error.
func TestReconcilePullsUsage(t *testing.T) {
	t.Parallel()
	const orgC = "cccccccc-0000-4000-8000-000000000003"
	ms := newMemStore()
	ms.addOrg(store.OrgReconcileView{OrgID: orgA, Status: "active", HostID: "host-1"})
	ms.addOrg(store.OrgReconcileView{OrgID: orgB, Status: "active", HostID: "host-2"})
	ms.addOrg(provisioning(orgC)) // unplaced: no host is asked for it
	days := hostapi.UsageDays(testNow, 0)
	bodies := map[string][]byte{}
	tr := &scripted{answer: func(h hostclient.Host, r hostapi.Request) hostapi.Answer {
		switch r.Path {
		case pc.PathRouteCheck:
			var rc pc.RouteCheckRequest
			_ = json.Unmarshal(r.Body, &rc)
			return answerJSON(t, pc.RouteCheckResponse{Served: true, State: pc.StateActive})
		case pc.PathUsage:
		default:
			return answerJSON(t, pc.HealthResponse{
				TenantID: orgA, Status: pc.HealthHealthy, LastPush: pc.PushRecent,
				Backlog: pc.BacklogClear, Quota: pc.QuotaOK, Error: pc.ErrNone,
			})
		}
		day := r.RawQuery[len("day="):]
		if h.ID == "host-2" {
			return hostapi.Answer{Kind: hostapi.AnswerUnverified, Reason: "unsigned:unavailable"}
		}
		resp := pc.UsageResponse{Day: day, Tenants: []pc.TenantUsage{
			{TenantID: orgA, ActiveSeatMemberIDs: []string{"m1", "m2"}, Sessions: 4, Members: 3},
			{TenantID: orgA, ActiveSeatMemberIDs: []string{"forged"}, Sessions: 99}, // duplicate: dropped
			{TenantID: orgB, ActiveSeatMemberIDs: []string{"x"}, Sessions: 1},       // host-2's tenant: dropped
			{TenantID: "a/b"}, // malformed: dropped
		}}
		b, _ := json.Marshal(resp)
		bodies[day] = b
		return hostapi.Answer{Kind: hostapi.AnswerVerified, Body: b}
	}}
	hosts := directory(t, hostAt("https://10.0.0.1:8443"), hostclient.Host{ID: "host-2", BaseURL: "https://10.0.0.2:8443", ResponseKeys: hostAt("https://10.0.0.1:8443").ResponseKeys})
	usage := &memUsage{rows: map[string]pc.TenantUsage{}, dig: map[string]string{}}
	rec, err := hostclient.NewReconciler(hostclient.ReconcilerConfig{Store: ms, Transport: tr, Hosts: hosts, Now: fixedNow, Usage: usage})
	if err != nil {
		t.Fatal(err)
	}
	st, err := rec.ReconcileOnce(context.Background())
	if err != nil {
		t.Fatalf("ReconcileOnce: %v", err)
	}
	u := st.Usage
	if u.Hosts != 2 || u.Reports != len(days) || u.Unanswered != len(days) || u.Recorded != len(days) {
		t.Fatalf("usage stats = %+v", u)
	}
	if u.Dropped[hostapi.UsageDropDuplicate] != len(days) || u.Dropped[hostapi.UsageDropNotPlaced] != len(days) || u.Dropped[hostapi.UsageDropMalformed] != len(days) {
		t.Fatalf("dropped = %+v", u.Dropped)
	}
	for _, day := range days {
		got, ok := usage.rows[orgA+"|"+day]
		if !ok || got.Sessions != 4 || len(got.ActiveSeatMemberIDs) != 2 {
			t.Fatalf("stored %s = %+v (%v)", day, got, ok)
		}
		sum := sha256.Sum256(bodies[day])
		if usage.dig[orgA+"|"+day] != hex.EncodeToString(sum[:]) {
			t.Fatalf("stored digest is not the signed body's")
		}
		if _, ok := usage.rows[orgB+"|"+day]; ok {
			t.Fatal("host-1's report billed host-2's tenant")
		}
	}

	// A store failure is an error of the pass; without a UsageStore no usage
	// verb is sent at all.
	usage.err = errBoom
	if _, err := rec.ReconcileOnce(context.Background()); !errors.Is(err, errBoom) {
		t.Fatalf("a usage store failure was not reported: %v", err)
	}
	quiet := &scripted{answer: tr.answer}
	rec2, err := hostclient.NewReconciler(hostclient.ReconcilerConfig{Store: ms, Transport: quiet, Hosts: hosts, Now: fixedNow})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rec2.ReconcileOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, r := range quiet.requests() {
		if r.Path == pc.PathUsage {
			t.Fatal("a reconciler with no UsageStore pulled usage")
		}
	}
}
