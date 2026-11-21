package hostclient_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/hostapi"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/hostapi/hostclient"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
	pc "github.com/marmutapp/superbased-observer/internal/platformcontract"
)

const orgC = "cccccccc-0000-4000-8000-000000000003"

// fakeHostView answers route-check and health from a per-tenant table, as
// verified answers; a tenant missing from reach answers unverified.
type fakeHostView struct {
	served map[string]pc.RouteCheckResponse
	health map[string]pc.HealthStatus
	reach  map[string]bool
}

func (f fakeHostView) answer(t *testing.T) func(hostclient.Host, hostapi.Request) hostapi.Answer {
	return func(_ hostclient.Host, r hostapi.Request) hostapi.Answer {
		var tenant string
		if r.Path == pc.PathRouteCheck {
			var q pc.RouteCheckRequest
			_ = json.Unmarshal(r.Body, &q)
			tenant = q.TenantID
		} else {
			for id := range f.served {
				if r.Path == pc.PathTenantHealth(id) {
					tenant = id
				}
			}
		}
		if !f.reach[tenant] {
			return hostapi.Answer{Kind: hostapi.AnswerUnverified, Reason: "signature", Body: []byte(`{"served":true}`)}
		}
		if r.Path == pc.PathRouteCheck {
			return answerJSON(t, f.served[tenant])
		}
		return answerJSON(t, pc.HealthResponse{
			TenantID: tenant, Status: f.health[tenant], LastPush: pc.PushRecent,
			Backlog: pc.BacklogClear, Quota: pc.QuotaOK, Error: pc.ErrNone,
		})
	}
}

func newReconciler(t *testing.T, ms *memStore, tr hostclient.Transport, page int) *hostclient.Reconciler {
	t.Helper()
	r, err := hostclient.NewReconciler(hostclient.ReconcilerConfig{
		Store: ms, Transport: tr, Hosts: directory(t, hostAt("https://10.0.0.1:8443")), Now: fixedNow, Page: page,
	})
	if err != nil {
		t.Fatalf("NewReconciler: %v", err)
	}
	return r
}

// TestReconcileEnqueuesExactlyTheMissingCorrections: a host behind its org
// gets one set_state correction; an org in sync, an unreachable host and an
// org with an intent in flight get none; repeating the pass adds nothing.
func TestReconcileEnqueuesExactlyTheMissingCorrections(t *testing.T) {
	t.Parallel()
	ms := newMemStore()
	ms.addOrg(store.OrgReconcileView{OrgID: orgA, DisplayName: "A", Status: "suspended", LifecycleGen: 3, HostID: "host-1"})
	ms.addOrg(store.OrgReconcileView{OrgID: orgB, DisplayName: "B", Status: "active", LifecycleGen: 1, HostID: "host-1"})
	ms.addOrg(store.OrgReconcileView{OrgID: orgC, DisplayName: "C", Status: "active", LifecycleGen: 1, HostID: "host-1"})
	const orgD = "dddddddd-0000-4000-8000-000000000004"
	ms.addOrg(store.OrgReconcileView{OrgID: orgD, DisplayName: "D", Status: "active", LifecycleGen: 1, HostID: "host-1"})
	inFlight := must(t)(hostapi.EvictIntent(orgD, 1))
	ms.enqueue(inFlight)
	view := fakeHostView{
		served: map[string]pc.RouteCheckResponse{
			orgA: {Served: true, State: pc.StateActive, LifecycleGen: 1},
			orgB: {Served: true, State: pc.StateActive, LifecycleGen: 1},
		},
		health: map[string]pc.HealthStatus{orgA: pc.HealthHealthy, orgB: pc.HealthDegraded},
		reach:  map[string]bool{orgA: true, orgB: true},
	}
	tr := &scripted{answer: view.answer(t)}
	rec := newReconciler(t, ms, tr, 2) // two pages and a short one

	st, err := rec.ReconcileOnce(context.Background())
	if err != nil {
		t.Fatalf("ReconcileOnce: %v", err)
	}
	if st.Orgs != 4 || st.Skipped != 1 || st.Corrections != 1 || st.WithFindings != 3 {
		t.Fatalf("stats = %+v", st)
	}
	wantKey := hostapi.KeyPrefixReconcile + "state:" + orgA + ":3:suspended"
	if row := ms.row(wantKey); row.Verb != store.OutboxSetState || row.LifecycleGen != 3 || row.state != "pending" {
		t.Fatalf("correction row = %+v", row)
	}
	assertFindings(t, ms, orgA, []string{"state_behind"})
	if f := ms.findings[orgA][0]; f.CorrectionKey != wantKey || f.HostGen == nil || *f.HostGen != 1 || f.Served == nil || !*f.Served {
		t.Fatalf("orgA finding = %+v", f)
	}
	assertFindings(t, ms, orgB, []string{"unhealthy"})
	assertFindings(t, ms, orgC, []string{"unreachable"})
	if f := ms.findings[orgC][0]; f.Served != nil || f.HostGen != nil {
		t.Fatalf("an unreachable host's finding carries an observation: %+v", f)
	}
	for _, r := range tr.requests() {
		if r.Path == pc.PathTenantHealth(orgD) {
			t.Fatal("the org with an intent in flight was probed")
		}
	}
	for _, u := range ms.applied {
		if u.OrgID == orgD {
			t.Fatal("the org with an intent in flight had its findings rewritten")
		}
	}

	// The correction is now in flight: the next pass skips orgA.
	st, err = rec.ReconcileOnce(context.Background())
	if err != nil || st.Corrections != 0 || st.Skipped != 2 {
		t.Fatalf("second pass = %+v, %v", st, err)
	}

	// The correction was acked but the host is still behind: the same
	// correction is not enqueued again (one key), the finding stays open.
	ms.mu.Lock()
	for _, r := range ms.rows {
		r.state = "acked"
	}
	ms.mu.Unlock()
	st, err = rec.ReconcileOnce(context.Background())
	if err != nil || st.Corrections != 0 {
		t.Fatalf("third pass = %+v, %v", st, err)
	}
	assertFindings(t, ms, orgA, []string{"state_behind"})
	n := 0
	for _, r := range ms.rows {
		if r.OrgID == orgA {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("orgA has %d outbox rows after three passes, want exactly 1 correction", n)
	}
}

// TestReconcileUnplacedProvisioningOrg: an org that never reached a host and
// has no create intent gets its create back (key = org id), with no probe.
func TestReconcileUnplacedProvisioningOrg(t *testing.T) {
	t.Parallel()
	ms := newMemStore()
	ms.addOrg(store.OrgReconcileView{OrgID: orgA, DisplayName: "Acme", Status: "provisioning"})
	tr := &scripted{answer: func(hostclient.Host, hostapi.Request) hostapi.Answer { return hostapi.Answer{} }}
	st, err := newReconciler(t, ms, tr, 0).ReconcileOnce(context.Background())
	if err != nil || st.Corrections != 1 {
		t.Fatalf("ReconcileOnce = %+v, %v", st, err)
	}
	if row := ms.row(orgA); row.Verb != store.OutboxCreateTenant {
		t.Fatalf("create correction = %+v", row)
	}
	if len(tr.requests()) != 0 {
		t.Fatal("an unplaced org was probed")
	}
	assertFindings(t, ms, orgA, []string{"not_served"})
}

func assertFindings(t *testing.T, ms *memStore, org string, want []string) {
	t.Helper()
	ms.mu.Lock()
	defer ms.mu.Unlock()
	var got []string
	for _, f := range ms.findings[org] {
		got = append(got, f.Kind)
	}
	if len(got) != len(want) {
		t.Fatalf("findings for %s = %v, want %v", org, got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("findings for %s = %v, want %v", org, got, want)
		}
	}
}
