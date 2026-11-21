package cloudagentssvc

import (
	"context"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudagents"
	"github.com/marmutapp/superbased-observer/internal/cloudlane"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// The Devin live check of 2026-11-01 (one organization, org-<32 hex> ids,
// 32-hex session ids, Unix-second times), replayed from the synthetic
// fixtures under testdata/cloudagents/devin.

const (
	devinOrg    = "org-7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d"
	devinParent = "5c1d2e3f4a5b6c7d8e9f0a1b2c3d4e01"
	devinChild  = "5c1d2e3f4a5b6c7d8e9f0a1b2c3d4e02"
	// devinLiveUser started both live sessions.
	devinLiveUser = "user-1f2e3d4c5b6a79880716253443526170"
)

// liveDevinAPI answers like the live organization; sessions, when set,
// replaces the list document.
func liveDevinAPI(t *testing.T, sessions *[]byte) *fakeAPI {
	api := &fakeAPI{}
	api.call = func(req cloudagents.Request) ([]byte, error) {
		u := req.URL
		switch {
		case strings.Contains(u, "/organizations/"+devinOrg+"/sessions?"):
			return *sessions, nil
		case strings.Contains(u, "/sessions/"+devinParent+"/messages?"):
			return fixture(t, "devin/messages.json"), nil
		case strings.Contains(u, "/messages?"):
			return []byte(`{"items":[],"end_cursor":null,"has_next_page":false,"total":null}`), nil
		}
		return nil, notFound(req)
	}
	return api
}

// TestDevinLiveShape pins the three live findings: a "running" session
// waiting for the user counts as waiting, not running; a child session
// whose parent_session_id is set gets that parent; and a session's ACUs,
// reported again with a later updated_at, are counted once at their latest
// value by the ledger reader (cloudlane), never added up.
func TestDevinLiveShape(t *testing.T) {
	sessions := fixture(t, "devin/sessions.json")
	api := liveDevinAPI(t, &sessions)
	clk := &clock{t: t0}
	svc, st, database, _, _ := newAPIService(t, api, clk)
	ctx := context.Background()
	_, av, err := svc.ConnectWith(ctx, cloudagents.ConnectorDevin, Credentials{Key: apiKey, Params: map[string]string{"org_id": devinOrg}})
	if err != nil || av == nil || av.AccountID != devinOrg {
		t.Fatalf("connect with an org-<32 hex> id: %+v %v", av, err)
	}
	if _, err := svc.ChooseVendorUser(ctx, av.ID, devinLiveUser); err != nil {
		t.Fatal(err)
	}
	res, err := svc.SyncAccount(ctx, av.ID)
	if err != nil || res.ErrorClass != "" || res.Tasks != 2 {
		t.Fatalf("sync: %v %+v", err, res)
	}
	// 1. waiting_for_user refines running.
	if res.OpenTasks != 1 || res.Waiting != 1 || res.Owed != 0 {
		t.Fatalf("counts: running %d, waiting %d, owed %d", res.OpenTasks, res.Waiting, res.Owed)
	}
	view, err := svc.Status(ctx)
	if err != nil || len(view.Accounts) != 1 || view.Accounts[0].OpenTasks != 1 || view.Accounts[0].Waiting != 1 {
		t.Fatalf("status view: %v %+v", err, view.Accounts)
	}
	// 3. The child's parent, from its own parent_session_id.
	var pt, src string
	if err := database.QueryRowContext(ctx, `SELECT COALESCE(parent_thread_id,''), COALESCE(thread_source,'') FROM sessions WHERE id = ?`, devinChild).Scan(&pt, &src); err != nil {
		t.Fatal(err)
	}
	if pt != devinParent || src != cloudagents.ThreadSourceSubagent {
		t.Fatalf("child lineage = %q %q", pt, src)
	}
	if err := database.QueryRowContext(ctx, `SELECT COALESCE(parent_thread_id,'') FROM sessions WHERE id = ?`, devinParent).Scan(&pt); err != nil || pt != "" {
		t.Fatalf("the parent got a parent: %q %v", pt, err)
	}
	if _, found, _ := st.LoadCloudSyncCheckpoint(ctx, av.ID, models.SyncStreamLive, childScopePrefix+devinChild); found {
		t.Fatal("an applied link is kept")
	}

	// 2. Later the parent reports more ACUs under a new updated_at: a second
	// cumulative row lands, and the reader counts the latest only.
	sessions = []byte(strings.NewReplacer(`"updated_at":1793353200,"is_archived":false,"acus_consumed":2.5`,
		`"updated_at":1793356800,"is_archived":false,"acus_consumed":4.75`).Replace(string(sessions)))
	clk.set(t0.Add(20 * time.Minute))
	if res, err := svc.SyncAccount(ctx, av.ID); err != nil || res.ErrorClass != "" {
		t.Fatalf("second sync: %v %+v", err, res)
	}
	entries, truncated, err := st.ListCloudUsageForSessions(ctx, []string{devinParent, devinChild}, 0)
	if err != nil || truncated {
		t.Fatal(err)
	}
	in := cloudlane.Input{Sessions: []cloudlane.Session{
		{ID: devinParent, Location: models.ExecutionVendorCloud}, {ID: devinChild, Location: models.ExecutionVendorCloud},
	}}
	acuRows := map[string]int{}
	for _, e := range entries {
		if e.Unit == "usd" {
			t.Errorf("an ACU became dollars: %+v", e)
		}
		if e.Unit == "acu" {
			acuRows[e.ScopeSession]++
			if e.ValueType != models.UsageValueCumulative {
				t.Errorf("acu row value type %s", e.ValueType)
			}
		}
		in.Ledger = append(in.Ledger, cloudlane.LedgerEntry{
			ID: e.ID, SupersedesID: e.SupersedesID, SessionID: e.ScopeSession, Connector: e.Connector, Unit: e.Unit,
			ValueType: e.ValueType, MeasurementSource: e.MeasurementSource, MonetaryStatus: e.MonetaryStatus,
			Value: e.Value, ReportedAt: e.ReportedAt,
		})
	}
	if acuRows[devinParent] != 2 || acuRows[devinChild] != 1 {
		t.Fatalf("acu rows per session = %v", acuRows)
	}
	var got *cloudlane.LedgerFigure
	for _, b := range cloudlane.Build(in).Buckets {
		for i := range b.Ledger {
			if b.Ledger[i].Unit == "acu" {
				got = &b.Ledger[i]
			}
		}
	}
	// The latest per session: 4.75 (parent) + 1.25 (child), not 2.5 + 4.75 + 1.25.
	if got == nil || math.Abs(got.Value-6.0) > 1e-9 || got.Rollup != cloudlane.RollupLatestPerSession || got.Sessions != 2 {
		t.Fatalf("acu figure = %+v", got)
	}
}
