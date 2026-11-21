package store

import (
	"context"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

func TestCloudConnectorAccounts(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	base := CloudConnectorAccount{Connector: "cursor-cloud", Provider: "cursor", AccountID: "acct-1", DisplayEmail: "dev@example.com"}
	cases := []struct {
		name    string
		in      CloudConnectorAccount
		wantErr bool
	}{
		{"valid", base, false},
		{"connector not a token", CloudConnectorAccount{Connector: "Cursor Cloud", Provider: "cursor", AccountID: "a"}, true},
		{"missing account id", CloudConnectorAccount{Connector: "devin", Provider: "cognition"}, true},
		{"error class carrying prose", CloudConnectorAccount{Connector: "devin", Provider: "cognition", AccountID: "a", LastErrorClass: "HTTP 500: upstream said no"}, true},
		{"coverage not a token", CloudConnectorAccount{Connector: "devin", Provider: "cognition", AccountID: "a", CoverageState: "Partial history"}, true},
	}
	for _, c := range cases {
		_, err := s.UpsertCloudConnectorAccount(ctx, c.in)
		if (err != nil) != c.wantErr {
			t.Errorf("%s: err = %v, wantErr %v", c.name, err, c.wantErr)
		}
	}

	id1, _ := s.UpsertCloudConnectorAccount(ctx, base)
	relinked := base
	relinked.DisplayEmail = "renamed@example.com"
	relinked.CoverageState = "verified"
	id2, err := s.UpsertCloudConnectorAccount(ctx, relinked)
	if err != nil || id2 != id1 {
		t.Fatalf("re-link: id %d err %v, want the same row %d", id2, err, id1)
	}
	other, err := s.UpsertCloudConnectorAccount(ctx, CloudConnectorAccount{Connector: "devin", Provider: "cognition", Issuer: "org-7", AccountID: "acct-1"})
	if err != nil || other == id1 {
		t.Fatalf("second account: id %d err %v", other, err)
	}
	if ok, err := s.SetCloudConnectorAccountState(ctx, id1, "partial_history", "rate_limited"); err != nil || !ok {
		t.Fatalf("SetCloudConnectorAccountState: ok %v err %v", ok, err)
	}
	if _, err := s.SetCloudConnectorAccountState(ctx, id1, "verified", "boom: details"); err == nil {
		t.Fatal("SetCloudConnectorAccountState: prose error class accepted")
	}

	all, err := s.ListCloudConnectorAccounts(ctx, "")
	if err != nil || len(all) != 2 {
		t.Fatalf("list all: %d rows err %v", len(all), err)
	}
	cursor, err := s.ListCloudConnectorAccounts(ctx, "cursor-cloud")
	if err != nil || len(cursor) != 1 {
		t.Fatalf("list cursor-cloud: %d rows err %v", len(cursor), err)
	}
	got := cursor[0]
	if got.DisplayEmail != "renamed@example.com" || got.CoverageState != "partial_history" || got.LastErrorClass != "rate_limited" || got.CreatedAt.IsZero() {
		t.Errorf("stored account = %+v", got)
	}
}

// TestCloudSyncCheckpointsAndPage covers the checkpoint round trip, the
// page-plus-checkpoint transaction (idempotent re-land, rollback on a bad
// entry), and the unlink rule (checkpoints cascade, ledger history stays).
func TestCloudSyncCheckpointsAndPage(t *testing.T) {
	t.Parallel()
	s, database := newTestStore(t)
	ctx := context.Background()
	acct, err := s.UpsertCloudConnectorAccount(ctx, CloudConnectorAccount{Connector: "openhands-cloud", Provider: "openhands", AccountID: "u-1"})
	if err != nil {
		t.Fatal(err)
	}

	if _, ok, err := s.LoadCloudSyncCheckpoint(ctx, acct, models.SyncStreamDiscovery, ""); err != nil || ok {
		t.Fatalf("fresh checkpoint: ok %v err %v", ok, err)
	}
	gapFrom := time.Date(2026, 10, 30, 22, 0, 0, 0, time.UTC)
	cp := CloudSyncCheckpoint{
		AccountPK: acct, Stream: models.SyncStreamLive, Scope: "conv-1", Cursor: "evt-42", OverlapSeconds: 300,
		LastSuccessAt: time.Date(2026, 10, 31, 8, 0, 0, 0, time.UTC),
		Gaps:          []CloudSyncGap{{From: gapFrom, To: gapFrom.Add(2 * time.Hour)}},
	}
	if err := s.SaveCloudSyncCheckpoint(ctx, cp); err != nil {
		t.Fatal(err)
	}
	got, ok, err := s.LoadCloudSyncCheckpoint(ctx, acct, models.SyncStreamLive, "conv-1")
	if err != nil || !ok {
		t.Fatalf("load: ok %v err %v", ok, err)
	}
	if got.Cursor != "evt-42" || got.OverlapSeconds != 300 || !got.LastSuccessAt.Equal(cp.LastSuccessAt) ||
		!got.LastAttemptAt.IsZero() || len(got.Gaps) != 1 || !got.Gaps[0].From.Equal(gapFrom) {
		t.Fatalf("checkpoint round trip = %+v", got)
	}

	badCP := []struct {
		name string
		cp   CloudSyncCheckpoint
	}{
		{"unknown stream", CloudSyncCheckpoint{AccountPK: acct, Stream: "firehose"}},
		{"no account", CloudSyncCheckpoint{Stream: models.SyncStreamUsage}},
		{"negative overlap", CloudSyncCheckpoint{AccountPK: acct, Stream: models.SyncStreamUsage, OverlapSeconds: -1}},
		{"inverted gap", CloudSyncCheckpoint{AccountPK: acct, Stream: models.SyncStreamUsage, Gaps: []CloudSyncGap{{From: gapFrom, To: gapFrom.Add(-time.Minute)}}}},
	}
	for _, c := range badCP {
		if err := s.SaveCloudSyncCheckpoint(ctx, c.cp); err == nil {
			t.Errorf("%s: accepted", c.name)
		}
	}

	reported := time.Date(2026, 10, 31, 9, 0, 0, 0, time.UTC)
	yes := true
	entry := func(rec string, v float64) CloudUsageEntry {
		return CloudUsageEntry{
			Connector: "openhands-cloud", SourceRecordID: rec,
			MeasurementSource: models.UsageSourceProviderRunTotal, ValueType: models.UsageValueInterval,
			Unit: "usd", Value: v, MonetaryStatus: models.UsageMonetaryReported,
			ScopeSession: "conv-1", IncludesChildren: &yes, ReportedAt: reported,
		}
	}
	discovery := CloudSyncCheckpoint{AccountPK: acct, Stream: models.SyncStreamUsage, Cursor: "page-2"}
	added, err := s.CommitCloudSyncPage(ctx, []CloudUsageEntry{entry("r1", 1.25), entry("r2", 0.5)}, discovery)
	if err != nil || added != 2 {
		t.Fatalf("first page: added %d err %v", added, err)
	}
	// The same page again (a retry after a crash before the response): no
	// duplicate rows.
	added, err = s.CommitCloudSyncPage(ctx, []CloudUsageEntry{entry("r1", 1.25), entry("r2", 0.5)}, discovery)
	if err != nil || added != 0 {
		t.Fatalf("re-landed page: added %d err %v, want 0", added, err)
	}
	// A page with one bad entry rolls back entirely, checkpoint included.
	bad := entry("r4", 1)
	bad.Unit = "US Dollars"
	if _, err := s.CommitCloudSyncPage(ctx, []CloudUsageEntry{entry("r3", 2), bad},
		CloudSyncCheckpoint{AccountPK: acct, Stream: models.SyncStreamUsage, Cursor: "page-3"}); err == nil {
		t.Fatal("bad page committed")
	}
	cpNow, _, _ := s.LoadCloudSyncCheckpoint(ctx, acct, models.SyncStreamUsage, "")
	if cpNow.Cursor != "page-2" {
		t.Errorf("checkpoint after a failed page = %q, want page-2 (no advance)", cpNow.Cursor)
	}

	rows, err := s.ListCloudUsage(ctx, CloudUsageFilter{ScopeSession: "conv-1"})
	if err != nil || len(rows) != 2 {
		t.Fatalf("ListCloudUsage: %d rows err %v, want 2 (r3 rolled back)", len(rows), err)
	}
	if rows[0].IncludesChildren == nil || !*rows[0].IncludesChildren || rows[0].ObservedAt.IsZero() || !rows[0].ReportedAt.Equal(reported) {
		t.Errorf("ledger row = %+v", rows[0])
	}

	// Unlink: checkpoints go, ledger history stays.
	if ok, err := s.DeleteCloudConnectorAccount(ctx, acct); err != nil || !ok {
		t.Fatalf("delete: ok %v err %v", ok, err)
	}
	var cps, ledger int
	if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM cloud_sync_checkpoints`).Scan(&cps); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM cloud_usage_ledger`).Scan(&ledger); err != nil {
		t.Fatal(err)
	}
	if cps != 0 || ledger != 2 {
		t.Errorf("after unlink: %d checkpoints, %d ledger rows; want 0 and 2", cps, ledger)
	}
}

func TestInsertCloudUsageValidation(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	ok := CloudUsageEntry{
		Connector: "devin", MeasurementSource: models.UsageSourceProviderRunTotal,
		ValueType: models.UsageValueCumulative, Unit: "acu", Value: 3.5, MonetaryStatus: models.UsageMonetaryNone,
		ReportedAt: time.Date(2026, 10, 31, 9, 0, 0, 0, time.UTC),
	}
	mut := func(f func(*CloudUsageEntry)) CloudUsageEntry { e := ok; f(&e); return e }
	cases := []struct {
		name    string
		in      CloudUsageEntry
		wantErr bool
	}{
		{"valid", ok, false},
		{"unknown source", mut(func(e *CloudUsageEntry) { e.MeasurementSource = "guess" }), true},
		{"unknown value type", mut(func(e *CloudUsageEntry) { e.ValueType = "sum" }), true},
		{"unknown monetary status", mut(func(e *CloudUsageEntry) { e.MonetaryStatus = "cash" }), true},
		{"unit not a token", mut(func(e *CloudUsageEntry) { e.Unit = "" }), true},
		{"missing reported_at", mut(func(e *CloudUsageEntry) { e.ReportedAt = time.Time{} }), true},
		{"inverted interval", mut(func(e *CloudUsageEntry) {
			e.IntervalStart = e.ReportedAt
			e.IntervalEnd = e.ReportedAt.Add(-time.Hour)
		}), true},
	}
	for _, c := range cases {
		_, _, err := s.InsertCloudUsage(ctx, c.in)
		if (err != nil) != c.wantErr {
			t.Errorf("%s: err = %v, wantErr %v", c.name, err, c.wantErr)
		}
	}
	// No record id: each insert is a new row (no idempotency key to dedupe on).
	id1, ins1, _ := s.InsertCloudUsage(ctx, ok)
	id2, ins2, _ := s.InsertCloudUsage(ctx, ok)
	if !ins1 || !ins2 || id1 == id2 {
		t.Errorf("record-id-less inserts: (%d,%v) (%d,%v), want two new rows", id1, ins1, id2, ins2)
	}
	// Supersedes points at an existing row.
	adj := mut(func(e *CloudUsageEntry) { e.SourceRecordID = "adj-1"; e.SupersedesID = id1 })
	id3, ins3, err := s.InsertCloudUsage(ctx, adj)
	if err != nil || !ins3 {
		t.Fatalf("supersede insert: %v", err)
	}
	again, ins4, err := s.InsertCloudUsage(ctx, adj)
	if err != nil || ins4 || again != id3 {
		t.Fatalf("re-insert by record id: (%d,%v,%v), want existing %d", again, ins4, err, id3)
	}
}

// TestCloudVocabulariesMatchMigrationChecks pins the Go vocabularies in
// internal/models to the CHECK constraints of agent migration 241: every
// member lands through a raw INSERT, and a non-member is refused by the
// database itself, so the two copies cannot drift silently.
func TestCloudVocabulariesMatchMigrationChecks(t *testing.T) {
	t.Parallel()
	_, database := newTestStore(t)
	ctx := context.Background()
	if _, err := database.ExecContext(ctx,
		`INSERT INTO cloud_connector_accounts (id, connector, provider, account_id, created_at, updated_at)
		 VALUES (1, 'c', 'p', 'a', 'now', 'now')`); err != nil {
		t.Fatal(err)
	}
	ledgerInsert := func(col, v string) error {
		vals := map[string]string{"measurement_source": "exporter", "value_type": "delta", "monetary_status": "not_monetary"}
		vals[col] = v
		_, err := database.ExecContext(ctx,
			`INSERT INTO cloud_usage_ledger (connector, measurement_source, value_type, unit, value, monetary_status, reported_at, observed_at)
			 VALUES ('c', ?, ?, 'u', 1, ?, 'now', 'now')`, vals["measurement_source"], vals["value_type"], vals["monetary_status"])
		return err
	}
	cases := []struct {
		name   string
		vocab  []string
		insert func(v string) error
	}{
		{"measurement_source", models.UsageSources(), func(v string) error { return ledgerInsert("measurement_source", v) }},
		{"value_type", models.UsageValueTypes(), func(v string) error { return ledgerInsert("value_type", v) }},
		{"monetary_status", models.UsageMonetaryStatuses(), func(v string) error { return ledgerInsert("monetary_status", v) }},
		{"stream", models.SyncStreams(), func(v string) error {
			_, err := database.ExecContext(ctx,
				`INSERT INTO cloud_sync_checkpoints (account_pk, stream, scope, updated_at) VALUES (1, ?, ?, 'now')`, v, v)
			return err
		}},
	}
	for _, c := range cases {
		for _, v := range c.vocab {
			if err := c.insert(v); err != nil {
				t.Errorf("%s: vocabulary member %q refused by the migration CHECK: %v", c.name, v, err)
			}
		}
		if err := c.insert("not-in-vocabulary"); err == nil {
			t.Errorf("%s: the migration CHECK accepts a value the vocabulary does not list", c.name)
		}
	}
}

func TestParseCloudTime(t *testing.T) {
	ts := time.Date(2026, 10, 31, 1, 2, 3, 4, time.UTC)
	cases := []struct {
		in   string
		want time.Time
	}{
		{"", time.Time{}},
		{"garbage", time.Time{}},
		{optionalCloudTime(ts), ts},
	}
	for _, c := range cases {
		if got := parseCloudTime(c.in); !got.Equal(c.want) {
			t.Errorf("parseCloudTime(%q) = %v, want %v", c.in, got, c.want)
		}
	}
	if optionalCloudTime(time.Time{}) != "" {
		t.Error("optionalCloudTime(zero) should be empty")
	}
}

func TestListAndDeleteCloudSyncCheckpoints(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestStore(t)
	id, err := s.UpsertCloudConnectorAccount(ctx, CloudConnectorAccount{Connector: "copilot-agent", Provider: "github", AccountID: "42"})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := s.ListCloudSyncCheckpoints(ctx, id, models.SyncStreamSessionHistory); err != nil || len(got) != 0 {
		t.Fatalf("empty list: %v %v", got, err)
	}
	for _, scope := range []string{"b-session", "a-session"} {
		if err := s.SaveCloudSyncCheckpoint(ctx, CloudSyncCheckpoint{AccountPK: id, Stream: models.SyncStreamSessionHistory, Scope: scope, Cursor: "running"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.SaveCloudSyncCheckpoint(ctx, CloudSyncCheckpoint{AccountPK: id, Stream: models.SyncStreamDiscovery, Cursor: "2026-10-31T00:00:00Z"}); err != nil {
		t.Fatal(err)
	}
	got, err := s.ListCloudSyncCheckpoints(ctx, id, models.SyncStreamSessionHistory)
	if err != nil || len(got) != 2 || got[0].Scope != "a-session" || got[1].Scope != "b-session" || got[0].Cursor != "running" {
		t.Fatalf("list: %+v %v", got, err)
	}
	if ok, err := s.DeleteCloudSyncCheckpoint(ctx, id, models.SyncStreamSessionHistory, "a-session"); err != nil || !ok {
		t.Fatalf("delete: %v %v", ok, err)
	}
	if ok, _ := s.DeleteCloudSyncCheckpoint(ctx, id, models.SyncStreamSessionHistory, "a-session"); ok {
		t.Error("second delete reported a row")
	}
	got, _ = s.ListCloudSyncCheckpoints(ctx, id, models.SyncStreamSessionHistory)
	if len(got) != 1 || got[0].Scope != "b-session" {
		t.Fatalf("after delete: %+v", got)
	}
	if _, ok, _ := s.LoadCloudSyncCheckpoint(ctx, id, models.SyncStreamDiscovery, ""); !ok {
		t.Error("deleting a session scope touched the discovery checkpoint")
	}
}

// TestCloudConnectorVendorUser: the chosen vendor user survives a re-link
// (Upsert never touches it); the purge marker applies only to the user still
// chosen.
func TestCloudConnectorVendorUser(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	acct := CloudConnectorAccount{Connector: "devin", Provider: "cognition", Issuer: "devin.ai", AccountID: "org-1"}
	id, err := s.UpsertCloudConnectorAccount(ctx, acct)
	if err != nil {
		t.Fatal(err)
	}
	get := func() CloudConnectorAccount {
		t.Helper()
		all, err := s.ListCloudConnectorAccounts(ctx, "devin")
		if err != nil || len(all) != 1 {
			t.Fatalf("list: %v %d", err, len(all))
		}
		return all[0]
	}
	if a := get(); a.VendorUserID != "" || a.VendorUserPurged != "" {
		t.Fatalf("new account = %+v", a)
	}
	for _, bad := range []string{"", "user a", "user-1\n", string(make([]byte, 200))} {
		if _, err := s.SetCloudConnectorVendorUser(ctx, id, bad); err == nil {
			t.Errorf("accepted vendor user %q", bad)
		}
	}
	if ok, err := s.SetCloudConnectorVendorUser(ctx, id, "user-a"); err != nil || !ok {
		t.Fatalf("set: %v %v", ok, err)
	}
	if ok, _ := s.SetCloudConnectorVendorUser(ctx, id+99, "user-a"); ok {
		t.Fatal("set on a missing account")
	}
	acct.DisplayEmail = "relinked"
	if _, err := s.UpsertCloudConnectorAccount(ctx, acct); err != nil {
		t.Fatal(err)
	}
	if a := get(); a.VendorUserID != "user-a" || a.DisplayEmail != "relinked" {
		t.Fatalf("re-link lost the choice: %+v", a)
	}
	if ok, _ := s.MarkCloudConnectorVendorUserPurged(ctx, id, "user-b"); ok {
		t.Fatal("marked a user that is not the chosen one")
	}
	if ok, err := s.MarkCloudConnectorVendorUserPurged(ctx, id, "user-a"); err != nil || !ok {
		t.Fatalf("mark: %v %v", ok, err)
	}
	if a := get(); a.VendorUserPurged != "user-a" {
		t.Fatalf("purged = %q", a.VendorUserPurged)
	}
	if _, err := s.SetCloudConnectorVendorUser(ctx, id, "user-b"); err != nil {
		t.Fatal(err)
	}
	if a := get(); a.VendorUserID != "user-b" || a.VendorUserPurged != "user-a" {
		t.Fatalf("a changed choice must leave its removal owed: %+v", a)
	}
}

// TestDeleteSessionlessCloudUsage (CA-T8): only the named connector's rows
// scoped to a named id that is NOT a session go; a landed session's rows,
// another connector's rows and unnamed scopes stay.
func TestDeleteSessionlessCloudUsage(t *testing.T) {
	t.Parallel()
	s, database := newTestStore(t)
	ctx := context.Background()
	at := time.Date(2026, 10, 30, 9, 0, 0, 0, time.UTC)
	if _, err := database.ExecContext(ctx, `INSERT INTO projects (root_path, name, created_at) VALUES ('/p', 'p', ?)`, timestamp(at)); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `INSERT INTO sessions (id, project_id, tool, started_at) VALUES ('landed', 1, 'claude-code', ?)`, timestamp(at)); err != nil {
		t.Fatal(err)
	}
	add := func(connector, scope, rec string) {
		t.Helper()
		if _, _, err := s.InsertCloudUsage(ctx, CloudUsageEntry{
			Connector: connector, SourceRecordID: rec, MeasurementSource: models.UsageSourceProviderRunTotal,
			ValueType: models.UsageValueCumulative, Unit: "warp_credit", Value: 1, MonetaryStatus: models.UsageMonetaryNone,
			ScopeSession: scope, ReportedAt: at,
		}); err != nil {
			t.Fatal(err)
		}
	}
	add("warp-cloud", "oz-other", "r1")
	add("warp-cloud", "oz-other", "r2")
	add("warp-cloud", "landed", "r3")
	add("warp-cloud", "oz-unnamed", "r4")
	add("devin", "oz-other", "r5")
	add("warp-cloud", "", "r6")
	n, err := s.DeleteSessionlessCloudUsage(ctx, "warp-cloud", []string{"oz-other", "landed", ""})
	if err != nil || n != 2 {
		t.Fatalf("deleted %d %v, want 2", n, err)
	}
	left := map[string]bool{}
	rows, err := s.ListCloudUsage(ctx, CloudUsageFilter{})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range rows {
		left[e.SourceRecordID] = true
	}
	if len(left) != 4 || !left["r3"] || !left["r4"] || !left["r5"] || !left["r6"] {
		t.Fatalf("left %v", left)
	}
	for _, bad := range [][]string{nil, {}} {
		if n, err := s.DeleteSessionlessCloudUsage(ctx, "warp-cloud", bad); n != 0 || err != nil {
			t.Fatalf("empty list: %d %v", n, err)
		}
	}
	if n, err := s.DeleteSessionlessCloudUsage(ctx, "Not A Token", []string{"oz-unnamed"}); n != 0 || err != nil {
		t.Fatalf("bad connector: %d %v", n, err)
	}
}
