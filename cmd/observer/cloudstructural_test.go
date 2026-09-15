package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/cloudevidence"
	"github.com/marmutapp/superbased-observer/internal/cloudgateway"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// cloudstructural_test.go covers the W2 node half end to end: the standing-grant
// CLI (grant / revoke / list), window capture, and the drain — including the
// case that matters most right now, a server whose /v1/structural-insights route
// has not shipped yet.

// seedCloudSessionAt inserts one PERSONAL session that started at a given
// instant, with three actions (one of them a run_command, so the verification
// coverage numerator is exercised).
func seedCloudSessionAt(t *testing.T, dbPath, sessionID string, started time.Time) {
	t.Helper()
	ctx := context.Background()
	database, err := db.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer database.Close()

	var projectID int64
	if err := database.QueryRowContext(ctx,
		`INSERT INTO projects (root_path, created_at) VALUES (?, ?) RETURNING id`,
		"/tmp/cloud-structural/"+sessionID, started.UTC().Format(time.RFC3339Nano)).
		Scan(&projectID); err != nil {
		t.Fatalf("insert project: %v", err)
	}
	if _, err := database.ExecContext(ctx,
		`INSERT INTO sessions (id, tool, project_id, model, started_at, ended_at, total_actions, authority, authority_classifier_version)
		 VALUES (?, 'claude-code', ?, 'claude-opus-4-8', ?, ?, 3, 'personal', 1)`,
		sessionID, projectID,
		started.UTC().Format(time.RFC3339Nano),
		started.Add(10*time.Minute).UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("insert session: %v", err)
	}
	for i, kind := range []string{"read", "edit", "run_command"} {
		if _, err := database.ExecContext(ctx,
			`INSERT INTO actions (session_id, project_id, timestamp, action_type, tool, success, target, source_file, source_event_id)
			 VALUES (?, ?, ?, ?, 'claude-code', 1, '/tmp/cloud-structural/main.go', 'f', ?)`,
			sessionID, projectID,
			started.Add(time.Duration(i)*time.Minute).UTC().Format(time.RFC3339Nano),
			kind, sessionID+"-"+kind); err != nil {
			t.Fatalf("insert action: %v", err)
		}
	}
}

// seedCloudStandingGrant records a live STANDING grant with a chosen creation
// time. The creation time is a test seam, not a production one: capture floors
// at the grant's day, so a grant minted "now" has no COMPLETED day at or after
// it and legitimately captures nothing until tomorrow.
func seedCloudStandingGrant(t *testing.T, st *store.Store, baseURL string, createdAt time.Time) string {
	t.Helper()
	reviewAt := createdAt.AddDate(0, cloudStandingGrantReviewMonths, 0)
	id, err := st.InsertCloudConsentReceipt(context.Background(), store.CloudConsentReceipt{
		AccountPseudonym:       "acct-test",
		Purpose:                string(cloudcontract.PurposeStructuralInsights),
		FieldClassesJSON:       cloudStandingFieldClassesJSON(cloudcontract.PurposeStructuralInsights),
		EnvelopeSchemaVersion:  cloudcontract.StructuralSnapshotSchemaVersion,
		ScrubberVersion:        cloudScrubberVersion,
		Endpoint:               baseURL + "/v1/structural-insights",
		RetentionPolicyVersion: cloudRetentionPolicyVersion,
		UploadDigest:           cloudcontract.StructuralDataDictionaryDigest(),
		DataDictionaryDigest:   cloudcontract.StructuralDataDictionaryDigest(),
		CreatedAt:              createdAt,
		GrantMode:              store.CloudGrantStanding,
		DeclaredTimezone:       "UTC",
		SourceWindowRule:       cloudStructuralSourceWindowRule,
		ReviewAt:               &reviewAt,
		ConsentGeneration:      1,
	})
	if err != nil {
		t.Fatalf("seed standing grant: %v", err)
	}
	return id
}

// TestCloudConsentGrantRecordsTheR1Binding proves `consent grant` binds every
// element of the R1 set and prints it before recording.
func TestCloudConsentGrantRecordsTheR1Binding(t *testing.T) {
	cfgPath, dbPath, _ := writeCloudTestConfig(t)

	out, err := runCloudCmd(t, "consent", "grant",
		"--config", cfgPath, "--base-url", "http://cloud.invalid",
		"--purpose", string(cloudcontract.PurposeStructuralInsights),
		"--timezone", "Europe/Berlin", "--yes")
	if err != nil {
		t.Fatalf("consent grant: %v\n%s", err, out)
	}

	// The binding screen must show the whole set before the confirmation.
	for _, want := range []string{
		"grant mode:", "standing",
		"schema version:", cloudcontract.StructuralSnapshotSchemaVersion,
		"data-dictionary digest:", cloudcontract.StructuralDataDictionaryDigest(),
		"field classes:", string(cloudcontract.FieldClassStructuralMetrics),
		"retention policy version:", cloudRetentionPolicyVersion,
		"declared timezone:", "Europe/Berlin",
		"source window rule:", cloudStructuralSourceWindowRule,
		"endpoint:", "http://cloud.invalid/v1/structural-insights",
		"review date:", "consent generation:",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the grant screen never showed %q:\n%s", want, out)
		}
	}

	st, cleanup := openCloudTestStore(t, dbPath)
	defer cleanup()
	ctx := context.Background()
	live, err := st.ListLiveCloudConsentReceipts(ctx, string(cloudcontract.PurposeStructuralInsights))
	if err != nil {
		t.Fatalf("list live: %v", err)
	}
	if len(live) != 1 {
		t.Fatalf("want 1 live standing grant, got %d", len(live))
	}
	r := live[0]
	if r.GrantMode != store.CloudGrantStanding {
		t.Errorf("grant mode = %q, want standing", r.GrantMode)
	}
	if r.DataDictionaryDigest != cloudcontract.StructuralDataDictionaryDigest() {
		t.Errorf("data-dictionary digest = %q", r.DataDictionaryDigest)
	}
	if r.UploadDigest != r.DataDictionaryDigest {
		t.Errorf("a standing receipt's upload_digest must carry the data-dictionary digest (got %q vs %q)",
			r.UploadDigest, r.DataDictionaryDigest)
	}
	if r.DeclaredTimezone != "Europe/Berlin" {
		t.Errorf("declared timezone = %q", r.DeclaredTimezone)
	}
	if r.SourceWindowRule != cloudStructuralSourceWindowRule {
		t.Errorf("source window rule = %q", r.SourceWindowRule)
	}
	if r.EnvelopeSchemaVersion != cloudcontract.StructuralSnapshotSchemaVersion {
		t.Errorf("schema version = %q", r.EnvelopeSchemaVersion)
	}
	if r.ConsentGeneration != 1 {
		t.Errorf("first grant generation = %d, want 1", r.ConsentGeneration)
	}
	if r.ReviewAt == nil {
		t.Fatal("a standing grant must carry a review date")
	}
	if months := int(r.ReviewAt.Sub(r.CreatedAt).Hours() / 24 / 30); months < 11 || months > 13 {
		t.Errorf("review date is %v after creation, want ~12 months", r.ReviewAt.Sub(r.CreatedAt))
	}
	var classes []string
	if err := json.Unmarshal([]byte(r.FieldClassesJSON), &classes); err != nil {
		t.Fatalf("field classes are not a JSON array: %v", err)
	}
	if len(classes) != 1 || classes[0] != string(cloudcontract.FieldClassStructuralMetrics) {
		t.Errorf("field classes = %v, want exactly [structural_metrics]", classes)
	}

	// A second grant is a NEW generation, never a reuse.
	if out, err := runCloudCmd(t, "consent", "grant",
		"--config", cfgPath, "--base-url", "http://cloud.invalid",
		"--purpose", string(cloudcontract.PurposeStructuralInsights), "--yes"); err != nil {
		t.Fatalf("second grant: %v\n%s", err, out)
	}
	gen, err := st.MaxCloudConsentGeneration(ctx, string(cloudcontract.PurposeStructuralInsights))
	if err != nil {
		t.Fatalf("max generation: %v", err)
	}
	if gen != 2 {
		t.Errorf("second grant generation = %d, want 2", gen)
	}
}

// TestCloudConsentGrantRefusesUngrantablePurposes proves only the structural
// purpose is standing-grantable this arc, with honest copy for the rest.
func TestCloudConsentGrantRefusesUngrantablePurposes(t *testing.T) {
	cfgPath, _, _ := writeCloudTestConfig(t)
	for _, p := range []cloudcontract.Purpose{
		cloudcontract.PurposeContextEnrichment,
		cloudcontract.PurposeResearch,
		cloudcontract.PurposeAccountDeviceOps,
	} {
		out, err := runCloudCmd(t, "consent", "grant",
			"--config", cfgPath, "--base-url", "http://cloud.invalid",
			"--purpose", string(p), "--yes")
		if err == nil {
			t.Errorf("%s: expected a refusal, got success\n%s", p, out)
			continue
		}
		if !strings.Contains(err.Error(), "cannot be granted standing consent") {
			t.Errorf("%s: refusal %q does not explain itself", p, err)
		}
	}
}

// TestCloudConsentRevokeCancelsQueuedSnapshots proves revoke both invalidates
// the grant and cancels what was already queued under it.
func TestCloudConsentRevokeCancelsQueuedSnapshots(t *testing.T) {
	f := newFakeCloudServer(t)
	cfgPath, dbPath, _ := writeCloudTestConfig(t)
	yesterday := time.Now().UTC().AddDate(0, 0, -1)
	seedCloudSessionAt(t, dbPath, "s-yesterday", yesterday.Truncate(24*time.Hour).Add(12*time.Hour))

	st, cleanup := openCloudTestStore(t, dbPath)
	ctx := context.Background()
	receiptID := seedCloudStandingGrant(t, st, f.srv.URL, time.Now().UTC().AddDate(0, 0, -3))

	grant, err := cloudTestGrant(ctx, st, receiptID)
	if err != nil {
		t.Fatalf("resolve grant: %v", err)
	}
	captured, err := cloudCaptureStructuralWindows(ctx, st, grant, time.Now())
	if err != nil {
		t.Fatalf("capture: %v", err)
	}
	if captured != 1 {
		t.Fatalf("want 1 captured window, got %d", captured)
	}
	cleanup()

	out, err := runCloudCmd(t, "consent", "revoke",
		"--config", cfgPath, "--purpose", string(cloudcontract.PurposeStructuralInsights))
	if err != nil {
		t.Fatalf("consent revoke: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Revoked 1 standing grant(s)") || !strings.Contains(out, "cancelled 1 queued item(s)") {
		t.Fatalf("revoke did not report both counts:\n%s", out)
	}

	st2, cleanup2 := openCloudTestStore(t, dbPath)
	defer cleanup2()
	items, err := st2.ListSendableStructuralOutbox(ctx)
	if err != nil {
		t.Fatalf("list structural outbox: %v", err)
	}
	if len(items) != 0 {
		t.Fatalf("revoke left %d snapshot(s) sendable", len(items))
	}
	live, err := st2.ListLiveCloudConsentReceipts(ctx, string(cloudcontract.PurposeStructuralInsights))
	if err != nil {
		t.Fatalf("list live: %v", err)
	}
	if len(live) != 0 {
		t.Fatalf("revoke left %d live grant(s)", len(live))
	}
}

// cloudTestGrant reads back a receipt as the gateway Grant projection the
// capture path takes, without going through the gateway (which would need a
// network client this test does not want).
func cloudTestGrant(ctx context.Context, st *store.Store, receiptID string) (cloudgateway.Grant, error) {
	r, ok, err := st.GetCloudConsentReceipt(ctx, receiptID)
	if err != nil || !ok {
		return cloudgateway.Grant{}, err
	}
	return cloudgateway.Grant{
		ReceiptID:        r.ID,
		Purpose:          cloudcontract.Purpose(r.Purpose),
		Standing:         r.GrantMode == store.CloudGrantStanding,
		Endpoint:         r.Endpoint,
		DeclaredTimezone: r.DeclaredTimezone,
		SourceWindowRule: r.SourceWindowRule,
		CreatedAt:        r.CreatedAt,
	}, nil
}

// TestCloudConsentListIsContentFree proves `consent list` shows the receipts and
// names, honestly, what can and cannot be granted.
func TestCloudConsentListIsContentFree(t *testing.T) {
	cfgPath, _, _ := writeCloudTestConfig(t)

	out, err := runCloudCmd(t, "consent", "list", "--config", cfgPath)
	if err != nil {
		t.Fatalf("consent list (empty): %v\n%s", err, out)
	}
	if !strings.Contains(out, "No consent receipts") {
		t.Errorf("empty list should say so plainly:\n%s", out)
	}
	if !strings.Contains(out, "not grantable —") {
		t.Errorf("empty list should still say which purposes are locked and why:\n%s", out)
	}

	if out, err := runCloudCmd(t, "consent", "grant", "--config", cfgPath,
		"--base-url", "http://cloud.invalid",
		"--purpose", string(cloudcontract.PurposeStructuralInsights), "--yes"); err != nil {
		t.Fatalf("grant: %v\n%s", err, out)
	}
	out, err = runCloudCmd(t, "consent", "list", "--config", cfgPath)
	if err != nil {
		t.Fatalf("consent list: %v\n%s", err, out)
	}
	for _, want := range []string{"RECEIPT", string(cloudcontract.PurposeStructuralInsights), "standing", "live"} {
		if !strings.Contains(out, want) {
			t.Errorf("list output missing %q:\n%s", want, out)
		}
	}
}

// TestCloudSyncCapturesAndSendsStructuralWindows is the rail's happy path
// through the real `sync` command: one completed day with activity is captured,
// serialized once, and uploaded verbatim.
func TestCloudSyncCapturesAndSendsStructuralWindows(t *testing.T) {
	f := newFakeCloudServer(t)
	cfgPath, dbPath, _ := writeCloudTestConfig(t)
	day := time.Now().UTC().AddDate(0, 0, -1).Truncate(24 * time.Hour)
	seedCloudSessionAt(t, dbPath, "s-yesterday", day.Add(9*time.Hour))

	st, cleanup := openCloudTestStore(t, dbPath)
	seedCloudStandingGrant(t, st, f.srv.URL, time.Now().UTC().AddDate(0, 0, -3))
	cleanup()

	if out, err := runCloudCmd(t, "login", "--config", cfgPath, "--base-url", f.srv.URL, "--dev-token", "wtok"); err != nil {
		t.Fatalf("login: %v\n%s", err, out)
	}
	out, err := runCloudCmd(t, "sync", "--config", cfgPath, "--base-url", f.srv.URL, "--dev-token", "wtok")
	if err != nil {
		t.Fatalf("sync: %v\n%s", err, out)
	}
	if f.structuralUploads != 1 {
		t.Fatalf("server saw %d structural uploads, want 1\n%s", f.structuralUploads, out)
	}
	if !strings.Contains(out, "1 window(s) captured, 1 sent") {
		t.Errorf("sync did not report the structural outcome:\n%s", out)
	}
	if !strings.Contains(out, "revision re-capture on late data arrives with the background service") {
		t.Errorf("sync must state the once-per-window limitation honestly:\n%s", out)
	}

	// The uploaded body must be a valid snapshot for the expected window, with a
	// digest the server can recompute from exactly these bytes.
	var snap cloudcontract.StructuralSnapshot
	if err := json.Unmarshal(f.structuralBodies[0], &snap); err != nil {
		t.Fatalf("uploaded body is not a snapshot: %v\n%s", err, f.structuralBodies[0])
	}
	if snap.Period != day.Format(cloudcontract.StructuralPeriodLayout) {
		t.Errorf("uploaded period = %q, want %q", snap.Period, day.Format(cloudcontract.StructuralPeriodLayout))
	}
	if snap.Revision != 1 || !snap.Active || snap.SessionCount != 1 || snap.ActionCount != 3 {
		t.Errorf("unexpected snapshot aggregates: %+v", snap)
	}
	if snap.DeclaredTimezone != "UTC" || snap.PeriodRuleVersion != cloudevidence.StructuralPeriodRuleV1 {
		t.Errorf("snapshot lost its rule binding: %+v", snap)
	}
	recomputed := snap.Digest
	snap.Digest = ""
	want, derr := cloudcontract.StructuralDigest(snap)
	if derr != nil {
		t.Fatalf("recompute digest: %v", derr)
	}
	if recomputed != want {
		t.Errorf("the server cannot recompute the embedded digest from the received bytes: %q != %q", recomputed, want)
	}

	// The R1 standing-grant binding rides as request HEADERS beside the body
	// (W2 server half): the server validates the upload against the account's
	// registered grant, and these three values are what it validates. They must
	// come from the RESOLVED grant, so they are checked against the receipt the
	// test seeded rather than against whatever the send path happened to send.
	h := f.structuralHeaders[0]
	if got := h.Get("SBO-Consent-Generation"); got != "1" {
		t.Errorf("SBO-Consent-Generation = %q, want %q (the seeded grant's generation)", got, "1")
	}
	if got := h.Get("SBO-Data-Dictionary-Digest"); got != cloudcontract.StructuralDataDictionaryDigest() {
		t.Errorf("SBO-Data-Dictionary-Digest = %q, want the schema digest %q",
			got, cloudcontract.StructuralDataDictionaryDigest())
	}
	if got := h.Get("SBO-Source-Window-Rule"); got != cloudStructuralSourceWindowRule {
		t.Errorf("SBO-Source-Window-Rule = %q, want %q", got, cloudStructuralSourceWindowRule)
	}
	if got := h.Get("SBO-Feature"); got != "structural_insights" {
		t.Errorf("SBO-Feature = %q, want %q", got, "structural_insights")
	}
	// The binding is METADATA about the grant, never part of the digested
	// window: putting it in the bytes would change every existing digest and
	// make an immutable snapshot go stale on an unrelated consent bump.
	if strings.Contains(string(f.structuralBodies[0]), "consent_generation") {
		t.Errorf("the grant binding leaked into the digested snapshot bytes:\n%s", f.structuralBodies[0])
	}

	// The snapshot carries no session identity and no path-shaped content.
	body := string(f.structuralBodies[0])
	for _, forbidden := range []string{"s-yesterday", "/tmp/cloud-structural", "main.go"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("the structural snapshot leaked %q:\n%s", forbidden, body)
		}
	}

	// A second sync captures nothing new (each window is captured once) and has
	// nothing left to send.
	out2, err := runCloudCmd(t, "sync", "--config", cfgPath, "--base-url", f.srv.URL, "--dev-token", "wtok")
	if err != nil {
		t.Fatalf("second sync: %v\n%s", err, out2)
	}
	if f.structuralUploads != 1 {
		t.Fatalf("a re-sync re-sent the window: uploads=%d\n%s", f.structuralUploads, out2)
	}
	if !strings.Contains(out2, "0 window(s) captured, 0 sent") {
		t.Errorf("second sync should be a no-op:\n%s", out2)
	}
}

// TestCloudSyncStructuralRouteAbsentIsRetryable is the point of the W2 ordering:
// the server route lands AFTER this node code, so a 404 (or 501) must leave the
// window queued for a later sync, never burn it terminally.
func TestCloudSyncStructuralRouteAbsentIsRetryable(t *testing.T) {
	for _, status := range []int{404, 501} {
		status := status
		t.Run(http404Name(status), func(t *testing.T) {
			f := newFakeCloudServer(t)
			f.structuralStatus = status
			cfgPath, dbPath, _ := writeCloudTestConfig(t)
			day := time.Now().UTC().AddDate(0, 0, -1).Truncate(24 * time.Hour)
			seedCloudSessionAt(t, dbPath, "s-yesterday", day.Add(9*time.Hour))

			st, cleanup := openCloudTestStore(t, dbPath)
			seedCloudStandingGrant(t, st, f.srv.URL, time.Now().UTC().AddDate(0, 0, -3))
			cleanup()

			if out, err := runCloudCmd(t, "login", "--config", cfgPath, "--base-url", f.srv.URL, "--dev-token", "wtok"); err != nil {
				t.Fatalf("login: %v\n%s", err, out)
			}
			out, err := runCloudCmd(t, "sync", "--config", cfgPath, "--base-url", f.srv.URL, "--dev-token", "wtok")
			if err != nil {
				t.Fatalf("sync: %v\n%s", err, out)
			}
			if !strings.Contains(out, "1 retryable") {
				t.Fatalf("a %d from an unshipped route must be retryable:\n%s", status, out)
			}

			st2, cleanup2 := openCloudTestStore(t, dbPath)
			defer cleanup2()
			items, lerr := st2.ListSendableStructuralOutbox(context.Background())
			if lerr != nil {
				t.Fatalf("list: %v", lerr)
			}
			if len(items) != 1 {
				t.Fatalf("the window must stay sendable after a %d, got %d item(s)", status, len(items))
			}
			if items[0].State != store.CloudOutboxFailedRetryable {
				t.Errorf("state = %q, want failed_retryable", items[0].State)
			}
			if !strings.Contains(items[0].LastError, "route_absent") {
				t.Errorf("error class = %q, want a route_absent class so an operator can tell "+
					"route absence from rejection", items[0].LastError)
			}
		})
	}
}

func http404Name(status int) string {
	if status == 404 {
		return "404_route_missing"
	}
	return "501_not_implemented"
}

// TestCloudSyncWithoutStandingGrantCapturesAndSendsNothing is the consent gate
// on the rail: no standing grant means no capture, no upload, and an honest line
// saying so.
func TestCloudSyncWithoutStandingGrantCapturesAndSendsNothing(t *testing.T) {
	f := newFakeCloudServer(t)
	cfgPath, dbPath, _ := writeCloudTestConfig(t)
	day := time.Now().UTC().AddDate(0, 0, -1).Truncate(24 * time.Hour)
	seedCloudSessionAt(t, dbPath, "s-yesterday", day.Add(9*time.Hour))

	if out, err := runCloudCmd(t, "login", "--config", cfgPath, "--base-url", f.srv.URL, "--dev-token", "wtok"); err != nil {
		t.Fatalf("login: %v\n%s", err, out)
	}
	out, err := runCloudCmd(t, "sync", "--config", cfgPath, "--base-url", f.srv.URL, "--dev-token", "wtok")
	if err != nil {
		t.Fatalf("sync: %v\n%s", err, out)
	}
	if f.structuralUploads != 0 {
		t.Fatalf("a snapshot was uploaded with no standing grant (%d uploads)", f.structuralUploads)
	}
	if !strings.Contains(out, "Structural: skipped — no standing grant") {
		t.Errorf("sync must say why the rail did nothing:\n%s", out)
	}

	st, cleanup := openCloudTestStore(t, dbPath)
	defer cleanup()
	captured, err := st.ListCapturedStructuralPeriods(context.Background(),
		cloudevidence.StructuralPeriodRuleV1, cloudcontract.StructuralSnapshotSchemaVersion)
	if err != nil {
		t.Fatalf("list captured: %v", err)
	}
	if len(captured) != 0 {
		t.Fatalf("windows were captured without a grant: %v", captured)
	}
}

// TestCloudCaptureEligibilityRules pins the source-window rule the receipt binds:
// completed days only, floored at the grant's day, never the current day.
func TestCloudCaptureEligibilityRules(t *testing.T) {
	_, dbPath, _ := writeCloudTestConfig(t)
	now := time.Date(2026, 9, 1, 15, 0, 0, 0, time.UTC)
	// Four candidate days: one before the grant, two completed after it, and
	// today (still accumulating).
	seedCloudSessionAt(t, dbPath, "s-before-grant", time.Date(2026, 8, 20, 9, 0, 0, 0, time.UTC))
	seedCloudSessionAt(t, dbPath, "s-day-1", time.Date(2026, 8, 30, 9, 0, 0, 0, time.UTC))
	seedCloudSessionAt(t, dbPath, "s-day-2", time.Date(2026, 8, 31, 9, 0, 0, 0, time.UTC))
	seedCloudSessionAt(t, dbPath, "s-today", time.Date(2026, 9, 1, 9, 0, 0, 0, time.UTC))

	st, cleanup := openCloudTestStore(t, dbPath)
	defer cleanup()
	ctx := context.Background()
	receiptID := seedCloudStandingGrant(t, st, "http://cloud.invalid", time.Date(2026, 8, 29, 8, 0, 0, 0, time.UTC))
	grant, err := cloudTestGrant(ctx, st, receiptID)
	if err != nil {
		t.Fatalf("resolve grant: %v", err)
	}

	n, err := cloudCaptureStructuralWindows(ctx, st, grant, now)
	if err != nil {
		t.Fatalf("capture: %v", err)
	}
	if n != 2 {
		t.Fatalf("captured %d window(s), want 2 (2026-08-30 and 2026-08-31)", n)
	}
	captured, err := st.ListCapturedStructuralPeriods(ctx,
		cloudevidence.StructuralPeriodRuleV1, cloudcontract.StructuralSnapshotSchemaVersion)
	if err != nil {
		t.Fatalf("list captured: %v", err)
	}
	for _, want := range []string{"2026-08-30", "2026-08-31"} {
		if _, ok := captured[want]; !ok {
			t.Errorf("window %s was not captured (got %v)", want, captured)
		}
	}
	for _, unwanted := range []string{"2026-08-20", "2026-09-01"} {
		if _, ok := captured[unwanted]; ok {
			t.Errorf("window %s must not be captured (before the grant / still accumulating)", unwanted)
		}
	}

	// Re-running captures nothing more: each window is captured once.
	again, err := cloudCaptureStructuralWindows(ctx, st, grant, now)
	if err != nil {
		t.Fatalf("re-capture: %v", err)
	}
	if again != 0 {
		t.Fatalf("re-capture produced %d additional window(s), want 0", again)
	}
}

// TestCloudCaptureExcludesNonPersonalSessions proves the plane separation the
// aggregate SQL enforces reaches the actual capture path: an org-authority
// session in the window contributes nothing, and a window with ONLY such
// sessions is not captured at all.
func TestCloudCaptureExcludesNonPersonalSessions(t *testing.T) {
	_, dbPath, _ := writeCloudTestConfig(t)
	now := time.Date(2026, 9, 1, 15, 0, 0, 0, time.UTC)
	seedCloudSessionAt(t, dbPath, "s-personal", time.Date(2026, 8, 31, 9, 0, 0, 0, time.UTC))
	seedCloudSession(t, dbPath, "s-org", "org") // 2026-06-09, org authority

	// An org session INSIDE the captured window.
	ctx := context.Background()
	database, err := db.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	if _, err := database.ExecContext(ctx,
		`UPDATE sessions SET started_at = '2026-08-31T10:00:00Z' WHERE id = 's-org'`); err != nil {
		t.Fatalf("move org session into the window: %v", err)
	}
	_ = database.Close()

	st, cleanup := openCloudTestStore(t, dbPath)
	defer cleanup()
	receiptID := seedCloudStandingGrant(t, st, "http://cloud.invalid", time.Date(2026, 8, 30, 8, 0, 0, 0, time.UTC))
	grant, err := cloudTestGrant(ctx, st, receiptID)
	if err != nil {
		t.Fatalf("resolve grant: %v", err)
	}
	if _, err := cloudCaptureStructuralWindows(ctx, st, grant, now); err != nil {
		t.Fatalf("capture: %v", err)
	}

	items, err := st.ListSendableStructuralOutbox(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("want 1 captured window, got %d", len(items))
	}
	payload, _, err := st.PrepareStructuralSend(ctx, items[0].ID, "http://cloud.invalid/v1/structural-insights")
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	var snap cloudcontract.StructuralSnapshot
	if err := json.Unmarshal(payload, &snap); err != nil {
		t.Fatalf("decode snapshot: %v", err)
	}
	if snap.SessionCount != 1 {
		t.Errorf("session_count = %d, want 1 — the org session must not be counted", snap.SessionCount)
	}
	if snap.ActionCount != 3 {
		t.Errorf("action_count = %d, want 3 — the org session's actions must not be summed", snap.ActionCount)
	}
}

// TestCloudStructuralPayloadIsStoredAndReplayed proves the stored bytes ARE the
// artifact: preparing the same item twice returns byte-identical payloads even
// after the source rows change, because prepare replays rather than
// re-aggregates.
func TestCloudStructuralPayloadIsStoredAndReplayed(t *testing.T) {
	_, dbPath, _ := writeCloudTestConfig(t)
	now := time.Date(2026, 9, 1, 15, 0, 0, 0, time.UTC)
	seedCloudSessionAt(t, dbPath, "s-day", time.Date(2026, 8, 31, 9, 0, 0, 0, time.UTC))

	st, cleanup := openCloudTestStore(t, dbPath)
	defer cleanup()
	ctx := context.Background()
	receiptID := seedCloudStandingGrant(t, st, "http://cloud.invalid", time.Date(2026, 8, 30, 8, 0, 0, 0, time.UTC))
	grant, err := cloudTestGrant(ctx, st, receiptID)
	if err != nil {
		t.Fatalf("resolve grant: %v", err)
	}
	if _, err := cloudCaptureStructuralWindows(ctx, st, grant, now); err != nil {
		t.Fatalf("capture: %v", err)
	}
	items, err := st.ListSendableStructuralOutbox(ctx)
	if err != nil || len(items) != 1 {
		t.Fatalf("list: %v (%d items)", err, len(items))
	}
	id := items[0].ID
	const endpoint = "http://cloud.invalid/v1/structural-insights"

	first, _, err := st.PrepareStructuralSend(ctx, id, endpoint)
	if err != nil {
		t.Fatalf("prepare 1: %v", err)
	}
	// LATE DATA: another session lands in the same window after the snapshot was
	// taken. A resend must NOT pick it up — that would be a different window
	// under the same revision.
	seedCloudSessionAt(t, dbPath, "s-late", time.Date(2026, 8, 31, 23, 0, 0, 0, time.UTC))
	if err := st.MarkCloudOutboxRetryable(ctx, id, "test_forced_retry"); err != nil {
		t.Fatalf("force retry: %v", err)
	}
	second, _, err := st.PrepareStructuralSend(ctx, id, endpoint)
	if err != nil {
		t.Fatalf("prepare 2: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("a retry re-aggregated instead of replaying the stored bytes:\nfirst:  %s\nsecond: %s", first, second)
	}
}

// TestCloudSyncExplainsTheDayOneCliff pins the honest copy for the one case
// where "0 windows captured" is the rule working: a grant made today has no
// COMPLETED day at or after it yet.
func TestCloudSyncExplainsTheDayOneCliff(t *testing.T) {
	f := newFakeCloudServer(t)
	cfgPath, dbPath, _ := writeCloudTestConfig(t)
	seedCloudSessionAt(t, dbPath, "s-today", time.Now().UTC().Add(-2*time.Hour))

	st, cleanup := openCloudTestStore(t, dbPath)
	seedCloudStandingGrant(t, st, f.srv.URL, time.Now().UTC())
	cleanup()

	if out, err := runCloudCmd(t, "login", "--config", cfgPath, "--base-url", f.srv.URL, "--dev-token", "wtok"); err != nil {
		t.Fatalf("login: %v\n%s", err, out)
	}
	out, err := runCloudCmd(t, "sync", "--config", cfgPath, "--base-url", f.srv.URL, "--dev-token", "wtok")
	if err != nil {
		t.Fatalf("sync: %v\n%s", err, out)
	}
	if f.structuralUploads != 0 {
		t.Fatalf("today's still-accumulating window was uploaded (%d uploads)", f.structuralUploads)
	}
	if !strings.Contains(out, "The first window is captured tomorrow") {
		t.Fatalf("sync must explain why a fresh grant captured nothing:\n%s", out)
	}
}

// TestCloudDrainStructuralRechecksAuthorizationBeforeEveryAttempt is the F2
// regression, driven through the REAL drain (cloudDrainStructural →
// cloudSendStructuralOne → the gateway → the network client).
//
// The gateway resolves the standing grant ONCE, before the drain callback runs.
// Before the fix the structural upload passed no PreAttempt hook, so nothing
// between that resolve and the socket could notice a `consent revoke` issued
// mid-drain: the POST went out, and so did every retry of it. Here the first
// attempt fails at the transport level and cancels the queued row as a side
// effect — exactly what revoke does to an in-flight item — while deliberately
// leaving the RECEIPT live, so the gateway's own re-resolve still passes and the
// only thing that can stop the retry is the store's per-item check.
//
// The gateway is built here rather than taken from `observer cloud sync`
// because sync leaves Options.MaxRetries at 0: with no retry there is no second
// attempt to gate, and the test would pass without testing anything. One retry
// makes the window real.
func TestCloudDrainStructuralRechecksAuthorizationBeforeEveryAttempt(t *testing.T) {
	f := newFakeCloudServer(t)
	// Keep-alives OFF so no connection is ever REUSED. Go's http.Transport
	// silently re-sends a request whose reused connection dies before the
	// response — a retry BELOW our client that no PreAttempt can gate. A fresh
	// connection per request makes the aborted attempt surface to sendRetryable,
	// so the retry this test is about is the one our authorization hook guards.
	f.srv.Config.SetKeepAlivesEnabled(false)

	_, dbPath, _ := writeCloudTestConfig(t)
	day := time.Now().UTC().AddDate(0, 0, -1).Truncate(24 * time.Hour)
	seedCloudSessionAt(t, dbPath, "s-yesterday", day.Add(9*time.Hour))

	st, cleanup := openCloudTestStore(t, dbPath)
	defer cleanup()
	ctx := context.Background()
	receiptID := seedCloudStandingGrant(t, st, f.srv.URL, time.Now().UTC().AddDate(0, 0, -3))
	grant, err := cloudTestGrant(ctx, st, receiptID)
	if err != nil {
		t.Fatalf("resolve grant: %v", err)
	}
	if captured, cerr := cloudCaptureStructuralWindows(ctx, st, grant, time.Now()); cerr != nil || captured != 1 {
		t.Fatalf("capture: %d window(s), err=%v", captured, cerr)
	}

	gw, err := cloudgateway.Open(cloudgateway.Options{
		Grants:     st,
		CredDir:    t.TempDir(),
		BaseURL:    f.srv.URL,
		DevToken:   "wtok",
		MaxRetries: 1,
		Backoff:    func(int) time.Duration { return 0 },
	})
	if err != nil {
		t.Fatalf("open gateway: %v", err)
	}
	if err := gw.BootstrapExchange(ctx); err != nil {
		t.Fatalf("exchange: %v", err)
	}

	f.structuralHook = func(attempt int) {
		if attempt > 1 {
			t.Errorf("attempt %d: a structural body left the machine after the queued item was cancelled", attempt)
			return
		}
		if _, cerr := st.CancelCloudOutboxForReceipt(context.Background(), receiptID); cerr != nil {
			t.Errorf("cancel in-flight item: %v", cerr)
		}
		panic(http.ErrAbortHandler)
	}

	var buf bytes.Buffer
	sent, _, _, derr := cloudDrainStructural(ctx, st, gw, &buf)
	if derr != nil {
		t.Fatalf("cloudDrainStructural: %v\n%s", derr, buf.String())
	}
	if sent != 0 {
		t.Fatalf("a cancelled item reported as sent\n%s", buf.String())
	}
	if f.structuralAttempts != 1 {
		t.Fatalf("the structural route saw %d attempt(s), want exactly 1\n%s", f.structuralAttempts, buf.String())
	}
	if f.structuralUploads != 0 {
		t.Fatalf("a cancelled item was accepted by the server\n%s", buf.String())
	}
}

// TestCloudConsentGrantSupersedesThePriorGrant is the F3 regression, through the
// real CLI. Re-granting a purpose that already has a live standing grant used to
// mint a SECOND live receipt: the drain then resolved the newest grant for the
// wire headers while validating each queued item against its older bound
// receipt, so a snapshot built under retired terms could ship declaring current
// ones. Now the re-grant retires the old receipt in the same transaction and
// parks what was queued under it.
func TestCloudConsentGrantSupersedesThePriorGrant(t *testing.T) {
	f := newFakeCloudServer(t)
	cfgPath, dbPath, _ := writeCloudTestConfig(t)
	day := time.Now().UTC().AddDate(0, 0, -1).Truncate(24 * time.Hour)
	seedCloudSessionAt(t, dbPath, "s-yesterday", day.Add(9*time.Hour))

	st, cleanup := openCloudTestStore(t, dbPath)
	ctx := context.Background()
	firstID := seedCloudStandingGrant(t, st, f.srv.URL, time.Now().UTC().AddDate(0, 0, -3))
	grant, err := cloudTestGrant(ctx, st, firstID)
	if err != nil {
		t.Fatalf("resolve grant: %v", err)
	}
	if captured, cerr := cloudCaptureStructuralWindows(ctx, st, grant, time.Now()); cerr != nil || captured != 1 {
		t.Fatalf("capture: %d windows, err=%v", captured, cerr)
	}
	cleanup()

	out, err := runCloudCmd(t, "consent", "grant", "--config", cfgPath, "--base-url", f.srv.URL,
		"--purpose", string(cloudcontract.PurposeStructuralInsights), "--yes")
	if err != nil {
		t.Fatalf("re-grant: %v\n%s", err, out)
	}
	// The consequence must be stated before the prompt AND reported after.
	for _, want := range []string{
		"THIS SUPERSEDES the standing grant already in force",
		"reconfirmation_required",
		"Superseded 1 prior standing grant(s)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the grant screen never said %q:\n%s", want, out)
		}
	}

	st2, cleanup2 := openCloudTestStore(t, dbPath)
	defer cleanup2()

	// Exactly one live standing grant, and it is NOT the first.
	live, err := st2.ListLiveCloudConsentReceipts(ctx, string(cloudcontract.PurposeStructuralInsights))
	if err != nil {
		t.Fatalf("list live: %v", err)
	}
	var standing []store.CloudConsentReceipt
	for _, r := range live {
		if r.GrantMode == store.CloudGrantStanding {
			standing = append(standing, r)
		}
	}
	if len(standing) != 1 {
		t.Fatalf("want exactly 1 live standing grant after a re-grant, got %d", len(standing))
	}
	if standing[0].ID == firstID {
		t.Fatal("the re-grant did not supersede the prior receipt")
	}
	if standing[0].ConsentGeneration != 2 {
		t.Errorf("new grant generation = %d, want 2", standing[0].ConsentGeneration)
	}

	// The window queued under the retired terms is parked, not sendable, and not
	// destroyed.
	items, err := st2.ListSendableStructuralOutbox(ctx)
	if err != nil {
		t.Fatalf("list sendable: %v", err)
	}
	if len(items) != 0 {
		t.Fatalf("a re-grant left %d snapshot(s) sendable under the new terms", len(items))
	}
	byState, total, err := st2.CloudOutboxCountsByState(ctx)
	if err != nil {
		t.Fatalf("outbox counts: %v", err)
	}
	if total != 1 || byState[string(store.CloudOutboxReconfirmationRequired)] != 1 {
		t.Fatalf("outbox states = %v (total %d), want one reconfirmation_required", byState, total)
	}

	// And a sync after the re-grant sends nothing: the old snapshot is not
	// silently re-declared under the new generation.
	if out, err := runCloudCmd(t, "login", "--config", cfgPath, "--base-url", f.srv.URL, "--dev-token", "wtok"); err != nil {
		t.Fatalf("login: %v\n%s", err, out)
	}
	syncOut, err := runCloudCmd(t, "sync", "--config", cfgPath, "--base-url", f.srv.URL, "--dev-token", "wtok")
	if err != nil {
		t.Fatalf("sync: %v\n%s", err, syncOut)
	}
	if f.structuralAttempts != 0 {
		t.Fatalf("a snapshot built under superseded terms was sent (%d attempt(s))\n%s", f.structuralAttempts, syncOut)
	}
}
