//go:build !sbo_omit_cloud_intelligence

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/cloudevidence"
	"github.com/marmutapp/superbased-observer/internal/cloudgateway"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// seedCloudBigSession is seedCloudSession plus n more actions with long,
// distinct targets, so the envelope's action sample is large enough that the
// budget ladder's action-sample steps shrink it.
func seedCloudBigSession(t *testing.T, dbPath, sessionID string, n int) {
	t.Helper()
	seedCloudSession(t, dbPath, sessionID, "personal")
	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer database.Close()
	var projectID int64
	if err := database.QueryRowContext(ctx, `SELECT project_id FROM sessions WHERE id = ?`, sessionID).Scan(&projectID); err != nil {
		t.Fatalf("read project: %v", err)
	}
	kinds := []string{"read", "edit", "bash", "search"}
	for i := 0; i < n; i++ {
		if _, err := database.ExecContext(ctx,
			`INSERT INTO actions (session_id, project_id, timestamp, action_type, tool, success, target, source_file, source_event_id)
			 VALUES (?, ?, ?, ?, 'claude-code', 1, ?, 'f', ?)`,
			sessionID, projectID,
			time.Date(2026, 6, 9, 0, 3, i, 0, time.UTC).Format(time.RFC3339Nano),
			kinds[i%len(kinds)], fmt.Sprintf("/tmp/cloud-cli/pkg%03d/a_rather_long_file_name_%03d.go", i, i),
			fmt.Sprintf("%s-big-%d", sessionID, i)); err != nil {
			t.Fatalf("insert action: %v", err)
		}
	}
}

// recordCloudEvidenceBudget stores budget as the last-known evidence budget,
// as a sync's usage read would.
func recordCloudEvidenceBudget(t *testing.T, st *store.Store, budget int) {
	t.Helper()
	now := time.Now().UTC()
	if err := st.RecordCloudSyncLast(context.Background(), store.CloudSyncLast{
		StartedAt: now, FinishedAt: now, OK: true, BudgetUnit: cloudBudgetUnitTokens, EvidenceTokenBudget: &budget,
	}); err != nil {
		t.Fatalf("record budget: %v", err)
	}
}

// TestCloudEnvelopeFitsEvidenceBudget pins the node half of R-AI1: an
// over-budget session is stepped down to a SMALLER, VALID envelope that fits;
// the receipt's frozen settings rebuild it byte-for-byte (the send-time
// digest re-check passes); and `observer cloud preview` prints the same
// upload digest the consent build binds (preview == upload).
func TestCloudEnvelopeFitsEvidenceBudget(t *testing.T) {
	cfg, dbPath, _ := writeCloudTestConfig(t)
	seedCloudBigSession(t, dbPath, "big", 200)
	st, cleanup := openCloudTestStore(t, dbPath)
	defer cleanup()
	ctx := context.Background()
	purpose := cloudcontract.PurposeStructuralInsights

	// No budget on the plan: the unstepped build, with no settings frozen.
	recordCloudEvidenceBudget(t, st, 0)
	full, err := buildCloudEnvelopeConfigured(ctx, st, "big", purpose, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if full.Budget == nil || full.Budget.SteppedDown || full.EvidenceSettingsJSON != "" {
		t.Fatalf("no-budget build = %+v, want unstepped with no frozen settings", full.Budget)
	}
	fullTokens := cloudcontract.EstimateEvidenceTokens(len(full.Bytes))

	budget := fullTokens * 6 / 10
	recordCloudEvidenceBudget(t, st, budget)
	fitted, err := buildCloudEnvelopeConfigured(ctx, st, "big", purpose, nil, 0)
	if err != nil {
		t.Fatalf("fit to %d tokens (full %d): %v", budget, fullTokens, err)
	}
	if fitted.Budget == nil || !fitted.Budget.SteppedDown || !fitted.Budget.BudgetKnown || fitted.Budget.BudgetTokens != budget {
		t.Fatalf("budget note = %+v, want a stepped-down fit to the known %d", fitted.Budget, budget)
	}
	if len(fitted.Bytes) >= len(full.Bytes) || !cloudcontract.EvidenceFitsBudget(len(fitted.Bytes), budget) {
		t.Fatalf("fitted %d bytes (about %d tokens) vs full %d bytes, budget %d", len(fitted.Bytes), fitted.Budget.EstimatedTokens, len(full.Bytes), budget)
	}
	var env cloudcontract.Envelope
	if err := json.Unmarshal(fitted.Bytes, &env); err != nil {
		t.Fatalf("fitted bytes are not an envelope: %v", err)
	}
	if err := env.Validate(); err != nil {
		t.Fatalf("fitted envelope is invalid: %v", err)
	}

	// The receipt freezes the fitted settings; the send-time rebuild with them
	// reproduces the exact bytes.
	frozen, err := store.ParseCloudEvidenceSettings(fitted.EvidenceSettingsJSON)
	if err != nil || frozen == nil {
		t.Fatalf("fitted settings %q: %v", fitted.EvidenceSettingsJSON, err)
	}
	rebuilt, err := buildCloudEnvelopeWithSettings(ctx, st, "big", purpose, cloudFieldClasses(purpose), nil, frozen)
	if err != nil || rebuilt.Digests != fitted.Digests || !bytes.Equal(rebuilt.Bytes, fitted.Bytes) {
		t.Fatalf("send-time rebuild drifted from the fitted bytes: %v", err)
	}

	// The CLI preview prints the fitted upload digest and says it stepped down.
	out, err := runCloudCmd(t, "preview", "--config", cfg, "--session", "big", "--purpose", string(purpose))
	if err != nil {
		t.Fatalf("preview: %v\n%s", err, out)
	}
	if !strings.Contains(out, "upload digest:           "+fitted.Digests.Upload) {
		t.Fatalf("preview digest is not the fitted upload digest %s:\n%s", fitted.Digests.Upload, out)
	}
	if !strings.Contains(out, "stepped down to step") || !strings.Contains(out, fmt.Sprintf("of %d tokens", budget)) {
		t.Fatalf("preview does not explain the step-down:\n%s", out)
	}
}

// TestCloudEnvelopeBudgetFloor pins the floor case: when even the smallest
// selection is over the budget, the build refuses with an error that is
// cloudevidence.ErrEvidenceOverBudget and tells the developer, in the CLI,
// that the session cannot be sent.
func TestCloudEnvelopeBudgetFloor(t *testing.T) {
	cfg, dbPath, _ := writeCloudTestConfig(t)
	seedCloudBigSession(t, dbPath, "floor", 10)
	st, cleanup := openCloudTestStore(t, dbPath)
	defer cleanup()
	recordCloudEvidenceBudget(t, st, 1)

	_, err := buildCloudEnvelopeConfigured(context.Background(), st, "floor", cloudcontract.PurposeStructuralInsights, nil, 0)
	if !errors.Is(err, cloudevidence.ErrEvidenceOverBudget) {
		t.Fatalf("floor build err = %v, want ErrEvidenceOverBudget", err)
	}
	out, err := runCloudCmd(t, "preview", "--config", cfg, "--session", "floor")
	if err == nil || !strings.Contains(err.Error(), "cannot be sent") || !strings.Contains(err.Error(), "evidence budget of 1 tokens") {
		t.Fatalf("preview at the floor: err=%v\n%s", err, out)
	}
}

// TestCloudEvidenceBudgetDefault pins the safe default: with no usage read on
// this device the build fits to the free tier's 4,000 tokens and says so.
func TestCloudEvidenceBudgetDefault(t *testing.T) {
	_, dbPath, _ := writeCloudTestConfig(t)
	seedCloudSession(t, dbPath, "small", "personal")
	st, cleanup := openCloudTestStore(t, dbPath)
	defer cleanup()
	res, err := buildCloudEnvelopeConfigured(context.Background(), st, "small", cloudcontract.PurposeStructuralInsights, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if res.Budget == nil || res.Budget.BudgetKnown || res.Budget.BudgetTokens != cloudcontract.DefaultEvidenceTokenBudget || res.Budget.SteppedDown {
		t.Fatalf("default budget note = %+v", res.Budget)
	}
	var buf bytes.Buffer
	cloudPrintBudgetLine(&buf, res.Budget)
	if !strings.Contains(buf.String(), "of 4000 tokens, the default") {
		t.Fatalf("budget line = %q", buf.String())
	}
}

// TestCloudApplyUsageTokens pins the sync's mapping of a usage read onto the
// record: nil leaves everything unknown (so the stored evidence budget is
// kept), a count plan stores its evidence budget (0) but no token windows,
// and a token plan stores every window.
func TestCloudApplyUsageTokens(t *testing.T) {
	var none store.CloudSyncLast
	cloudApplyUsageTokens(&none, nil)
	if none.EvidenceTokenBudget != nil || none.DailyTokenBudget != nil || none.BudgetUnit != "" {
		t.Fatalf("no read = %+v, want all unknown", none)
	}
	var count store.CloudSyncLast
	cloudApplyUsageTokens(&count, &cloudgateway.UsageView{BudgetUnit: "count"})
	if count.EvidenceTokenBudget == nil || *count.EvidenceTokenBudget != 0 || count.DailyTokenBudget != nil {
		t.Fatalf("count plan = %+v", count)
	}
	var tok store.CloudSyncLast
	cloudApplyUsageTokens(&tok, &cloudgateway.UsageView{
		BudgetUnit: "tokens", EnrichmentTier: "free", EvidenceTokenBudget: 4000, SessionTokenBudget: 60000,
		DailyTokensUsed: 10, DailyTokenBudget: 250000, MonthlyTokensUsed: 20, MonthlyTokenBudget: 3000000,
	})
	if *tok.EvidenceTokenBudget != 4000 || *tok.SessionTokenBudget != 60000 || *tok.DailyTokensUsed != 10 ||
		*tok.DailyTokenBudget != 250000 || *tok.MonthlyTokensUsed != 20 || *tok.MonthlyTokenBudget != 3000000 || tok.EnrichmentTier != "free" {
		t.Fatalf("token plan = %+v", tok)
	}
}

// TestCloudPrintPlanLineTokens pins `observer cloud status` on a token plan:
// it prints the token windows with what is left and the per-session cap,
// never the count caps that read 0 on such a plan.
func TestCloudPrintPlanLineTokens(t *testing.T) {
	_, dbPath, _ := writeCloudTestConfig(t)
	seedCloudSession(t, dbPath, "s", "personal")
	st, cleanup := openCloudTestStore(t, dbPath)
	defer cleanup()
	ctx := context.Background()
	now := time.Now().UTC()
	rec := store.CloudSyncLast{StartedAt: now, FinishedAt: now, OK: true, PlanName: "free", PlanLabel: "Signed-in Free"}
	zero := 0
	rec.DailyCap, rec.MonthlyCap = &zero, &zero
	cloudApplyUsageTokens(&rec, &cloudgateway.UsageView{
		BudgetUnit: "tokens", EvidenceTokenBudget: 4000, SessionTokenBudget: 60000,
		DailyTokensUsed: 250, DailyTokenBudget: 250000, MonthlyTokensUsed: 3000001, MonthlyTokenBudget: 3000000,
	})
	if err := st.RecordCloudSyncLast(ctx, rec); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	cloudPrintPlanLine(ctx, st, &buf)
	cloudPrintEvidenceBudgetLine(ctx, st, &buf)
	out := buf.String()
	for _, want := range []string{
		"Signed-in Free (token budget;",
		"tokens today:        250 of 250000 used, 249750 left",
		"tokens this month:   3000001 of 3000000 used, 0 left",
		"per session:         60000 tokens",
		"evidence budget:     4000 tokens per upload",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("status missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "0/day") {
		t.Errorf("status prints the inert count caps:\n%s", out)
	}
}
