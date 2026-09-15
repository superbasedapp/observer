package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// runCloudCmdWithInput is runCloudCmd (cloud_test.go) plus a stdin body, for
// the confirmation-prompt tests below.
func runCloudCmdWithInput(t *testing.T, stdin string, args ...string) (string, error) {
	t.Helper()
	cmd := newCloudCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetIn(strings.NewReader(stdin))
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

func TestCloudEnableDeclinedDoesNotAuthorizePolicy(t *testing.T) {
	for _, existingGrant := range []bool{false, true} {
		name := "fresh"
		if existingGrant {
			name = "existing standing grant"
		}
		t.Run(name, func(t *testing.T) {
			cfgPath, dbPath, _ := writeCloudTestConfig(t)
			if existingGrant {
				out, err := runCloudCmd(t, "enable", "--config", cfgPath, "--base-url", "http://cloud.invalid", "--yes")
				if err != nil {
					t.Fatalf("initial enable: %v\n%s", err, out)
				}
			}
			out, err := runCloudCmdWithInput(t, "n\n", "enable", "--with-excerpts", "--config", cfgPath, "--base-url", "http://cloud.invalid")
			if err != nil || !strings.Contains(out, "Aborted") || strings.Contains(out, "Cloud Intelligence is on:") {
				t.Fatalf("declined enable: %v\n%s", err, out)
			}
			st, cleanup := openCloudTestStore(t, dbPath)
			defer cleanup()
			policy, ok, err := st.GetCloudEnrichPolicy(context.Background())
			if err != nil || ok != existingGrant || (ok && policy.Level != store.CloudEnrichTitles) {
				t.Fatalf("declined enable changed policy: %+v, ok=%v, err=%v", policy, ok, err)
			}
			live, err := st.ListLiveCloudConsentReceipts(context.Background(), string(cloudcontract.PurposeStructuralInsights))
			want := 0
			if existingGrant {
				want = 1
			}
			if err != nil || len(live) != want {
				t.Fatalf("live receipts=%d, want %d: %v", len(live), want, err)
			}
		})
	}
}

// TestCloudEnableRecordsPolicyAndStandingGrant pins the default (titles,
// background on) path end to end: the explanation, the minted standing
// structural grant, the recorded policy row, and the exact last line.
func TestCloudEnableRecordsPolicyAndStandingGrant(t *testing.T) {
	cfgPath, dbPath, _ := writeCloudTestConfig(t)

	out, err := runCloudCmd(t, "enable", "--config", cfgPath, "--base-url", "http://cloud.invalid", "--yes")
	if err != nil {
		t.Fatalf("enable: %v\n%s", err, out)
	}
	for _, want := range []string{
		"Turning on Cloud Intelligence means:",
		"named and tagged for you in the background",
		"background enrichment is on - it is on here",
		"a structural summary and your first prompt, nothing else",
		cloudcontract.ProviderPostureDisclosure,
		"privacy policy v" + cloudcontract.ProviderPosturePolicyVersion,
		"observer cloud consent list",
		"Cloud Intelligence is on: titles (background on).",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("enable output missing %q:\n%s", want, out)
		}
	}

	st, cleanup := openCloudTestStore(t, dbPath)
	defer cleanup()
	ctx := context.Background()

	live, err := st.ListLiveCloudConsentReceipts(ctx, string(cloudcontract.PurposeStructuralInsights))
	if err != nil {
		t.Fatalf("list live: %v", err)
	}
	if len(live) != 1 || live[0].GrantMode != store.CloudGrantStanding {
		t.Fatalf("live standing receipts = %+v, want exactly one standing grant", live)
	}

	policy, ok, err := st.GetCloudEnrichPolicy(ctx)
	if err != nil || !ok {
		t.Fatalf("GetCloudEnrichPolicy: ok=%v err=%v", ok, err)
	}
	if policy.Level != store.CloudEnrichTitles || !policy.Background {
		t.Fatalf("policy = %+v, want titles/background=true", policy)
	}
	if policy.PolicyVersion != cloudcontract.ProviderPosturePolicyVersion {
		t.Errorf("policy version = %q, want %q", policy.PolicyVersion, cloudcontract.ProviderPosturePolicyVersion)
	}
	if policy.Source != "cli" {
		t.Errorf("policy source = %q, want cli", policy.Source)
	}
}

// TestCloudEnableWithExcerpts pins --with-excerpts: level=excerpts, and the
// excerpts-specific disclosure line (never the titles-only one).
func TestCloudEnableWithExcerpts(t *testing.T) {
	cfgPath, dbPath, _ := writeCloudTestConfig(t)

	out, err := runCloudCmd(t, "enable", "--config", cfgPath, "--base-url", "http://cloud.invalid",
		"--with-excerpts", "--yes")
	if err != nil {
		t.Fatalf("enable: %v\n%s", err, out)
	}
	if !strings.Contains(out, "short scrubbed excerpts of your task and final summary") {
		t.Errorf("excerpts disclosure missing:\n%s", out)
	}
	if strings.Contains(out, "nothing else; plus a daily zero-content activity summary") {
		t.Errorf("titles-only disclosure leaked into an excerpts enable:\n%s", out)
	}
	if !strings.Contains(out, "Cloud Intelligence is on: excerpts (background on).") {
		t.Errorf("last line wrong:\n%s", out)
	}

	st, cleanup := openCloudTestStore(t, dbPath)
	defer cleanup()
	policy, ok, err := st.GetCloudEnrichPolicy(context.Background())
	if err != nil || !ok || policy.Level != store.CloudEnrichExcerpts {
		t.Fatalf("policy = %+v ok=%v err=%v, want level=excerpts", policy, ok, err)
	}
}

// TestCloudEnableNoBackground pins --no-background: the policy row and the
// explanation both say background is off.
func TestCloudEnableNoBackground(t *testing.T) {
	cfgPath, dbPath, _ := writeCloudTestConfig(t)

	out, err := runCloudCmd(t, "enable", "--config", cfgPath, "--base-url", "http://cloud.invalid",
		"--no-background", "--yes")
	if err != nil {
		t.Fatalf("enable: %v\n%s", err, out)
	}
	if !strings.Contains(out, "background enrichment is on - it is off here") {
		t.Errorf("explanation did not say background is off:\n%s", out)
	}
	if !strings.Contains(out, "Cloud Intelligence is on: titles (background off).") {
		t.Errorf("last line wrong:\n%s", out)
	}

	st, cleanup := openCloudTestStore(t, dbPath)
	defer cleanup()
	policy, ok, err := st.GetCloudEnrichPolicy(context.Background())
	if err != nil || !ok || policy.Background {
		t.Fatalf("policy = %+v ok=%v err=%v, want background=false", policy, ok, err)
	}
}

// TestCloudEnableKeepsExistingStandingGrant pins the "do not supersede"
// behaviour: a second `enable` with a live standing grant already recorded
// keeps it (generation unchanged) rather than re-queuing snapshots.
func TestCloudEnableKeepsExistingStandingGrant(t *testing.T) {
	cfgPath, dbPath, _ := writeCloudTestConfig(t)

	if out, err := runCloudCmd(t, "enable", "--config", cfgPath, "--base-url", "http://cloud.invalid", "--yes"); err != nil {
		t.Fatalf("first enable: %v\n%s", err, out)
	}

	out, err := runCloudCmd(t, "enable", "--config", cfgPath, "--base-url", "http://cloud.invalid",
		"--with-excerpts", "--yes")
	if err != nil {
		t.Fatalf("second enable: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Standing consent for the daily activity summary is already recorded") {
		t.Errorf("second enable did not report the kept grant:\n%s", out)
	}
	if strings.Contains(out, "Superseded") {
		t.Errorf("second enable must not supersede the existing standing grant:\n%s", out)
	}

	st, cleanup := openCloudTestStore(t, dbPath)
	defer cleanup()
	ctx := context.Background()
	gen, err := st.MaxCloudConsentGeneration(ctx, string(cloudcontract.PurposeStructuralInsights))
	if err != nil {
		t.Fatalf("MaxCloudConsentGeneration: %v", err)
	}
	if gen != 1 {
		t.Fatalf("generation = %d, want 1 (unchanged)", gen)
	}
	// The excerpts level from the SECOND call still recorded, even though the
	// standing grant itself was kept.
	policy, ok, err := st.GetCloudEnrichPolicy(ctx)
	if err != nil || !ok || policy.Level != store.CloudEnrichExcerpts {
		t.Fatalf("policy = %+v ok=%v err=%v, want level=excerpts", policy, ok, err)
	}
}

// TestCloudDisable pins the full off path: policy -> off (background kept),
// the standing grant revoked, and the exact last line.
func TestCloudDisable(t *testing.T) {
	cfgPath, dbPath, _ := writeCloudTestConfig(t)

	if out, err := runCloudCmd(t, "enable", "--config", cfgPath, "--base-url", "http://cloud.invalid",
		"--no-background", "--yes"); err != nil {
		t.Fatalf("enable: %v\n%s", err, out)
	}

	out, err := runCloudCmd(t, "disable", "--config", cfgPath, "--yes")
	if err != nil {
		t.Fatalf("disable: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Revoked 1 standing grant(s)") {
		t.Errorf("disable did not revoke the standing grant:\n%s", out)
	}
	if !strings.Contains(out, "Cancelled 0 queued session enrichment job(s).") {
		t.Errorf("disable job count wrong:\n%s", out)
	}
	if !strings.HasSuffix(strings.TrimRight(out, "\n"), "Cloud Intelligence is off.") {
		t.Fatalf("last line != %q:\n%s", "Cloud Intelligence is off.", out)
	}

	st, cleanup := openCloudTestStore(t, dbPath)
	defer cleanup()
	ctx := context.Background()
	live, err := st.ListLiveCloudConsentReceipts(ctx, string(cloudcontract.PurposeStructuralInsights))
	if err != nil {
		t.Fatalf("list live: %v", err)
	}
	if len(live) != 0 {
		t.Fatalf("live standing receipts after disable = %d, want 0", len(live))
	}
	policy, ok, err := st.GetCloudEnrichPolicy(ctx)
	if err != nil || !ok {
		t.Fatalf("GetCloudEnrichPolicy: ok=%v err=%v", ok, err)
	}
	// Background is the pre-disable value (false, from --no-background above),
	// KEPT rather than reset — disable turns the level off, not the developer's
	// background preference for a future re-enable.
	if policy.Level != store.CloudEnrichOff || policy.Background {
		t.Fatalf("policy after disable = %+v, want level=off background=false (kept)", policy)
	}
}

// TestCloudDisableCancelsPendingSessionEvidence pins that disable also drains
// the per-session queue: a pending session_evidence job under a live
// per-upload receipt is cancelled and its receipt invalidated.
func TestCloudDisableCancelsPendingSessionEvidence(t *testing.T) {
	cfgPath, dbPath, _ := writeCloudTestConfig(t)
	seedCloudSession(t, dbPath, "sess-pending", "personal")

	st, cleanup := openCloudTestStore(t, dbPath)
	ctx := context.Background()
	receiptID, err := st.InsertCloudConsentReceipt(ctx, store.CloudConsentReceipt{
		AccountPseudonym: "acct-test",
		Purpose:          string(cloudcontract.PurposeContextEnrichment),
		UploadDigest:     "sha256:pending-evidence",
	})
	if err != nil {
		t.Fatalf("insert receipt: %v", err)
	}
	jobID, err := st.EnqueueCloudOutbox(ctx, store.CloudOutboxItem{
		SessionID:             "sess-pending",
		EvidenceContentDigest: "sha256:ec",
		UploadDigest:          "sha256:pending-evidence",
		ReceiptID:             receiptID,
	})
	if err != nil {
		t.Fatalf("enqueue outbox: %v", err)
	}
	cleanup()

	out, err := runCloudCmd(t, "disable", "--config", cfgPath, "--yes")
	if err != nil {
		t.Fatalf("disable: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Cancelled 1 queued session enrichment job(s).") {
		t.Errorf("disable did not report the cancelled job:\n%s", out)
	}

	st2, cleanup2 := openCloudTestStore(t, dbPath)
	defer cleanup2()
	item, ok, err := st2.GetCloudOutbox(context.Background(), jobID)
	if err != nil || !ok {
		t.Fatalf("GetCloudOutbox: ok=%v err=%v", ok, err)
	}
	if item.State != store.CloudOutboxCancelled {
		t.Fatalf("job state = %q, want cancelled", item.State)
	}
}

// TestCloudDisableRequiresConfirmation pins that a "n" answer aborts without
// changing anything.
func TestCloudDisableRequiresConfirmation(t *testing.T) {
	cfgPath, dbPath, _ := writeCloudTestConfig(t)
	if out, err := runCloudCmd(t, "enable", "--config", cfgPath, "--base-url", "http://cloud.invalid", "--yes"); err != nil {
		t.Fatalf("enable: %v\n%s", err, out)
	}

	out, err := runCloudCmdWithInput(t, "n\n", "disable", "--config", cfgPath)
	if err != nil {
		t.Fatalf("disable (declined): %v\n%s", err, out)
	}
	if !strings.Contains(out, "Aborted — nothing changed.") {
		t.Errorf("declined disable did not abort:\n%s", out)
	}

	st, cleanup := openCloudTestStore(t, dbPath)
	defer cleanup()
	policy, ok, err := st.GetCloudEnrichPolicy(context.Background())
	if err != nil || !ok || policy.Level != store.CloudEnrichTitles {
		t.Fatalf("policy after a declined disable = %+v ok=%v err=%v, want unchanged level=titles", policy, ok, err)
	}
}

// TestCloudStatusShowsEnrichmentPolicy pins the `observer cloud status` line
// this arc adds: "not set" before enable, the recorded level/background after.
func TestCloudStatusShowsEnrichmentPolicy(t *testing.T) {
	cfgPath, _, _ := writeCloudTestConfig(t)

	out, err := runCloudCmd(t, "status", "--config", cfgPath)
	if err != nil {
		t.Fatalf("status (before enable): %v\n%s", err, out)
	}
	if !strings.Contains(out, "enrichment policy:   not set (run observer cloud enable)") {
		t.Errorf("status before enable missing the not-set line:\n%s", out)
	}

	if out, err := runCloudCmd(t, "enable", "--config", cfgPath, "--base-url", "http://cloud.invalid", "--yes"); err != nil {
		t.Fatalf("enable: %v\n%s", err, out)
	}
	out, err = runCloudCmd(t, "status", "--config", cfgPath)
	if err != nil {
		t.Fatalf("status (after enable): %v\n%s", err, out)
	}
	if !strings.Contains(out, "enrichment policy:   titles (background on") {
		t.Errorf("status after enable missing the recorded policy line:\n%s", out)
	}
}
