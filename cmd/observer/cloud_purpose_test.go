package main

import (
	"context"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
)

// TestCloudPurposeSetBoundedCarriesBothPurposesSorted is the live-bug
// regression: `observer cloud consent --purpose bounded_context_enrichment`
// used to build an envelope whose DisclosurePurposes was ONLY
// bounded_context_enrichment, so the server's out-of-purpose check (which
// requires structural_activity_insights on every session-evidence envelope)
// refused it with a 403 and parked the outbox item terminal. A bounded build
// must disclose under BOTH purposes, sorted (cloudevidence's own
// sortedUniquePurposes ordering), never bounded alone.
func TestCloudPurposeSetBoundedCarriesBothPurposesSorted(t *testing.T) {
	_, dbPath, _ := writeCloudTestConfig(t)
	seedRichCloudSession(t, dbPath, "bounded1")
	st, cleanup := openCloudTestStore(t, dbPath)
	defer cleanup()

	res, err := buildCloudEnvelope(context.Background(), st, "bounded1", cloudcontract.PurposeContextEnrichment, nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	got := res.Envelope.DisclosurePurposes
	want := []cloudcontract.Purpose{
		cloudcontract.PurposeContextEnrichment,
		cloudcontract.PurposeStructuralInsights,
	}
	if len(got) != len(want) {
		t.Fatalf("DisclosurePurposes = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("DisclosurePurposes[%d] = %q, want %q (full = %v)", i, got[i], want[i], got)
		}
	}
}

// TestCloudPurposeSetStructuralStaysSinglePurpose proves the fix is additive,
// not a blanket widening: a structural build still discloses under exactly
// structural_activity_insights.
func TestCloudPurposeSetStructuralStaysSinglePurpose(t *testing.T) {
	_, dbPath, _ := writeCloudTestConfig(t)
	seedRichCloudSession(t, dbPath, "structural1")
	st, cleanup := openCloudTestStore(t, dbPath)
	defer cleanup()

	res, err := buildCloudEnvelope(context.Background(), st, "structural1", cloudcontract.PurposeStructuralInsights, nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	got := res.Envelope.DisclosurePurposes
	if len(got) != 1 || got[0] != cloudcontract.PurposeStructuralInsights {
		t.Errorf("DisclosurePurposes = %v, want exactly [%q]", got, cloudcontract.PurposeStructuralInsights)
	}
}

// TestCloudPurposeSetRejectsUnsupportedPurpose pins the honest refusal: a
// purpose cloudPurposeSet does not know how to expand (anything but the two
// session-evidence purposes) fails closed instead of silently under-declaring
// an envelope's disclosure — the mistake that produced the live bug.
func TestCloudPurposeSetRejectsUnsupportedPurpose(t *testing.T) {
	_, err := cloudPurposeSet(cloudcontract.PurposeExtendedEvidence)
	if err == nil {
		t.Fatal("cloudPurposeSet(extended_evidence_deep_review) = nil error, want a refusal")
	}
	msg := err.Error()
	if !strings.Contains(msg, string(cloudcontract.PurposeStructuralInsights)) ||
		!strings.Contains(msg, string(cloudcontract.PurposeContextEnrichment)) {
		t.Errorf("error %q does not name both supported purposes", msg)
	}
}

// TestCloudPurposeSetStructuralIsClosedUnderItself is a boundary sanity check:
// structural, the base every upload rides on, expands to exactly itself (it
// has nothing further to imply).
func TestCloudPurposeSetStructuralIsClosedUnderItself(t *testing.T) {
	set, err := cloudPurposeSet(cloudcontract.PurposeStructuralInsights)
	if err != nil {
		t.Fatalf("cloudPurposeSet(structural): %v", err)
	}
	if len(set) != 1 || set[0] != cloudcontract.PurposeStructuralInsights {
		t.Errorf("cloudPurposeSet(structural) = %v, want [structural_activity_insights]", set)
	}
}

// TestCloudSyncBoundedUploadPreviewConfirmsBothPurposes is the end-to-end
// regression for the actual reported bug: it drives `observer cloud consent
// --purpose bounded_context_enrichment` and `observer cloud sync` against a
// fake server and asserts the wire-level preview-confirmation body — the
// thing internal/cloudserver/api/jobs.go reads as `grantedPurposes` for its
// out-of-purpose check — names BOTH structural_activity_insights and
// bounded_context_enrichment, not just the one purpose the CLI was invoked
// with.
func TestCloudSyncBoundedUploadPreviewConfirmsBothPurposes(t *testing.T) {
	f := newFakeCloudServer(t)
	cfgPath, dbPath, _ := writeCloudTestConfig(t)
	seedRichCloudSession(t, dbPath, "bounded2")

	if out, err := runCloudCmd(t, "consent",
		"--config", cfgPath, "--base-url", f.srv.URL,
		"--session", "bounded2", "--purpose", string(cloudcontract.PurposeContextEnrichment), "--yes"); err != nil {
		t.Fatalf("consent: %v\n%s", err, out)
	}
	if out, err := runCloudCmd(t, "login",
		"--config", cfgPath, "--base-url", f.srv.URL, "--dev-token", "workos-dev-token"); err != nil {
		t.Fatalf("login: %v\n%s", err, out)
	}
	out, err := runCloudCmd(t, "sync",
		"--config", cfgPath, "--base-url", f.srv.URL, "--dev-token", "workos-dev-token")
	if err != nil {
		t.Fatalf("sync: %v\n%s", err, out)
	}
	if f.previewConfirms != 1 {
		t.Fatalf("want 1 preview-confirmation, server saw %d\n%s", f.previewConfirms, out)
	}
	if f.uploads != 1 {
		t.Errorf("want 1 upload, server saw %d\n%s", f.uploads, out)
	}
	got := f.lastPreviewConfirmPurposes
	wantOne := func(p cloudcontract.Purpose) bool {
		for _, g := range got {
			if g == string(p) {
				return true
			}
		}
		return false
	}
	if !wantOne(cloudcontract.PurposeStructuralInsights) {
		t.Errorf("preview-confirmation purposes = %v, missing %q (the live bug this closes)", got, cloudcontract.PurposeStructuralInsights)
	}
	if !wantOne(cloudcontract.PurposeContextEnrichment) {
		t.Errorf("preview-confirmation purposes = %v, missing %q", got, cloudcontract.PurposeContextEnrichment)
	}
	if len(got) != 2 {
		t.Errorf("preview-confirmation purposes = %v, want exactly 2 entries", got)
	}
}

// TestCloudOutOfPurposeHintNamesTheMissingPurposeAndRemedy pins the honest
// terminal-failure copy: a 403 out_of_purpose body from the server should turn
// into a message naming the missing purpose and the exact command to grant it
// — hyphens only, no em-dashes.
func TestCloudOutOfPurposeHintNamesTheMissingPurposeAndRemedy(t *testing.T) {
	hint := cloudOutOfPurposeHint("required purpose not granted: structural_activity_insights", "sess-1")
	if !strings.Contains(hint, "structural_activity_insights") {
		t.Errorf("hint does not name the missing purpose: %q", hint)
	}
	if !strings.Contains(hint, "observer cloud consent --session sess-1 --purpose bounded_context_enrichment") {
		t.Errorf("hint does not give the exact remedy command: %q", hint)
	}
	if strings.ContainsRune(hint, '—') {
		t.Errorf("hint contains an em-dash, want hyphens only: %q", hint)
	}

	declared := cloudOutOfPurposeHint("declared disclosure purpose not granted: bounded_context_enrichment", "sess-2")
	if !strings.Contains(declared, "bounded_context_enrichment") {
		t.Errorf("hint does not name the missing purpose: %q", declared)
	}
	if strings.ContainsRune(declared, '—') {
		t.Errorf("hint contains an em-dash, want hyphens only: %q", declared)
	}
}
