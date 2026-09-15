package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
)

func TestCloudSyncSelectedSessionLeavesOtherUploadsQueued(t *testing.T) {
	f := newFakeCloudServer(t)
	cfgPath, dbPath, _ := writeCloudTestConfig(t)
	for _, id := range []string{"older-queued", "chosen"} {
		seedCloudSession(t, dbPath, id, "personal")
		if out, err := runCloudCmd(t, "consent", "--config", cfgPath, "--base-url", f.srv.URL,
			"--session", id, "--purpose", string(cloudcontract.PurposeStructuralInsights), "--yes"); err != nil {
			t.Fatalf("consent: %v\n%s", err, out)
		}
	}
	day := time.Now().UTC().AddDate(0, 0, -1).Truncate(24 * time.Hour)
	seedCloudSessionAt(t, dbPath, "daily-activity", day.Add(9*time.Hour))
	grantStore, closeGrantStore := openCloudTestStore(t, dbPath)
	seedCloudStandingGrant(t, grantStore, f.srv.URL, day.AddDate(0, 0, -1))
	closeGrantStore()
	if out, err := runCloudCmd(t, "login", "--config", cfgPath, "--base-url", f.srv.URL,
		"--dev-token", "workos-dev-token"); err != nil {
		t.Fatalf("fixture sign-in: %v\n%s", err, out)
	}
	if out, err := runCloudCmd(t, "sync", "--config", cfgPath, "--base-url", f.srv.URL,
		"--dev-token", "workos-dev-token", "--session", "chosen"); err != nil {
		t.Fatalf("scoped sync: %v\n%s", err, out)
	}
	st, cleanup := openCloudTestStore(t, dbPath)
	defer cleanup()
	ctx := context.Background()
	items, err := st.ListSendableCloudOutbox(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].SessionID != "older-queued" {
		t.Fatalf("unselected session must remain queued: %+v", items)
	}
	if f.uploads != 1 || f.structuralAttempts != 0 || f.communityAttempts != 0 {
		t.Fatalf("uploads/session/structural/community = %d/%d/%d", f.uploads, f.structuralAttempts, f.communityAttempts)
	}
	_, _, found, err := st.GetCloudSessionResult(ctx, "chosen")
	if err != nil || !found {
		t.Fatalf("selected session result not pulled: found=%v err=%v", found, err)
	}
	// Positive control: a general sync still uploads the older session and
	// the granted daily activity that the selected-session sync skipped.
	if out, err := runCloudCmd(t, "sync", "--config", cfgPath, "--base-url", f.srv.URL); err != nil {
		t.Fatalf("general sync: %v\n%s", err, out)
	}
	if f.uploads != 2 || f.structuralAttempts == 0 {
		t.Fatalf("general sync did not drain the other rails: sessions=%d structural=%d", f.uploads, f.structuralAttempts)
	}
}

func TestCloudSyncEmptySessionCannotDrainEverything(t *testing.T) {
	for _, id := range []string{"", " "} {
		t.Run("empty"+id, func(t *testing.T) {
			_, err := runCloudCmd(t, "sync", "--session", id)
			if err == nil || !strings.Contains(err.Error(), "--session must name a session") {
				t.Fatalf("expected empty scope refusal, got %v", err)
			}
		})
	}
}
