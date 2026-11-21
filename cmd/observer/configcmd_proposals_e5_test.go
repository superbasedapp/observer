//go:build !sbo_omit_integration_mcp_server

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/store"
)

func proposalTestStore(t *testing.T) (string, *store.Store) {
	t.Helper()
	cfgPath, dbPath := settingsTestEnv(t)
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o700); err != nil {
		t.Fatal(err)
	}
	database, err := db.Open(context.Background(), db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return cfgPath, store.New(database)
}

// TestApproveRefusesAStaleProposal pins review E-50: a proposal whose setting
// was changed by hand after it was filed, and one older than the age limit,
// are refused at approval and nothing is written.
func TestApproveRefusesAStaleProposal(t *testing.T) {
	ctx := context.Background()
	cfgPath, st := proposalTestStore(t)
	changed, err := st.FileSettingsProposal(ctx, store.NewSettingsProposal{
		Key: "observability.sdk.destination", Value: "online", PrevValue: `""`, Category: "destination_online", RequestedBy: "mcp",
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if out, err := runConfigCmdHere(t, "set", "observability.sdk.destination", "local", "--yes", "--config", cfgPath); err != nil {
		t.Fatalf("hand edit: %v\n%s", err, out)
	}
	out, err := runConfigCmdHere(t, "proposals", "approve", jsonNumber(changed), "--yes", "--config", cfgPath)
	if err == nil || !strings.Contains(err.Error(), "changed after the agent asked") {
		t.Fatalf("approving over a hand edit = %v\n%s, want a refusal", err, out)
	}
	cfg, _ := config.Load(config.LoadOptions{GlobalPath: cfgPath})
	if cfg.Observability.SDK.Destination != "local" {
		t.Fatalf("the hand-set value was overwritten: %q", cfg.Observability.SDK.Destination)
	}
	if p, _ := st.GetSettingsProposal(ctx, changed); p.Status != store.SettingsProposalPending {
		t.Fatalf("a refused approval changed the status: %+v", p)
	}

	old, err := st.FileSettingsProposal(ctx, store.NewSettingsProposal{
		Key: "observability.sdk.destination", Value: "online", PrevValue: "local", Category: "destination_online", RequestedBy: "mcp",
	}, time.Now().Add(-30*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runConfigCmdHere(t, "proposals", "approve", jsonNumber(old), "--yes", "--config", cfgPath); err == nil || !strings.Contains(err.Error(), "older than") {
		t.Fatalf("approving an expired proposal = %v, want a refusal", err)
	}
	if _, err := runConfigCmdHere(t, "proposals", "reject", jsonNumber(old), "--config", cfgPath); err != nil {
		t.Fatalf("rejecting an expired proposal must work: %v", err)
	}
}

// TestProposalValuesArePrintedSafely pins review E-51: an agent-authored
// value with control characters is printed escaped, never raw, and a
// secret-shaped value is hidden.
func TestProposalValuesArePrintedSafely(t *testing.T) {
	ctx := context.Background()
	cfgPath, st := proposalTestStore(t)
	const evil = "local\x1b[2K\rsafe"
	id, err := st.FileSettingsProposal(ctx, store.NewSettingsProposal{
		Key: "observability.sdk.destination", Value: evil, Category: "destination_online", Reason: "it sends\x1b[1A data", RequestedBy: "mcp",
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.FileSettingsProposal(ctx, store.NewSettingsProposal{
		Key: "observability.sdk.gateway_url", Value: "https://gw.example.com/?token=ghp_" + strings.Repeat("aB3dE5", 6), Category: "destination_online", RequestedBy: "mcp",
	}, time.Now()); err != nil {
		t.Fatal(err)
	}
	out, err := runConfigCmdHere(t, "proposals", "--config", cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(out, "\x1b\r") {
		t.Fatalf("listing prints a raw control character: %q", out)
	}
	if !strings.Contains(out, `"local\x1b[2K\rsafe"`) {
		t.Fatalf("listing does not show the escaped value: %q", out)
	}
	if strings.Contains(out, "ghp_") || !strings.Contains(out, "(hidden)") {
		t.Fatalf("a secret-shaped value is not hidden: %q", out)
	}
	_, err = runConfigCmdHere(t, "proposals", "approve", jsonNumber(id), "--config", cfgPath)
	if err == nil || strings.ContainsAny(err.Error(), "\x1b\r") {
		t.Fatalf("approve prompt = %q, want an escaped refusal", err)
	}
}
