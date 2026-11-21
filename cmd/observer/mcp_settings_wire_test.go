//go:build !sbo_omit_integration_mcp_server

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/mcp"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestMCPSettingsBackendAppliesOrdinaryAndProposesSensitive is the D19 gate
// end to end through the cmd backend: an ordinary key lands in the file, a
// sensitive one only files a proposal (the file is untouched), and approving
// it from the CLI writes the value and marks the proposal.
func TestMCPSettingsBackendAppliesOrdinaryAndProposesSensitive(t *testing.T) {
	cfgPath, dbPath := settingsTestEnv(t)
	ctx := context.Background()
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o700); err != nil {
		t.Fatal(err)
	}
	database, err := db.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	b := newMCPSettingsBackend(cfgPath, database)

	res, err := b.SetSetting(ctx, mcp.SetSettingRequest{Key: "observer.retention.prune_on_startup", Value: "false", Client: "test-client"})
	if err != nil || res.Status != "applied" {
		t.Fatalf("ordinary key: %+v %v", res, err)
	}
	res, err = b.SetSetting(ctx, mcp.SetSettingRequest{Key: "observability.sdk.destination", Value: "online", Client: "test-client", Note: "send to the team"})
	if err != nil || res.Status != "proposed" || res.Proposal == 0 || res.Category != "destination_online" {
		t.Fatalf("sensitive key: %+v %v", res, err)
	}
	cfg, err := config.Load(config.LoadOptions{GlobalPath: cfgPath})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Observer.Retention.PruneOnStartup {
		t.Fatalf("ordinary key was not written: %v", cfg.Observer.Retention.PruneOnStartup)
	}
	if cfg.Observability.SDK.Destination != "" {
		t.Fatalf("a proposal must not write: destination = %q", cfg.Observability.SDK.Destination)
	}
	res, err = b.SetSetting(ctx, mcp.SetSettingRequest{Key: "observability.sdk.destination", Value: "sideways"})
	if err != nil || res.Status != "refused" {
		t.Fatalf("an invalid value is refused before a proposal is filed: %+v %v", res, err)
	}
	res, err = b.SetSetting(ctx, mcp.SetSettingRequest{Key: "observability.alerts.webhook_url", Value: "https://example.com/hook?token=ghp_" + strings.Repeat("aB3dE5", 6)})
	if err != nil || res.Status != "refused" {
		t.Fatalf("a credential-shaped value is refused: %+v %v", res, err)
	}

	st := store.New(database)
	pending, err := st.ListSettingsProposals(ctx, true, 0)
	if err != nil || len(pending) != 1 || pending[0].RequestedBy != "mcp:test-client" || pending[0].Note != "send to the team" {
		t.Fatalf("pending = %+v %v", pending, err)
	}
	id := pending[0].ID
	if _, err := runConfigCmdHere(t, "proposals", "approve", jsonNumber(id), "--config", cfgPath); err == nil {
		t.Fatal("approve without --yes must refuse")
	}
	out, err := runConfigCmdHere(t, "proposals", "approve", jsonNumber(id), "--yes", "--config", cfgPath)
	if err != nil {
		t.Fatalf("approve: %v\n%s", err, out)
	}
	cfg, _ = config.Load(config.LoadOptions{GlobalPath: cfgPath})
	if cfg.Observability.SDK.Destination != "online" {
		t.Fatalf("approval did not write: %q", cfg.Observability.SDK.Destination)
	}
	p, _ := st.GetSettingsProposal(ctx, id)
	if p.Status != store.SettingsProposalApproved || !strings.HasPrefix(p.DecidedBy, "cli") {
		t.Fatalf("proposal after approval = %+v", p)
	}
	if _, err := runConfigCmdHere(t, "proposals", "reject", jsonNumber(id), "--config", cfgPath); err == nil {
		t.Fatal("a decided proposal cannot be rejected")
	}
	out, err = runConfigCmdHere(t, "proposals", "--all", "--config", cfgPath)
	if err != nil || !strings.Contains(out, "approved") {
		t.Fatalf("proposals --all = %q %v", out, err)
	}

	got, err := b.GetSettings(ctx, mcp.SettingsQuery{Key: "observability.sdk.destination"})
	if err != nil || got.(settingView).Value != "online" {
		t.Fatalf("GetSettings = %+v %v", got, err)
	}
}
