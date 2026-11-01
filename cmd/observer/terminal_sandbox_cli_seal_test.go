//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals && !sbo_omit_isolation_seal

package main

import (
	"context"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/execevidence"
	"github.com/marmutapp/superbased-observer/internal/keystore"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/termrun"
)

// TestSandboxCLIRunIsSealed (lane GATES-SEC residual, LEFT-SBX merged): a
// sandboxed CLI launch's terminal_run row is sealed when isolation.seal is
// selected, the seal verifies over the row's evidence digest, and the
// handle's sealer is removed after the write; with the component off the
// row is unsealed.
func TestSandboxCLIRunIsSealed(t *testing.T) {
	ctx := context.Background()
	ks := &keystore.MemStore{}
	prev := evidenceSealOpenStore
	evidenceSealOpenStore = func(config.Config, *slog.Logger) keystore.Store { return ks }
	t.Cleanup(func() { evidenceSealOpenStore = prev })
	iso := termrun.Isolation{
		Class: "process", Stack: []string{"bwrap"}, EgressTier: "internet", CaptureLevel: "full",
		CaptureRule: "C6", CaptureOrigin: "sandboxed", Verification: "live", KeyCustody: "host_bound",
	}
	seal := func(cfg config.Config) (store.TerminalRunSeal, string) {
		t.Helper()
		runID, err := recordSandboxCLIRun(ctx, cfg, "claude-code", t.TempDir(), iso)
		if err != nil {
			t.Fatal(err)
		}
		database, closeDB, err := openDBForConfig(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer closeDB()
		st := store.New(database)
		s, err := st.TerminalRunSealOf(ctx, runID)
		if err != nil {
			t.Fatal(err)
		}
		var digest string
		if err := database.QueryRowContext(ctx, `SELECT evidence_digest FROM terminal_run WHERE run_id = ?`, runID).Scan(&digest); err != nil {
			t.Fatal(err)
		}
		return s, digest
	}
	on := config.Config{}
	on.Observer.DBPath = filepath.Join(t.TempDir(), "observer.db")
	on.Components = config.ComponentsConfig{Distro: "full", Add: []string{"isolation", "isolation.seal"}}
	s, digest := seal(on)
	if s.KeyID == "" || digest == "" {
		t.Fatalf("the sandboxed CLI run is not sealed: %+v (digest %q)", s, digest)
	}
	if err := execevidence.VerifySeal(execevidence.Seal{KeyID: s.KeyID, PublicKey: s.PublicKey, Sig: s.Sig}, digest); err != nil {
		t.Fatalf("the seal does not verify: %v", err)
	}
	off := config.Config{}
	off.Observer.DBPath = filepath.Join(t.TempDir(), "observer.db")
	if s, _ := seal(off); s.KeyID != "" {
		t.Fatalf("a run was sealed with isolation.seal off: %+v", s)
	}
}
