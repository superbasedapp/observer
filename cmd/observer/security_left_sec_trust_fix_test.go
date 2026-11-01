//go:build !sbo_omit_security && !sbo_omit_security_trust

package main

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestLeftSecSessionStartHonoursLocalTrustStep (audit F5): the session-start
// flag applies the node's own [security.trust] prelaunch = ask the way the
// launch path does, and its line says so; the default warn changes nothing.
func TestLeftSecSessionStartHonoursLocalTrustStep(t *testing.T) {
	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "obs.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	st := store.New(database)
	root := writeTrustRepo(t, map[string]string{".mcp.json": `{"mcpServers":{"fs":{"command":"npx","args":["server"]}}}`})
	now := time.Now()

	_, plain, err := flagSessionStartTrust(ctx, st, "codex", root, "", now)
	if err != nil {
		t.Fatal(err)
	}
	if plain.localRaised || plain.verdict.Decision >= policy.DecisionAsk {
		t.Fatalf("the default step raised the verdict: %+v", plain.verdict)
	}
	trust := config.SecurityTrustConfig{Prelaunch: "ask"}
	_, out, err := flagSessionStartTrustWith(ctx, st, "codex", root, "", repoTrustLocalStep(trust), now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if !out.localRaised || out.verdict.Decision != policy.DecisionAsk {
		t.Fatalf("prelaunch = ask did not reach the session-start flag: %+v", out.verdict)
	}
	if line := sessionStartTrustLine(out, 1, false); !strings.Contains(line, "your [security.trust] prelaunch setting asks before a launch here") {
		t.Fatalf("line %q", line)
	}
}
