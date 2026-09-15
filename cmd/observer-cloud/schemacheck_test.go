package main

import (
	"context"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/cloudtestpg"
	clouddb "github.com/marmutapp/superbased-observer/internal/cloudserver/db"
)

func TestSchemaCheckOutcome(t *testing.T) {
	cases := []struct {
		name             string
		embedded         int
		deployed         int
		wantCode         int
		wantMessageParts []string
	}{
		{"match", 33, 33, schemaCheckExitMatch, []string{"schema OK", "embedded head=33", "deployed=33"}},
		{"match_zero", 0, 0, schemaCheckExitMatch, []string{"schema OK"}},
		{"behind", 33, 32, schemaCheckExitBehind, []string{"BEHIND", "observer-cloud migrate"}},
		{"ahead", 33, 40, schemaCheckExitAhead, []string{"AHEAD", "older than the database"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			msg, code := schemaCheckOutcome(c.embedded, c.deployed)
			if code != c.wantCode {
				t.Fatalf("schemaCheckOutcome(%d, %d) code = %d, want %d", c.embedded, c.deployed, code, c.wantCode)
			}
			for _, part := range c.wantMessageParts {
				if !strings.Contains(msg, part) {
					t.Fatalf("message %q does not contain %q", msg, part)
				}
			}
		})
	}
}

// TestSchemaCheckAgainstThrowawayPG runs the real embedded/deployed reads
// (clouddb.MaxEmbeddedVersion + clouddb.Version, and a redundant
// clouddb.Migrate to prove it's idempotent at head) against a throwaway
// Postgres — the D5 "test against the throwaway PG" requirement. Skips
// gracefully when SBCI_TEST_PG_DSN is unset (cloudtestpg.NewDB).
//
// cloudtestpg.NewDB ALREADY migrates the returned pool to head (that's the
// whole point of the harness — every store test gets a fully-migrated,
// isolated database) — so unlike a hand-rolled clouddb.Open, there is no
// "fresh, unmigrated" state to observe here. The BEHIND/AHEAD arithmetic is
// exhaustively covered by the pure TestSchemaCheckOutcome above; this test's
// job is narrower and PG-specific: prove the real clouddb.Version call
// against a real database returns exactly what a real clouddb.Migrate
// produced, which is the one thing a pure unit test can't check.
func TestSchemaCheckAgainstThrowawayPG(t *testing.T) {
	pool := cloudtestpg.NewDB(t)
	ctx := context.Background()

	embedded, err := clouddb.MaxEmbeddedVersion()
	if err != nil {
		t.Fatalf("MaxEmbeddedVersion: %v", err)
	}

	deployed, err := clouddb.Version(ctx, pool)
	if err != nil {
		t.Fatalf("Version: %v", err)
	}
	if deployed != embedded {
		t.Fatalf("cloudtestpg.NewDB's freshly-migrated database reports schema %d, want the embedded head %d", deployed, embedded)
	}
	if msg, code := schemaCheckOutcome(embedded, deployed); code != schemaCheckExitMatch {
		t.Fatalf("schemaCheckOutcome(%d, %d) = %q, code %d — want schemaCheckExitMatch (%d)",
			embedded, deployed, msg, code, schemaCheckExitMatch)
	}

	// Migrate is idempotent — running it again against an already-head
	// database must be a no-op, not an error, and the version must not move.
	if err := clouddb.Migrate(ctx, pool); err != nil {
		t.Fatalf("Migrate (idempotent re-run): %v", err)
	}
	deployedAfter, err := clouddb.Version(ctx, pool)
	if err != nil {
		t.Fatalf("Version (after idempotent re-migrate): %v", err)
	}
	if deployedAfter != embedded {
		t.Fatalf("re-running Migrate against a head database changed the version: %d -> %d", embedded, deployedAfter)
	}
}
