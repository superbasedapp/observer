package invariant

import (
	"context"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// sessionquality_wire_test.go pins the BL2-ORG session quality wire
// (docs/plans/post-agent-access-backlog-tracker-2026-09-27.md):
//
//  1. METADATA POSTURE. The score ships in EVERY share mode, including the
//     zero-value metadata-only one: it is a derived, rule-based grade (ratios,
//     token counts, a timestamp) - the SessionLOC / total_actions disclosure
//     class - so no tier and no raw-content gate governs it.
//  2. HONEST ABSENCE. A session the scorer never wrote reaches the org as NO
//     row, never a zero score.
//  3. NO CONTENT-SHAPED FIELD. The wire row carries only numbers, the session
//     id, the stamp and the agent-stamped attribution. A new string field is a
//     wire-shape decision this test makes loud.
func TestSessionQualityShipsAsMetadataAndOnlyWhenScored(t *testing.T) {
	for _, tc := range []struct {
		name  string
		share store.ShareOptions
	}{
		{"metadata_only", store.ShareOptions{}},
		{"full_content", store.ShareOptions{FullContent: true}},
		{"admin_managed", store.ShareOptions{AdminManaged: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			database, err := db.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
			if err != nil {
				t.Fatalf("db.Open: %v", err)
			}
			defer func() { _ = database.Close() }()
			st := store.New(database)
			seed(ctx, t, st) // sess-cc-1, sess-cur-1, sess-cdx-1

			// Exactly ONE session is scored, in the column shape Scorer.Write
			// leaves (RFC3339Nano stamp), so the absence half is non-vacuous.
			if _, err := database.ExecContext(ctx,
				`UPDATE sessions SET quality_score = 0.7, redundancy_ratio = 0.2, error_rate = 0.1,
				        exploration_efficiency = 0.5, continuity_score = 0.6,
				        scored_at = ?, scored_action_count = 3 WHERE id = 'sess-cc-1'`,
				time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
				t.Fatalf("stamp quality: %v", err)
			}

			batch, err := st.SelectUnpushedSince(ctx, store.PushCursor{}, 1<<20, "org-1", "dev@acme.example",
				tc.share, store.ScopeOptions{})
			if err != nil {
				t.Fatalf("SelectUnpushedSince: %v", err)
			}
			if len(batch.SessionQuality) != 1 || batch.SessionQuality[0].SessionID != "sess-cc-1" {
				t.Fatalf("session quality on the wire = %+v, want exactly the one scored session in mode %s",
					batch.SessionQuality, tc.name)
			}
			if batch.SessionQuality[0].QualityScore != 0.7 {
				t.Errorf("quality_score = %v, want 0.7", batch.SessionQuality[0].QualityScore)
			}
		})
	}
}

// TestSessionQualityRowCarriesNoFreeText pins the row's string fields to the
// known, non-content set. Any new string field fails here until it is added
// with a reason.
func TestSessionQualityRowCarriesNoFreeText(t *testing.T) {
	allowed := map[string]string{
		"OrgID":     "agent-stamped attribution, re-stamped server-side",
		"UserEmail": "agent-stamped attribution, re-stamped server-side",
		"SessionID": "the session key, already on the wire as SessionRow.ID",
		"ScoredAt":  "fixed-width UTC timestamp",
	}
	typ := reflect.TypeOf(orgcontract.SessionQualityRow{})
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if f.Type.Kind() != reflect.String {
			continue
		}
		if _, ok := allowed[f.Name]; !ok {
			t.Errorf("SessionQualityRow.%s is a new string field; the quality wire carries numbers only - review it for content before allowing it here", f.Name)
		}
	}
}
