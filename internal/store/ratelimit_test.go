package store

import (
	"context"
	"testing"
)

// codex token_count rate_limits envelope, as the adapter marshals it into
// actions.raw_tool_input. primary = 5h window, secondary = weekly.
const codexRateLimitRawJSON = `{"limit_id":"codex","primary":{"used_percent":18,"window_minutes":300,"resets_at":1778867450},"secondary":{"used_percent":3,"window_minutes":10080,"resets_at":1779454250},"plan_type":"plus","rate_limit_reached_type":null}`

func TestParseRateLimitWindows(t *testing.T) {
	t.Parallel()
	w, ok := parseRateLimitWindows(codexRateLimitRawJSON)
	if !ok {
		t.Fatal("parseRateLimitWindows: ok=false, want true")
	}
	if w.Window5hUtil == nil || *w.Window5hUtil != 0.18 {
		t.Errorf("5h util = %v, want 0.18", w.Window5hUtil)
	}
	if w.Window7dUtil == nil || *w.Window7dUtil != 0.03 {
		t.Errorf("7d util = %v, want 0.03", w.Window7dUtil)
	}
	if w.Window5hReset == nil || *w.Window5hReset != 1778867450 {
		t.Errorf("5h reset = %v, want 1778867450", w.Window5hReset)
	}
	if w.PlanType != "plus" {
		t.Errorf("plan = %q, want plus", w.PlanType)
	}

	// Garbage / non-rate_limit body → ok=false, never panics.
	if _, ok := parseRateLimitWindows("not json"); ok {
		t.Error("garbage body parsed ok=true, want false")
	}
	if _, ok := parseRateLimitWindows(`{"limit_id":"codex"}`); ok {
		t.Error("window-less body parsed ok=true, want false")
	}
}

// TestParseRateLimitWindowsClassifyByDuration pins the 2026-09-22 fix:
// each window is classified by its OWN window_minutes, never by whether
// Codex called it "primary" or "secondary". Live-observed shape: a
// "prolite"-plan account reports only ONE window, and it is the WEEKLY
// one (window_minutes=10080), crammed into the "primary" slot with
// secondary=null. Before this fix that window rendered under the
// "5-hour window" label with the weekly cap showing n/a.
func TestParseRateLimitWindowsClassifyByDuration(t *testing.T) {
	t.Parallel()

	t.Run("single weekly window in the primary slot", func(t *testing.T) {
		t.Parallel()
		// Live 2026-09-22 shape (anonymized: real field values, no account
		// identifiers). plan_type is null in the live capture but that is
		// Fix A's concern, not Fix B's — set a benign non-null value here
		// so this test isolates the classification logic.
		raw := `{"limit_id":"codex","primary":{"used_percent":2,"window_minutes":10080,"resets_at":1790578122},"secondary":null,"plan_type":"prolite","rate_limit_reached_type":null}`
		w, ok := parseRateLimitWindows(raw)
		if !ok {
			t.Fatal("ok=false, want true")
		}
		if w.Window5hUtil != nil {
			t.Errorf("Window5hUtil = %v, want nil (a 10080-minute window must never render as \"5-hour\")", w.Window5hUtil)
		}
		if w.Window7dUtil == nil || *w.Window7dUtil != 0.02 {
			t.Errorf("Window7dUtil = %v, want 0.02", w.Window7dUtil)
		}
		if w.Window7dReset == nil || *w.Window7dReset != 1790578122 {
			t.Errorf("Window7dReset = %v, want 1790578122", w.Window7dReset)
		}
	})

	t.Run("both windows in the same class (defensive, not observed live)", func(t *testing.T) {
		t.Parallel()
		// Two short windows: the larger used_percent must win, not an
		// arbitrary last-write.
		raw := `{"limit_id":"codex","primary":{"used_percent":10,"window_minutes":300,"resets_at":100},"secondary":{"used_percent":40,"window_minutes":250,"resets_at":200},"plan_type":"plus","rate_limit_reached_type":null}`
		w, ok := parseRateLimitWindows(raw)
		if !ok {
			t.Fatal("ok=false, want true")
		}
		if w.Window7dUtil != nil {
			t.Errorf("Window7dUtil = %v, want nil (neither window is weekly-class)", w.Window7dUtil)
		}
		if w.Window5hUtil == nil || *w.Window5hUtil != 0.40 {
			t.Errorf("Window5hUtil = %v, want 0.40 (the larger of the two same-class readings)", w.Window5hUtil)
		}
		if w.Window5hReset == nil || *w.Window5hReset != 200 {
			t.Errorf("Window5hReset = %v, want 200 (paired with the winning 0.40 reading)", w.Window5hReset)
		}
	})

	t.Run("dual-window shape unaffected (regression)", func(t *testing.T) {
		t.Parallel()
		w, ok := parseRateLimitWindows(codexRateLimitRawJSON)
		if !ok {
			t.Fatal("ok=false, want true")
		}
		if w.Window5hUtil == nil || *w.Window5hUtil != 0.18 {
			t.Errorf("Window5hUtil = %v, want 0.18 (300min primary, unaffected by the classifier change)", w.Window5hUtil)
		}
		if w.Window7dUtil == nil || *w.Window7dUtil != 0.03 {
			t.Errorf("Window7dUtil = %v, want 0.03 (10080min secondary, unaffected)", w.Window7dUtil)
		}
	})
}

func TestLatestRateLimitWindows(t *testing.T) {
	t.Parallel()
	st, db := newTestStore(t)
	ctx := context.Background()

	pid, err := st.UpsertProject(ctx, "/tmp/rl", "")
	if err != nil {
		t.Fatalf("UpsertProject: %v", err)
	}
	if _, err := db.ExecContext(ctx,
		`INSERT INTO sessions (id, project_id, tool, started_at) VALUES (?,?,?,?)`,
		"sCodex", pid, "codex", "2026-05-15T12:00:00Z"); err != nil {
		t.Fatalf("insert session: %v", err)
	}

	insertRL := func(ts, raw string) {
		t.Helper()
		if _, err := db.ExecContext(ctx,
			`INSERT INTO actions (session_id, project_id, timestamp, action_type, tool, raw_tool_input, source_file, source_event_id)
			 VALUES (?,?,?,?,?,?,?,?)`,
			"sCodex", pid, ts, "rate_limit", "codex", raw,
			"rollout.jsonl", "ratelimit:rollout.jsonl:"+ts); err != nil {
			t.Fatalf("insert rate_limit action: %v", err)
		}
	}

	// No rows yet → ok=false (every non-codex tool stays here forever).
	if _, ok, err := st.LatestRateLimitWindows(ctx, "codex", "sCodex"); err != nil || ok {
		t.Fatalf("empty: ok=%v err=%v, want ok=false", ok, err)
	}

	// Older then newer; the newest by timestamp must win.
	insertRL("2026-05-15T12:30:00Z", codexRateLimitRawJSON)
	newer := `{"limit_id":"codex","primary":{"used_percent":55,"window_minutes":300,"resets_at":1778870000},"secondary":{"used_percent":9,"window_minutes":10080,"resets_at":1779454250},"plan_type":"plus","rate_limit_reached_type":null}`
	insertRL("2026-05-15T12:45:00Z", newer)

	got, ok, err := st.LatestRateLimitWindows(ctx, "codex", "sCodex")
	if err != nil || !ok {
		t.Fatalf("latest: ok=%v err=%v", ok, err)
	}
	if got.Window5hUtil == nil || *got.Window5hUtil != 0.55 {
		t.Errorf("latest 5h util = %v, want 0.55 (newest)", got.Window5hUtil)
	}
	if got.ObservedAt.IsZero() {
		t.Error("ObservedAt not set")
	}

	// Account-wide fallback: a session with no rate_limit row of its own
	// still gets the tool's most-recent window.
	if _, err := db.ExecContext(ctx,
		`INSERT INTO sessions (id, project_id, tool, started_at) VALUES (?,?,?,?)`,
		"sFresh", pid, "codex", "2026-05-15T13:00:00Z"); err != nil {
		t.Fatalf("insert fresh session: %v", err)
	}
	got2, ok, err := st.LatestRateLimitWindows(ctx, "codex", "sFresh")
	if err != nil || !ok {
		t.Fatalf("fallback: ok=%v err=%v", ok, err)
	}
	if got2.Window5hUtil == nil || *got2.Window5hUtil != 0.55 {
		t.Errorf("fallback 5h util = %v, want 0.55", got2.Window5hUtil)
	}
}
