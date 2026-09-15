// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 SuperBased

package store

import (
	"context"
	"strings"
	"testing"
	"time"
)

// insertCacheEventRaw writes one cache_events row directly, so a test can set
// the columns the typed InsertCacheEvents path does not expose (detail, and an
// explicit NULL for the two nullable numerics).
func insertCacheEventRaw(ctx context.Context, t *testing.T, s *Store, session, model string, ts time.Time, detail string) {
	t.Helper()
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO cache_events
		   (session_id, tier, timestamp, model, kind, cause,
		    diverged_seq, diverged_level, tokens_read, tokens_written,
		    tokens_written_1h, cost_delta_usd, predicted_kind, message_id, detail)
		 VALUES (?, 'proxy', ?, ?, 'hit', 'suffix_growth', NULL, NULL, 9000, 0, 0, NULL, NULL, NULL, ?)`,
		session, timestamp(ts), model, detail); err != nil {
		t.Fatalf("insert cache_events: %v", err)
	}
}

// TestSelectSessionCacheEvents_GateIsStructural proves the seam refuses on its
// own, independently of orgpush.go's outer shipsRawContent() block. Both gates
// exist on purpose: a future caller that forgets the outer one must still not
// be able to get per-event cache rows out of this function.
//
// It also pins the ORTHOGONALITY of the fleet tier: CacheDetail alone unlocks
// nothing here.
func TestSelectSessionCacheEvents_GateIsStructural(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestStore(t)
	insertCacheEventRaw(ctx, t, s, "sess-1", "claude-opus-4-7", time.Now().UTC(), "")

	for _, tc := range []struct {
		name  string
		share ShareOptions
		want  int
	}{
		{"zero-value", ShareOptions{}, 0},
		{"cache_detail-only", ShareOptions{CacheDetail: true}, 0},
		{"full_content", ShareOptions{FullContent: true}, 1},
		{"admin_managed", ShareOptions{AdminManaged: true}, 1},
		{"enterprise_granted", ShareOptions{EnterpriseGranted: true}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rows, err := s.SelectSessionCacheEvents(ctx, tc.share)
			if err != nil {
				t.Fatalf("SelectSessionCacheEvents: %v", err)
			}
			if len(rows) != tc.want {
				t.Errorf("rows = %d, want %d under %s — the gate must live in the seam, not only at the call site",
					len(rows), tc.want, tc.name)
			}
		})
	}
}

// TestSelectSessionCacheEvents_ExcludesDetailColumn is the structural half of
// the `detail` exclusion: rather than only checking that no scanned value
// carries it, this asserts the SELECT list itself never names the column. The
// value can never reach the process, so there is no window in which it sits in
// a wire row awaiting a strip step someone could forget.
func TestSelectSessionCacheEvents_ExcludesDetailColumn(t *testing.T) {
	if strings.Contains(sessionCacheEventsQuery, "detail") {
		t.Error("sessionCacheEventsQuery names `detail` — the engine's diagnostic JSON is excluded BY POLICY " +
			"and must not be selected at any posture")
	}
	for _, forbidden := range []string{"api_turn_id", "token_usage_id", "prefix_hash", "cache_scope"} {
		if strings.Contains(sessionCacheEventsQuery, forbidden) {
			t.Errorf("sessionCacheEventsQuery names %q — node-local anchor ids and cache/prefix hashes "+
				"have no org referent and are not part of this wire", forbidden)
		}
	}
}

// TestSelectSessionCacheEvents_WindowAndCap pins the two bounds this wire
// relies on in place of a cursor: the trailing window and the per-session cap.
// Both matter because, unlike its bucketed siblings, this family is one row per
// cache-touching turn.
func TestSelectSessionCacheEvents_WindowAndCap(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestStore(t)
	now := time.Now().UTC()

	// One event outside the trailing window.
	insertCacheEventRaw(ctx, t, s, "sess-old", "m", now.AddDate(0, 0, -(sessionCacheEventWindowDays+2)), "")
	// More than the per-session cap, inside the window.
	for i := 0; i < sessionCacheEventCap+25; i++ {
		insertCacheEventRaw(ctx, t, s, "sess-hot", "m", now.Add(-time.Duration(i)*time.Minute), "")
	}

	rows, err := s.SelectSessionCacheEvents(ctx, ShareOptions{FullContent: true})
	if err != nil {
		t.Fatalf("SelectSessionCacheEvents: %v", err)
	}
	perSession := map[string]int{}
	for _, r := range rows {
		perSession[r.SessionID]++
	}
	if perSession["sess-old"] != 0 {
		t.Errorf("events outside the %d-day window shipped (%d) — the recompute must stay bounded",
			sessionCacheEventWindowDays, perSession["sess-old"])
	}
	if got := perSession["sess-hot"]; got != sessionCacheEventCap {
		t.Errorf("per-session rows = %d, want the cap %d — the cap is enforced IN SQL so discarded rows "+
			"never reach the Go scan", got, sessionCacheEventCap)
	}
	// Chronological within a session: BuildTimeline's contiguous-run collapse
	// depends on it, and the cap must have dropped the OLDEST events, not the
	// newest — a timeline missing its most recent turns is the useless half.
	var last string
	for _, r := range rows {
		if r.SessionID != "sess-hot" {
			continue
		}
		if last != "" && r.Timestamp < last {
			t.Fatalf("rows are not chronological: %q after %q", r.Timestamp, last)
		}
		last = r.Timestamp
	}
	if last == "" {
		t.Fatal("no sess-hot rows at all")
	}
}

// TestSelectSessionCacheEvents_PreservesNulls pins the honesty rule on the two
// nullable numerics in the seam itself: a stored NULL must arrive as a nil
// pointer, because 0 is a REAL reading for both columns (block 0 diverged / a
// genuinely zero cost delta).
//
// It ALSO pins ZeroUsageOf's one rule (orgcontract delegates to
// cachetrack.IsZeroUsage): a 0/0 HIT or WRITE is NOT vacant — only a mispredict
// whose provider envelope carried no token data is. The write row and the
// mispredict row both carry a zero token pair, so the discrimination is on Kind
// alone.
func TestSelectSessionCacheEvents_PreservesNulls(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestStore(t)
	now := time.Now().UTC()
	insertCacheEventRaw(ctx, t, s, "sess-1", "m", now, "")
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO cache_events
		   (session_id, tier, timestamp, model, kind, diverged_seq, cost_delta_usd, tokens_read, tokens_written)
		 VALUES ('sess-1', 'proxy', ?, 'm', 'write', 0, 0, 0, 0)`, timestamp(now.Add(time.Minute))); err != nil {
		t.Fatalf("insert zero-valued row: %v", err)
	}
	// A mispredict with a zero token pair: THIS one is the vacant case.
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO cache_events
		   (session_id, tier, timestamp, model, kind, tokens_read, tokens_written)
		 VALUES ('sess-1', 'proxy', ?, 'm', 'mispredict', 0, 0)`, timestamp(now.Add(2*time.Minute))); err != nil {
		t.Fatalf("insert zero-usage mispredict row: %v", err)
	}

	rows, err := s.SelectSessionCacheEvents(ctx, ShareOptions{FullContent: true})
	if err != nil {
		t.Fatalf("SelectSessionCacheEvents: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("rows = %d, want 3", len(rows))
	}
	var sawNil, sawZero, sawMispredict bool
	for _, r := range rows {
		switch r.Kind {
		case "hit":
			sawNil = true
			if r.DivergedSeq != nil || r.CostDeltaUSD != nil {
				t.Errorf("NULL columns arrived non-nil (%v / %v) — nil means the engine did not compute it",
					r.DivergedSeq, r.CostDeltaUSD)
			}
			if r.ZeroUsageOf() {
				t.Error("ZeroUsageOf() = true for a 9000-read row — the derivation disagrees with its own tokens")
			}
		case "write":
			sawZero = true
			if r.DivergedSeq == nil || *r.DivergedSeq != 0 {
				t.Errorf("stored 0 arrived as %v — 0 means the FIRST block diverged and must not read as absent", r.DivergedSeq)
			}
			if r.CostDeltaUSD == nil || *r.CostDeltaUSD != 0 {
				t.Errorf("stored 0.0 arrived as %v — a zero delta is a value, not an absence", r.CostDeltaUSD)
			}
			if r.ZeroUsageOf() {
				t.Error("ZeroUsageOf() = true for a 0/0 WRITE — only a mispredict with no tokens is vacant, not a write")
			}
		case "mispredict":
			sawMispredict = true
			if !r.ZeroUsageOf() {
				t.Error("ZeroUsageOf() = false for a 0/0 MISPREDICT — the provider returned no token data, so it is vacant")
			}
		}
	}
	if !sawNil || !sawZero || !sawMispredict {
		t.Fatal("all three rows must ship")
	}
}
