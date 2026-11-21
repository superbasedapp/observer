package store

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestGrantGuardApprovalIdempotent pins the P-232 grant-or-extend seam as a
// table: each case runs a sequence of grants (ttl 0 = never expires) and
// checks every reply's existing flag, the row count for the key, the one
// surviving id and its final expiry.
func TestGrantGuardApprovalIdempotent(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(time.Second)
	never := time.Duration(0)
	type grant struct {
		scope, session, hash string
		ttl                  time.Duration // 0 = never; negative = already expired
		wantExisting         bool
	}
	cases := []struct {
		name       string
		grants     []grant
		wantRows   int           // rows for the first grant's key
		wantExpiry time.Duration // final expiry of the surviving row (0 = never)
	}{
		{"same key twice: one row", []grant{
			{"global", "", "", never, false}, {"global", "", "", never, true},
		}, 1, never},
		{"a longer ttl extends", []grant{
			{"session", "s1", "", 2 * time.Hour, false}, {"session", "s1", "", 24 * time.Hour, true},
		}, 1, 24 * time.Hour},
		{"a shorter ttl never shortens", []grant{
			{"session", "s1", "", 24 * time.Hour, false}, {"session", "s1", "", 2 * time.Hour, true},
		}, 1, 24 * time.Hour},
		{"never beats a ttl", []grant{
			{"project", "", "ph", 2 * time.Hour, false}, {"project", "", "ph", never, true},
		}, 1, never},
		{"a ttl over never changes nothing", []grant{
			{"project", "", "ph", never, false}, {"project", "", "ph", 2 * time.Hour, true},
		}, 1, never},
		{"an expired grant is re-granted in place", []grant{
			{"session", "s1", "", -time.Hour, false}, {"session", "s1", "", 3 * time.Hour, true},
		}, 1, 3 * time.Hour},
		{"a different session is a new row", []grant{
			{"session", "s1", "", never, false}, {"session", "s2", "", never, false},
		}, 1, never},
		{"a different project is a new row", []grant{
			{"project", "", "ph1", never, false}, {"project", "", "ph2", never, false},
		}, 1, never},
		{"a different scope is a new row", []grant{
			{"global", "", "", never, false}, {"session", "s1", "", never, false},
		}, 1, never},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s, _ := newTestStore(t)
			ctx := context.Background()
			var firstID int64
			for i, g := range tc.grants {
				row := GuardApprovalRow{
					TS: now.Add(time.Duration(i) * time.Minute), RuleID: "S-794", Scope: g.scope,
					SessionID: g.session, ProjectRootHash: g.hash, GrantedBy: "dashboard",
				}
				if g.ttl != 0 {
					row.ExpiresAt = now.Add(g.ttl)
				}
				id, existing, err := s.GrantGuardApproval(ctx, row)
				if err != nil {
					t.Fatalf("grant %d: %v", i, err)
				}
				if existing != g.wantExisting {
					t.Errorf("grant %d existing = %v, want %v", i, existing, g.wantExisting)
				}
				if i == 0 {
					firstID = id
				} else if g.wantExisting && id != firstID {
					t.Errorf("grant %d id = %d, want the older id %d", i, id, firstID)
				}
			}
			first := tc.grants[0]
			var n int
			var expires string
			if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*), MAX(expires_at) FROM guard_approvals
				WHERE rule_id = 'S-794' AND scope = ? AND session_id = ? AND project_root_hash = ?`,
				first.scope, first.session, first.hash).Scan(&n, &expires); err != nil {
				t.Fatal(err)
			}
			if n != tc.wantRows {
				t.Fatalf("rows for the key = %d, want %d", n, tc.wantRows)
			}
			wantExp := ""
			if tc.wantExpiry != 0 {
				wantExp = timestamp(now.Add(tc.wantExpiry))
			}
			if expires != wantExp {
				t.Errorf("expires_at = %q, want %q", expires, wantExp)
			}
		})
	}
}

// TestGrantGuardApprovalRegrantStampsTheNewGrant: re-granting an expired row
// takes the new grant's ts and granted_by (it is a new decision), while
// extending a live one keeps the original grant's.
func TestGrantGuardApprovalRegrantStampsTheNewGrant(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	read := func(id int64) (ts, by string) {
		t.Helper()
		if err := s.db.QueryRowContext(ctx, `SELECT ts, granted_by FROM guard_approvals WHERE id = ?`, id).Scan(&ts, &by); err != nil {
			t.Fatal(err)
		}
		return ts, by
	}
	live, _, err := s.GrantGuardApproval(ctx, GuardApprovalRow{TS: now, RuleID: "R-1", Scope: "global", GrantedBy: "dashboard", ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.GrantGuardApproval(ctx, GuardApprovalRow{TS: now.Add(time.Minute), RuleID: "R-1", Scope: "global", GrantedBy: "llm_judge", ExpiresAt: now.Add(2 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if ts, by := read(live); ts != timestamp(now) || by != "dashboard" {
		t.Errorf("extended live grant = (%s, %s), want the original (%s, dashboard)", ts, by, timestamp(now))
	}
	expired, _, err := s.GrantGuardApproval(ctx, GuardApprovalRow{TS: now.Add(-2 * time.Hour), RuleID: "R-2", Scope: "global", GrantedBy: "dashboard", ExpiresAt: now.Add(-time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.GrantGuardApproval(ctx, GuardApprovalRow{TS: now, RuleID: "R-2", Scope: "global", GrantedBy: "operator", ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if ts, by := read(expired); ts != timestamp(now) || by != "operator" {
		t.Errorf("re-granted expired row = (%s, %s), want the new grant's (%s, operator)", ts, by, timestamp(now))
	}
}

// TestProbeGuardApprovalsSeesAnExtend: the org snapshot's change probe moves
// when a repeated grant extends a row in place (no new id, same count), so
// the org sees the new expiry on the next push instead of an hour later.
func TestProbeGuardApprovalsSeesAnExtend(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	probe := func() string {
		t.Helper()
		fp, err := s.probeGuardApprovals(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return fp
	}
	grant := func(ttl time.Duration) {
		t.Helper()
		row := GuardApprovalRow{TS: now, RuleID: "S-794", Scope: "global", GrantedBy: "dashboard"}
		if ttl > 0 {
			row.ExpiresAt = now.Add(ttl)
		}
		if _, _, err := s.GrantGuardApproval(ctx, row); err != nil {
			t.Fatal(err)
		}
	}
	grant(time.Hour)
	p1 := probe()
	grant(2 * time.Hour)
	p2 := probe()
	grant(0)
	p3 := probe()
	if p1 == p2 || p2 == p3 {
		t.Fatalf("probe did not move across extends: %q, %q, %q", p1, p2, p3)
	}
	grant(time.Hour) // a ttl over never changes nothing
	if p4 := probe(); p4 != p3 {
		t.Fatalf("probe moved on a no-op grant: %q -> %q", p3, p4)
	}
}

// approvalAuditReasons returns the reasons of the guard_approval audit
// events, oldest first.
func approvalAuditReasons(t *testing.T, s *Store) []string {
	t.Helper()
	rows, err := s.db.QueryContext(context.Background(), `
		SELECT reason, event_kind, decision, COALESCE(tool, '') FROM guard_events
		 WHERE rule_id = ? ORDER BY id`, GuardApprovalAuditRuleID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var reason, kind, decision, tool string
		if err := rows.Scan(&reason, &kind, &decision, &tool); err != nil {
			t.Fatal(err)
		}
		if kind != "audit" || decision != "allow" {
			t.Errorf("audit row kind=%q decision=%q, want audit/allow (never a verdict)", kind, decision)
		}
		out = append(out, tool+"|"+reason)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestGrantGuardApprovalAuditTrail pins P-232 fix round 1 (M1): one row per
// key keeps one grantor, so every create, extend and re-grant is an audit
// event on the guard_events chain naming the op, the channel and actor, the
// expiries and, on an extend or re-grant, the previous grantor. Table: each
// case runs its grants and checks the audit record in order.
func TestGrantGuardApprovalAuditTrail(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(time.Second)
	type grant struct {
		by, channel string
		at          time.Duration // grant time relative to now
		ttl         time.Duration // 0 = never
	}
	cases := []struct {
		name   string
		grants []grant
		// want: per audit event, substrings its "tool|reason" must hold.
		want [][]string
		// wantRowBy is the grant row's granted_by after the sequence.
		wantRowBy string
	}{
		{
			name: "an extend by a second actor leaves both actors on the record",
			grants: []grant{
				{"dashboard", "dashboard", 0, time.Hour},
				{"santa", "cli", time.Minute, 24 * time.Hour},
			},
			want: [][]string{
				{"dashboard|", "approval create: rule S-794 scope global", "by dashboard (dashboard)"},
				{"cli|", "approval extend:", "by cli (santa)", "(was " + timestamp(now.Add(time.Hour)) + ")", "previously granted by dashboard at " + timestamp(now)},
			},
			wantRowBy: "dashboard",
		},
		{
			name: "a re-grant after expiry keeps the earlier grantor on the record",
			grants: []grant{
				{"llm_judge", "judge", -3 * time.Hour, time.Hour},
				{"dashboard", "dashboard", 0, 0},
			},
			want: [][]string{
				{"judge|", "approval create:", "by judge (llm_judge)"},
				{"dashboard|", "approval re-grant:", "by dashboard (dashboard); expires never", "previously granted by llm_judge at " + timestamp(now.Add(-3*time.Hour))},
			},
			wantRowBy: "dashboard",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s, _ := newTestStore(t)
			ctx := context.Background()
			var id int64
			for i, g := range tc.grants {
				row := GuardApprovalRow{TS: now.Add(g.at), RuleID: "S-794", Scope: "global", GrantedBy: g.by, Channel: g.channel}
				if g.ttl != 0 {
					row.ExpiresAt = now.Add(g.at).Add(g.ttl)
				}
				got, _, err := s.GrantGuardApproval(ctx, row)
				if err != nil {
					t.Fatalf("grant %d: %v", i, err)
				}
				id = got
			}
			reasons := approvalAuditReasons(t, s)
			if len(reasons) != len(tc.want) {
				t.Fatalf("audit events = %q, want %d", reasons, len(tc.want))
			}
			for i, subs := range tc.want {
				for _, sub := range subs {
					if !strings.Contains(reasons[i], sub) {
						t.Errorf("audit event %d %q lacks %q", i, reasons[i], sub)
					}
				}
			}
			var by string
			if err := s.db.QueryRowContext(ctx, `SELECT granted_by FROM guard_approvals WHERE id = ?`, id).Scan(&by); err != nil {
				t.Fatal(err)
			}
			if by != tc.wantRowBy {
				t.Errorf("grant row granted_by = %q, want %q", by, tc.wantRowBy)
			}
			// The audit rows are on the hash chain like every guard event,
			// and never count as verdicts.
			sum, err := s.SummarizeGuardEventsBetween(ctx, time.Time{}, time.Time{})
			if err != nil {
				t.Fatal(err)
			}
			if sum.Total != 0 {
				t.Errorf("verdict summary total = %d, want 0 (audit rows are not verdicts)", sum.Total)
			}
		})
	}
}
