//go:build !sbo_omit_security

package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
)

func secEventKinds(t *testing.T, s *Store, findingID string) []string {
	t.Helper()
	rows, err := s.db.QueryContext(context.Background(), `SELECT kind FROM sec_finding_events WHERE finding_id = ? ORDER BY id`, findingID)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var k string
		_ = rows.Scan(&k)
		out = append(out, k)
	}
	return out
}

func TestSecExceptionGrantEndAndUnblock(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	t0 := time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)
	id, _, err := s.UpsertSecFinding(ctx, secFinding("p1", "k1"), t0)
	if err != nil {
		t.Fatal(err)
	}
	high := SecBlockingQuery{ProjectRootHash: "p1", Severities: []secfinding.Severity{policy.FindingSeverityHigh}}
	exID, err := s.GrantSecException(ctx, SecException{
		FindingID: id, Reason: "false_positive", Expiry: "7d", ExpiresAt: t0.Add(7 * 24 * time.Hour), GrantedBy: "cli", GrantedAt: t0,
	}, policy.FindingStatusFalsePositive)
	if err != nil {
		t.Fatal(err)
	}
	if keys, _ := s.SecBlockingKeys(ctx, high, 10); len(keys) != 0 {
		t.Fatalf("an excepted finding still blocks: %v", keys)
	}
	f, ok, err := s.SecFindingByID(ctx, id)
	if err != nil || !ok || f.Status != policy.FindingStatusFalsePositive || f.ExceptionID != SecExceptionRef(exID) || f.LocalKey != "k1" {
		t.Fatalf("finding after grant: %+v %v %v", f, ok, err)
	}
	// A rescan keeps the exception's status.
	if _, _, err := s.UpsertSecFinding(ctx, secFinding("p1", "k1"), t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if f, _, _ := s.SecFindingByID(ctx, id); f.Status != policy.FindingStatusFalsePositive {
		t.Fatalf("a rescan reopened an excepted finding: %s", f.Status)
	}
	// A second grant on the same finding is refused: it is not open.
	if _, err := s.GrantSecException(ctx, SecException{FindingID: id, Reason: "accepted_risk", Expiry: "1d", GrantedBy: "cli", GrantedAt: t0},
		policy.FindingStatusAcceptedRisk); !errors.Is(err, ErrSecFindingNotOpen) {
		t.Fatalf("second grant: %v", err)
	}
	open, err := s.ListSecExceptions(ctx, SecExceptionFilter{ProjectRootHash: "p1", OpenOnly: true})
	if err != nil || len(open) != 1 || open[0].RuleID != "S-721" || open[0].LocalKey != "k1" || open[0].RelPath != "a.go" {
		t.Fatalf("open exceptions: %+v %v", open, err)
	}
	if err := s.EndSecException(ctx, exID, SecExceptionExpired, t0.Add(8*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if keys, _ := s.SecBlockingKeys(ctx, high, 10); len(keys) != 1 {
		t.Fatalf("an expired exception stops matching: blocking %v", keys)
	}
	if err := s.EndSecException(ctx, exID, SecExceptionRevoked, t0); !errors.Is(err, ErrSecExceptionNotFound) {
		t.Fatalf("ending twice: %v", err)
	}
	got := secEventKinds(t, s, id)
	want := []string{SecEventSeen, SecEventSuppressed, SecEventExceptionExpired}
	if len(got) != len(want) {
		t.Fatalf("events %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("events %v, want %v", got, want)
		}
	}
	if open, _ := s.ListSecExceptions(ctx, SecExceptionFilter{OpenOnly: true}); len(open) != 0 {
		t.Fatalf("ended exception still open: %+v", open)
	}
}

func TestSecExceptionRevokeAndPrune(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	t0 := time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)
	id, _, _ := s.UpsertSecFinding(ctx, secFinding("p1", "k1"), t0)
	exID, err := s.GrantSecException(ctx, SecException{
		FindingID: id, Reason: "test_fixture", Expiry: "until_change", FileHash: "h",
		ExpiresAt: t0.Add(time.Hour), GrantedBy: "dashboard", GrantedAt: t0,
	}, policy.FindingStatusSuppressed)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.EndSecException(ctx, exID, "forgotten", t0); err == nil {
		t.Fatal("an unknown end reason is refused")
	}
	if err := s.EndSecException(ctx, exID, SecExceptionRevoked, t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if f, _, _ := s.SecFindingByID(ctx, id); f.Status != policy.FindingStatusOpen || f.ExceptionID != "" {
		t.Fatalf("revoked: %+v", f)
	}
	if kinds := secEventKinds(t, s, id); kinds[len(kinds)-1] != SecEventReopened {
		t.Fatalf("revoke event: %v", kinds)
	}
	if n, err := s.PruneSecExceptions(ctx, t0); err != nil || n != 0 {
		t.Fatalf("prune before the cutoff: %d %v", n, err)
	}
	if n, err := s.PruneSecExceptions(ctx, t0.Add(time.Hour)); err != nil || n != 1 {
		t.Fatalf("prune after: %d %v", n, err)
	}
	if _, err := s.GrantSecException(ctx, SecException{FindingID: id, Reason: "x", Expiry: "1d", GrantedBy: "cli", GrantedAt: t0}, policy.FindingStatusOpen); err == nil {
		t.Fatal("an exception that leaves the finding open is refused")
	}
}

func TestSecSeenAfter(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	t0 := time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)
	start, err := s.SecMaxFindingEventID(ctx)
	if err != nil || start != 0 {
		t.Fatalf("empty: %d %v", start, err)
	}
	crit := secFinding("p1", "k1")
	crit.Severity = policy.FindingSeverityCritical
	if _, _, err := s.UpsertSecFinding(ctx, crit, t0); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.UpsertSecFinding(ctx, secFinding("p1", "k2"), t0); err != nil {
		t.Fatal(err)
	}
	got, err := s.SecSeenAfter(ctx, start, policy.FindingSeverityCritical, 10)
	if err != nil || len(got) != 1 || got[0].RuleID != "S-721" || got[0].RelPath != "a.go" {
		t.Fatalf("critical seen: %+v %v", got, err)
	}
	if again, _ := s.SecSeenAfter(ctx, got[0].EventID, policy.FindingSeverityCritical, 10); len(again) != 0 {
		t.Fatalf("after the watermark: %+v", again)
	}
}

// TestListSecExceptionsSoonestFirst (lane sec-gate2 milestone 2c): the
// sweep's listing reads the soonest-to-expire exceptions first and the
// until-change ones last, whatever order they were granted in.
func TestListSecExceptionsSoonestFirst(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	t0 := time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)
	grants := []struct {
		key    string
		expiry string
		at     time.Time
	}{
		{"k1", "30d", t0.AddDate(0, 0, 30)},
		{"k2", "until_change", time.Time{}},
		{"k3", "1d", t0.AddDate(0, 0, 1)},
		{"k4", "7d", t0.AddDate(0, 0, 7)},
	}
	for _, g := range grants {
		id, _, err := s.UpsertSecFinding(ctx, secFinding("p1", g.key), t0)
		if err != nil {
			t.Fatal(err)
		}
		ex := SecException{
			FindingID: id, ProjectRootHash: "p1", RuleID: "S-721", Reason: "false_positive",
			Expiry: g.expiry, ExpiresAt: g.at, FileHash: "h", GrantedBy: "cli", GrantedAt: t0,
		}
		if _, err := s.GrantSecException(ctx, ex, policy.FindingStatusSuppressed); err != nil {
			t.Fatal(err)
		}
	}
	list, err := s.ListSecExceptions(ctx, SecExceptionFilter{OpenOnly: true, SoonestFirst: true})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range list {
		got = append(got, e.Expiry)
	}
	if strings.Join(got, ",") != "1d,7d,30d,until_change" {
		t.Fatalf("order = %v", got)
	}
}

// TestListSecExceptionsByKindAndCursor (lane sec-gate3 milestone 2d): the
// sweep reads the timed and the until-change exceptions separately, the
// latter oldest first after a cursor.
func TestListSecExceptionsByKindAndCursor(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	t0 := time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)
	var ids []int64
	for i, expiry := range []string{"until_change", "1d", "until_change", "until_change"} {
		id, _, err := s.UpsertSecFinding(ctx, secFinding("p1", "k"+string(rune('a'+i))), t0)
		if err != nil {
			t.Fatal(err)
		}
		ex := SecException{FindingID: id, ProjectRootHash: "p1", RuleID: "S-721", Reason: "false_positive", Expiry: expiry, GrantedBy: "cli", GrantedAt: t0}
		ex.ExpiresAt = t0.AddDate(0, 0, 1)
		if expiry == "until_change" {
			ex.ExpiresAt = t0.AddDate(0, 0, 90) // the ceiling
		}
		xid, err := s.GrantSecException(ctx, ex, policy.FindingStatusSuppressed)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, xid)
	}
	timed, err := s.ListSecExceptions(ctx, SecExceptionFilter{OpenOnly: true, Timed: true, SoonestFirst: true})
	if err != nil || len(timed) != 1 || timed[0].ID != ids[1] {
		t.Fatalf("timed = %+v %v", timed, err)
	}
	page, err := s.ListSecExceptions(ctx, SecExceptionFilter{OpenOnly: true, UntilChange: true, OldestFirst: true, AfterID: ids[0], Limit: 1})
	if err != nil || len(page) != 1 || page[0].ID != ids[2] {
		t.Fatalf("page after %d = %+v %v, want %d", ids[0], page, err, ids[2])
	}
}
