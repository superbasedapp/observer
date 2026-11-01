//go:build !sbo_omit_security

package store

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
)

// TestPruneSecFindingsScoped (lane SEC-P4 decision 10): a scoped prune
// removes only the named projects' closed findings (Only), or every
// project's but the named ones (Except); the zero scope is the old prune.
func TestPruneSecFindingsScoped(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	t0 := time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC)
	closed := func(project, key string) string {
		t.Helper()
		id, _, err := s.UpsertSecFinding(ctx, secFinding(project, key), t0)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.SetSecFindingStatus(ctx, id, policy.FindingStatusFixedVerified, "", t0); err != nil {
			t.Fatal(err)
		}
		return id
	}
	a, b, c := closed("pa", "k"), closed("pb", "k"), closed("pc", "k")
	left := func() map[string]bool {
		t.Helper()
		out := map[string]bool{}
		for _, id := range []string{a, b, c} {
			var n int
			if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sec_findings WHERE id = ?`, id).Scan(&n); err != nil {
				t.Fatal(err)
			}
			out[id] = n == 1
		}
		return out
	}
	cut := t0.Add(time.Hour)
	if _, err := s.PruneSecFindingsScoped(ctx, cut, SecPruneScope{Except: []string{"pa"}}); err != nil {
		t.Fatal(err)
	}
	if l := left(); !l[a] || l[b] || l[c] {
		t.Fatalf("except pa: left %v, want only pa's", l)
	}
	if _, err := s.PruneSecFindingsScoped(ctx, cut, SecPruneScope{Only: []string{"pa"}}); err != nil {
		t.Fatal(err)
	}
	if l := left(); l[a] {
		t.Fatalf("only pa: left %v", l)
	}
	many := make([]string, secPruneHashCap+1)
	if _, err := s.PruneSecFindingsScoped(ctx, cut, SecPruneScope{Except: many}); err == nil {
		t.Fatal("a scope over the cap pruned")
	}
}

// TestSecCommitHoldTable pins secCommitHoldRows (lane SEC-P4 decision 13,
// ruling P-165): a secret is held at any confidence; every other finding is
// held exactly when it can block (high confidence: a code rule, a
// dependency finding, anything else), and a flag-only one never is.
func TestSecCommitHoldTable(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		cat  policy.FindingCategory
		conf policy.FindingConfidence
		want bool
	}{
		{policy.FindingSecret, policy.FindingConfidenceHigh, true},
		{policy.FindingSecret, policy.FindingConfidenceLow, true},
		{policy.FindingSecurityRegression, policy.FindingConfidenceLow, false}, // inference, unverified_fix
		{policy.FindingScopeDrift, policy.FindingConfidenceLow, false},
		{policy.FindingTestTampering, policy.FindingConfidenceMedium, false}, // diff observation
		{policy.FindingCIConfig, policy.FindingConfidenceMedium, false},      // workflow check
		{policy.FindingCodeVuln, policy.FindingConfidenceMedium, false},      // code rule, imported SARIF
		{policy.FindingIaC, policy.FindingConfidenceLow, false},
		{policy.FindingCodeVuln, policy.FindingConfidenceHigh, true}, // a code rule that can block
		{policy.FindingIaC, policy.FindingConfidenceHigh, true},
		{policy.FindingMaliciousPackage, policy.FindingConfidenceHigh, true}, // a blocking dependency finding
		{policy.FindingVulnerableDependency, policy.FindingConfidenceHigh, true},
		{policy.FindingHallucinatedPackage, policy.FindingConfidenceHigh, true},
		{policy.FindingMaliciousPackage, policy.FindingConfidenceMedium, false}, // flag-only dependency
		{policy.FindingVulnerableDependency, policy.FindingConfidenceLow, false},
	} {
		if got := secCommitHeld(string(c.cat), string(c.conf)); got != c.want {
			t.Errorf("%s at %s: held %v, want %v", c.cat, c.conf, got, c.want)
		}
	}
	if len(secCommitHoldRows) != 3 {
		t.Fatalf("the hold table has %d rows; ruling P-165 has the secret row, the flag-only row and the blocking default", len(secCommitHoldRows))
	}
	for _, c := range []struct {
		cat  policy.FindingCategory
		want bool
	}{{policy.FindingSecret, true}, {policy.FindingCodeVuln, false}, {policy.FindingVulnerableDependency, false}} {
		if got := secPushedNoted(string(c.cat)); got != c.want {
			t.Errorf("%s: the already-pushed note %v, want %v (secrets only)", c.cat, got, c.want)
		}
	}
}

// TestFlagOnlyCommitFindingIsNotHeld (lane SEC-P4 decision 13): a
// flag-only code finding of a commit gets no commit row, closes on its
// own proof of absence while the commit is unpushed, and never gets the
// secrets note, even when an earlier build wrote a commit row and stamped
// it as pushed; a secret of the same commit stays held.
func TestFlagOnlyCommitFindingIsNotHeld(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	t0 := time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC)
	sha := "0123456789abcdef0123456789abcdef01234567"
	flag := secFinding("p1", "flag")
	flag.Rule.ID, flag.Category, flag.Confidence, flag.Severity = "code.unverified_fix", policy.FindingSecurityRegression, policy.FindingConfidenceLow, policy.FindingSeverityInfo
	flag.Scope, flag.Commit.SHA = policy.FindingScopeCommit, sha
	secret := secFinding("p1", "secret")
	secret.Scope, secret.Commit.SHA = policy.FindingScopeCommit, sha
	fid, _, err := s.UpsertSecFinding(ctx, flag, t0)
	if err != nil {
		t.Fatal(err)
	}
	sid, _, err := s.UpsertSecFinding(ctx, secret, t0)
	if err != nil {
		t.Fatal(err)
	}
	rows := func(id string) int {
		var n int
		if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sec_finding_commits WHERE finding_id = ?`, id).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if rows(fid) != 0 || rows(sid) != 1 {
		t.Fatalf("commit rows: flag %d secret %d, want 0 and 1", rows(fid), rows(sid))
	}
	// An earlier build's row and push stamp on the flag finding.
	if _, err := s.db.ExecContext(ctx, `INSERT INTO sec_finding_commits (finding_id, commit_sha, last_seen) VALUES (?, ?, ?)`, fid, sha, t0.Format(secTime)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetSecFindingCommitRemotes(ctx, SecFindingCommit{ProjectRootHash: "p1", CommitSHA: sha}, []string{"origin"}, t0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE sec_findings SET reached_remote_at = ? WHERE id = ?`, t0.Format(secTime), fid); err != nil {
		t.Fatal(err)
	}
	got, ok, err := s.SecFindingByID(ctx, fid)
	if err != nil || !ok || strings.Contains(got.FixHint, SecPushedNote) {
		t.Fatalf("the flag finding reads %q, want no secrets note", got.FixHint)
	}
	list, err := s.ListSecFindings(ctx, SecFindingFilter{ProjectRootHash: "p1"})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range list {
		if want := f.ID == sid; strings.Contains(f.FixHint, SecPushedNote) != want {
			t.Errorf("%s: fix hint %q, secrets note wanted %v", f.Rule.ID, f.FixHint, want)
		}
	}
	closed, err := s.CloseSecFindingNotReproduced(ctx, fid, t0.Add(time.Minute))
	if err != nil || !closed {
		t.Fatalf("the flag finding did not close: %v %v", closed, err)
	}
	if closed, err := s.CloseSecFindingNotReproduced(ctx, sid, t0.Add(time.Minute)); err != nil || closed {
		t.Fatalf("the held secret closed: %v %v", closed, err)
	}
	// A re-sighting drops the stale row.
	if _, _, err := s.UpsertSecFinding(ctx, flag, t0.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if rows(fid) != 0 {
		t.Fatal("an upsert kept the stale commit row")
	}
}

// TestBlockingCommitFindingsAreHeldUntilProofOfAbsence (ruling P-165,
// S-792): a blocking (high-confidence) code finding and a blocking
// dependency finding of an unpushed commit stay open and keep the history
// gate holding the commit after the tree is fixed, carry no "already
// pushed" note, and close on their own proof of absence once the commit is
// pushed; a flag-only dependency finding is never held; a secret of the same
// commit is held, carries the note once pushed and stays open.
func TestBlockingCommitFindingsAreHeldUntilProofOfAbsence(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	t0 := time.Date(2026, 10, 25, 9, 0, 0, 0, time.UTC)
	sha := "89abcdef0123456789abcdef0123456789abcdef"
	commit := func(key string, cat policy.FindingCategory, conf policy.FindingConfidence) secfinding.Finding {
		f := secFinding("p2", key)
		f.Rule.ID, f.Category, f.Confidence, f.Severity = "rule."+key, cat, conf, policy.FindingSeverityHigh
		f.Rule.Pack, f.Engine.Driver = "pack.p165", "native"
		f.Scope, f.Commit.SHA = policy.FindingScopeCommit, sha
		return f
	}
	ids := map[string]string{}
	for key, f := range map[string]secfinding.Finding{
		"code":    commit("code", policy.FindingCodeVuln, policy.FindingConfidenceHigh),
		"dep":     commit("dep", policy.FindingVulnerableDependency, policy.FindingConfidenceHigh),
		"depflag": commit("depflag", policy.FindingVulnerableDependency, policy.FindingConfidenceLow),
		"secret":  commit("secret", policy.FindingSecret, policy.FindingConfidenceHigh),
	} {
		id, _, err := s.UpsertSecFinding(ctx, f, t0)
		if err != nil {
			t.Fatal(err)
		}
		ids[key] = id
	}
	// The tree is fixed: a run reads a.go and finds none of them. The
	// flag-only one closes on that proof of absence; the history gate
	// (S-792) still holds the commit for the blocking ones.
	gone := SecGoneQuery{ProjectRootHash: "p2", Driver: "native", RulePack: "pack.p165", Paths: []string{"a.go"}}
	if _, err := s.CloseGoneSecFindings(ctx, gone, t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if got, ok, err := s.SecFindingByID(ctx, ids["depflag"]); err != nil || !ok || got.Status == policy.FindingStatusOpen {
		t.Fatalf("the flag-only dependency finding was held by the commit: %+v %v", got.Status, err)
	}
	held, err := s.SecHeldHistory(ctx, SecBlockingQuery{ProjectRootHash: "p2", Severities: []secfinding.Severity{policy.FindingSeverityHigh}, HistoryOnly: true}, 50)
	if err != nil {
		t.Fatal(err)
	}
	gated := map[string]bool{}
	for _, h := range held {
		gated[h.LocalKey] = true
	}
	for key, want := range map[string]bool{"code": true, "dep": true, "secret": true, "depflag": false} {
		if gated[key] != want {
			t.Errorf("%s: held by the unpushed commit %v, want %v", key, gated[key], want)
		}
	}
	for key, wantClosed := range map[string]bool{"code": false, "dep": false, "secret": false} {
		closed, err := s.CloseSecFindingNotReproduced(ctx, ids[key], t0.Add(time.Minute))
		if err != nil || closed != wantClosed {
			t.Fatalf("%s before the push: closed %v (%v), want %v", key, closed, err, wantClosed)
		}
	}
	// The commit reaches a remote.
	if _, err := s.DropSecFindingCommit(ctx, SecFindingCommit{ProjectRootHash: "p2", CommitSHA: sha}, SecHistoryReasonPushed, []string{"origin"}, t0.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	for key, wantNote := range map[string]bool{"code": false, "dep": false, "secret": true} {
		got, ok, err := s.SecFindingByID(ctx, ids[key])
		if err != nil || !ok {
			t.Fatalf("%s: %v", key, err)
		}
		if strings.Contains(got.FixHint, SecPushedNote) != wantNote {
			t.Errorf("%s: fix hint %q, the secrets note wanted %v", key, got.FixHint, wantNote)
		}
	}
	for key, wantClosed := range map[string]bool{"code": true, "dep": true, "secret": false} {
		closed, err := s.CloseSecFindingNotReproduced(ctx, ids[key], t0.Add(3*time.Minute))
		if err != nil || closed != wantClosed {
			t.Fatalf("%s after the push: closed %v (%v), want %v", key, closed, err, wantClosed)
		}
	}
}
