//go:build !sbo_omit_security

package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/platform/xcodehost"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
)

func secFinding(root, key string) secfinding.Finding {
	return secfinding.Normalize(secfinding.Finding{
		LocalKey: key, Rule: secfinding.Rule{ID: "S-721"}, Category: policy.FindingSecret,
		Severity: policy.FindingSeverityHigh, Confidence: policy.FindingConfidenceHigh, Baseline: policy.FindingBaselineNew,
		Project: secfinding.Project{RootHash: root}, Location: secfinding.Location{RelPath: "a.go", StartLine: 3, EndLine: 3},
		Lineage: secfinding.Lineage{SessionID: "s1", Tool: "claude-code"}, Message: "secret in code",
	})
}

func TestSecFindingLifecycle(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	t0 := time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC)
	id, created, err := s.UpsertSecFinding(ctx, secFinding("p1", "k1"), t0)
	if err != nil || !created || len(id) != 26 {
		t.Fatalf("insert: %q %v %v", id, created, err)
	}
	moved := secFinding("p1", "k1")
	moved.Location.StartLine = 40
	id2, created, err := s.UpsertSecFinding(ctx, moved, t0.Add(time.Minute))
	if err != nil || created || id2 != id {
		t.Fatalf("a rescan of the same local key updates the row: %q %v %v", id2, created, err)
	}
	if _, created, _ := s.UpsertSecFinding(ctx, secFinding("p2", "k1"), t0); !created {
		t.Fatal("the same key in another project is another finding")
	}
	keys, err := s.SecBlockingKeys(ctx, SecBlockingQuery{ProjectRootHash: "p1", Severities: []secfinding.Severity{policy.FindingSeverityHigh, policy.FindingSeverityCritical}}, 10)
	if err != nil || len(keys) != 1 || keys[0] != "k1" {
		t.Fatalf("blocking keys: %v %v", keys, err)
	}
	counts, err := s.SecOpenCounts(ctx, "p1")
	if err != nil || len(counts) != 1 || counts[0].N != 1 || counts[0].Category != policy.FindingSecret {
		t.Fatalf("counts: %+v %v", counts, err)
	}
	if err := s.SetSecFindingStatus(ctx, id, policy.FindingStatusFixedVerified, "", t0.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if keys, _ := s.SecBlockingKeys(ctx, SecBlockingQuery{ProjectRootHash: "p1", Severities: []secfinding.Severity{policy.FindingSeverityHigh}}, 10); len(keys) != 0 {
		t.Fatal("a closed finding does not block")
	}
	// Seen again: reopened.
	if _, _, err := s.UpsertSecFinding(ctx, secFinding("p1", "k1"), t0.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	got, err := s.ListSecFindings(ctx, SecFindingFilter{ProjectRootHash: "p1"})
	if err != nil || len(got) != 1 || got[0].Status != policy.FindingStatusOpen || got[0].Location.StartLine != 3 {
		t.Fatalf("reopened: %+v %v", got, err)
	}
	var kinds []string
	rows, _ := s.db.QueryContext(ctx, `SELECT kind FROM sec_finding_events WHERE finding_id = ? ORDER BY id`, id)
	for rows.Next() {
		var k string
		_ = rows.Scan(&k)
		kinds = append(kinds, k)
	}
	_ = rows.Close()
	if strings.Join(kinds, ",") != "seen,closed,reopened" {
		t.Fatalf("events = %v", kinds)
	}
	// A suppressed finding keeps its status when seen again.
	if err := s.SetSecFindingStatus(ctx, id, policy.FindingStatusSuppressed, "grant-1", t0.Add(4*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.UpsertSecFinding(ctx, secFinding("p1", "k1"), t0.Add(5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	got, _ = s.ListSecFindings(ctx, SecFindingFilter{ProjectRootHash: "p1"})
	if got[0].Status != policy.FindingStatusSuppressed || got[0].ExceptionID != "grant-1" {
		t.Fatalf("suppressed: %+v", got[0])
	}
	// Retention: a closed finding older than the cutoff goes, an open one stays.
	if n, err := s.PruneSecFindings(ctx, t0.Add(time.Hour)); err != nil || n != 1 {
		t.Fatalf("prune: %d %v", n, err)
	}
	if got, _ := s.ListSecFindings(ctx, SecFindingFilter{}); len(got) != 1 || got[0].Project.RootHash != "p2" {
		t.Fatalf("after prune: %+v", got)
	}
	if err := s.SetSecFindingStatus(ctx, "nope", policy.FindingStatusOpen, "", t0); !errors.Is(err, ErrSecFindingNotFound) {
		t.Fatalf("unknown id: %v", err)
	}
}

func TestSecScanRunsAndBaselines(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	t0 := time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC)
	if err := s.InsertSecScanRun(ctx, SecScanRun{ProjectRootHash: "p1", Driver: "secrets", Scope: policy.FindingScopeStaged, Outcome: "clean", StartedAt: t0, Duration: time.Second}); err != nil {
		t.Fatal(err)
	}
	if last, err := s.SecLastScan(ctx, "p1"); err != nil || !last.Equal(t0) {
		t.Fatalf("last scan %v %v", last, err)
	}
	if last, _ := s.SecLastScan(ctx, "none"); !last.IsZero() {
		t.Fatal("no runs, no time")
	}
	if _, ok, _ := s.LatestSecBaseline(ctx, "p1"); ok {
		t.Fatal("no baseline yet")
	}
	if err := s.AddSecBaseline(ctx, SecBaseline{ProjectRootHash: "p1", Kind: "commit", Ref: "abc", Approver: "dev", CreatedAt: t0}); err != nil {
		t.Fatal(err)
	}
	if b, ok, err := s.LatestSecBaseline(ctx, "p1"); err != nil || !ok || b.Ref != "abc" {
		t.Fatalf("baseline %+v %v %v", b, ok, err)
	}
	if err := s.AddSecBaseline(ctx, SecBaseline{ProjectRootHash: "p1", Kind: "reset", CreatedAt: t0.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.LatestSecBaseline(ctx, "p1"); ok {
		t.Fatal("a reset leaves no trusted baseline")
	}
	projects, err := s.SecProjects(ctx)
	if err != nil || len(projects) != 1 || projects[0] != "p1" {
		t.Fatalf("projects %v %v", projects, err)
	}
}

// TestSecTablesHaveOneWriter: no other store file names a sec_* table
// (CLAUDE.md module rule 4: one owner per table). The findings store's
// seam is secfindings.go and its exceptions half, secexceptions.go (lane
// sec-c3), which moves a finding's status in the same transaction as the
// exception that excepts it.
func TestSecTablesHaveOneWriter(t *testing.T) {
	t.Parallel()
	re := regexp.MustCompile(`\bsec_(findings|finding_events|finding_exceptions|scan_runs|baselines)\b`)
	files, _ := filepath.Glob("*.go")
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") || f == "secfindings.go" || f == "secexceptions.go" {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		// The security org wire's reads (lane SEC-E2, secorgrows_reads.go)
		// name the tables but may never write them.
		// The change record builder's fact reads (lane SEC-F2A,
		// secchange_facts.go) likewise only read them, as does the
		// box-ref walk's read of box commit runs (lane sec-box, secbox.go).
		// The project-root repair's count of root-keyed rows (WINNODE2
		// merge, projectrootrepair_sec.go) only names them. The Code
		// security page's facets, groups and coverage reads (the 2026-11-06
		// redesign, secfindings_facets.go) only read them too.
		if f == "secorgrows_reads.go" || f == "secchange_facts.go" || f == "secbox.go" || f == "projectrootrepair_sec.go" || f == "secfindings_facets.go" {
			if regexp.MustCompile(`(?i)\b(INSERT|UPDATE|DELETE|REPLACE)\b`).Match(b) {
				t.Errorf("%s writes a sec_* table; it may only read them", f)
			}
			continue
		}
		if re.Match(b) && f != "componentpurge.go" {
			t.Errorf("%s names a sec_* table; only secfindings.go and secexceptions.go may", f)
		}
	}
}

// TestPruneSecFindingsPrunesEvents: retention also removes the lifecycle
// events of deleted findings and old project-level events, and keeps the
// history of an open finding (audit P-002 finding 9).
func TestPruneSecFindingsPrunesEvents(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	t0 := time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC)
	closedID, _, err := s.UpsertSecFinding(ctx, secFinding("p1", "closed"), t0)
	if err != nil {
		t.Fatal(err)
	}
	openID, _, err := s.UpsertSecFinding(ctx, secFinding("p1", "open"), t0)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetSecFindingStatus(ctx, closedID, policy.FindingStatusFixedVerified, "", t0); err != nil {
		t.Fatal(err)
	}
	if err := s.AppendSecFindingEvent(ctx, "", "p1", "baseline_set", "", t0); err != nil {
		t.Fatal(err)
	}
	if err := s.AppendSecFindingEvent(ctx, "", "p1", "baseline_set", "", t0.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PruneSecFindings(ctx, t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	count := func(q string, args ...any) int {
		t.Helper()
		var n int
		if err := s.db.QueryRowContext(ctx, q, args...).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if n := count(`SELECT COUNT(*) FROM sec_finding_events WHERE finding_id = ?`, closedID); n != 0 {
		t.Fatalf("%d events of a deleted finding remain", n)
	}
	if n := count(`SELECT COUNT(*) FROM sec_finding_events WHERE finding_id = ?`, openID); n == 0 {
		t.Fatal("an open finding's history must stay")
	}
	if n := count(`SELECT COUNT(*) FROM sec_finding_events WHERE finding_id = ''`); n != 1 {
		t.Fatalf("project-level events = %d, want only the one after the cutoff", n)
	}
}

// TestSecActiveProjectRoots: a project counts as active by a recent
// session (started or ended) or a recent first record.
func TestSecActiveProjectRoots(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	old := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	recent := time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)
	since := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	project := func(root string, created time.Time) int64 {
		t.Helper()
		res, err := s.db.ExecContext(ctx, `INSERT INTO projects (root_path, created_at) VALUES (?, ?)`, root, timestamp(created))
		if err != nil {
			t.Fatal(err)
		}
		id, _ := res.LastInsertId()
		return id
	}
	session := func(id string, pid int64, started time.Time, ended string) {
		t.Helper()
		if _, err := s.db.ExecContext(ctx, `INSERT INTO sessions (id, project_id, tool, started_at, ended_at) VALUES (?, ?, 'claude-code', ?, ?)`, id, pid, timestamp(started), ended); err != nil {
			t.Fatal(err)
		}
	}
	project("/new", recent)
	session("s1", project("/started", old), recent, "")
	session("s2", project("/ended", old), old, timestamp(recent))
	session("s3", project("/idle", old), old, timestamp(old))
	project("/never", old)
	got, err := s.SecActiveProjectRoots(ctx, since)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, ",") != "/ended,/new,/started" {
		t.Fatalf("active roots = %v", got)
	}
}

// TestSecActiveProjectRootsLeaveOutANonPathRoot (audit finding 1 on the
// w14 hand-back): the set the scheduled security scans walk never lists the
// stored non-path "Xcode (project unknown)" root; each consumer reads every
// root as a directory.
func TestSecActiveProjectRootsLeaveOutANonPathRoot(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	for _, root := range []string{"/Users/lume/Library/Autosave Information", "/Users/lume/superbasedtest"} {
		if _, err := s.UpsertProject(ctx, root, ""); err != nil {
			t.Fatal(err)
		}
	}
	var stored int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM projects WHERE root_path = ?`, xcodehost.ProjectUnknown).Scan(&stored); err != nil || stored != 1 {
		t.Fatalf("the non-path root is not stored: %d %v", stored, err)
	}
	got, err := s.SecActiveProjectRoots(ctx, time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(got, xcodehost.ProjectUnknown) || !slices.Equal(got, []string{"/Users/lume/superbasedtest"}) {
		t.Errorf("SecActiveProjectRoots = %q, want the real project only", got)
	}
}

// TestCloseGoneSecFindings (lane SEC-GATEFIX milestone 2d): a run that read
// a whole file closes the open findings of its driver and pack there that
// it did not report again; a removed key closes its finding; another
// pack's finding and a suppressed one stay as they are; a later sighting
// reopens.
func TestCloseGoneSecFindings(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	t0 := time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)
	mk := func(key, path, pack string) secfinding.Finding {
		f := secFinding("p1", key)
		f.Location.RelPath, f.Rule.Pack, f.Engine.Driver = path, pack, "native"
		return secfinding.Normalize(f)
	}
	for _, f := range []secfinding.Finding{
		mk("k1", "a.go", "security.secrets"), mk("k2", "a.go", "security.secrets"),
		mk("k3", "a.go", "security.code"), mk("k4", "b.go", "security.secrets"), mk("k5", "a.go", "security.secrets"),
	} {
		if _, _, err := s.UpsertSecFinding(ctx, f, t0); err != nil {
			t.Fatal(err)
		}
	}
	all, _ := s.ListSecFindings(ctx, SecFindingFilter{ProjectRootHash: "p1"})
	for _, f := range all {
		if f.LocalKey == "k5" {
			if err := s.SetSecFindingStatus(ctx, f.ID, policy.FindingStatusSuppressed, "g", t0); err != nil {
				t.Fatal(err)
			}
		}
	}
	n, err := s.CloseGoneSecFindings(ctx, SecGoneQuery{ProjectRootHash: "p1", Driver: "native", RulePack: "security.secrets", Paths: []string{"a.go"}, Keep: []SecSighting{{Key: "k1", Path: "a.go"}}}, t0.Add(time.Minute))
	if err != nil || n != 1 {
		t.Fatalf("close by path: %d %v", n, err)
	}
	if n, err := s.CloseGoneSecFindings(ctx, SecGoneQuery{ProjectRootHash: "p1", Driver: "native", RulePack: "security.secrets", Removed: []SecSighting{{Key: "k4", Path: "b.go"}}}, t0.Add(time.Minute)); err != nil || n != 1 {
		t.Fatalf("close by key: %d %v", n, err)
	}
	if n, _ := s.CloseGoneSecFindings(ctx, SecGoneQuery{ProjectRootHash: "p1", Driver: "native", RulePack: "security.secrets"}, t0); n != 0 {
		t.Fatal("an empty query closed something")
	}
	status := map[string]secfinding.Status{}
	all, _ = s.ListSecFindings(ctx, SecFindingFilter{ProjectRootHash: "p1"})
	for _, f := range all {
		status[f.LocalKey] = f.Status
	}
	want := map[string]secfinding.Status{
		"k1": policy.FindingStatusOpen, "k2": policy.FindingStatusNotReproduced, "k3": policy.FindingStatusOpen,
		"k4": policy.FindingStatusNotReproduced, "k5": policy.FindingStatusSuppressed,
	}
	for k, w := range want {
		if status[k] != w {
			t.Errorf("%s: %s, want %s", k, status[k], w)
		}
	}
	if _, _, err := s.UpsertSecFinding(ctx, mk("k2", "a.go", "security.secrets"), t0.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.ListSecFindings(ctx, SecFindingFilter{ProjectRootHash: "p1", Status: policy.FindingStatusOpen}); len(got) != 3 {
		t.Fatalf("a sighting reopens: %d open", len(got))
	}
}

// TestCloseGoneKeysByPathAndIdentity (lane sec-gate2 milestone 1b): the same
// secret in two files is one finding with two sightings; removing it from
// one file (by key at that path, or a whole-file rescan of that path) keeps
// it open, located at the file that still holds it, and only the last
// removal closes it. A removal at a path it was never seen at drops nothing.
func TestCloseGoneKeysByPathAndIdentity(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	t0 := time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)
	at := func(path string) secfinding.Finding {
		f := secFinding("p1", "k1")
		f.Location.RelPath, f.Rule.Pack, f.Engine.Driver = path, "security.secrets", "native"
		return secfinding.Normalize(f)
	}
	for i, p := range []string{"a.go", "b.go"} {
		if _, _, err := s.UpsertSecFinding(ctx, at(p), t0.Add(time.Duration(i)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	q := func(paths []string, removed ...SecSighting) SecGoneQuery {
		return SecGoneQuery{ProjectRootHash: "p1", Driver: "native", RulePack: "security.secrets", Paths: paths, Removed: removed}
	}
	one := func() secfinding.Finding {
		all, _ := s.ListSecFindings(ctx, SecFindingFilter{ProjectRootHash: "p1"})
		if len(all) != 1 {
			t.Fatalf("findings = %d, want one row for one identity", len(all))
		}
		return all[0]
	}
	if n, err := s.CloseGoneSecFindings(ctx, q(nil, SecSighting{Key: "k1", Path: "c.go"}), t0.Add(time.Minute)); err != nil || n != 0 {
		t.Fatalf("removal at an unseen path: %d %v", n, err)
	}
	if n, err := s.CloseGoneSecFindings(ctx, q(nil, SecSighting{Key: "k1", Path: "b.go"}), t0.Add(time.Minute)); err != nil || n != 0 {
		t.Fatalf("removed from b.go while a.go holds it: closed %d %v", n, err)
	}
	if f := one(); f.Status != policy.FindingStatusOpen || f.Location.RelPath != "a.go" {
		t.Fatalf("after removal from b.go: %s at %s, want open at a.go", f.Status, f.Location.RelPath)
	}
	if n, err := s.CloseGoneSecFindings(ctx, q([]string{"a.go"}), t0.Add(2*time.Minute)); err != nil || n != 1 {
		t.Fatalf("last sighting gone: closed %d %v", n, err)
	}
	if f := one(); f.Status != policy.FindingStatusNotReproduced {
		t.Fatalf("status %s, want not_reproduced", f.Status)
	}
	// Seen again: reopened with a fresh sighting, which a later close drops.
	if _, _, err := s.UpsertSecFinding(ctx, at("b.go"), t0.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if f := one(); f.Status != policy.FindingStatusOpen {
		t.Fatalf("not reopened: %s", f.Status)
	}
	if n, _ := s.CloseGoneSecFindings(ctx, q([]string{"b.go"}), t0.Add(4*time.Minute)); n != 1 {
		t.Fatalf("closed %d, want 1", n)
	}
}

// TestSecRescanSightingsFiltersAndPages (lane sec-gate3 milestone 1a): the
// rescan's query reads only the classes it names and the projects it
// knows, in key order, page by page after a cursor.
func TestSecRescanSightingsFiltersAndPages(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	t0 := time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)
	add := func(root, pack, rule, key, rel string) {
		f := secFinding(root, key)
		f.Rule = secfinding.Rule{ID: rule, Pack: pack}
		f.Engine.Driver = "native"
		f.Location.RelPath = rel
		if _, _, err := s.UpsertSecFinding(ctx, f, t0); err != nil {
			t.Fatal(err)
		}
	}
	add("p1", "security.secrets", "secret.a", "k1", "b.py")
	add("p1", "security.secrets", "secret.a", "k2", "a.py")
	add("p1", "security.code", "code.s-767", "k3", "0.py")
	add("p1", "security.code", "ci.unpinned", "k4", "w.yml")
	add("p2", "security.secrets", "secret.a", "k5", "a.py")
	q := SecRescanQuery{
		Driver: "native", RootHashes: []string{"p1"}, Limit: 2,
		Classes: []SecRescanClass{{Pack: "security.secrets"}, {Pack: "security.code", RulePrefixes: []string{"ci."}, RuleIDs: []string{"code.s-761"}}},
	}
	var got []string
	for range 4 {
		rows, err := s.SecRescanSightings(ctx, q)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range rows {
			got = append(got, r.ProjectRootHash+":"+r.Path)
		}
		if len(rows) < q.Limit {
			break
		}
		q.After = rows[len(rows)-1]
	}
	if strings.Join(got, ",") != "p1:a.py,p1:b.py,p1:w.yml" {
		t.Fatalf("rows = %v", got)
	}
	if rows, err := s.SecRescanSightings(ctx, SecRescanQuery{Driver: "native", RootHashes: []string{"p1"}}); err != nil || rows != nil {
		t.Fatalf("no class must read nothing: %v %v", rows, err)
	}
}

// TestSecFindingHeldByUnpushedCommit (lane sec-gate3 milestone 1b): a
// commit-scope finding naming its commit is held open by it: proofs of
// absence from the working tree and an exception ending on a gone secret
// drop sightings but do not close it, until the commit is dropped as
// pushed or gone.
func TestSecFindingHeldByUnpushedCommit(t *testing.T) {
	t.Parallel()
	s, database := newTestStore(t)
	ctx := context.Background()
	t0 := time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)
	sha := strings.Repeat("ab", 20)
	f := secFinding("p1", "k1")
	f.Rule.Pack = "security.secrets"
	f.Engine.Driver = "native"
	f.Scope = policy.FindingScopeCommit
	f.Commit.SHA = strings.ToUpper(sha)
	id, _, err := s.UpsertSecFinding(ctx, f, t0)
	if err != nil {
		t.Fatal(err)
	}
	gone := SecGoneQuery{ProjectRootHash: "p1", Driver: "native", RulePack: "security.secrets", Paths: []string{"a.go"}}
	if n, err := s.CloseGoneSecFindings(ctx, gone, t0.Add(time.Minute)); err != nil || n != 0 {
		t.Fatalf("a working-tree proof closed a held finding: %d %v", n, err)
	}
	if got, _, _ := s.SecFindingByID(ctx, id); got.Status != policy.FindingStatusOpen {
		t.Fatalf("status %s, want open", got.Status)
	}
	held, err := s.SecHeldCommits(ctx, []string{"p1"}, SecFindingCommit{}, 10)
	if err != nil || len(held) != 1 || held[0].CommitSHA != sha {
		t.Fatalf("held = %+v %v (stored lower case)", held, err)
	}
	if n, err := s.DropSecFindingCommit(ctx, SecFindingCommit{ProjectRootHash: "p1", CommitSHA: "not-a-sha"}, SecHistoryReasonGone, nil, t0); err != nil || n != 0 {
		t.Fatalf("a malformed id dropped something: %d %v", n, err)
	}
	if n, err := s.DropSecFindingCommit(ctx, held[0], SecHistoryReasonGone, nil, t0.Add(2*time.Minute)); err != nil || n != 1 {
		t.Fatalf("drop as gone: %d %v, want one closed", n, err)
	}
	if got, _, _ := s.SecFindingByID(ctx, id); got.Status != policy.FindingStatusNotReproduced {
		t.Fatalf("status %s, want not_reproduced", got.Status)
	}
	var left int
	if err := database.QueryRow(`SELECT COUNT(*) FROM sec_finding_commits`).Scan(&left); err != nil || left != 0 {
		t.Fatalf("history rows left: %d %v", left, err)
	}

	// A commit-scope finding still sighted in a file stays open when its
	// commit is pushed: the file still holds it.
	f2 := secFinding("p1", "k2")
	f2.Engine.Driver = "native"
	f2.Scope = policy.FindingScopeCommit
	f2.Commit.SHA = strings.Repeat("cd", 20)
	id2, _, err := s.UpsertSecFinding(ctx, f2, t0)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := s.DropSecFindingCommit(ctx, SecFindingCommit{ProjectRootHash: "p1", CommitSHA: f2.Commit.SHA}, SecHistoryReasonPushed, []string{"origin"}, t0); err != nil || n != 0 {
		t.Fatalf("drop of a still sighted finding: %d %v", n, err)
	}
	if got, _, _ := s.SecFindingByID(ctx, id2); got.Status != policy.FindingStatusOpen {
		t.Fatalf("status %s, want open", got.Status)
	}
}

// TestSecBlockingKeysHistoryOnly (lane sec-gate3 audit finding 2): a
// commit-scope finding a file still holds is blocking and not
// history-only; once no file holds it and only its unpushed commit does,
// it is both. A working-tree finding with no commit is never history-only.
func TestSecBlockingKeysHistoryOnly(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	t0 := time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)
	f := secFinding("p1", "k1")
	f.Rule.Pack = "security.secrets"
	f.Engine.Driver = "native"
	f.Scope = policy.FindingScopeCommit
	f.Commit.SHA = strings.Repeat("ab", 20)
	if _, _, err := s.UpsertSecFinding(ctx, f, t0); err != nil {
		t.Fatal(err)
	}
	tree := secFinding("p1", "k2")
	tree.Engine.Driver = "other"
	if _, _, err := s.UpsertSecFinding(ctx, tree, t0); err != nil {
		t.Fatal(err)
	}
	sev := []secfinding.Severity{policy.FindingSeverityHigh, policy.FindingSeverityCritical}
	all := SecBlockingQuery{ProjectRootHash: "p1", Severities: sev}
	held := SecBlockingQuery{ProjectRootHash: "p1", Severities: sev, HistoryOnly: true}
	if keys, err := s.SecBlockingKeys(ctx, held, 10); err != nil || len(keys) != 0 {
		t.Fatalf("a finding a file still holds reads as history-only: %v %v", keys, err)
	}
	gone := SecGoneQuery{ProjectRootHash: "p1", Driver: "native", RulePack: "security.secrets", Paths: []string{"a.go"}}
	if _, err := s.CloseGoneSecFindings(ctx, gone, t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if keys, err := s.SecBlockingKeys(ctx, all, 10); err != nil || strings.Join(keys, ",") != "k1,k2" {
		t.Fatalf("blocking = %v %v, want k1,k2", keys, err)
	}
	if keys, err := s.SecBlockingKeys(ctx, held, 10); err != nil || strings.Join(keys, ",") != "k1" {
		t.Fatalf("history-only = %v %v, want k1", keys, err)
	}
}

// TestSecFindingPushedStaysOpenWithRotate (lane sec-gate4 milestone 1b): a
// held commit seen on one remote of two keeps holding (only that remote is
// recorded, and the finding is marked as reached: it carries the rotate
// note); dropped as pushed, the finding stays open with the note instead of
// closing, and stops blocking once no file and no commit holds it. The
// hold-aware close (milestone 1c) keeps it open too; triage closes it.
func TestSecFindingPushedStaysOpenWithRotate(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	t0 := time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)
	sha := strings.Repeat("ef", 20)
	f := secFinding("p1", "k1")
	f.Rule.Pack = "security.secrets"
	f.Engine.Driver = "native"
	f.Scope = policy.FindingScopeCommit
	f.Commit.SHA = sha
	f.FixHint = "move it to the environment"
	id, _, err := s.UpsertSecFinding(ctx, f, t0)
	if err != nil {
		t.Fatal(err)
	}
	gone := SecGoneQuery{ProjectRootHash: "p1", Driver: "native", RulePack: "security.secrets", Paths: []string{"a.go"}}
	if _, err := s.CloseGoneSecFindings(ctx, gone, t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	sev := []secfinding.Severity{policy.FindingSeverityHigh, policy.FindingSeverityCritical}
	held := SecBlockingQuery{ProjectRootHash: "p1", Severities: sev, HistoryOnly: true}
	c := SecFindingCommit{ProjectRootHash: "p1", CommitSHA: sha}
	if n, err := s.SetSecFindingCommitRemotes(ctx, c, []string{"origin", "origin"}, t0.Add(2*time.Minute)); err != nil || n != 2 {
		t.Fatalf("remotes: %d %v, want the row changed and the finding marked", n, err)
	}
	if n, err := s.SetSecFindingCommitRemotes(ctx, c, []string{"origin"}, t0.Add(2*time.Minute)); err != nil || n != 0 {
		t.Fatalf("the same remotes again: %d %v, want no change", n, err)
	}
	rows, err := s.SecHeldHistory(ctx, held, 10)
	if err != nil || len(rows) != 1 || rows[0].LocalKey != "k1" || strings.Join(rows[0].Remotes, ",") != "origin" {
		t.Fatalf("held history = %+v %v", rows, err)
	}
	if keys, err := s.SecBlockingKeys(ctx, held, 10); err != nil || strings.Join(keys, ",") != "k1" {
		t.Fatalf("a commit one remote still lacks must keep blocking: %v %v", keys, err)
	}
	got, _, _ := s.SecFindingByID(ctx, id)
	if !strings.HasPrefix(got.FixHint, SecPushedNote+"; move it") {
		t.Fatalf("hint %q, want the rotate note first", got.FixHint)
	}
	if n, err := s.DropSecFindingCommit(ctx, c, SecHistoryReasonPushed, []string{"backup", "origin"}, t0.Add(3*time.Minute)); err != nil || n != 0 {
		t.Fatalf("drop as pushed: %d %v, want nothing closed", n, err)
	}
	if got, _, _ := s.SecFindingByID(ctx, id); got.Status != policy.FindingStatusOpen || !strings.HasPrefix(got.FixHint, SecPushedNote) {
		t.Fatalf("a pushed secret: %s %q, want open with the rotate note", got.Status, got.FixHint)
	}
	all := SecBlockingQuery{ProjectRootHash: "p1", Severities: sev}
	if keys, err := s.SecBlockingKeys(ctx, all, 10); err != nil || len(keys) != 0 {
		t.Fatalf("a pushed secret nothing holds must not block: %v %v", keys, err)
	}
	if closed, err := s.CloseSecFindingNotReproduced(ctx, id, t0.Add(4*time.Minute)); err != nil || closed {
		t.Fatalf("the hold-aware close closed a pushed secret: %v %v", closed, err)
	}
	if err := s.SetSecFindingStatus(ctx, id, policy.FindingStatusAcceptedRisk, "", t0.Add(5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if got, _, _ := s.SecFindingByID(ctx, id); got.Status != policy.FindingStatusAcceptedRisk {
		t.Fatalf("triage: %s", got.Status)
	}

	// A finding with no hold and no reach closes through the same call.
	plain := secFinding("p1", "k9")
	plain.Engine.Driver = "osv"
	id9, _, err := s.UpsertSecFinding(ctx, plain, t0)
	if err != nil {
		t.Fatal(err)
	}
	if closed, err := s.CloseSecFindingNotReproduced(ctx, id9, t0.Add(time.Minute)); err != nil || !closed {
		t.Fatalf("plain close: %v %v", closed, err)
	}
	if got, _, _ := s.SecFindingByID(ctx, id9); got.Status != policy.FindingStatusNotReproduced {
		t.Fatalf("plain: %s", got.Status)
	}
}

// TestSecFindingReachedWhileSuppressed (lane SEC-GATE5 milestone 2, GATE4
// audit finding 10): a finding an exception suppresses keeps its held
// commit under the history check, and a push of that commit stamps it as
// having reached a remote. When the exception ends it stays open with the
// rotate note instead of closing as not reproduced; a triage close is
// never stamped.
func TestSecFindingReachedWhileSuppressed(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	t0 := time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)
	mk := func(key, sha string) string {
		f := secFinding("p1", key)
		f.Rule.Pack = "security.secrets"
		f.Engine.Driver = "native"
		f.Scope = policy.FindingScopeCommit
		f.Commit.SHA = sha
		id, _, err := s.UpsertSecFinding(ctx, f, t0)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	sha := strings.Repeat("ef", 20)
	id := mk("k1", sha)
	if err := s.SetSecFindingStatus(ctx, id, policy.FindingStatusSuppressed, "", t0); err != nil {
		t.Fatal(err)
	}
	held, err := s.SecHeldCommits(ctx, []string{"p1"}, SecFindingCommit{}, 10)
	if err != nil || len(held) != 1 || held[0].CommitSHA != sha {
		t.Fatalf("held = %+v %v, want the suppressed finding's commit", held, err)
	}
	if n, err := s.SetSecFindingCommitRemotes(ctx, held[0], []string{"origin"}, t0.Add(time.Minute)); err != nil || n == 0 {
		t.Fatalf("push recorded: %d %v", n, err)
	}
	if n, err := s.DropSecFindingCommit(ctx, held[0], SecHistoryReasonPushed, []string{"origin"}, t0.Add(2*time.Minute)); err != nil || n != 0 {
		t.Fatalf("drop as pushed: %d %v", n, err)
	}
	got, _, _ := s.SecFindingByID(ctx, id)
	if got.Status != policy.FindingStatusSuppressed {
		t.Fatalf("status %s, want still suppressed", got.Status)
	}
	// The exception ends: the finding is open again and stays open.
	if err := s.SetSecFindingStatus(ctx, id, policy.FindingStatusOpen, "", t0.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if closed, err := s.CloseSecFindingNotReproduced(ctx, id, t0.Add(4*time.Minute)); err != nil || closed {
		t.Fatalf("a pushed secret closed when its exception ended: %v %v", closed, err)
	}
	list, err := s.ListSecFindings(ctx, SecFindingFilter{ProjectRootHash: "p1"})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range list {
		if f.ID == id {
			found = true
			if !strings.HasPrefix(f.FixHint, SecPushedNote) {
				t.Fatalf("fix hint %q, want it to start with %q", f.FixHint, SecPushedNote)
			}
		}
	}
	if !found {
		t.Fatal("finding not listed")
	}

	// A finding closed by triage is never stamped, and its commit is not
	// checked.
	id2 := mk("k2", strings.Repeat("12", 20))
	if err := s.SetSecFindingStatus(ctx, id2, policy.FindingStatusFalsePositive, "", t0); err != nil {
		t.Fatal(err)
	}
	held, err = s.SecHeldCommits(ctx, []string{"p1"}, SecFindingCommit{}, 10)
	if err != nil || len(held) != 0 {
		t.Fatalf("held = %+v %v, want none (the pushed one was dropped, the false positive is not checked)", held, err)
	}
	if _, err := s.DropSecFindingCommit(ctx, SecFindingCommit{ProjectRootHash: "p1", CommitSHA: strings.Repeat("12", 20)}, SecHistoryReasonPushed, []string{"origin"}, t0); err != nil {
		t.Fatal(err)
	}
	if got, _, _ := s.SecFindingByID(ctx, id2); got.Status != policy.FindingStatusFalsePositive {
		t.Fatalf("status %s, want false_positive", got.Status)
	}
}
