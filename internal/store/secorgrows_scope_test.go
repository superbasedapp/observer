//go:build !sbo_omit_security

package store

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"testing"
	"time"
)

// seedScopedSecFinding stores one finding in the project at root, the way
// the scanners key it (sha256 of the root, secposture.ProjectRootHash's
// spelling), with a path that names the project.
func seedScopedSecFinding(t *testing.T, s *Store, root, path string, now time.Time) {
	t.Helper()
	ctx := context.Background()
	if _, err := s.UpsertProject(ctx, root, ""); err != nil {
		t.Fatalf("UpsertProject: %v", err)
	}
	f := secFinding(sha256Hex(root), "key-"+path)
	f.Location.RelPath = path
	f.EvidenceRedacted = "evidence in " + path
	if _, _, err := s.UpsertSecFinding(ctx, f, now); err != nil {
		t.Fatalf("UpsertSecFinding: %v", err)
	}
}

// TestComposeSecurityHonoursProjectScope pins lane SEC-E2 audit finding 1:
// the security rows honour the push's project allow and deny lists exactly
// as the delivery rows do. Under raw content a denied project's finding,
// path and evidence never ship and its findings are not in the posture
// counts; an allowlist ships only its projects, and an allowlist that names
// no known project ships no security row at all (the whole push is empty, as
// resolveScopeFilter's noMatch makes it).
func TestComposeSecurityHonoursProjectScope(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Now().UTC()
	_, database := newTestStore(t)
	seed := New(database)
	seedScopedSecFinding(t, seed, "/repo/allowed", "allowed/main.go", now)
	seedScopedSecFinding(t, seed, "/repo/denied", "denied/CLIENT-CODENAME.go", now)

	cases := []struct {
		name      string
		scope     ScopeOptions
		wantPaths []string
		wantCount int64
	}{
		{"unscoped", ScopeOptions{}, []string{"allowed/main.go", "denied/CLIENT-CODENAME.go"}, 2},
		{"denylist", ScopeOptions{ProjectRootDenylist: []string{"/repo/denied"}}, []string{"allowed/main.go"}, 1},
		{"allowlist", ScopeOptions{ProjectRootAllowlist: []string{"/repo/allowed"}}, []string{"allowed/main.go"}, 1},
		{"allowlist names nothing", ScopeOptions{ProjectRootAllowlist: []string{"/repo/unknown"}}, nil, 0},
	}
	for _, c := range cases {
		s := New(database)
		s.SetSecurityOrgProviders(secOrgProviders(s, SecurityShare{Level: "findings"}))
		b, err := s.SelectUnpushedSince(ctx, PushCursor{}, 1<<20, "org", "dev@x", ShareOptions{FullContent: true}, c.scope)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		var paths []string
		for _, f := range b.SecurityFindings {
			paths = append(paths, f.RelPath)
		}
		sort.Strings(paths)
		if strings.Join(paths, ",") != strings.Join(c.wantPaths, ",") {
			t.Errorf("%s: shipped paths %v, want %v", c.name, paths, c.wantPaths)
		}
		if c.wantPaths == nil {
			if len(b.SecurityPosture) != 0 || len(b.SecurityFindings) != 0 {
				t.Errorf("%s: an allowlist naming no project shipped security rows", c.name)
			}
			continue
		}
		if len(b.SecurityPosture) != 1 {
			t.Fatalf("%s: %d posture rows", c.name, len(b.SecurityPosture))
		}
		var counted int64
		for _, n := range b.SecurityPosture[0].Findings {
			counted += n.Count
		}
		if counted != c.wantCount || b.SecurityPosture[0].Projects != c.wantCount {
			t.Errorf("%s: posture counts %d findings in %d projects, want %d", c.name, counted, b.SecurityPosture[0].Projects, c.wantCount)
		}
		raw, _ := json.Marshal(b)
		if c.name != "unscoped" && strings.Contains(string(raw), "CLIENT-CODENAME") {
			t.Errorf("%s: the denied project's finding reached the wire: %s", c.name, raw)
		}
	}
}

// TestSecurityProbeSaltResends pins lane SEC-E2 audit finding 7: once a
// compose is delivered, an unchanged node skips the families, but a change
// of the share level, the raw-content flag, the org-key state or the scope
// re-sends them at once (not only on the one-hour floor).
func TestSecurityProbeSaltResends(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, _ := newTestStore(t)
	seedSecOrgFinding(t, s, time.Now().UTC())
	// A known project, so a denylist naming another one leaves a push.
	if _, err := s.UpsertProject(ctx, "/repo/kept", ""); err != nil {
		t.Fatal(err)
	}
	level := SecurityShare{Level: "findings"}
	s.SetSecurityOrgProviders(SecurityOrgProviders{
		Level:    func(context.Context, ShareOptions) SecurityShare { return level },
		Findings: s.SelectSecurityFindingRows,
	})
	compose := func(share ShareOptions, scope ScopeOptions) int {
		t.Helper()
		b, err := s.SelectUnpushedSince(ctx, PushCursor{}, 1<<20, "org", "dev@x", share, scope)
		if err != nil {
			t.Fatal(err)
		}
		s.CommitPushedSnapshots()
		return len(b.SecurityFindings)
	}
	if n := compose(ShareOptions{}, ScopeOptions{}); n != 1 {
		t.Fatalf("first compose: %d findings", n)
	}
	if n := compose(ShareOptions{}, ScopeOptions{}); n != 0 {
		t.Fatalf("an unchanged node re-sent %d findings", n)
	}
	steps := []struct {
		name  string
		share ShareOptions
		scope ScopeOptions
		lvl   SecurityShare
	}{
		{"raw content switched on", ShareOptions{FullContent: true}, ScopeOptions{}, SecurityShare{Level: "findings"}},
		{"org key now held", ShareOptions{FullContent: true}, ScopeOptions{}, SecurityShare{Level: "findings", HoldsOrgKey: true}},
		{"scope changed", ShareOptions{FullContent: true}, ScopeOptions{ProjectRootDenylist: []string{"/elsewhere"}}, SecurityShare{Level: "findings", HoldsOrgKey: true}},
	}
	for _, st := range steps {
		level = st.lvl
		if n := compose(st.share, st.scope); n != 1 {
			t.Errorf("%s: re-sent %d findings, want 1", st.name, n)
		}
		if n := compose(st.share, st.scope); n != 0 {
			t.Errorf("%s: the next unchanged compose re-sent %d", st.name, n)
		}
	}
}

// TestSecurityScopeCoversLinkedWorktrees (audit finding 2, lane
// shr-worktree2): a finding kept under a linked worktree checkout's own
// hash (the trust baseline, custom scanners) follows its project's scope. A
// deny-listed project's worktree findings never ship, and an allowlist
// naming the project ships them.
func TestSecurityScopeCoversLinkedWorktrees(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Now().UTC()
	f := newHandWorktrees(t)
	_, database := newTestStore(t)
	seed := New(database)
	seedScopedSecFinding(t, seed, f.main, "main/MAIN-CODENAME.go", now)
	seedScopedSecFinding(t, seed, "/repo/other", "other/main.go", now)
	for i, wt := range []string{f.inTree, f.outOfTree} {
		fd := secFinding(sha256Hex(wt), "wt-key-"+string(rune('a'+i)))
		fd.Location.RelPath = "wt/WORKTREE-CODENAME-" + string(rune('a'+i)) + ".go"
		fd.EvidenceRedacted = "evidence in WORKTREE-CODENAME"
		if _, _, err := seed.UpsertSecFinding(ctx, fd, now); err != nil {
			t.Fatalf("UpsertSecFinding: %v", err)
		}
	}
	cases := []struct {
		name      string
		scope     ScopeOptions
		wantPaths []string
	}{
		{"denylist names the main checkout", ScopeOptions{ProjectRootDenylist: []string{f.main}}, []string{"other/main.go"}},
		{"allowlist names the main checkout", ScopeOptions{ProjectRootAllowlist: []string{f.main}}, []string{"main/MAIN-CODENAME.go", "wt/WORKTREE-CODENAME-a.go", "wt/WORKTREE-CODENAME-b.go"}},
	}
	for _, c := range cases {
		s := New(database)
		s.SetSecurityOrgProviders(secOrgProviders(s, SecurityShare{Level: "findings"}))
		b, err := s.SelectUnpushedSince(ctx, PushCursor{}, 1<<20, "org", "dev@x", ShareOptions{FullContent: true}, c.scope)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		var paths []string
		for _, sf := range b.SecurityFindings {
			paths = append(paths, sf.RelPath)
		}
		sort.Strings(paths)
		if strings.Join(paths, ",") != strings.Join(c.wantPaths, ",") {
			t.Errorf("%s: shipped paths %v, want %v", c.name, paths, c.wantPaths)
		}
		if strings.HasPrefix(c.name, "denylist") {
			raw, _ := json.Marshal(b)
			if strings.Contains(string(raw), "CODENAME") {
				t.Errorf("%s: the denied project's worktree finding reached the wire", c.name)
			}
		}
	}
}
