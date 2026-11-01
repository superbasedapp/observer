//go:build !sbo_omit_security && !sbo_omit_security_deps

package main

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secdiffobs"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestDepsCommitFindings is milestone 2f: a commit (or a staged change)
// that adds a listed or near-miss dependency to a manifest is recorded as
// an S-747 finding (flag-only, medium confidence); a version bump of a
// dependency already there is not an addition, and nothing is recorded
// while package checks are not set up.
func TestDepsCommitFindings(t *testing.T) {
	depsScopeHome(t)
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.toml")
	root := t.TempDir()
	if r, err := filepath.EvalSymlinks(root); err == nil {
		root = r
	}
	diff := secdiffobs.FileDiff{
		Path:    "web/package.json",
		Removed: []secdiffobs.Line{{N: 4, Text: `    "left-pad": "1.3.0",`}},
		Added: []secdiffobs.Line{
			{N: 4, Text: `    "left-pad": "1.3.1",`},
			{N: 5, Text: `    "evil-pkg": "1.0.0",`},
			{N: 6, Text: `    "lodahs": "^4.0.0",`},
		},
	}
	if fs := depsManifestFindings(cfg, root, "abc", policy.FindingScopeCommit, []secdiffobs.FileDiff{diff}, time.Now()); len(fs) != 0 {
		t.Errorf("not set up: %+v", fs)
	}
	installTestIndex(t, depsContentStore(cfg).Root)
	fs := depsManifestFindings(cfg, root, "abc", policy.FindingScopeCommit, []secdiffobs.FileDiff{diff}, time.Now())
	got := map[string]policy.FindingSeverity{}
	for _, f := range fs {
		got[f.Message] = f.Severity
		if f.Confidence != policy.FindingConfidenceMedium || f.Rule.ID != depsCommitRule || f.Commit.SHA != "abc" {
			t.Errorf("finding shape %+v", f)
		}
	}
	if len(fs) != 2 {
		t.Fatalf("findings %v", got)
	}
	if fs[0].Severity != policy.FindingSeverityHigh || fs[0].Location.StartLine != 5 {
		t.Errorf("malicious finding %+v", fs[0])
	}
	if !depsRetainPath("a/b/Cargo.toml") || depsRetainPath("main.go") {
		t.Error("retain")
	}
}

// TestDepsCommitFindingsClose pins lane SEC-DEPS3 item 8: S-747 at commit
// records under its own diff driver, so it never moves the project's last
// working-tree scan; a later commit that removes the dependency from that
// manifest closes that manifest's finding only, and deleting the manifest
// closes what is left there.
func TestDepsCommitFindingsClose(t *testing.T) {
	depsScopeHome(t)
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.toml")
	root := t.TempDir()
	if r, err := filepath.EvalSymlinks(root); err == nil {
		root = r
	}
	installTestIndex(t, depsContentStore(cfg).Root)
	prev := depsActiveConfig.Load()
	depsActiveConfig.Store(&cfg)
	t.Cleanup(func() { depsActiveConfig.Store(prev) })
	database, err := db.Open(context.Background(), db.Options{Path: filepath.Join(dir, "o.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	st := store.New(database)
	ctx := context.Background()
	add := func(p string) secdiffobs.FileDiff {
		return secdiffobs.FileDiff{Path: p, Added: []secdiffobs.Line{{N: 5, Text: `    "evil-pkg": "1.0.0",`}}}
	}
	open := func() map[string]bool {
		fs, err := st.ListSecFindings(ctx, store.SecFindingFilter{ProjectRootHash: secposture.ProjectRootHash(root), Status: policy.FindingStatusOpen})
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]bool{}
		for _, f := range fs {
			if f.Engine.Driver != depsCommitDriver {
				t.Fatalf("driver %q, want %q", f.Engine.Driver, depsCommitDriver)
			}
			out[f.Location.RelPath] = true
		}
		return out
	}
	recordDepsManifests(ctx, st, root, "c1", policy.FindingScopeCommit, []secdiffobs.FileDiff{add("web/package.json"), add("api/package.json")}, nil)
	if got := open(); !got["web/package.json"] || !got["api/package.json"] || len(got) != 2 {
		t.Fatalf("open after the adding commit: %v", got)
	}
	if last, err := st.SecLastScan(ctx, secposture.ProjectRootHash(root)); err != nil || !last.IsZero() {
		t.Fatalf("a commit diff run must not move the last scan: %v %v", last, err)
	}
	remove := secdiffobs.FileDiff{Path: "web/package.json", Removed: []secdiffobs.Line{{N: 5, Text: `    "evil-pkg": "1.0.0",`}}}
	recordDepsManifests(ctx, st, root, "c2", policy.FindingScopeCommit, []secdiffobs.FileDiff{remove}, nil)
	if got := open(); got["web/package.json"] || !got["api/package.json"] {
		t.Fatalf("removing it from web/ closes web/'s finding only: %v", got)
	}
	recordDepsManifests(ctx, st, root, "c3", policy.FindingScopeCommit, []secdiffobs.FileDiff{{Path: "api/package.json", Deleted: true}}, nil)
	if got := open(); len(got) != 0 {
		t.Fatalf("deleting the manifest closes its findings: %v", got)
	}
}
