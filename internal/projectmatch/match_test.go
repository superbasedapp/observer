package projectmatch

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// runGit runs git in dir (tests only; the package itself never execs).
func runGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return string(out)
}

func repoWithRemote(t *testing.T, dir, remote string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// `git init -b` needs git 2.28; init plus symbolic-ref names the branch on
	// older git too (this host has 2.25).
	runGit(t, dir, "init", "-q")
	runGit(t, dir, "symbolic-ref", "HEAD", "refs/heads/main")
	if remote != "" {
		runGit(t, dir, "remote", "add", "origin", remote)
	}
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(t, dir, "add", ".")
	runGit(t, dir, "commit", "-q", "-m", "root")
	return dir
}

// TestMatchCorpus is milestone 4a with real git: a new clone matches by its
// remote before any session, a linked worktree matches its main project (the
// identity root, never the checkout), a fork with an upstream remote matches
// by the upstream, a copy with its remote removed matches only with a cached
// root commit, a monorepo subdirectory matches every project of its
// repository, and an unrelated repository matches nothing.
func TestMatchCorpus(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	base := t.TempDir()
	widgetURL := "https://github.com/acme/widget.git"
	widget := repoWithRemote(t, filepath.Join(base, "widget"), widgetURL)
	rootSHA := runGit(t, widget, "rev-list", "--max-parents=0", "HEAD")
	rootSHA = rootSHA[:len(rootSHA)-1]
	remote := Hash(git.NormalizeRemote(widgetURL))
	m := orgcontract.ProjectMapping{Epoch: 1, Projects: []orgcontract.ProjectMappingEntry{
		{OrgProjectID: "widget", Repos: []orgcontract.ProjectRepoHashes{{RemoteHash: remote, RootCommitHash: Hash(rootSHA)}}},
		{OrgProjectID: "mono-b", Repos: []orgcontract.ProjectRepoHashes{{RemoteHash: remote}}},
	}}
	ix := BuildIndex(m)

	worktree := filepath.Join(base, "widget-wt")
	runGit(t, widget, "worktree", "add", "-q", worktree)
	fork := repoWithRemote(t, filepath.Join(base, "fork"), "https://github.com/someone/widget.git")
	runGit(t, fork, "remote", "add", "upstream", widgetURL)
	copyDir := repoWithRemote(t, filepath.Join(base, "copy"), "")
	sub := filepath.Join(widget, "pkg", "deep")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	other := repoWithRemote(t, filepath.Join(base, "other"), "https://github.com/acme/other.git")

	rows := []struct {
		name   string
		dir    string
		cached string
		want   []string
	}{
		{"new clone, file reads only", widget, "", []string{"mono-b", "widget"}},
		{"linked worktree matches its main project", worktree, "", []string{"mono-b", "widget"}},
		{"fork with an upstream remote", fork, "", []string{"mono-b", "widget"}},
		{"copy with its remote removed, no cache", copyDir, "", nil},
		{"copy with its remote removed, root commit cached", copyDir, rootSHA, []string{"widget"}},
		{"monorepo subdirectory", sub, "", []string{"mono-b", "widget"}},
		{"unrelated repository", other, "", nil},
		{"not a git directory", base, "", nil},
	}
	for _, r := range rows {
		s, err := SignalsFor(r.dir, r.cached)
		if err != nil {
			t.Fatalf("%s: %v", r.name, err)
		}
		got := ix.Match(s)
		if len(got) == 0 {
			got = nil
		}
		if !reflect.DeepEqual(got, r.want) {
			t.Errorf("%s: matched %v, want %v", r.name, got, r.want)
		}
	}
	// The worktree's identity root is the main repository, so a match record
	// and the store's root-commit cache are keyed on it, not on the checkout.
	if s, _ := SignalsFor(worktree, ""); s.Root != widgetRoot(t, widget) {
		t.Fatalf("worktree identity root = %q, want the main repository %q", s.Root, widget)
	}
}

func widgetRoot(t *testing.T, dir string) string {
	t.Helper()
	r, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// TestDecide is the per-directory decision table.
func TestDecide(t *testing.T) {
	now := time.Now()
	m := orgcontract.ProjectMapping{Epoch: 3, MaxAgeSeconds: 3600, Projects: []orgcontract.ProjectMappingEntry{
		{OrgProjectID: "X", Repos: []orgcontract.ProjectRepoHashes{{RemoteHash: "rh"}}},
	}}
	digest := orgcontract.ProjectMappingDigest(m)
	bind := &orgcontract.ProjectBinding{Epoch: 3, MappingDigest: digest}
	fresh := &MappingFile{Mapping: m, BundleVersion: 7, AcceptedAt: now}
	stale := &MappingFile{Mapping: m, BundleVersion: 7, AcceptedAt: now.Add(-2 * time.Hour)}
	matching := func() (Signals, error) { return Signals{RemoteHash: "rh"}, nil }
	missing := func() (Signals, error) { return Signals{RemoteHash: "other"}, nil }
	notGit := func() (Signals, error) { return Signals{Root: "/tmp/scratch"}, nil }
	em := orgcontract.ProjectMapping{Epoch: 3, MaxAgeSeconds: 3600}
	emptyBind := &orgcontract.ProjectBinding{Epoch: 3, MappingDigest: orgcontract.ProjectMappingDigest(em)}
	emptyStale := &MappingFile{Mapping: em, BundleVersion: 7, AcceptedAt: now.Add(-2 * time.Hour)}
	tm := orgcontract.ProjectMapping{Epoch: 3, MaxAgeSeconds: 3600, Truncated: true}
	truncBind := &orgcontract.ProjectBinding{Epoch: 3, MappingDigest: orgcontract.ProjectMappingDigest(tm)}
	truncStale := &MappingFile{Mapping: tm, BundleVersion: 7, AcceptedAt: now.Add(-2 * time.Hour)}
	truncFresh := &MappingFile{Mapping: tm, BundleVersion: 7, AcceptedAt: now}
	rows := []struct {
		name string
		in   DecideInput
		want Decision
	}{
		{"no v3 delivery", DecideInput{Now: now}, Decision{State: StateNone}},
		{"no mapping", DecideInput{Composed: bind, ComposedVersion: 7, Now: now}, Decision{State: StateUnknown}},
		{
			"a current record inside its lifetime answers without the mapping",
			DecideInput{
				Composed: bind, ComposedVersion: 7,
				Record:      &MatchFile{OrgProjectIDs: []string{"X"}, Epoch: 3, MappingDigest: digest, ValidUntil: now.Add(time.Hour)},
				LoadMapping: func() *MappingFile { panic("the mapping was read") }, Now: now,
			},
			Decision{State: StateMatched, IDs: []string{"X"}, FromRecord: true},
		},
		{"a current record past its lifetime needs a live mapping", DecideInput{
			Composed: bind, ComposedVersion: 7,
			Record:  &MatchFile{OrgProjectIDs: []string{"X"}, Epoch: 3, MappingDigest: digest, ValidUntil: now.Add(-time.Minute)},
			Mapping: stale, Now: now,
		}, Decision{State: StateUnknown}},
		{"mapping of another version", DecideInput{Composed: bind, ComposedVersion: 8, Mapping: fresh, Now: now}, Decision{State: StateUnknown}},
		{"mapping past its lifetime", DecideInput{Composed: bind, ComposedVersion: 7, Mapping: stale, Signals: matching, Now: now}, Decision{State: StateUnknown}},
		// Lane sec-p2a audit finding 2: unknown only where a project bundle
		// could apply.
		{"mapping past its lifetime, a directory with no identity (not git)", DecideInput{
			Composed: bind, ComposedVersion: 7, Mapping: stale, Signals: notGit, Now: now,
		}, Decision{State: StateUnmatched}},
		{"no mapping, a directory with no identity (not git)", DecideInput{
			Composed: bind, ComposedVersion: 7, Signals: notGit, Now: now,
		}, Decision{State: StateUnmatched}},
		{"mapping past its lifetime listing no project for the member", DecideInput{
			Composed: emptyBind, ComposedVersion: 7, Mapping: emptyStale, Signals: matching, Now: now,
		}, Decision{State: StateUnmatched}},
		{"a truncated empty mapping past its lifetime stays unknown", DecideInput{
			Composed: truncBind, ComposedVersion: 7, Mapping: truncStale, Signals: matching, Now: now,
		}, Decision{State: StateUnknown}},
		{"an empty mapping of another delivery stays unknown", DecideInput{
			Composed: emptyBind, ComposedVersion: 8, Mapping: emptyStale, Signals: matching, Now: now,
		}, Decision{State: StateUnknown}},
		{"a truncated mapping, a directory with no identity", DecideInput{
			Composed: truncBind, ComposedVersion: 7, Mapping: truncFresh, Signals: notGit, Now: now,
		}, Decision{State: StateUnmatched}},
		{"a truncated mapping, an unmatched repository", DecideInput{
			Composed: truncBind, ComposedVersion: 7, Mapping: truncFresh, Signals: missing, Now: now,
		}, Decision{State: StateUnknown, Reason: ReasonTruncated}},
		{
			"current record answers",
			DecideInput{
				Composed: bind, ComposedVersion: 7, Mapping: fresh,
				Record: &MatchFile{OrgProjectIDs: []string{"X"}, Epoch: 3, MappingDigest: digest}, Signals: missing, Now: now,
			},
			Decision{State: StateMatched, IDs: []string{"X"}, FromRecord: true},
		},
		{
			"stale record falls back to the mapping",
			DecideInput{
				Composed: bind, ComposedVersion: 7, Mapping: fresh,
				Record: &MatchFile{OrgProjectIDs: []string{"X"}, Epoch: 2, MappingDigest: "old"}, Signals: missing, Now: now,
			},
			Decision{State: StateUnmatched},
		},
		{
			"no record, matched from the mapping",
			DecideInput{Composed: bind, ComposedVersion: 7, Mapping: fresh, Signals: matching, Now: now},
			Decision{State: StateMatched, IDs: []string{"X"}},
		},
	}
	for _, r := range rows {
		if got := Decide(r.in); !reflect.DeepEqual(got, r.want) {
			t.Errorf("%s: %+v, want %+v", r.name, got, r.want)
		}
	}
}
