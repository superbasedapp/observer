package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/projectmatch"
)

// TestProjectPolicyLine pins the New Terminal "project policy" line (lane
// sec-p2b), one row per state: no project delivery shows nothing; a current
// match record naming a project reads matched; a directory nothing matched
// reads not matched; a mapping past its offline lifetime reads unknown.
func TestProjectPolicyLine(t *testing.T) {
	now := time.Now()
	write := func(t *testing.T, path string, v any) {
		t.Helper()
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	setup := func(t *testing.T, v3 bool, acceptedAt time.Time) (bundlePath, matchedDir, otherDir string) {
		t.Helper()
		base := t.TempDir()
		bundlePath = filepath.Join(base, "guard", "org-policy-bundle.json")
		m := orgcontract.ProjectMapping{
			OrgID: "org", Subject: "u", Epoch: 4, MaxAgeSeconds: orgcontract.DefaultProjectMappingMaxAge,
			Projects: []orgcontract.ProjectMappingEntry{{OrgProjectID: "p1", Repos: []orgcontract.ProjectRepoHashes{{RemoteHash: "rh"}}}},
		}
		b := orgcontract.PolicyBundle{Version: 9, BundleTOML: "# org\n"}
		if v3 {
			b.ProjectBinding = &orgcontract.ProjectBinding{OrgID: "org", Subject: "u", Epoch: 4, MappingDigest: orgcontract.ProjectMappingDigest(m)}
		}
		write(t, bundlePath, b)
		layout := projectmatch.LayoutFor(bundlePath)
		write(t, layout.MappingPath(), projectmatch.MappingFile{Mapping: m, BundleVersion: 9, AcceptedAt: acceptedAt})
		matchedDir, otherDir = filepath.Join(base, "billing"), filepath.Join(base, "scratch")
		for _, d := range []string{matchedDir, otherDir} {
			if err := os.MkdirAll(d, 0o700); err != nil {
				t.Fatal(err)
			}
		}
		sig, err := projectmatch.SignalsFor(matchedDir, "")
		if err != nil {
			t.Fatal(err)
		}
		write(t, layout.MatchPath(projectmatch.RootHash(sig.Root)), projectmatch.MatchFile{
			ProjectRootHash: projectmatch.RootHash(sig.Root), OrgProjectIDs: []string{"p1"}, Epoch: 4,
			MappingDigest: orgcontract.ProjectMappingDigest(m), MatchedAt: now, ValidUntil: acceptedAt.Add(time.Duration(m.MaxAgeSeconds) * time.Second),
		})
		return bundlePath, matchedDir, otherDir
	}
	ctx := context.Background()

	noV3, noV3Dir, _ := setup(t, false, now)
	if got := projectPolicyLineFor(ctx, noV3, nil, noV3Dir, now); got.Shown {
		t.Fatalf("no project delivery: %+v", got)
	}

	bundle, matched, other := setup(t, true, now)
	if got := projectPolicyLineFor(ctx, bundle, nil, matched, now); got != (dashapi.ProjectPolicyLine{Shown: true, State: dashapi.ProjectPolicyMatched, Projects: 1}) {
		t.Fatalf("matched dir: %+v", got)
	}
	if got := projectPolicyLineFor(ctx, bundle, nil, other, now); got != (dashapi.ProjectPolicyLine{Shown: true, State: dashapi.ProjectPolicyNotMatched}) {
		t.Fatalf("other dir: %+v", got)
	}

	// Past its offline lifetime the mapping cannot answer for a repository
	// (unknown); a directory that is not a repository can match no project
	// either way, so it stays not matched (lane sec-p2a audit finding 2,
	// projectmatch.Decide).
	bundle, _, other = setup(t, true, now.Add(-30*24*time.Hour))
	if got := projectPolicyLineFor(ctx, bundle, nil, other, now); got != (dashapi.ProjectPolicyLine{Shown: true, State: dashapi.ProjectPolicyNotMatched}) {
		t.Fatalf("expired mapping, not a repository: %+v", got)
	}
	if _, err := exec.LookPath("git"); err == nil {
		for _, args := range [][]string{{"init", "-q"}, {"remote", "add", "origin", "https://github.com/acme/scratch.git"}} {
			cmd := exec.Command("git", args...)
			cmd.Dir = other
			cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("git %v: %v %s", args, err, out)
			}
		}
		if got := projectPolicyLineFor(ctx, bundle, nil, other, now); got != (dashapi.ProjectPolicyLine{Shown: true, State: dashapi.ProjectPolicyUnknown}) {
			t.Fatalf("expired mapping, a repository: %+v", got)
		}
	}

	var cfg config.Config
	if terminalProjectPolicySeam(cfg, nil) != nil {
		t.Fatal("no org bundle path must give no seam")
	}
}
