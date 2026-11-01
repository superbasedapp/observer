package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/policystate"
	"github.com/marmutapp/superbased-observer/internal/projectmatch"
)

// TestDaemonMatcherFeedsTheSectionReport is SEC-P2B audit finding 4: the
// per-section status end to end through the daemon's own pieces, not a hand
// written record: the matcher (projectMatcher.matchAndRecord) writes the
// match record for a repository of project X, the live guard reads it
// (OrgProjectSectionReport), and the policy-state reporter sends it on the
// guard row: X applied, Y not matched.
func TestDaemonMatcherFeedsTheSectionReport(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	base := t.TempDir()
	dir := filepath.Join(base, "widget")
	remote := "https://github.com/acme/widget.git"
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"init", "-q"}, {"remote", "add", "origin", remote}} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	pub := base64.RawURLEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
	const version, epoch = int64(9), int64(2)
	m := orgcontract.SignProjectMapping(priv, orgcontract.ProjectMapping{
		OrgID: "org", Subject: "u", Epoch: epoch, MaxAgeSeconds: orgcontract.DefaultProjectMappingMaxAge,
		Projects: []orgcontract.ProjectMappingEntry{
			{OrgProjectID: "X", Repos: []orgcontract.ProjectRepoHashes{{RemoteHash: projectmatch.Hash(git.NormalizeRemote(remote))}}},
			{OrgProjectID: "Y", Repos: []orgcontract.ProjectRepoHashes{{RemoteHash: projectmatch.Hash("github.com/acme/gadget")}}},
		},
	})
	b := orgcontract.PolicyBundle{
		Version: version, BundleTOML: "# floor\n", PublicKey: pub,
		ProjectBinding: &orgcontract.ProjectBinding{OrgID: "org", Subject: "u", Epoch: epoch, MappingDigest: orgcontract.ProjectMappingDigest(m)},
	}
	b.Signature = orgcontract.SignPolicyBundleEnvelope(priv, b)
	home := filepath.Join(base, "home")
	bundlePath := filepath.Join(home, "org-policy-bundle.json")
	layout := projectmatch.LayoutFor(bundlePath)
	write := func(path string, v any) {
		t.Helper()
		raw, _ := json.Marshal(v)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(bundlePath, b)
	write(layout.MappingPath(), projectmatch.MappingFile{Mapping: m, BundleVersion: version, AcceptedAt: time.Now()})
	for _, id := range []string{"X", "Y"} {
		env := orgcontract.PolicyBundle{
			Version: version, BundleTOML: "[[override]]\nrule = \"R-110\"\ndecision = \"deny\"\nenforce = true\n", PublicKey: pub,
			ProjectBinding: &orgcontract.ProjectBinding{OrgID: "org", Subject: "u", OrgProjectID: id, Epoch: epoch},
		}
		env.Signature = orgcontract.SignPolicyBundleEnvelope(priv, env)
		write(layout.EnvelopePath(id), env)
	}

	// The daemon's matcher writes the record.
	if rec, ok, err := (projectMatcher{bundlePath: bundlePath, now: time.Now}).matchAndRecord(context.Background(), dir); err != nil || !ok || len(rec.OrgProjectIDs) != 1 || rec.OrgProjectIDs[0] != "X" {
		t.Fatalf("matcher = %+v ok=%v err=%v", rec, ok, err)
	}
	// The live guard reads it.
	g, err := guard.New(guard.Options{Config: config.GuardConfig{Enabled: true, Mode: "enforce", Rules: config.GuardRulesConfig{OrgBundle: bundlePath}}, Home: home})
	if err != nil {
		t.Fatal(err)
	}
	// The reporter sends it, through the daemon's own decoration.
	readers := gen2Readers(t)
	readers[policystate.PointGuard] = withProjectSectionStatus(newGuardPointReader(
		guardBundleCheckFrom(&fakeBundleVerifier{check: orgclient.CachedBundleCheck{Integrity: orgcontract.BundleIntegrityVerified}}, bundlePath),
		func() guardRunning {
			return guardRunning{RunningVersion: version, EffectiveHash: psHex64, Mode: "enforce"}
		},
		func() orgclient.GuardFetchOutcome { return orgclient.GuardFetchOutcome{} },
		nil,
		time.Now,
	), projectSectionStatusFrom(g, time.Now))
	fp := &fakePoster{}
	newPolicyStateReporter(fp, readers, seqCounter(t), "v", true, nil).report(context.Background())
	if fp.callCount() != 1 {
		t.Fatalf("posted %d times, want 1", fp.callCount())
	}
	row := guardRowOf(t, fp.last)
	want := []orgcontract.ProjectSectionState{
		{OrgProjectID: "X", Status: orgcontract.ProjectSectionApplied},
		{OrgProjectID: "Y", Status: orgcontract.ProjectSectionNotMatched},
	}
	if len(row.ProjectSectionStatus) != 2 || row.ProjectSectionStatus[0] != want[0] || row.ProjectSectionStatus[1] != want[1] || row.ProjectSectionTruncated {
		t.Fatalf("guard row sections = %+v (truncated %v), want %+v", row.ProjectSectionStatus, row.ProjectSectionTruncated, want)
	}
}
