package invariant

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

// release_workflow_helpers_test.go is the parsed model of the release
// pipeline (.github/workflows/npm-release.yml) that the release, cosign and
// codesign tests share. It ships on the public tree because the codesign
// tests also pin public scripts (scripts/codesign.sh,
// scripts/codesign-apple-inputs.sh) and the installer/ sources; the workflow
// itself is private-only (scripts/release.sh PRIVATE_ONLY_FILES), so
// loadWorkflow skips its caller on the public tree and the script tests in
// the same files still run there.

// workflowPath is the release pipeline, relative to the repository root.
const workflowPath = ".github/workflows/npm-release.yml"

// workflowJob is the subset of a job's shape these tests reason about.
type workflowJob struct {
	Name        string            `yaml:"name"`
	If          string            `yaml:"if"`
	Needs       yaml.Node         `yaml:"needs"`
	Environment yaml.Node         `yaml:"environment,omitempty"`
	Permissions map[string]string `yaml:"permissions"`
	Steps       []workflowStep    `yaml:"steps"`
}

// workflowStep is the subset of a step's shape these tests reason about.
type workflowStep struct {
	Name string            `yaml:"name"`
	ID   string            `yaml:"id"`
	If   string            `yaml:"if"`
	Uses string            `yaml:"uses"`
	Run  string            `yaml:"run"`
	Env  map[string]string `yaml:"env"`
	With map[string]any    `yaml:"with"`
}

// workflowDoc is the parsed release pipeline.
type workflowDoc struct {
	Jobs map[string]workflowJob `yaml:"jobs"`
}

// workflowEnvDoc is the top-level env block of the release pipeline.
type workflowEnvDoc struct {
	Env map[string]string `yaml:"env"`
}

// loadWorkflow parses the release pipeline, failing the test if it is not
// valid YAML at all (which is itself worth catching before a tag push). On
// the public tree, which does not carry the release pipeline, it skips t.
func loadWorkflow(t *testing.T) (workflowDoc, string) {
	t.Helper()
	root := repoRoot(t)
	skipInPublicTree(t, root, workflowPath)
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(workflowPath)))
	if err != nil {
		t.Fatalf("read %s: %v", workflowPath, err)
	}
	var doc workflowDoc
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("%s is not valid YAML: %v", workflowPath, err)
	}
	if len(doc.Jobs) == 0 {
		t.Fatalf("%s declares no jobs", workflowPath)
	}
	return doc, string(raw)
}

// jobText renders one job back to YAML so a test can assert on everything it
// contains without walking every nested field by hand.
func jobText(t *testing.T, j workflowJob) string {
	t.Helper()
	b, err := yaml.Marshal(j)
	if err != nil {
		t.Fatalf("re-marshal job: %v", err)
	}
	return string(b)
}
