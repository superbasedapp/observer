package secassessfixture

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The scorer of the module (internal/secassess, score_test.go scFixture and the
// golden tests) skips when it cannot find this fixture tree, so that it runs on
// its own in a checkout that lacks testdata/secassess. A skip is a pass: if the
// tree were ever excluded, moved or dropped by a merge, the whole golden tier
// would pass without scoring anything (review m10). This package owns the tree,
// so the check that it is there lives here and FAILS instead of skipping. It is
// the one test in the fixture that must never use t.Skip.

// fixtureDirEnv is the variable the scorer honours to point at a copy of the
// tree (internal/secassess/scorekey_test.go scFixtureDir).
const fixtureDirEnv = "OBSERVER_SECASSESS_FIXTURE_DIR"

// resolveFixtureDir resolves the fixture root the way the scorer does: the first
// candidate, in order, that holds truth/manifest.json as a regular file; an
// empty candidate is skipped. It returns "" when none does, which is the
// condition the scorer reads as "skip".
func resolveFixtureDir(cands ...string) string {
	for _, c := range cands {
		if c == "" {
			continue
		}
		if st, err := os.Stat(filepath.Join(c, "truth", "manifest.json")); err == nil && !st.IsDir() {
			return c
		}
	}
	return ""
}

func TestResolveFixtureDir(t *testing.T) {
	withManifest := func() string {
		dir := t.TempDir()
		if err := os.MkdirAll(filepath.Join(dir, "truth"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "truth", "manifest.json"), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	a, b, empty := withManifest(), withManifest(), t.TempDir()
	asDir := t.TempDir() // truth/manifest.json is a directory, not a file
	if err := os.MkdirAll(filepath.Join(asDir, "truth", "manifest.json"), 0o755); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name  string
		cands []string
		want  string
	}{
		{"the first candidate wins", []string{a, b}, a},
		{"an empty candidate is skipped", []string{"", b}, b},
		{"a candidate without the manifest falls through", []string{empty, b}, b},
		{"a manifest that is a directory is not a manifest", []string{asDir, b}, b},
		{"a missing directory falls through", []string{filepath.Join(empty, "nope"), a}, a},
		{"nothing holds the manifest", []string{"", empty, asDir}, ""},
		{"no candidates", nil, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := resolveFixtureDir(tc.cands...); got != tc.want {
				t.Errorf("resolved %q, want %q", got, tc.want)
			}
		})
	}
}

// TestFixtureTreeIsPresent fails, never skips, when the fixture tree is not
// where the scorer looks: it resolves the root with the scorer's own rule
// (OBSERVER_SECASSESS_FIXTURE_DIR, then the repository's testdata/secassess
// relative to the package directory, where `go test` runs a package's tests),
// and it requires the repository's own tree as well, because every other test
// of this package reads it from there. It then requires the answer key to parse
// and every file of the golden tier the scorer's tests rely on to exist.
func TestFixtureTreeIsPresent(t *testing.T) {
	wd, _ := os.Getwd()
	dir := resolveFixtureDir(os.Getenv(fixtureDirEnv), fixtureRoot)
	if dir == "" {
		t.Fatalf("the fixture tree is missing: no truth/manifest.json at %s=%q or at %s (working directory %s). "+
			"The scorer's golden tests skip in this state, which is a vacuous pass; `go test` runs a package in its own directory, "+
			"so run it from there or restore testdata/secassess",
			fixtureDirEnv, os.Getenv(fixtureDirEnv), fixtureRoot, wd)
	}
	if own := resolveFixtureDir(fixtureRoot); own == "" {
		t.Fatalf("the repository's fixture tree is missing: no truth/manifest.json at %s (working directory %s); "+
			"%s points at a copy (%s), which keeps the scorer running but not the tests of this package",
			fixtureRoot, wd, fixtureDirEnv, dir)
	}

	read := func(rel string) []byte {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatalf("the fixture tree at %s lacks %s: %v", dir, rel, err)
		}
		if len(b) == 0 {
			t.Fatalf("%s of the fixture tree at %s is empty", rel, dir)
		}
		return b
	}

	// The answer key: present and parseable by this package's strict decoders.
	if m, err := ParseManifest(read("truth/manifest.json")); err != nil {
		t.Errorf("truth/manifest.json does not parse: %v", err)
	} else if len(m.Flaws) == 0 {
		t.Errorf("truth/manifest.json lists no flaws")
	}
	if tm, err := ParseThreatModel(read("truth/threatmodel.json")); err != nil {
		t.Errorf("truth/threatmodel.json does not parse: %v", err)
	} else if len(tm.Threats) == 0 {
		t.Errorf("truth/threatmodel.json lists no threats")
	}
	if _, err := ParseProbes(read("truth/probes.json")); err != nil {
		t.Errorf("truth/probes.json does not parse: %v", err)
	}

	// The application the key's anchors resolve into.
	read("app/server.py")

	// The golden tier: the directory and every file the scorer's tests read.
	st, err := os.Stat(filepath.Join(dir, "golden"))
	if err != nil || !st.IsDir() {
		t.Fatalf("the fixture tree at %s has no golden directory: %v", dir, err)
	}
	for _, name := range goldenFileNames() {
		var top map[string]json.RawMessage
		if err := json.Unmarshal(read("golden/"+name), &top); err != nil {
			t.Errorf("golden/%s is not a JSON object: %v", name, err)
		}
	}
}
