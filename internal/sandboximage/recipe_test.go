package sandboximage

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// recipeDir is the default image's recipe (deploy/sandbox-image).
var recipeDir = filepath.Join("..", "..", "deploy", "sandbox-image")

func readRecipe(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(recipeDir, name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestRecipeCarriesNoAgentCLI pins SBX-IMG-1 on the recipe itself: no
// package, install step or entry point brings an agent CLI into the image.
func TestRecipeCarriesNoAgentCLI(t *testing.T) {
	for _, line := range strings.Split(readRecipe(t, "packages.txt"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if IsAgentPackage(line) {
			t.Errorf("packages.txt names an agent CLI: %s", line)
		}
		if !debNameRE.MatchString(line) {
			t.Errorf("packages.txt line %q is not a Debian package name", line)
		}
	}
	df := readRecipe(t, "Dockerfile")
	for _, bad := range []*regexp.Regexp{
		regexp.MustCompile(`(?m)\bnpm\s+(i|install)\b`),
		regexp.MustCompile(`(?m)\bpipx?\s+install\b`),
		regexp.MustCompile(`(?m)\b(curl|wget)\b[^\n]*\|\s*(ba)?sh\b`),
		regexp.MustCompile(`(?m)^\s*(ENTRYPOINT|CMD|USER|ENV)\b`),
		regexp.MustCompile(`(?m)^\s*ADD\b`),
	} {
		if bad.MatchString(df) {
			t.Errorf("the Dockerfile matches %s: the image installs nothing beyond packages.txt and sets no entry point, user or environment", bad)
		}
	}
	for _, m := range agentMarkers {
		if regexp.MustCompile(`(?i)\b` + regexp.QuoteMeta(m) + `\b`).MatchString(strings.ReplaceAll(df, "agent-cli", "")) {
			t.Errorf("the Dockerfile names agent CLI %s", m)
		}
	}
	// build.sh's static check carries the same closed list.
	sh := readRecipe(t, "build.sh")
	for _, m := range agentMarkers {
		if !strings.Contains(sh, "|"+m+"|") && !strings.Contains(sh, "("+m+"|") && !strings.Contains(sh, "|"+m+")") {
			t.Errorf("build.sh's agent list lacks %s", m)
		}
	}
}

// TestRecipeIsPinned: the base by digest, the packages by a snapshot, the
// timestamps by SOURCE_DATE_EPOCH, and the build never signs or pushes.
func TestRecipeIsPinned(t *testing.T) {
	df := readRecipe(t, "Dockerfile")
	m := regexp.MustCompile(`(?m)^ARG BASE=(\S+)$`).FindStringSubmatch(df)
	if m == nil || !baseRefRE.MatchString(m[1]) {
		t.Fatalf("the Dockerfile's BASE is not pinned by digest: %v", m)
	}
	for _, want := range []string{"snapshot.debian.org", "DEBIAN_SNAPSHOT", "SOURCE_DATE_EPOCH", "--no-install-recommends", "FROM scratch AS packages"} {
		if !strings.Contains(df, want) {
			t.Errorf("the Dockerfile lacks %q", want)
		}
	}
	sh := readRecipe(t, "build.sh")
	for _, want := range []string{"rewrite-timestamp=true", "SOURCE_DATE_EPOCH", "--provenance=false", "vendorsign sandboximage", "set -euo pipefail"} {
		if !strings.Contains(sh, want) {
			t.Errorf("build.sh lacks %q", want)
		}
	}
	for _, bad := range []string{"-key", "docker push", "buildx imagetools", "skopeo copy", "--push"} {
		for _, line := range strings.Split(sh, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "#") {
				continue
			}
			if strings.Contains(line, bad) {
				t.Errorf("build.sh must never sign or push: %q", line)
			}
		}
	}
	if fi, err := os.Stat(filepath.Join(recipeDir, "build.sh")); err != nil || fi.Mode()&0o111 == 0 {
		t.Errorf("build.sh must be executable: %v", err)
	}
}
