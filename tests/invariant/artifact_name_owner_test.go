package invariant

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestArtifactNameRuleHasOneOwner pins that the release-archive filename
// rule (`observer-<version>-<os>-<arch>.tar.gz|zip`) is compiled in exactly
// one place: internal/update. Two copies (the org server's importer and the
// release pipeline's manifest producer) each failed a real release on the
// first pre-release tags ever cut, v1.34.0-rc.1 and v1.34.0-rc.2, because
// the rc.1 fix landed in the copy the pipeline does not run.
func TestArtifactNameRuleHasOneOwner(t *testing.T) {
	t.Parallel()
	root := filepath.Join("..", "..")
	decl := regexp.MustCompile(`artifactNameRe\s*=\s*regexp\.MustCompile`)
	var owners []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := d.Name()
		if d.IsDir() {
			if name == ".git" || name == "node_modules" || name == "vendor" || name == "website" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		b, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		if decl.Match(b) {
			rel, _ := filepath.Rel(root, path)
			owners = append(owners, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"internal/update/artifactname.go"}
	if strings.Join(owners, ",") != strings.Join(want, ",") {
		t.Errorf("artifactNameRe is declared in %v, want exactly %v (one owner; every consumer calls update.ParseArtifactName)", owners, want)
	}
}
