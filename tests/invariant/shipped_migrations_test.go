package invariant

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/migplan/shipped"
)

// TestShippedMigrationsNeverChange is the released-step gate (D-880, T-982).
// Once a migration step has shipped (a public release tag, or the production
// cloud database), no new step in its lineage may be numbered at or below the
// shipped head, and a shipped step's file never changes or disappears. Then a
// release only appends after the previous release's last step, no install
// ever receives a late lower-numbered step, and the update path's snapshot
// rule (snapshot when the manifest schema_version rises) is always enough.
//
// The record of what shipped is shipped.RecordPath, written by
// tools/shippedmiggen after each release tag and each production cloud roll
// (docs/migration-numbering.md, "The released-step rule").
func TestShippedMigrationsNeverChange(t *testing.T) {
	root := repoRoot(t)
	recordFile := filepath.Join(root, filepath.FromSlash(shipped.RecordPath))
	data, err := os.ReadFile(recordFile)
	if err != nil {
		t.Fatalf("read the shipped-migrations record %s: %v\n"+
			"It is required: restore it from git, or regenerate it with `make shipped-migrations REF=<last release tag>` (see %s).",
			shipped.RecordPath, err, shipped.RuleDoc)
	}
	rec, err := shipped.Parse(data)
	if err != nil {
		t.Fatalf("%s is malformed: %v\n"+
			"Never edit it by hand: restore it from git, or regenerate it with `make shipped-migrations REF=<last release tag>` "+
			"and `make shipped-migrations LINEAGE=cloud REF=<deployed cloud build sha>` (see %s).",
			shipped.RecordPath, err, shipped.RuleDoc)
	}
	for _, entry := range rec.Lineages {
		t.Run(entry.Name, func(t *testing.T) {
			dir := filepath.Join(root, filepath.FromSlash(entry.Dir))
			des, err := os.ReadDir(dir)
			if errors.Is(err, fs.ErrNotExist) {
				skipInPublicTree(t, root, entry.Dir)
				t.Fatalf("%s: the %s lineage's directory %s is gone, but %d steps of it shipped in %s. "+
					"A shipped step is never removed: restore the directory (git checkout %s -- %s).",
					shipped.RecordPath, entry.Name, entry.Dir, len(entry.Steps), entry.Ref, entry.Ref, entry.Dir)
			}
			if err != nil {
				t.Fatalf("read %s: %v", entry.Dir, err)
			}
			var tree []shipped.Step
			for _, de := range des {
				if de.IsDir() {
					continue
				}
				if _, ok := shipped.StepNumber(de.Name()); !ok {
					continue
				}
				b, err := os.ReadFile(filepath.Join(dir, de.Name()))
				if err != nil {
					t.Fatalf("read %s/%s: %v", entry.Dir, de.Name(), err)
				}
				tree = append(tree, shipped.Step{File: de.Name(), Blob: shipped.BlobID(b)})
			}
			for _, v := range shipped.Check(entry, tree) {
				t.Errorf("released-step rule (%s; record %s):\n%s", shipped.RuleDoc, shipped.RecordPath, v)
			}
		})
	}
}
