package invariant

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
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

// unrecordedMigrationDirs are the directories holding NNN_name.sql files that
// are deliberately not a lineage of the released-step record, each with its
// reason (INTEL-03, 2026-11-24). A directory the walk finds that is neither
// recorded nor listed here fails TestEveryMigrationDirectoryIsARecordedLineage,
// which is how the obs lineage would have been caught.
var unrecordedMigrationDirs = map[string]string{
	"marketing/internal/store/migrations": "the private-only marketing pipeline (release.sh PRIVATE_ONLY_PATHS): " +
		"never in a release, one operator database",
	"model-pricing/db/migrations": "the private-only pricing pipeline (PRIVATE_ONLY_PATHS): its own database, " +
		"never shipped to an install",
	"deploy/aggregate-collector/migrations": "the hosted aggregate collector's Cloudflare D1 database, applied and " +
		"tracked by wrangler (d1_migrations), not by an Observer runner; recording its production head is a " +
		"follow-up (2026-11-24), see docs/migration-numbering.md",
}

// TestEveryMigrationDirectoryIsARecordedLineage walks the tree for every
// directory that holds numbered NNN_name.sql steps and requires each to be a
// lineage of the released-step record or a listed exception: a runner added
// with its own lineage (as internal/obs/store was, 28 steps unrecorded until
// INTEL-03) cannot ship outside the rule again.
func TestEveryMigrationDirectoryIsARecordedLineage(t *testing.T) {
	root := repoRoot(t)
	recorded := map[string]bool{}
	for _, d := range shipped.Lineages() {
		recorded[d.Dir] = true
	}
	skip := map[string]bool{".git": true, "node_modules": true, "testdata": true, "dist": true}
	found := map[string]bool{}
	err := filepath.WalkDir(root, func(path string, de fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if de.IsDir() {
			if skip[de.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if _, ok := shipped.StepNumber(de.Name()); !ok {
			return nil
		}
		rel, err := filepath.Rel(root, filepath.Dir(path))
		if err != nil {
			return err
		}
		found[filepath.ToSlash(rel)] = true
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	for dir := range found {
		if recorded[dir] {
			continue
		}
		if _, ok := unrecordedMigrationDirs[dir]; ok {
			continue
		}
		t.Errorf("%s holds numbered migration steps but is not a lineage of %s: add it to the lineage table in "+
			"internal/migplan/shipped and record it with `make shipped-migrations LINEAGE=<name> REF=<last release tag>` "+
			"(%s), or list it with its reason in unrecordedMigrationDirs", dir, shipped.RecordPath, shipped.RuleDoc)
	}
	for _, d := range shipped.Lineages() {
		if !found[d.Dir] {
			skipInPublicTree(t, root, d.Dir)
			t.Errorf("lineage %s's directory %s holds no steps: the walk or the table is wrong", d.Name, d.Dir)
		}
	}
}

// TestShippedObsStepsCannotBeRenumbered pins INTEL-03 against the committed
// record: renumbering a shipped obs step above the head, or adding a step in a
// gap at or below it, breaks the released-step rule. The obs runner keys a
// per-step ledger, so either would otherwise leave existing nodes on a schema
// a fresh install never has.
func TestShippedObsStepsCannotBeRenumbered(t *testing.T) {
	root := repoRoot(t)
	data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(shipped.RecordPath)))
	if err != nil {
		t.Fatalf("read %s: %v", shipped.RecordPath, err)
	}
	rec, err := shipped.Parse(data)
	if err != nil {
		t.Fatalf("parse %s: %v", shipped.RecordPath, err)
	}
	var obs *shipped.Lineage
	for i := range rec.Lineages {
		if rec.Lineages[i].Name == "obs" {
			obs = &rec.Lineages[i]
		}
	}
	if obs == nil || obs.Dir != "internal/obs/store/migrations" || obs.Head < 28 {
		t.Fatalf("the record's obs lineage = %+v, want internal/obs/store/migrations with head >= 28", obs)
	}
	shippedTree := append([]shipped.Step(nil), obs.Steps...)
	if vs := shipped.Check(*obs, shippedTree); len(vs) != 0 {
		t.Fatalf("the shipped tree itself fails: %v", vs)
	}

	last := shippedTree[len(shippedTree)-1]
	n, _ := shipped.StepNumber(last.File)
	_, name, _ := strings.Cut(last.File, "_")
	renumbered := append(append([]shipped.Step(nil), shippedTree[:len(shippedTree)-1]...),
		shipped.Step{File: fmt.Sprintf("%04d_%s", n+1, name), Blob: last.Blob})
	if vs := shipped.Check(*obs, renumbered); len(vs) == 0 {
		t.Errorf("renumbering shipped obs step %s to %04d passed the released-step rule", last.File, n+1)
	}

	gap := 0
	have := map[int]bool{}
	for _, s := range shippedTree {
		k, _ := shipped.StepNumber(s.File)
		have[k] = true
	}
	for k := 1; k <= obs.Head; k++ {
		if !have[k] {
			gap = k
			break
		}
	}
	if gap == 0 {
		gap = obs.Head
	}
	late := append(append([]shipped.Step(nil), shippedTree...),
		shipped.Step{File: fmt.Sprintf("%04d_late_step.sql", gap), Blob: strings.Repeat("e", 40)})
	if vs := shipped.Check(*obs, late); len(vs) == 0 {
		t.Errorf("a new obs step numbered %04d (at or below the shipped head %d) passed the released-step rule", gap, obs.Head)
	}
}
