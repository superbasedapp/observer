package stakpak

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/adapter/mirrorbase/mirrortest"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// TestMirrorSpecCoversQueries pins that every table this package queries
// is in mirrorSpec's allow-list, so the filtered foreign-mount mirror never
// silently lacks one (T-927).
func TestMirrorSpecCoversQueries(t *testing.T) {
	// chain is the recursive CTE of the transcript query, not a table.
	mirrortest.AssertSpecCoversQueries(t, mirrorSpec, ".", "chain")
}

// TestForeignMirrorKeepsOnlyAllowListedTables pins T-927 for this adapter
// (RB1 sweep finding A2): a foreign-mount store is mirrored with its
// allow-listed tables only; every other table and its rows (checkpointed or
// still in the WAL) never reach the copy.
func TestForeignMirrorKeepsOnlyAllowListedTables(t *testing.T) {
	mirrortest.AssertForeignStageFiltered(t, mirrorSpec, func(root string) {
		orig := allHomesFunc
		t.Cleanup(func() { allHomesFunc = orig })
		allHomesFunc = func() []crossmount.HomeRoot {
			return []crossmount.HomeRoot{{Path: root, OS: crossmount.OSWindows, Origin: "wsl-mnt:fake"}}
		}
	}, stageMirrorIfForeign)
}
