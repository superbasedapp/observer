package goose

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/adapter/mirrorbase/mirrortest"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// TestMirrorSpecCoversQueries pins that every table this package queries
// is in mirrorSpec's allow-list, so the filtered foreign-mount mirror never
// silently lacks one (T-927).
func TestMirrorSpecCoversQueries(t *testing.T) {
	mirrortest.AssertSpecCoversQueries(t, mirrorSpec, ".")
}

// TestForeignMirrorKeepsOnlyAllowListedTables pins T-927: a foreign-mount
// store is mirrored with its allow-listed tables only; credential tables
// and their rows (checkpointed or still in the WAL) never reach the copy.
func TestForeignMirrorKeepsOnlyAllowListedTables(t *testing.T) {
	mirrortest.AssertForeignStageFiltered(t, mirrorSpec, func(root string) {
		orig := allHomesFunc
		t.Cleanup(func() { allHomesFunc = orig })
		allHomesFunc = func() []crossmount.HomeRoot {
			return []crossmount.HomeRoot{{Path: root, OS: crossmount.OSWindows, Origin: "wsl-mnt:fake"}}
		}
	}, stageMirrorIfForeign)
}
