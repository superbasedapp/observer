package invariant

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// web_case_collision_test.go pins that no two web source modules differ
// only by letter case.
//
// shared/components/sessiondetail once held both GaugeStat.tsx and
// gaugeStat.ts. Linux resolves `./GaugeStat` to the .tsx, but on a
// case-insensitive file system (Windows, default macOS) Vite tries the .ts
// extension first, finds gaugeStat.ts under the GaugeStat.ts spelling, and
// the node and org dashboard builds fail ("GaugeStat" is not exported). The
// Linux CI dist gates cannot see this class, so it is pinned here.

// webModuleRoots are the npm-workspace source trees Vite bundles.
var webModuleRoots = []string{"web", "web2", "webcloud", "shared"}

// webModuleExts are the extensions Vite's resolver tries for a bare import.
var webModuleExts = map[string]bool{
	".mjs": true, ".js": true, ".mts": true, ".ts": true, ".jsx": true, ".tsx": true, ".json": true,
}

func TestWebModulesDoNotCollideByCase(t *testing.T) {
	root := repoRoot(t)
	// lower-cased import path (extension stripped) -> distinct exact spellings.
	spellings := map[string]map[string]bool{}
	for _, top := range webModuleRoots {
		base := filepath.Join(root, top)
		if _, err := os.Stat(base); os.IsNotExist(err) {
			continue
		}
		err := filepath.WalkDir(base, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				switch d.Name() {
				case "node_modules", "dist", ".vite":
					return filepath.SkipDir
				}
				return nil
			}
			ext := filepath.Ext(p)
			if !webModuleExts[ext] {
				return nil
			}
			rel, err := filepath.Rel(root, p)
			if err != nil {
				return err
			}
			stem := filepath.ToSlash(strings.TrimSuffix(rel, ext))
			key := strings.ToLower(stem)
			if spellings[key] == nil {
				spellings[key] = map[string]bool{}
			}
			spellings[key][stem] = true
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", base, err)
		}
	}
	for _, set := range spellings {
		if len(set) < 2 {
			continue
		}
		names := make([]string, 0, len(set))
		for s := range set {
			names = append(names, s)
		}
		sort.Strings(names)
		t.Errorf("web modules differ only by case (break Windows/macOS builds): %v", names)
	}
}
