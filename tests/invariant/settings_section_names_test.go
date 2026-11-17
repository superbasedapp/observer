package invariant

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestNodeSettingsPointersNameRealSections is the section-name drift test the
// 2026-11-11 control-coverage audit proposed (CG-24, CG-27): every
// "Settings > X" pointer a node surface prints in a Go string literal must
// name a section the node dashboard's Settings rail actually shows (its
// labels, read from web/src/pages/Settings.tsx), or Components (a route of
// its own, linked from the rail). "Settings > Setup" and "Settings >
// Terminal" sent developers to sections that do not exist.
//
// Not checked: "Terminals > Settings > X" (the Terminals page's own settings
// area) and the org dashboard's Settings, which is web2 and lives outside the
// scanned trees.
func TestNodeSettingsPointersNameRealSections(t *testing.T) {
	root := filepath.Join("..", "..")
	raw, err := os.ReadFile(filepath.Join(root, "web", "src", "pages", "Settings.tsx"))
	if err != nil {
		t.Fatalf("read Settings.tsx: %v", err)
	}
	labelRE := regexp.MustCompile(`(?m)^    id: "[a-z-]+",\s*\n    label: "([^"]+)"`)
	labels := []string{"Components"}
	for _, m := range labelRE.FindAllStringSubmatch(string(raw), -1) {
		labels = append(labels, m[1])
	}
	if len(labels) < 20 {
		t.Fatalf("parsed only %d Settings labels from Settings.tsx; the section table moved", len(labels))
	}

	// exempt names files whose "Settings > X" text points at a VENDOR's own
	// app, not at this dashboard.
	exempt := map[string]string{
		"cmd/observer/cloudagents.go": "vendor consoles (OpenHands, Warp) name their own Settings menus",
	}

	pointerRE := regexp.MustCompile(`(Terminals > )?Settings > ([A-Z][A-Za-z]*(?: [A-Za-z]+)*)`)
	var bad []string
	for _, dir := range []string{"cmd/observer", "internal/intelligence/dashboard", "internal/guard"} {
		err := filepath.WalkDir(filepath.Join(root, filepath.FromSlash(dir)), func(p string, d fs.DirEntry, werr error) error {
			if werr != nil {
				return werr
			}
			if d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return nil
			}
			rel, _ := filepath.Rel(root, p)
			rel = filepath.ToSlash(rel)
			if _, ok := exempt[rel]; ok {
				return nil
			}
			body, rerr := os.ReadFile(p)
			if rerr != nil {
				return rerr
			}
			for i, line := range strings.Split(string(body), "\n") {
				trim := strings.TrimSpace(line)
				if strings.HasPrefix(trim, "//") || !strings.Contains(line, `"`) {
					continue
				}
				for _, m := range pointerRE.FindAllStringSubmatch(line, -1) {
					if m[1] != "" {
						continue // the Terminals page's own settings area
					}
					if !namesLabel(m[2], labels) {
						bad = append(bad, rel+":"+itoa(int64(i+1))+": Settings > "+m[2])
					}
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}
	for _, b := range bad {
		t.Errorf("%s names no Settings section (labels: %s)", b, strings.Join(labels, ", "))
	}
}

// namesLabel reports whether the words after "Settings > " start with one of
// the section labels at a word boundary.
func namesLabel(words string, labels []string) bool {
	for _, l := range labels {
		if words == l || strings.HasPrefix(words, l+" ") {
			return true
		}
	}
	return false
}
