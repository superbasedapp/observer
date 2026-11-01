package invariant

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// winrelay_test.go pins the fail-open Windows route relay's reach (lane
// `winrelay` in egress_lanes_test.go; finding CC-9, decision D12): the
// package that forwards a request straight to a provider is linked ONLY by
// the `observer relay` command file, so no always-on daemon path (watcher,
// proxy, hook, store, the maintain loops in cmd/observer) can start it, and
// the hook path never touches the relay at all (the relay fails open for
// model traffic only; the hook gate keeps its own fail-closed semantics).

const winrelaySvcImport = modulePath + "internal/winrelaysvc"

// winrelaySvcImporters is the closed set of files allowed to import the
// relay's forwarding package.
var winrelaySvcImporters = map[string]bool{
	"cmd/observer/relay.go": true,
}

func TestWinrelaySvcLinkedOnlyByTheRelayCommand(t *testing.T) {
	root := filepath.Join("..", "..")
	fset := token.NewFileSet()
	for _, dir := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			rel, _ := filepath.Rel(root, path)
			rel = filepath.ToSlash(rel)
			if strings.HasPrefix(rel, "internal/winrelaysvc/") {
				return nil
			}
			af, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
			if err != nil {
				t.Fatalf("parse %s: %v", rel, err)
			}
			for _, imp := range af.Imports {
				if strings.Trim(imp.Path.Value, `"`) == winrelaySvcImport && !winrelaySvcImporters[rel] {
					t.Errorf("%s imports %s: the relay's forwarding package may be linked only by the `observer relay` command (winrelaySvcImporters)", rel, winrelaySvcImport)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}
}

// TestHookPathNeverReachesTheRelay: no file of the hook package or of the
// `observer hook` command imports either relay package.
func TestHookPathNeverReachesTheRelay(t *testing.T) {
	root := filepath.Join("..", "..")
	fset := token.NewFileSet()
	matches, _ := filepath.Glob(filepath.Join(root, "cmd", "observer", "hook*.go"))
	_ = filepath.WalkDir(filepath.Join(root, "internal", "hook"), func(path string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(path, ".go") {
			matches = append(matches, path)
		}
		return nil
	})
	if len(matches) < 10 {
		t.Fatalf("only %d hook-path files found; the scan no longer sees them", len(matches))
	}
	for _, path := range matches {
		af, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, imp := range af.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			if p == winrelaySvcImport || p == modulePath+"internal/winrelay" {
				t.Errorf("%s imports %s: the hook path never goes through the relay", filepath.ToSlash(path), p)
			}
		}
	}
}
