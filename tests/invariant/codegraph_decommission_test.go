package invariant

import (
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// The external code-graph dependency (the `codebase-memory-mcp` companion
// behind internal/codegraph) was decommissioned in Phase 4 of the
// internal/codeintel build-out — replaced by the in-process, CGO-free
// code-intelligence engine. These guards fail loudly if it reappears, so a
// future change can't silently re-introduce a third-party binary download
// or a dependency on the deleted package (plan §12.5;
// docs/codeintel/migration-from-codegraph.md). Since the final removal
// (post-Agent-Access backlog item 3, 2026-09-27) they also pin that the
// legacy config blocks and every "codegraph" identifier stay gone, and
// that a config file still carrying the legacy blocks keeps loading.
//
// The forbidden tokens are assembled from fragments so this guard file
// never matches itself.
var (
	forbiddenPkg    = "github.com/marmutapp/superbased-observer/internal/" + "codegraph"
	forbiddenBinary = "codebase-memory" + "-mcp"

	// forbiddenIdents are matched case-insensitively against source text.
	forbiddenIdents = []string{"code" + "graph", "code" + "_graph"}

	// legacyConfigTag is the TOML table name both removed config blocks
	// used ([compression.<tag>] and [intelligence.<tag>]).
	legacyConfigTag = "code" + "_graph"
)

// identScanRoots are the source trees (relative to the repo root) and the
// file extensions TestNoCodegraphIdentifier walks.
var identScanRoots = []struct {
	dir  string
	exts []string
}{
	{"internal", []string{".go"}},
	{"cmd", []string{".go"}},
	{"tests", []string{".go"}},
	{"web/src", []string{".ts", ".tsx"}},
	{"web2/src", []string{".ts", ".tsx"}},
	{"webcloud/src", []string{".ts", ".tsx"}},
	{"shared", []string{".ts", ".tsx"}},
	{"vscode/src", []string{".ts", ".tsx"}},
}

// identAllowDirs may name the legacy keys: the config migrate registry is
// the one owner of the record of removed keys (its step 1 carries a
// never-migrated file's values onto [codeintel]; step 4 strips the blocks
// from already-stamped files), and its tests feed it those keys.
var identAllowDirs = []string{
	filepath.Join("internal", "config", "migrate"),
}

// scanRoots are the source trees the guard walks, relative to the repo
// root (resolved from this test's working dir).
var scanRoots = []string{"internal", "cmd"}

// repoRoot walks up from the test's working directory until it finds the
// go.mod, so the guard works regardless of where `go test` is invoked.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("repoRoot: go.mod not found above %s", dir)
		}
		dir = parent
	}
}

// TestCodegraphPackageDeleted asserts the internal/codegraph directory no
// longer exists.
func TestCodegraphPackageDeleted(t *testing.T) {
	t.Parallel()
	root := repoRoot(t)
	dir := filepath.Join(root, "internal", "codegraph")
	if info, err := os.Stat(dir); err == nil && info.IsDir() {
		t.Fatalf("internal/codegraph reappeared at %s — the external code-graph dependency is decommissioned (Phase 4); use internal/codeintel", dir)
	}
}

// TestNoCodegraphImport walks every .go file under the scan roots and
// fails if any imports the deleted package. AST import parsing keeps this
// precise — a string literal naming the path (e.g. a forbidden-imports
// allow-list) is intentionally not flagged.
func TestNoCodegraphImport(t *testing.T) {
	t.Parallel()
	root := repoRoot(t)
	fset := token.NewFileSet()
	for _, sub := range scanRoots {
		base := filepath.Join(root, sub)
		walkErr := filepath.WalkDir(base, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") {
				return nil
			}
			f, perr := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
			if perr != nil {
				t.Errorf("parse %s: %v", path, perr)
				return nil
			}
			for _, imp := range f.Imports {
				p := strings.Trim(imp.Path.Value, `"`)
				if p == forbiddenPkg || strings.HasPrefix(p, forbiddenPkg+"/") {
					rel, _ := filepath.Rel(root, path)
					t.Errorf("%s imports the decommissioned package %q — use internal/codeintel (Phase 4)", filepath.ToSlash(rel), p)
				}
			}
			return nil
		})
		if walkErr != nil {
			t.Fatalf("walk %s: %v", base, walkErr)
		}
	}
}

// TestNoCodebaseMemoryMCPReference walks every .go file under the scan
// roots and fails if the external binary name reappears (the GitHub
// release download path that Phase 4 removed). This guard's own needle is
// assembled from fragments, so it does not match this file.
func TestNoCodebaseMemoryMCPReference(t *testing.T) {
	t.Parallel()
	root := repoRoot(t)
	self := "codegraph_decommission_test.go"
	for _, sub := range scanRoots {
		base := filepath.Join(root, sub)
		walkErr := filepath.WalkDir(base, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || filepath.Base(path) == self {
				return nil
			}
			body, rerr := os.ReadFile(path)
			if rerr != nil {
				return rerr
			}
			if strings.Contains(string(body), forbiddenBinary) {
				rel, _ := filepath.Rel(root, path)
				t.Errorf("%s references %q — Observer no longer downloads a third-party code-graph binary (Phase 4)", filepath.ToSlash(rel), forbiddenBinary)
			}
			return nil
		})
		if walkErr != nil {
			t.Fatalf("walk %s: %v", base, walkErr)
		}
	}
}

// TestNoCodegraphIdentifier fails if "codegraph" / "code_graph" reappears
// in Go or web source outside the migrate registry: an identifier, a
// config key, a comment or a UI string. The decommissioned dependency is
// described by docs (historical records), never by live code. References
// to this guard's own filename are not identifiers and are stripped first.
func TestNoCodegraphIdentifier(t *testing.T) {
	t.Parallel()
	root := repoRoot(t)
	selfName := strings.TrimSuffix(filepath.Base("codegraph_decommission_test.go"), ".go")
	for _, sr := range identScanRoots {
		base := filepath.Join(root, sr.dir)
		if _, err := os.Stat(base); err != nil {
			continue // optional tree absent in this checkout
		}
		walkErr := filepath.WalkDir(base, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if name := d.Name(); name == "node_modules" || name == "dist" {
					return filepath.SkipDir
				}
				rel, _ := filepath.Rel(root, path)
				for _, allow := range identAllowDirs {
					if rel == allow {
						return filepath.SkipDir
					}
				}
				return nil
			}
			ok := false
			for _, ext := range sr.exts {
				if strings.HasSuffix(path, ext) {
					ok = true
					break
				}
			}
			if !ok || filepath.Base(path) == selfName+".go" {
				return nil
			}
			body, rerr := os.ReadFile(path)
			if rerr != nil {
				return rerr
			}
			text := strings.ReplaceAll(strings.ToLower(string(body)), selfName, "")
			for _, needle := range forbiddenIdents {
				if strings.Contains(text, needle) {
					rel, _ := filepath.Rel(root, path)
					t.Errorf("%s mentions %q — the external code-graph dependency and its config blocks are removed; use codeintel naming (only internal/config/migrate may name the legacy keys)", filepath.ToSlash(rel), needle)
				}
			}
			return nil
		})
		if walkErr != nil {
			t.Fatalf("walk %s: %v", base, walkErr)
		}
	}
}

// TestNoLegacyCodeGraphConfigFields walks config.Config's TOML tags and
// fails if a field decodes the removed legacy table again. Reintroducing
// the field would also bring back the full-re-marshal leak that kept
// writing the block into every saved config.toml.
func TestNoLegacyCodeGraphConfigFields(t *testing.T) {
	t.Parallel()
	seen := map[reflect.Type]bool{}
	var walk func(typ reflect.Type, path string)
	walk = func(typ reflect.Type, path string) {
		for typ.Kind() == reflect.Pointer || typ.Kind() == reflect.Slice || typ.Kind() == reflect.Map {
			typ = typ.Elem()
		}
		if typ.Kind() != reflect.Struct || seen[typ] {
			return
		}
		seen[typ] = true
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			tag := strings.Split(f.Tag.Get("toml"), ",")[0]
			if tag == legacyConfigTag {
				t.Errorf("config field %s.%s decodes the removed legacy table %q — configure [codeintel] instead", path, f.Name, tag)
			}
			walk(f.Type, path+"."+f.Name)
		}
	}
	walk(reflect.TypeOf(config.Config{}), "Config")
}

// TestLegacyCodeGraphConfigStillLoads pins the low-friction contract of the
// removal: a config.toml that still carries both legacy blocks (the shape a
// full re-marshal wrote while the structs existed) loads without error, and
// its [codeintel] values are the ones in force.
func TestLegacyCodeGraphConfigStillLoads(t *testing.T) {
	t.Parallel()
	body := "[compression]\n" +
		"  [compression." + legacyConfigTag + "]\n" +
		"    enabled = true\n" +
		"    auto_install = true\n" +
		"    auto_index = true\n" +
		"    path = \"\"\n" +
		"[intelligence]\n" +
		"  [intelligence." + legacyConfigTag + "]\n" +
		"    enabled = true\n" +
		"[codeintel]\n" +
		"  enabled = false\n" +
		"  [codeintel.index]\n" +
		"    on_start = false\n"
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, err := config.Load(config.LoadOptions{GlobalPath: path, Env: func(string) string { return "" }})
	if err != nil {
		t.Fatalf("a config carrying the removed legacy blocks must still load: %v", err)
	}
	if cfg.CodeIntel.Enabled || cfg.CodeIntel.Index.OnStart {
		t.Errorf("[codeintel] must be the values in force (enabled=false, on_start=false); got enabled=%v on_start=%v",
			cfg.CodeIntel.Enabled, cfg.CodeIntel.Index.OnStart)
	}
}
