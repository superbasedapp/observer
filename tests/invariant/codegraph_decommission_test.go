package invariant

import (
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// The external code-graph dependency (the companion binary behind the
// deleted internal/codegraph) was decommissioned in Phase 4 of the
// internal/codeintel build-out, replaced by the in-process, CGO-free
// code-intelligence engine (plan section 12.5;
// docs/codeintel/migration-from-codegraph.md). What stays pinned (D-612):
// the external binary is never referenced again (no third-party download,
// a supply-chain guard), no config field decodes the removed legacy table,
// and a config file still carrying the legacy blocks keeps loading (config
// migration safety). The package, import and identifier name pins were
// retired under D-612.
//
// The forbidden tokens are assembled from fragments so this guard file
// never matches itself.
var (
	forbiddenBinary = "codebase-memory" + "-mcp"

	// legacyConfigTag is the TOML table name both removed config blocks
	// used ([compression.<tag>] and [intelligence.<tag>]).
	legacyConfigTag = "code" + "_graph"
)

// scanRoots are the source trees the guard walks, relative to the repo
// root (resolved from this test's working dir).
var scanRoots = []string{"internal", "cmd"}

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
				t.Errorf("%s references %q: Observer no longer downloads a third-party code-graph binary (Phase 4)", filepath.ToSlash(rel), forbiddenBinary)
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
				t.Errorf("config field %s.%s decodes the removed legacy table %q: configure [codeintel] instead", path, f.Name, tag)
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
