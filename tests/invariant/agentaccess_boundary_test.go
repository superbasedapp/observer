package invariant

import (
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// agentAccessBoundaries is the doc3 §2.2 reverse-import table: each row names
// a package tree and the module prefixes its PRODUCTION files must never
// import. internal/proxy (the node's hot path) stays independent of the Agent
// Access identity core and the org-side companion; the node relay
// (internal/mcprelay, wave P4) never reaches into the org server or the
// org-side companion core.
var agentAccessBoundaries = []struct {
	root      string
	forbidden []string
	why       string
}{
	{
		root: "internal/proxy",
		forbidden: []string{
			"internal/mcpgw",
			"internal/agentid",
			"internal/mcprelay",
		},
		why: "the node proxy must not link the Agent Access companion, identity core or relay (doc3 §2.2)",
	},
	{
		root: "internal/mcprelay",
		forbidden: []string{
			"internal/orgserver",
			"internal/mcpgw",
		},
		why: "the node relay must not import the org server or the org-side companion core (doc3 §2.1/§2.2)",
	},
	// P4 W4d (doc3 §12.5/§12.6): the node-side enforcement points consult
	// the compiled table ONLY through plain-result seams the cmd
	// composition binds (proxy.ToolsAllowlistSeam, guard.MCPAccessLookup);
	// none of them links the relay, the companion or the org server.
	{
		root:      "internal/guard",
		forbidden: []string{"internal/mcprelay", "internal/mcpgw", "internal/orgserver", "internal/agentid"},
		why:       "guard answers R-306/R-307 from an injected MCPAccessLookup, never by importing the relay (doc3 §12.6)",
	},
	{
		root:      "internal/policy",
		forbidden: []string{"internal/mcprelay", "internal/mcpgw", "internal/orgserver", "internal/agentid"},
		why:       "policy is pure; R-306/R-307 match on an Event finding (doc3 §12.6)",
	},
	{
		root:      "internal/hook",
		forbidden: []string{"internal/mcprelay", "internal/mcpgw", "internal/orgserver", "internal/agentid"},
		why:       "the hook deny rides the existing guard.Evaluator seam, never the relay (doc3 §12.6)",
	},
}

// TestAgentAccessImportBoundary scans production (non-_test.go) files of each
// row's tree. A tree that does not exist yet (internal/mcprelay before P4) is
// vacuously clean and logged, so the row is in force the moment it lands.
func TestAgentAccessImportBoundary(t *testing.T) {
	fset := token.NewFileSet()
	for _, row := range agentAccessBoundaries {
		root := filepath.Join("..", "..", filepath.FromSlash(row.root))
		if _, err := os.Stat(root); os.IsNotExist(err) {
			t.Logf("%s does not exist yet - boundary row armed, vacuously clean", row.root)
			continue
		}
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			af, perr := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
			if perr != nil {
				t.Fatalf("parse %s: %v", path, perr)
			}
			for _, imp := range af.Imports {
				p := strings.Trim(imp.Path.Value, `"`)
				for _, bad := range row.forbidden {
					full := modulePath + bad
					if p == full || strings.HasPrefix(p, full+"/") {
						t.Errorf("%s imports %q - %s", filepath.ToSlash(path), p, row.why)
					}
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}
}

// TestAgentAccessImportBoundaryTransitive closes the gap a direct scan leaves:
// `go list -deps` over internal/proxy must not reach the Agent Access
// packages through any intermediary, and the pure crypto cores
// (internal/agentid, internal/dpop) must not transitively link database/sql,
// net/http or the org server.
func TestAgentAccessImportBoundaryTransitive(t *testing.T) {
	cases := []struct {
		pkg       string
		forbidden []string
	}{
		{"./internal/proxy", []string{modulePath + "internal/mcpgw", modulePath + "internal/agentid", modulePath + "internal/mcprelay"}},
		{"./internal/agentid", []string{"database/sql", "net/http", modulePath + "internal/orgserver", modulePath + "internal/proxy"}},
		{"./internal/dpop", []string{"database/sql", "net/http", modulePath + "internal/orgserver", modulePath + "internal/agentid"}},
		// P4 W4d: the coverage matrix is pure data (doc3 §12.7).
		{"./internal/mcprelay/coverage", []string{"database/sql", "net/http", "github.com/fsnotify/fsnotify", modulePath + "internal/orgserver", modulePath + "internal/mcpgw", modulePath + "internal/proxy", modulePath + "internal/store"}},
		// The proxy's tools[] filter must not pull the relay in transitively either.
		{"./internal/guard", []string{modulePath + "internal/mcprelay", modulePath + "internal/mcpgw", modulePath + "internal/orgserver"}},
	}
	for _, c := range cases {
		cmd := exec.Command("go", "list", "-deps", c.pkg)
		cmd.Dir = filepath.Join("..", "..")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("go list -deps %s: %v\n%s", c.pkg, err, out)
		}
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			dep := strings.TrimSpace(line)
			for _, bad := range c.forbidden {
				if dep == bad || strings.HasPrefix(dep, bad+"/") {
					t.Errorf("%s transitively imports %q (doc3 §2.1/§2.2 Agent Access boundary)", c.pkg, dep)
				}
			}
		}
	}
}
