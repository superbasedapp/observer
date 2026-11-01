//go:build !sbo_omit_terminals_sandbox_oci && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/agentconfig"
)

// TestN2EveryFieldUnderTheContainerSandbox: the parser the container hook
// passes reports every ignored field.
func TestN2EveryFieldUnderTheContainerSandbox(t *testing.T) {
	full := devcontainerFieldsFor(agentconfig.TrustCondDevcontainerHost, agentconfig.TrustCondOCISandbox)
	ignored, _, err := full([]byte(n2Devcontainer))
	if err != nil || strings.Join(ignored, ",") != "initializeCommand,postCreateCommand,runArgs" {
		t.Fatalf("got %v %v", ignored, err)
	}
}

// TestOneDevcontainerReader pins N2's one parser: exactly one function
// decodes a devcontainer.json (internal/devcontainer.ParseDevcontainer,
// built into every install); the container driver's
// sandboxoci.ParseDevcontainer only adopts from its result, and every
// trust-check parser goes through devcontainerFields.
func TestOneDevcontainerReader(t *testing.T) {
	root := filepath.Join("..", "..")
	re := regexp.MustCompile(`(?i)^parse.*devcontainer`)
	var found []string
	for _, dir := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if strings.Contains(p, "thirdparty") || d.Name() == "node_modules" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return nil
			}
			src, err := os.ReadFile(p) //nolint:gosec // test reads the repository's own sources
			if err != nil || !strings.Contains(string(src), "evcontainer") {
				return nil
			}
			f, err := parser.ParseFile(token.NewFileSet(), p, src, parser.SkipObjectResolution)
			if err != nil {
				return nil
			}
			for _, decl := range f.Decls {
				if fn, ok := decl.(*ast.FuncDecl); ok && re.MatchString(fn.Name.Name) {
					found = append(found, filepath.ToSlash(p)+":"+fn.Name.Name)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	slices.Sort(found)
	if len(found) != 2 || !strings.HasSuffix(found[0], "internal/devcontainer/devcontainer.go:ParseDevcontainer") ||
		!strings.HasSuffix(found[1], "internal/sandboxoci/devcontainer.go:ParseDevcontainer") {
		t.Fatalf("devcontainer readers: %v", found)
	}
	// The driver's function adopts from the shared reader; it decodes nothing
	// itself.
	src, err := os.ReadFile(filepath.Join(root, "internal", "sandboxoci", "devcontainer.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), "devcontainer.ParseDevcontainer(raw)") || strings.Contains(string(src), "StripJSONC(raw)") {
		t.Fatal("sandboxoci.ParseDevcontainer does not go through the shared reader")
	}
}
