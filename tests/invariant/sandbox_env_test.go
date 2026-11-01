package invariant

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// sandbox_env_test.go pins the box environment rule (WINFIX2 audit finding
// 1, tracker R-167, ledger SBX-WIN-ENV-1): every sandbox backend builds the
// box's environment from the allow-list of internal/sandboxenv
// (cmd/observer's sandboxBoxEnv), never from the parent's minus a
// deny-list. It walks the sandbox driver files of cmd/observer and fails
// when os.Environ() is handed to anything but one of the filtering env
// functions, outside a function the table below names as host side.

// sandboxEnvFilters are the env functions that run their input through
// sandboxBoxEnv first (each one's body is checked to call it).
var sandboxEnvFilters = map[string]bool{
	"sandboxBoxEnv": true, "sandboxHostChildEnv": true, "mxcBoxEnv": true,
	"ociContainerEnv": true, "vmRunEnv": true, "landlockEnv": true,
	"seatbeltAgentEnv": true, "appleRunEnv": true,
}

// sandboxEnvHostSide are the functions of the driver files that read
// os.Environ() for a process that is NOT a box's tool, each with why:
// file -> function -> reason.
var sandboxEnvHostSide = map[string]map[string]string{
	"sandbox_relay.go":                         {"relayExecutor": "the capture relay's own gate child on the host"},
	"sandbox_helpers_linux.go":                 {"runSandboxGuest": "in the box: its environment is the one the host side built (the allow-list, or the hosted row's fixed table)", "runGuestStagedDiff": "the guest's own git step for the copy's return, not the tool"},
	"terminal_sandbox_oci_linux.go":            {"ociInit": "the container's init: its environment is ociContainerEnv's"},
	"sandbox_guest_relaystdio_linux.go":        {"guestRunPTY": "in the box: its environment is the one the host side built"},
	"terminal_sandbox_mxc.go":                  {"runMXCProbeHelper": "the MXC host helper's own environment on the host (mxcHelperEnv)"},
	"terminal_sandbox_mxc_windows.go":          {"serveAndRun": "wxc-exec's own environment, its own allow-list (mxcExecEnv); the box's is mxcBoxEnv"},
	"terminal_sandbox.go":                      {"gitPrepEnv": "the daemon's host-side workspace git step"},
	"terminal_sandbox_cli.go":                  {"runSandboxCLI": "the host helper's own environment (the box boundary filters it)"},
	"terminal_sandbox_applecontainer_linux.go": {"runAppleInit": "the container's init: its environment is appleRunEnv's"},
}

// sandboxDriverFile reports whether a cmd/observer file is a sandbox driver
// file the rule covers.
func sandboxDriverFile(name string) bool {
	if strings.HasSuffix(name, "_test.go") || !strings.HasSuffix(name, ".go") {
		return false
	}
	for _, p := range []string{"terminal_sandbox", "sandbox_", "box_", "hook_relay"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

func isOSEnviron(e ast.Expr) bool {
	c, ok := e.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := c.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Environ" {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == "os"
}

func callName(c *ast.CallExpr) string {
	switch f := c.Fun.(type) {
	case *ast.Ident:
		return f.Name
	case *ast.SelectorExpr:
		return f.Sel.Name
	}
	return ""
}

func TestSandboxDriversNeverPassTheParentEnvironment(t *testing.T) {
	dir := filepath.Join(repoRoot(t), "cmd", "observer")
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	usedExempt := map[string]bool{}
	callsFilter := map[string]bool{}
	declared := map[string]bool{}
	var offenders []string
	for _, e := range ents {
		if !sandboxDriverFile(e.Name()) {
			continue
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, filepath.Join(dir, e.Name()), nil, 0)
		if err != nil {
			t.Fatalf("%s: %v", e.Name(), err)
		}
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			fn := fd.Name.Name
			if sandboxEnvFilters[fn] {
				declared[fn] = true
			}
			var stack []ast.Node
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				if n == nil {
					stack = stack[:len(stack)-1]
					return true
				}
				stack = append(stack, n)
				c, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if sandboxEnvFilters[fn] && fn != "sandboxBoxEnv" && callName(c) == "sandboxBoxEnv" {
					callsFilter[fn] = true
				}
				if fn == "sandboxBoxEnv" && callName(c) == "Filter" {
					callsFilter[fn] = true
				}
				if !isOSEnviron(c) {
					return true
				}
				filtered := false
				for i := len(stack) - 2; i >= 0; i-- {
					if p, ok := stack[i].(*ast.CallExpr); ok && sandboxEnvFilters[callName(p)] {
						filtered = true
						break
					}
				}
				if filtered {
					return true
				}
				if _, ok := sandboxEnvHostSide[e.Name()][fn]; ok {
					usedExempt[e.Name()+"/"+fn] = true
					return true
				}
				offenders = append(offenders, fset.Position(c.Pos()).String()+" in "+fn)
				return true
			})
		}
	}
	sort.Strings(offenders)
	for _, o := range offenders {
		t.Errorf("%s hands os.Environ() to the box without the allow-list (run it through sandboxBoxEnv or a driver env function, or name the host-side function in sandboxEnvHostSide with its reason)", o)
	}
	for fn := range sandboxEnvFilters {
		if !declared[fn] {
			t.Errorf("filter %s is not declared in a sandbox driver file", fn)
		} else if !callsFilter[fn] {
			t.Errorf("filter %s does not run its input through the allow-list", fn)
		}
	}
	for file, fns := range sandboxEnvHostSide {
		for fn := range fns {
			if !usedExempt[file+"/"+fn] {
				t.Errorf("host-side row %s/%s matches no os.Environ() call; remove it", file, fn)
			}
		}
	}
}
