package invariant

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// home_env_getenv_test.go is the surface-gap Wave 5 audit follow-up G1
// (finding 1, R-188 F1): every writer that resolves a tool's home reads its
// relocation variables (CLAUDE_CONFIG_DIR, CODEX_HOME, XDG_CONFIG_HOME, ...)
// through ONE pinned-home rule, crossmount.HomeEnv / HomeEnvAt: os.Getenv
// only when no home is pinned and the process home is not isolated, no
// variable otherwise. A cmd/observer caller that hands os.Getenv to such a
// constructor brings the R-188 F1 split back silently (`HOME=/tmp/x observer
// init` wrote hooks into the developer's real settings.json while the route
// went under /tmp/x), because a given getenv is used as is.
//
// The test parses every non-test cmd/observer file (go/parser, go/ast, all
// build tags) and finds each place os.Getenv is handed on as a VALUE into a
// home-resolving target. A value counts as os.Getenv when it is:
//
//   - the selector os.Getenv itself;
//   - an identifier bound to one (x := os.Getenv, var x = os.Getenv, y := x,
//     in the function or at package level);
//   - a named package-level wrapper of type func(string) string whose body
//     calls os.Getenv (or a bound identifier) anywhere, however many
//     statements it has;
//   - a function literal of type func(string) string whose body does the
//     same.
//
// A target is a composite literal of an options type (also when the type is
// left out, as the elements of []hook.Options{{...}} or a map's values), a
// call of a function that takes a getenv for home resolution, or an
// assignment to a Getenv field. The current sites are a ratchet
// (homeEnvAllowedSites), each with its reason: a NEW site fails with the
// rule named, and an allowed site that disappears fails until its entry is
// removed, so the list only shrinks.
//
// Known misses (the check is syntactic, without type information):
//
//   - struct-field carriers: a getenv stored in a field of a type this test
//     does not list (deps.hostEnv = os.Getenv, then the field handed on
//     later) is caught only where that type is in homeEnvLocalTargets;
//   - parameters: a function that receives a getenv and forwards it is
//     caught only at its callers, and only when it is listed;
//   - hookctx.Process().Getenv (and any other method value) is not
//     recognised, although on the hook host path it is os.Getenv;
//   - a wrapper that does not have the func(string) string type (a method,
//     a generic helper, a func returning os.Getenv);
//   - internal/* packages: only cmd/observer is scanned; the constructors
//     there apply crossmount.HomeEnv themselves, and a direct os.Getenv in
//     an internal package is a different review.

// homeEnvModule is the module path the import paths below are relative to.
const homeEnvModule = "github.com/marmutapp/superbased-observer/"

// homeEnvTargetTypes are the option types whose getenv resolves a tool's
// home: package import path (module-relative) -> type names. Each must
// declare a func(string) string field.
var homeEnvTargetTypes = map[string][]string{
	"internal/hook":           {"Options"},
	"internal/mcpregister":    {"RegisterOptions"},
	"internal/clientwire":     {"RemoveOptions", "TelemetryOptions"},
	"internal/proxyroute":     {"RegisterOptions", "InspectOptions"},
	"internal/agentconfigsvc": {"Options"},
	"internal/agentconfig":    {"PathEnv"},
	"internal/diag":           {"DoctorOptions"},
	"internal/hookdisable":    {"Options"},
}

// homeEnvTargetFuncs are the functions whose getenv argument resolves a
// tool's home (or decides which getenv does). Each must take a
// func(string) string parameter.
var homeEnvTargetFuncs = map[string][]string{
	"internal/platform/crossmount": {"HomeEnv", "HomeEnvAt"},
	"internal/mcp/locate":          {"LocationsEnv", "ClineMCPSettingsPath", "ClineDataDir", "ForClientEnv"},
	"internal/diag":                {"VendorPolicyFindings"},
}

// homeEnvLocalTargets are cmd/observer's own types and functions that
// forward a getenv into one of the targets above (the reason each is
// listed). Each must exist and carry a func(string) string field or
// parameter.
var homeEnvLocalTargets = map[string]string{
	"configLayerHost":        "type: its Getenv feeds agentconfigsvc.Options and hookdisable.Options (managed_integrity_layers.go)",
	"artifactProbes":         "type: its Getenv resolves the plugin-shim host directories (components_artifacts.go)",
	"hookDisableWatch":       "type: its getenv feeds hookdisable.Options (hook_disabled_wire.go)",
	"clineProvidersPathFor":  "func: resolves the Cline CLI providers.json through agentconfig.ResolveArtifact",
	"launcherArtifactPathAt": "func: resolves a launched tool's artifact through agentconfig.ResolveArtifact",
	"addVendorPolicyRisks":   "func: forwards to diag.VendorPolicyFindings",
	"claudeUserSettingsPath": "func: resolves the Claude user settings.json through CLAUDE_CONFIG_DIR",
	"claudeUserConfigDir":    "func: resolves the Claude user config directory through CLAUDE_CONFIG_DIR (the settings.json and sign-in file resolver)",
}

// homeEnvAllowedSites is the ratchet: "file|enclosing function|target" ->
// how many times os.Getenv may still be handed on there, and why it is
// allowed. Remove an entry when its site moves onto the rule; never add one
// for a writer.
var homeEnvAllowedSites = map[string]struct {
	n      int
	reason string
}{
	"clinecli.go|clineProvidersFile|clineProvidersPathFor":                     {1, "a launched tool: `observer cline-cli` starts Cline in Observer's own environment, so its providers.json is where that Cline will read it"},
	"launcher_homes.go|launcherArtifactPath|launcherArtifactPathAt":            {1, "a launched tool: the pi / prime-agent launchers start the tool in Observer's own environment and write the file it will read"},
	"claude_proxy_route.go|claudeSettingsPath|claudeUserSettingsPath":          {1, "a launched tool: `observer claude` starts claude in Observer's own environment, so the launcher reads the user settings.json that claude will load; it writes nothing there"},
	"claude_proxy_route.go|claudeProxyBackendProven|claudeUserSettingsPath":    {1, "a launched tool: the budget admission check reads every settings scope the claude it launches will merge, in that claude's environment; it writes nothing"},
	"claude_proxy_route.go|resolveClaudeEffectiveRoute|claudeUserSettingsPath": {1, "a launched tool: the launcher's effective-route resolution asks whether the user settings.json of the claude it launches is named by a relative relocation; it writes nothing"},
	"claude.go|claudeCredentialsLookup|claudeUserConfigDir":                    {1, "a launched tool: `observer claude` (and the benchmark provisioner, as its copy source) reads the sign-in file the claude it launches will use, in that claude's environment; nothing writes through this path"},
	"start.go|newStartCmd|addVendorPolicyRisks":                                {1, "read-only probe: the managed-integrity report reads the cached vendor org policies; it writes nothing"},
}

// homeEnvSite is one place os.Getenv is handed to a target.
type homeEnvSite struct {
	file, fn, target string
	line             int
}

func (s homeEnvSite) key() string { return s.file + "|" + s.fn + "|" + s.target }

func TestCmdObserverHandsNoOSGetenvToAHomeResolver(t *testing.T) {
	root := repoRoot(t)
	checkHomeEnvTargetsDeclared(t, root)
	sites := scanHomeEnvSites(t, filepath.Join(root, "cmd", "observer"))

	if os.Getenv("SBO_DUMP_HOME_ENV_SITES") != "" {
		for _, s := range sites {
			t.Logf("%s:%d %s", s.file, s.line, s.key())
		}
	}

	got := map[string][]homeEnvSite{}
	for _, s := range sites {
		got[s.key()] = append(got[s.key()], s)
	}
	var problems []string
	for k, list := range got {
		allowed := homeEnvAllowedSites[k].n
		if len(list) <= allowed {
			continue
		}
		for _, s := range list[allowed:] {
			problems = append(problems, fmt.Sprintf("cmd/observer/%s:%d (in %s): os.Getenv is handed to %s, which resolves a tool's home from the relocation variables it reads. "+
				"That breaks the pinned-home rule (crossmount.HomeEnv / HomeEnvAt, R-188 F1): under a pinned or isolated HOME a writer must read no relocation variable. "+
				"Pass nil and let the constructor apply the rule; only a read-only probe or a tool Observer launches may be added to homeEnvAllowedSites, with its reason",
				s.file, s.line, s.fn, s.target))
		}
	}
	for k, a := range homeEnvAllowedSites {
		if a.reason == "" {
			problems = append(problems, fmt.Sprintf("homeEnvAllowedSites[%q] has no reason", k))
		}
		if n := len(got[k]); n < a.n {
			problems = append(problems, fmt.Sprintf("homeEnvAllowedSites[%q] allows %d site(s) but %d remain: lower or remove the entry", k, a.n, n))
		}
	}
	sort.Strings(problems)
	for _, p := range problems {
		t.Error(p)
	}
}

// checkHomeEnvTargetsDeclared fails when a target in the tables is no longer
// declared, or no longer takes a getenv (the tables would rot silently).
func checkHomeEnvTargetsDeclared(t *testing.T, root string) {
	t.Helper()
	check := func(dir string, types, funcs []string, what string) {
		decls := getenvTakingDecls(t, filepath.Join(root, filepath.FromSlash(dir)))
		for _, n := range append(append([]string{}, types...), funcs...) {
			if !decls[n] {
				t.Errorf("%s %s.%s is not declared or takes no func(string) string: update the home-resolving target tables", what, dir, n)
			}
		}
	}
	for dir, types := range homeEnvTargetTypes {
		check(dir, types, nil, "type")
	}
	for dir, funcs := range homeEnvTargetFuncs {
		check(dir, nil, funcs, "func")
	}
	var locals []string
	for n, why := range homeEnvLocalTargets {
		if why == "" {
			t.Errorf("homeEnvLocalTargets[%q] has no reason", n)
		}
		locals = append(locals, n)
	}
	check("cmd/observer", locals, nil, "local target")
}

// getenvTakingDecls parses the non-test files of dir and returns the names
// of the types with a func(string) string field and the functions with a
// func(string) string parameter.
func getenvTakingDecls(t *testing.T, dir string) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, f := range parseNonTestGo(t, dir) {
		for _, d := range f.Decls {
			switch d := d.(type) {
			case *ast.FuncDecl:
				if d.Recv == nil && fieldsTakeGetenv(d.Type.Params) {
					out[d.Name.Name] = true
				}
			case *ast.GenDecl:
				for _, sp := range d.Specs {
					ts, ok := sp.(*ast.TypeSpec)
					if !ok {
						continue
					}
					if st, ok := ts.Type.(*ast.StructType); ok && fieldsTakeGetenv(st.Fields) {
						out[ts.Name.Name] = true
					}
				}
			}
		}
	}
	return out
}

func fieldsTakeGetenv(fl *ast.FieldList) bool {
	if fl == nil {
		return false
	}
	for _, f := range fl.List {
		if isGetenvFuncType(f.Type) {
			return true
		}
	}
	return false
}

// isGetenvFuncType reports a func(string) string type expression.
func isGetenvFuncType(e ast.Expr) bool {
	ft, ok := e.(*ast.FuncType)
	if !ok || ft.Params == nil || ft.Results == nil {
		return false
	}
	isString := func(fl *ast.FieldList) bool {
		n := 0
		for _, f := range fl.List {
			id, ok := f.Type.(*ast.Ident)
			if !ok || id.Name != "string" {
				return false
			}
			if len(f.Names) == 0 {
				n++
			} else {
				n += len(f.Names)
			}
		}
		return n == 1
	}
	return isString(ft.Params) && isString(ft.Results)
}

func parseNonTestGo(t *testing.T, dir string) []*ast.File {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	fset := token.NewFileSet()
	var out []*ast.File
	for _, e := range ents {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, n), nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", n, err)
		}
		out = append(out, f)
	}
	return out
}

// scanHomeEnvSites returns every place a non-test file of dir hands
// os.Getenv to a home-resolving target, sorted.
func scanHomeEnvSites(t *testing.T, dir string) []homeEnvSite {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	fset := token.NewFileSet()
	type parsed struct {
		name string
		f    *ast.File
	}
	var files []parsed
	for _, e := range ents {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, n), nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", n, err)
		}
		files = append(files, parsed{n, f})
	}
	if len(files) < 100 {
		t.Fatalf("cmd/observer parsed only %d files; the scan would prove nothing", len(files))
	}

	types, funcs := map[string]string{}, map[string]string{}
	for dir, names := range homeEnvTargetTypes {
		for _, n := range names {
			types[homeEnvModule+dir+"."+n] = filepath.Base(dir) + "." + n
		}
	}
	for dir, names := range homeEnvTargetFuncs {
		for _, n := range names {
			funcs[homeEnvModule+dir+"."+n] = filepath.Base(dir) + "." + n
		}
	}

	// Package-level variables bound to os.Getenv and named func(string)
	// string wrappers of it, across every file, to a fixed point (a wrapper
	// may call a bound variable or another wrapper).
	pkgBound := map[string]bool{}
	for {
		before := len(pkgBound)
		for _, p := range files {
			sc := homeEnvScanner{osName: importName(p.f, "os"), bound: pkgBound}
			for _, d := range p.f.Decls {
				switch d := d.(type) {
				case *ast.GenDecl:
					if d.Tok == token.VAR {
						sc.bindSpecs(d)
					}
				case *ast.FuncDecl:
					if d.Recv == nil && d.Body != nil && isGetenvFuncType(d.Type) && sc.callsGetenv(d.Body) {
						pkgBound[d.Name.Name] = true
					}
				}
			}
		}
		if len(pkgBound) == before {
			break
		}
	}

	var out []homeEnvSite
	for _, p := range files {
		imports := map[string]string{}
		for _, im := range p.f.Imports {
			path, _ := strconv.Unquote(im.Path.Value)
			name := filepath.Base(path)
			if im.Name != nil {
				name = im.Name.Name
			}
			imports[name] = path
		}
		target := func(e ast.Expr, table map[string]string) (string, bool) {
			switch x := e.(type) {
			case *ast.SelectorExpr:
				if id, ok := x.X.(*ast.Ident); ok {
					if path, ok := imports[id.Name]; ok {
						n, ok := table[path+"."+x.Sel.Name]
						return n, ok
					}
				}
			case *ast.Ident:
				if _, ok := homeEnvLocalTargets[x.Name]; ok {
					return x.Name, true
				}
			}
			return "", false
		}
		for _, d := range p.f.Decls {
			fn, body := "<package>", ast.Node(d)
			if fd, ok := d.(*ast.FuncDecl); ok {
				fn = funcDeclName(fd)
				if fd.Body == nil {
					continue
				}
				body = fd.Body
			}
			sc := homeEnvScanner{osName: importName(p.f, "os"), bound: map[string]bool{}, outer: pkgBound}
			sc.bindAll(body)
			add := func(pos token.Pos, tgt string) {
				out = append(out, homeEnvSite{file: p.name, fn: fn, target: tgt, line: fset.Position(pos).Line})
			}
			ast.Inspect(body, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.CompositeLit:
					if tgt, ok := target(x.Type, types); ok {
						for _, v := range litValues(x) {
							if sc.isSource(v) {
								add(v.Pos(), tgt)
							}
						}
					}
					// A slice, array or map of a target type: its elements
					// may leave the type out ([]hook.Options{{Getenv: ...}}).
					if tgt, ok := target(elidedElem(x.Type), types); ok {
						for _, v := range litValues(x) {
							if u, ok := v.(*ast.UnaryExpr); ok && u.Op == token.AND {
								v = u.X
							}
							if inner, ok := v.(*ast.CompositeLit); ok && inner.Type == nil {
								for _, iv := range litValues(inner) {
									if sc.isSource(iv) {
										add(iv.Pos(), tgt)
									}
								}
							}
						}
					}
				case *ast.CallExpr:
					if tgt, ok := target(x.Fun, funcs); ok {
						for _, a := range x.Args {
							if sc.isSource(a) {
								add(a.Pos(), tgt)
							}
						}
					}
				case *ast.AssignStmt:
					if len(x.Lhs) != len(x.Rhs) {
						return true
					}
					for i, l := range x.Lhs {
						if sel, ok := l.(*ast.SelectorExpr); ok && (sel.Sel.Name == "Getenv" || sel.Sel.Name == "getenv") && sc.isSource(x.Rhs[i]) {
							add(x.Rhs[i].Pos(), "."+sel.Sel.Name+" field")
						}
					}
				}
				return true
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].file != out[j].file {
			return out[i].file < out[j].file
		}
		return out[i].line < out[j].line
	})
	return out
}

// homeEnvScanner decides whether an expression is os.Getenv as a value.
type homeEnvScanner struct {
	osName string
	// bound are the identifiers bound to os.Getenv in this scope; outer
	// are the package-level ones.
	bound, outer map[string]bool
}

// isSource reports os.Getenv as a value: the selector itself, an
// identifier bound to it (including a named wrapper), or a function literal
// of type func(string) string whose body calls it.
func (s homeEnvScanner) isSource(e ast.Expr) bool {
	switch x := e.(type) {
	case *ast.ParenExpr:
		return s.isSource(x.X)
	case *ast.SelectorExpr:
		id, ok := x.X.(*ast.Ident)
		return ok && s.osName != "" && id.Name == s.osName && x.Sel.Name == "Getenv"
	case *ast.Ident:
		return s.bound[x.Name] || s.outer[x.Name]
	case *ast.FuncLit:
		return x.Body != nil && isGetenvFuncType(x.Type) && s.callsGetenv(x.Body)
	}
	return false
}

// callsGetenv reports a call anywhere in body whose function is a source
// (os.Getenv, a bound identifier or a wrapper).
func (s homeEnvScanner) callsGetenv(body ast.Node) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if found {
			return false
		}
		if c, ok := n.(*ast.CallExpr); ok {
			switch c.Fun.(type) {
			case *ast.SelectorExpr, *ast.Ident, *ast.ParenExpr:
				if s.isSource(c.Fun) {
					found = true
				}
			}
		}
		return true
	})
	return found
}

// litValues returns a composite literal's element values (a keyed
// element's value).
func litValues(lit *ast.CompositeLit) []ast.Expr {
	out := make([]ast.Expr, 0, len(lit.Elts))
	for _, el := range lit.Elts {
		if kv, ok := el.(*ast.KeyValueExpr); ok {
			out = append(out, kv.Value)
			continue
		}
		out = append(out, el)
	}
	return out
}

// elidedElem is the element type a slice, array or map literal's elements
// may leave out (pointer element types included); nil otherwise.
func elidedElem(t ast.Expr) ast.Expr {
	var elt ast.Expr
	switch x := t.(type) {
	case *ast.ArrayType:
		elt = x.Elt
	case *ast.MapType:
		elt = x.Value
	default:
		return nil
	}
	if st, ok := elt.(*ast.StarExpr); ok {
		return st.X
	}
	return elt
}

// bindAll records, to a fixed point, every identifier in n bound to
// os.Getenv (x := os.Getenv, var x = os.Getenv, y := x).
func (s homeEnvScanner) bindAll(n ast.Node) {
	for {
		before := len(s.bound)
		ast.Inspect(n, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.AssignStmt:
				if len(x.Lhs) == len(x.Rhs) {
					for i, l := range x.Lhs {
						if id, ok := l.(*ast.Ident); ok && id.Name != "_" && s.isSource(x.Rhs[i]) {
							s.bound[id.Name] = true
						}
					}
				}
			case *ast.GenDecl:
				s.bindSpecs(x)
			}
			return true
		})
		if len(s.bound) == before {
			return
		}
	}
}

// bindSpecs records the var specs of d bound to os.Getenv.
func (s homeEnvScanner) bindSpecs(d *ast.GenDecl) {
	if d.Tok != token.VAR {
		return
	}
	for _, sp := range d.Specs {
		vs, ok := sp.(*ast.ValueSpec)
		if !ok || len(vs.Names) != len(vs.Values) {
			continue
		}
		for i, n := range vs.Names {
			if n.Name != "_" && s.isSource(vs.Values[i]) {
				s.bound[n.Name] = true
			}
		}
	}
}

// funcDeclName names a function declaration, receiver-qualified.
func funcDeclName(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return fd.Name.Name
	}
	recv := fd.Recv.List[0].Type
	star := ""
	if se, ok := recv.(*ast.StarExpr); ok {
		star, recv = "*", se.X
	}
	if ix, ok := recv.(*ast.IndexExpr); ok {
		recv = ix.X
	}
	if id, ok := recv.(*ast.Ident); ok {
		return "(" + star + id.Name + ")." + fd.Name.Name
	}
	return fd.Name.Name
}

// claudeConfigDirVars are the names of Claude Code's user config directory
// variables (FU-131, FU-138).
var claudeConfigDirVars = map[string]bool{"CLAUDE_CONFIG_DIR": true, "ANTHROPIC_CONFIG_DIR": true}

// claudeConfigDirAllowedSites is the FU-131 / FU-138 ratchet: every reader
// that joins Claude Code's config directory goes through the one resolver
// (agentconfig.ClaudeConfigDir) and every writer through the relocation rule,
// so a string literal naming CLAUDE_CONFIG_DIR or ANTHROPIC_CONFIG_DIR in a
// non-test file of cmd/ or internal/ sits only at the sites below
// ("module-relative file|enclosing function" -> how many, and why). A new
// literal (a raw os.Getenv("CLAUDE_CONFIG_DIR") join, a hand-rolled loop over
// the two names) fails with the resolver named; an allowed site that
// disappears fails until its entry is lowered, so the list only shrinks.
var claudeConfigDirAllowedSites = map[string]struct {
	n      int
	reason string
}{
	"internal/agentconfig/relocate.go|<package>":                {2, "the writers' relocation rules (relocClaudeConfigDir, relocClaudeJSON): the owner of the variable"},
	"internal/agentconfig/claudehome.go|<package>":              {1, "the one reader resolver's second name (ANTHROPIC_CONFIG_DIR)"},
	"internal/agentconfig/catalog_claude_code.gen.go|<package>": {1, "the env.CLAUDE_CONFIG_DIR settings key row: a key name in settings.json, no path is joined"},
	"cmd/observer/claude.go|claudeAttachEnv":                    {2, "forwards the variables verbatim to the claude a daemon attach launches; joins nothing"},
	"internal/integration/integration.go|<package>":             {2, "registry metadata: the claude-code provider variables and its sandbox config-home variable; joins nothing"},
	"internal/hookliveness/env.go|<package>":                    {1, "names the variable for its env-class path hash; joins nothing"},
}

func TestClaudeConfigDirIsJoinedOnlyThroughTheResolver(t *testing.T) {
	root := repoRoot(t)
	got := map[string][]string{}
	files := 0
	for _, top := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join(root, top), func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == "testdata" || d.Name() == "node_modules" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return nil
			}
			files++
			rel, _ := filepath.Rel(root, p)
			rel = filepath.ToSlash(rel)
			fset := token.NewFileSet()
			f, perr := parser.ParseFile(fset, p, nil, parser.SkipObjectResolution)
			if perr != nil {
				t.Fatalf("parse %s: %v", rel, perr)
			}
			for _, d := range f.Decls {
				fn := "<package>"
				if fd, ok := d.(*ast.FuncDecl); ok {
					fn = funcDeclName(fd)
				}
				ast.Inspect(d, func(n ast.Node) bool {
					lit, ok := n.(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						return true
					}
					if v, err := strconv.Unquote(lit.Value); err == nil && claudeConfigDirVars[v] {
						key := rel + "|" + fn
						got[key] = append(got[key], fmt.Sprintf("%s:%d", rel, fset.Position(lit.Pos()).Line))
					}
					return true
				})
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", top, err)
		}
	}
	if files < 1000 {
		t.Fatalf("parsed only %d files under cmd/ and internal/; the scan would prove nothing", files)
	}
	var problems []string
	for k, list := range got {
		allowed := claudeConfigDirAllowedSites[k].n
		for _, at := range list[min(allowed, len(list)):] {
			problems = append(problems, fmt.Sprintf("%s names CLAUDE_CONFIG_DIR or ANTHROPIC_CONFIG_DIR (in %s). "+
				"Resolve Claude Code's config directory through agentconfig.ClaudeConfigDir (a reader; it refuses a relative value, FU-131) "+
				"or the relocation rule through agentconfig.ResolveArtifact (a writer), never with a raw join; "+
				"only a site that joins nothing may be added to claudeConfigDirAllowedSites, with its reason", at, strings.SplitN(k, "|", 2)[1]))
		}
	}
	for k, a := range claudeConfigDirAllowedSites {
		if a.reason == "" {
			problems = append(problems, fmt.Sprintf("claudeConfigDirAllowedSites[%q] has no reason", k))
		}
		if n := len(got[k]); n < a.n {
			problems = append(problems, fmt.Sprintf("claudeConfigDirAllowedSites[%q] allows %d site(s) but %d remain: lower or remove the entry", k, a.n, n))
		}
	}
	sort.Strings(problems)
	for _, p := range problems {
		t.Error(p)
	}
}
