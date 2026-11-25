package main

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// daemonOnlyDashboardFields are the dashapi.Options fields `observer start`
// sets on top of nodeDashboardOptions, each with why the standalone
// `observer dashboard` does not serve it. A field set by one command and not
// the other must be listed here (CMD-01); everything else comes from the one
// builder.
//
// Most rows need something only the daemon's process has: its proxy, its
// watcher, its push loop or its restart. The "today" rows have no such
// reason; they were wired in the daemon only and are kept that way because
// turning them on in the standalone dashboard is a change of its own.
var daemonOnlyDashboardFields = map[string]string{
	"FeatureGate":                "the node.features handle the daemon's policy poller installs into",
	"TerminalFeatureGate":        "the node.features handle the daemon's policy poller installs into",
	"WatcherRunning":             "the daemon runs the watcher beside the dashboard",
	"CaptureProgress":            "the daemon's watcher reports its initial scan",
	"ProxyPort":                  "the daemon's own proxy listener",
	"ProxyClientToken":           "the daemon's own proxy client auth",
	"OnConfigSaved":              "hot-reloads the daemon's proxy compression router",
	"RoutingDemotions":           "the daemon's live router state",
	"ExtraRoutes":                "the AI Apps routes ride the daemon's admission service and hot-enable gate",
	"RefreshWatchRoots":          "hot-adds roots to the daemon's live watcher",
	"RestartFunc":                "restarts the daemon",
	"RestartPreflight":           "restarts the daemon",
	"RestartHandover":            "restarts the daemon (L-168: reports its proxy socket hand-over)",
	"LiveSandboxRuns":            "the daemon's restart gate for live sandboxed runs",
	"UpdateApplyFunc":            "the update handshake runs where the listeners live",
	"UpdateStatusFunc":           "the daemon's update runtime",
	"UpdateExtensionVersionFunc": "the daemon's update runtime",
	"OrgClient":                  "the daemon's org push client",
	"Requests":                   "rides the daemon's org push client",
	"Messages":                   "rides the daemon's org push client",
	"CustomScanners":             "today: built from the daemon's component snapshot",
	"SDK":                        "today",
	"SandboxInstallVersions":     "today",
	"SandboxSignInForbidden":     "today",
	"SandboxSeize":               "today",
	"SandboxEgressHostCheck":     "today",
	"SandboxProviderHost":        "today",
	"MCPAccessStatus":            "today",
	"PromptJudgeStatus":          "today",
}

// parseCmdFile parses one file of this package.
func parseCmdFile(t *testing.T, fset *token.FileSet, name string) *ast.File {
	t.Helper()
	f, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	return f
}

// isOptionsLiteral reports whether n is a dashapi.Options{...} literal.
func isOptionsLiteral(n ast.Node) (*ast.CompositeLit, bool) {
	lit, ok := n.(*ast.CompositeLit)
	if !ok {
		return nil, false
	}
	sel, ok := lit.Type.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Options" {
		return nil, false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return lit, ok && pkg.Name == "dashapi"
}

// isBuilderCall reports whether n calls nodeDashboardOptions.
func isBuilderCall(n ast.Node) bool {
	call, ok := n.(*ast.CallExpr)
	if !ok {
		return false
	}
	id, ok := call.Fun.(*ast.Ident)
	return ok && id.Name == "nodeDashboardOptions"
}

// builderFields returns the keys of the dashapi.Options literal
// nodeDashboardOptions returns.
func builderFields(t *testing.T, f *ast.File) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "nodeDashboardOptions" {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			ret, ok := n.(*ast.ReturnStmt)
			if !ok || len(ret.Results) != 1 {
				return true
			}
			lit, ok := isOptionsLiteral(ret.Results[0])
			if !ok {
				return true
			}
			for _, e := range lit.Elts {
				if kv, ok := e.(*ast.KeyValueExpr); ok {
					out[kv.Key.(*ast.Ident).Name] = true
				}
			}
			return false
		})
	}
	if len(out) == 0 {
		t.Fatal("nodeDashboardOptions returns no dashapi.Options literal")
	}
	return out
}

// commandFields returns the fields a command sets on top of the builder: the
// `<v>.Field = ...` assignments, in the block that declares `<v> :=
// nodeDashboardOptions(...)`, to that variable. It also fails when the file
// builds a dashapi.Options literal of its own, or calls the builder other
// than exactly once.
func commandFields(t *testing.T, f *ast.File, name string) map[string]bool {
	t.Helper()
	calls := 0
	ast.Inspect(f, func(n ast.Node) bool {
		if _, ok := isOptionsLiteral(n); ok {
			t.Errorf("%s builds its own dashapi.Options literal; set the field in nodeDashboardOptions (or, daemon only, after it with a daemonOnlyDashboardFields row)", name)
		}
		if isBuilderCall(n) {
			calls++
		}
		return true
	})
	if calls != 1 {
		t.Fatalf("%s calls nodeDashboardOptions %d times, want once", name, calls)
	}
	out := map[string]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		block, ok := n.(*ast.BlockStmt)
		if !ok {
			return true
		}
		varName := ""
		for _, st := range block.List {
			if as, ok := st.(*ast.AssignStmt); ok && len(as.Lhs) == 1 && len(as.Rhs) == 1 && isBuilderCall(as.Rhs[0]) {
				varName = as.Lhs[0].(*ast.Ident).Name
			}
		}
		if varName == "" {
			return true
		}
		ast.Inspect(block, func(m ast.Node) bool {
			as, ok := m.(*ast.AssignStmt)
			if !ok {
				return true
			}
			for _, lhs := range as.Lhs {
				sel, ok := lhs.(*ast.SelectorExpr)
				if !ok {
					continue
				}
				if x, ok := sel.X.(*ast.Ident); ok && x.Name == varName {
					out[sel.Sel.Name] = true
				}
			}
			return true
		})
		return false
	})
	return out
}

// dashFieldNames lists a set's members in order.
func dashFieldNames(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestDashboardCommandsShareOneOptionsBuilder pins CMD-01 by comparing the two
// wirings: `observer start` (start.go) and `observer dashboard`
// (dashboard.go) both take their options from nodeDashboardOptions, the
// standalone dashboard serves nothing the daemon's does not, and the daemon
// adds exactly the fields of daemonOnlyDashboardFields. Before the shared
// builder, the standalone dashboard alone set SecurityExplain,
// SecurityExplainFix and SecurityOrgShare, so the daemon's dashboard
// answered 404 for Explain and hid the org-share notice.
func TestDashboardCommandsShareOneOptionsBuilder(t *testing.T) {
	fset := token.NewFileSet()
	shared := builderFields(t, parseCmdFile(t, fset, "dashboard_options.go"))
	daemon := map[string]bool{}
	standalone := map[string]bool{}
	for k := range shared {
		daemon[k] = true
		standalone[k] = true
	}
	added := commandFields(t, parseCmdFile(t, fset, "start.go"), "start.go")
	for k := range added {
		daemon[k] = true
	}
	for k := range commandFields(t, parseCmdFile(t, fset, "dashboard.go"), "dashboard.go") {
		standalone[k] = true
	}

	for _, k := range dashFieldNames(standalone) {
		if !daemon[k] {
			t.Errorf("%s: `observer dashboard` serves it and `observer start` does not; set it in nodeDashboardOptions", k)
		}
	}
	for _, k := range dashFieldNames(daemon) {
		_, listed := daemonOnlyDashboardFields[k]
		switch {
		case !standalone[k] && !listed:
			t.Errorf("%s: only `observer start` sets it; set it in nodeDashboardOptions, or add a daemonOnlyDashboardFields row with the reason", k)
		case standalone[k] && listed:
			t.Errorf("%s: both commands serve it; drop its daemonOnlyDashboardFields row", k)
		}
	}
	for k := range daemonOnlyDashboardFields {
		if !added[k] {
			t.Errorf("daemonOnlyDashboardFields lists %s, which start.go does not set", k)
		}
	}
	optionsType := reflect.TypeOf(dashapi.Options{})
	for _, k := range dashFieldNames(daemon) {
		if _, ok := optionsType.FieldByName(k); !ok {
			t.Errorf("%s is not a dashapi.Options field", k)
		}
	}
	for _, k := range []string{"SecurityExplain", "SecurityExplainFix", "SecurityOrgShare"} {
		if !shared[k] {
			t.Errorf("%s is not set by the shared builder", k)
		}
	}
}

// TestBothDashboardsWrapInstallSignals pins the one post-step both commands
// apply to the builder's options: withInstallSignals (the standalone
// dashboard directly, the daemon inside newDaemonDashboard).
func TestBothDashboardsWrapInstallSignals(t *testing.T) {
	for file, want := range map[string]string{
		"dashboard.go":    "dashboard.New(withInstallSignals(nodeDashboardOptions(",
		"ui_dashboard.go": "dashboard.New(withInstallSignals(opts))",
	} {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), want) {
			t.Errorf("%s no longer contains %q", file, want)
		}
	}
}

// TestNodeDashboardOptionsServesExplainAndOrgShare builds the shared options
// against a throwaway config and database and checks the three seams CMD-01
// turned on for the daemon's dashboard are set wherever the build carries
// them (a build without the security module compiles them out to nil).
func TestNodeDashboardOptionsServesExplainAndOrgShare(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	cfgPath := filepath.Join(home, "config.toml")
	body := "[observer]\ndb_path = " + strconv.Quote(filepath.Join(home, "observer.db")) + "\n"
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	cfg, database, cleanup, err := loadConfigAndDB(ctx, cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanup)
	gov := newNodeGovernanceHandle(governanceIdentityLoader(store.New(database)), slog.Default())
	opts := nodeDashboardOptions(nodeDashboardDeps{
		Ctx: ctx, Cfg: cfg, ConfigPath: cfgPath, ResolvedConfigPath: cfgPath,
		DB: database, Governance: gov,
		EnrolManager: enrolManagerFor(cfgPath, false, gov),
	})
	inBuild := securityExplainDash(cfgPath, database) != nil
	for name, set := range map[string]bool{
		"SecurityExplain":    opts.SecurityExplain != nil,
		"SecurityExplainFix": opts.SecurityExplainFix != nil,
		"SecurityOrgShare":   opts.SecurityOrgShare != nil,
	} {
		if set != inBuild {
			t.Errorf("%s set = %v, want %v (security module in this build: %v)", name, set, inBuild, inBuild)
		}
	}
	if opts.DB != database || opts.ConfigPath != cfgPath || opts.Governance == nil {
		t.Errorf("the builder dropped its inputs: DB %v, ConfigPath %q, Governance nil %v", opts.DB == database, opts.ConfigPath, opts.Governance == nil)
	}
}
