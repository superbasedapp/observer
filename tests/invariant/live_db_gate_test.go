package invariant

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
)

// TestLiveDBGate_RealDefaultPathIsRefused is the standing behavioural guard
// for incident "task #17" (2026-07-30).
//
// WHAT HAPPENED: a working-tree test resolved config.Default()'s
// `~/.observer/observer.db`, handed it to db.Open, and Open applied every
// pending migration — including the then-unreleased agent migration 078 —
// to the operator's live 55k-row production database. The result happened to
// be correct. Nothing about the mechanism made that likely.
//
// WHAT THIS PINS: from inside a test binary, db.Open refuses the REAL default
// database path with db.ErrRealDBInTest. Delete the guard call from db.Open,
// or weaken the predicate, and this fails.
//
// SAFE WHEN RED IS LOAD-BEARING. The probe path deliberately sits in a
// NON-EXISTENT subdirectory of the real ~/.observer: db.Open never MkdirAlls,
// so if the gate is gone, SQLite cannot create the file and Open returns a
// plain "unable to open database file" — this test then fails on the
// errors.Is check having written NOTHING. A guard that only detects the
// incident by re-running it is not a guard.
func TestLiveDBGate_RealDefaultPathIsRefused(t *testing.T) {
	// FINDING 2 (codex, HIGH): the previous cut skipped when os.UserHomeDir
	// failed, so `env -u HOME go test ./...` left the gate silently OFF and
	// this suite green. A home is now resolved from the passwd database too,
	// and the test only skips when BOTH sources fail — anything short of that
	// is a real assertion.
	home, envErr := os.UserHomeDir()
	pwHome, pwErr := passwdHome()
	if envErr != nil || strings.TrimSpace(home) == "" {
		if pwErr != nil || strings.TrimSpace(pwHome) == "" {
			t.Skipf("no home resolvable from any source (env: %v, passwd: %v)", envErr, pwErr)
		}
		home = pwHome
	}
	realDir := filepath.Join(home, ".observer")

	// The literal incident path, for the assertion message only — never passed
	// to Open, because a deleted gate would then migrate it.
	incidentPath := filepath.Join(realDir, "observer.db")
	if want := expandHomeLike(t, config.Default().Observer.DBPath, home); want != incidentPath {
		t.Fatalf("config.Default() DB path resolves to %q, but this guard watches %q — "+
			"the default moved and the gate is now aimed at the wrong directory", want, incidentPath)
	}

	probe := filepath.Join(realDir, "live-db-gate-probe-do-not-create", "probe.db")
	if _, err := os.Stat(filepath.Dir(probe)); err == nil {
		t.Fatalf("probe directory %q unexpectedly exists — pick a different name", filepath.Dir(probe))
	}
	if v := os.Getenv(db.AllowRealDBInTestEnv); v != "" {
		t.Skipf("%s=%q is set: the operator opted out of the gate for this run", db.AllowRealDBInTestEnv, v)
	}

	database, openErr := db.Open(context.Background(), db.Options{Path: probe})
	if openErr == nil {
		_ = database.Close()
		_ = os.RemoveAll(filepath.Dir(probe))
		t.Fatalf("db.Open(%q) SUCCEEDED inside the live data directory — the task #17 gate is GONE. "+
			"The same call with %q would have migrated the operator's production database.", probe, incidentPath)
	}
	if !errors.Is(openErr, db.ErrRealDBInTest) {
		t.Fatalf("db.Open(%q) failed with %v, want db.ErrRealDBInTest. "+
			"A non-gate error means the refusal came from the filesystem, not from the guard — "+
			"the guard at internal/db/testguard.go is missing or no longer covers %q.",
			probe, openErr, realDir)
	}
	// Nothing may exist on disk either way.
	if _, err := os.Stat(filepath.Dir(probe)); err == nil {
		_ = os.RemoveAll(filepath.Dir(probe))
		t.Errorf("db.Open created %q despite refusing — the guard must sit above sql.Open", filepath.Dir(probe))
	}
}

// gateCallSite is one place the live-DB gate must be invoked. Both SQLite
// openers in the tree are listed: the agent DB and the org-server DB. Each has
// a path seam (Open) and a DAMAGE seam (runMigrations) — codex FINDING 3
// showed that guarding only the former leaves migrations_test.go's raw
// database/sql handle able to reproduce the incident.
type gateCallSite struct {
	file    string // repo-relative
	fn      string // function that must call the guard
	guard   string // guard function name, as written at the call site
	beforeS bool   // the call must precede sql.Open in the same function
}

// gateCallSites holds the AGENT-side seams, which exist in every tree.
// The org-server seams are appended by live_db_gate_orgserver_test.go's
// init() — a separate file because it names paths under
// internal/orgserver/, which the public source snapshot does not contain
// (scripts/release.sh PRIVATE_ONLY_PATHS). One owner, one feed path: this
// var is declared here and appended to in exactly that one other place.
// Do NOT inline the org-server rows back into this literal — the pins are
// path-based, so a missing file is a t.Fatalf, not a skip.
var gateCallSites = []gateCallSite{
	{filepath.Join("internal", "db", "db.go"), "Open", "GuardLiveDB", true},
	// The handle-form gate lives in runMigrationsFrom, the one runner every
	// path reaches (T-979 split it out so tests can drive synthetic
	// lineages, as T-977 did on the org side): runMigrationsWait only
	// delegates to it with the embedded lineage, Open calls runMigrationsWait
	// directly with its migration-lock wait (D-604), and runMigrations is a
	// thin wrapper over runMigrationsWait. The delegation rows pin that no
	// entry point can bypass the gate.
	{filepath.Join("internal", "db", "db.go"), "runMigrationsFrom", "GuardLiveDBHandle", false},
	{filepath.Join("internal", "db", "db.go"), "runMigrationsWait", "runMigrationsFrom", false},
	{filepath.Join("internal", "db", "db.go"), "runMigrations", "runMigrationsWait", false},
	{filepath.Join("internal", "db", "db.go"), "Open", "runMigrationsWait", false},
}

// TestLiveDBGate_StructuralPins is the cheap structural half: it fails if the
// guard file disappears, stops keying off testing.Testing(), or is no longer
// called from EVERY seam that can reach a live SQLite file. The behavioural
// tests can only observe the guard's effect at one seam; this one pins the
// shape at all four, so a refactor that drops a call site — or moves it below
// the file-creating line — is caught even if the other seams still work.
func TestLiveDBGate_StructuralPins(t *testing.T) {
	root := repoRoot(t) // shared helper, tests/invariant/codegraph_decommission_test.go
	guardFile := filepath.Join(root, "internal", "db", "testguard.go")
	src, err := os.ReadFile(guardFile)
	if err != nil {
		t.Fatalf("the live-DB test gate file is gone: %v", err)
	}
	for _, want := range []string{
		"testing.Testing()",
		"AllowRealDBInTestEnv",
		"ErrRealDBInTest",
		"func GuardLiveDB(",
		"func GuardLiveDBHandle(",
		// FINDING 1: full-path symlink resolution + inode aliasing.
		"os.SameFile",
		// FINDING 2: the passwd-backed second home source.
		"currentUserHome",
		// FINDING 4: the hatch is captured once, not read per call.
		"captureAllowRealDB",
	} {
		if !strings.Contains(string(src), want) {
			t.Errorf("internal/db/testguard.go no longer contains %q — the gate has been hollowed out", want)
		}
	}

	for _, cs := range gateCallSites {
		t.Run(cs.file+":"+cs.fn, func(t *testing.T) {
			guardLine, sqlOpenLine := findCallLines(t, filepath.Join(root, cs.file), cs.fn, cs.guard)
			if guardLine == 0 {
				t.Fatalf("%s: %s no longer calls %s — the task #17 gate has been removed from this seam",
					cs.file, cs.fn, cs.guard)
			}
			if cs.beforeS && sqlOpenLine != 0 && guardLine > sqlOpenLine {
				t.Errorf("%s: %s is called at line %d, AFTER sql.Open at line %d — "+
					"the gate must refuse before any file can be created", cs.file, cs.guard, guardLine, sqlOpenLine)
			}
		})
	}
}

// findCallLines parses file, locates the top-level function fn, and returns
// the line of the first call to guard and the line of the first sql.Open call
// inside it (0 when absent). The guard is matched both bare (same package) and
// through a package qualifier (orgserver/db imports it as agentdb).
func findCallLines(t *testing.T, file, fn, guard string) (guardLine, sqlOpenLine int) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	var decl *ast.FuncDecl
	ast.Inspect(f, func(n ast.Node) bool {
		if fd, ok := n.(*ast.FuncDecl); ok && fd.Recv == nil && fd.Name.Name == fn {
			decl = fd
		}
		return true
	})
	if decl == nil {
		t.Fatalf("%s: function %s not found", file, fn)
	}
	ast.Inspect(decl, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch e := call.Fun.(type) {
		case *ast.Ident:
			if e.Name == guard && guardLine == 0 {
				guardLine = fset.Position(call.Pos()).Line
			}
		case *ast.SelectorExpr:
			if e.Sel.Name == guard && guardLine == 0 {
				guardLine = fset.Position(call.Pos()).Line
			}
			if id, ok := e.X.(*ast.Ident); ok && id.Name == "sql" && e.Sel.Name == "Open" && sqlOpenLine == 0 {
				sqlOpenLine = fset.Position(call.Pos()).Line
			}
		}
		return true
	})
	return guardLine, sqlOpenLine
}

// expandHomeLike mirrors config's unexported expandHome so the guard can
// assert it is watching the directory config.Default() actually names.
func expandHomeLike(t *testing.T, p, home string) string {
	t.Helper()
	if !strings.HasPrefix(p, "~/") {
		return p
	}
	return filepath.Join(home, p[2:])
}

// passwdHome resolves the home directory from the OS user database, mirroring
// the gate's own second source so this suite skips only when the gate really
// had nothing to work with.
func passwdHome() (string, error) {
	u, err := user.Current()
	if err != nil {
		return "", err
	}
	return u.HomeDir, nil
}
