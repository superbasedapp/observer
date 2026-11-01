package diag

import (
	"context"
	"database/sql"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/routeattest"
)

// diagTestDB opens a migrated node database in a temp dir.
func diagTestDB(t *testing.T) *sql.DB {
	t.Helper()
	database, err := dbtemplate.Open(context.Background(), db.Options{Path: filepath.Join(t.TempDir(), "d.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	return database
}

// observedSession is one seeded session: its surface stamp and how many
// api_turns rows it has.
type observedSession struct {
	id, tool, surface, host string
	age                     time.Duration
	turns                   int
}

func seedObservedSessions(t *testing.T, database *sql.DB, now time.Time, sessions []observedSession) {
	t.Helper()
	if _, err := database.Exec(`INSERT INTO projects (root_path, name, created_at) VALUES ('/p', 'p', ?)`, now.Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	for _, s := range sessions {
		ts := now.Add(-s.age).UTC().Format(time.RFC3339Nano)
		if _, err := database.Exec(
			`INSERT INTO sessions (id, project_id, tool, started_at, surface, surface_host) VALUES (?, 1, ?, ?, NULLIF(?, ''), NULLIF(?, ''))`,
			s.id, s.tool, ts, s.surface, s.host,
		); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < s.turns; i++ {
			if _, err := database.Exec(
				`INSERT INTO api_turns (session_id, timestamp, provider, model, input_tokens, output_tokens) VALUES (?, ?, 'p', 'm', 1, 1)`,
				s.id, ts,
			); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// firstToolWhere returns the first registry tool satisfying pred, so the
// test never hard-codes which tool happens to carry a capability shape.
func firstToolWhere(t *testing.T, pred func(integration.Capability) bool) string {
	t.Helper()
	for _, id := range integration.Tools() {
		if c, ok := integration.For(id); ok && pred(c) {
			return id
		}
	}
	t.Skip("no registry tool has the required capability shape")
	return ""
}

// desktopRoutablePolicy is the review's OBS-2 fixture policy: a CLI and a
// desktop surface, both routable and measurable (the registry grounds the
// desktop row only in Wave 3).
func desktopRoutablePolicy(_, _, _ string) routeattest.SurfaceFacts {
	return routeattest.SurfaceFacts{Routable: true, Correlation: integration.CorrelationRequestID}
}

func TestRouteObserved(t *testing.T) {
	now := time.Now().UTC()
	routableCLI := firstToolWhere(t, func(c integration.Capability) bool {
		// A request-id joined CLI (partial blocks) of a multi-surface
		// adapter (an unstamped group stays unknown_surface): surface-gap
		// Wave 3 made process-bridge and unstamped tools judge otherwise.
		row, match := c.RouteSurfaceFor("cli", "")
		_, unstamped := c.UnstampedSurface()
		return match != integration.SurfaceMatchTool && row.CorrelationMode.JoinsEveryTurn() && !unstamped &&
			row.EffectiveRoutability(c) == integration.RouteStatusRoutableNow
	})
	exempt := firstToolWhere(t, func(c integration.Capability) bool {
		ok, _ := routeattest.IsExempt(c)
		return ok
	})
	probeOnly := firstToolWhere(t, func(c integration.Capability) bool {
		return c.Proxy == nil && c.Routability == integration.RouteStatusProbeRequired
	})

	cases := []struct {
		name       string
		sessions   []observedSession
		policy     routeattest.SurfacePolicy
		wantStatus Status
		// wantInMessage / wantInDetails are substrings that must appear.
		wantInMessage []string
		wantInDetails []string
		notInMessage  []string
	}{
		{
			name:          "empty store reads nothing to judge",
			wantStatus:    StatusOK,
			wantInMessage: []string{"no sessions recorded"},
		},
		{
			name: "review fixture: 5 CLI proxied, 3 desktop unproxied warns naming the desktop surface",
			sessions: []observedSession{
				{"c1", routableCLI, "cli", "", time.Hour, 2},
				{"c2", routableCLI, "cli", "", time.Hour, 1},
				{"c3", routableCLI, "cli", "", time.Hour, 4},
				{"c4", routableCLI, "cli", "", time.Hour, 1},
				{"c5", routableCLI, "cli", "", time.Hour, 1},
				{"d1", routableCLI, "desktop", "", time.Hour, 0},
				{"d2", routableCLI, "desktop", "", time.Hour, 0},
				{"d3", routableCLI, "desktop", "", time.Hour, 0},
			},
			policy:        desktopRoutablePolicy,
			wantStatus:    StatusWarn,
			wantInMessage: []string{routableCLI + "/desktop"},
			notInMessage:  []string{routableCLI + "/cli"},
			wantInDetails: []string{routableCLI + "/cli: attested - all 5 sessions proxied", routableCLI + "/desktop: bypass_suspect"},
		},
		{
			name: "registry: an ungrounded desktop surface is unknown measurability, never a bypass",
			sessions: []observedSession{
				{"c1", routableCLI, "cli", "", time.Hour, 3},
				{"d1", routableCLI, "desktop", "claude-desktop", time.Hour, 0},
			},
			wantStatus:    StatusOK,
			wantInDetails: []string{routableCLI + "/desktop (claude-desktop): unknown_measurability"},
		},
		{
			name: "registry: a routable CLI with no proxied session warns",
			sessions: []observedSession{
				{"c1", routableCLI, "cli", "", time.Hour, 0}, {"c2", routableCLI, "cli", "", time.Hour, 0},
			},
			wantStatus:    StatusWarn,
			wantInMessage: []string{routableCLI + "/cli"},
			wantInDetails: []string{"bypass_suspect - none of 2 sessions was proxied"},
		},
		{
			name: "a session with several api turns counts once: partial, never invalid",
			sessions: []observedSession{
				{"c1", routableCLI, "cli", "", time.Hour, 9}, {"c2", routableCLI, "cli", "", time.Hour, 0},
			},
			wantStatus:    StatusWarn,
			wantInDetails: []string{routableCLI + "/cli: partial - 1 of 2 sessions proxied"},
		},
		{
			name: "sessions only before the window read nothing to judge",
			sessions: []observedSession{
				{"o1", routableCLI, "cli", "", 30 * 24 * time.Hour, 0},
			},
			wantStatus:    StatusOK,
			wantInMessage: []string{"no sessions recorded in the 7d window"},
		},
		{
			name: "a declared surface the node never stamped is added as unobserved",
			sessions: []observedSession{
				{"i1", routableCLI, "ide", "vscode", time.Hour, 0},
			},
			wantStatus:    StatusOK,
			wantInDetails: []string{routableCLI + "/cli: unobserved", routableCLI + "/ide (vscode): unknown_measurability"},
		},
		{
			name: "a native-exempt tool is exempt",
			sessions: []observedSession{
				{"e1", exempt, "cli", "", time.Hour, 0},
			},
			wantStatus:    StatusOK,
			wantInDetails: []string{exempt + "/cli: exempt"},
		},
		{
			name: "a probe_required tool with no Proxy row is still judged",
			sessions: []observedSession{
				{"p1", probeOnly, "cli", "", time.Hour, 0},
			},
			wantStatus:    StatusOK,
			wantInDetails: []string{probeOnly + "/cli:"},
		},
		{
			name: "a bypass of a not-yet-routable surface is reported, not warned",
			sessions: []observedSession{
				{"p1", probeOnly, "cli", "", time.Hour, 0},
			},
			policy: func(_, _, _ string) routeattest.SurfaceFacts {
				return routeattest.SurfaceFacts{Correlation: integration.CorrelationRequestID}
			},
			wantStatus:    StatusOK,
			wantInDetails: []string{probeOnly + "/cli: bypass_suspect"},
		},
		{
			// DEC-4 addendum (P-172): with no proxied session and no stamped
			// sibling, the unstamped group is judged at tool level and warns,
			// as the pre-arc tool-level gate did.
			name: "an unstamped session group with no proxied session is a tool-level bypass",
			sessions: []observedSession{
				{"u1", routableCLI, "", "", time.Hour, 0},
			},
			wantStatus:    StatusWarn,
			wantInDetails: []string{routableCLI + "/unstamped: bypass_suspect - tool-level reading (P-172)"},
		},
		{
			name: "an unstamped session group with a proxied session is unknown_surface",
			sessions: []observedSession{
				{"u1", routableCLI, "", "", time.Hour, 1},
			},
			wantStatus:    StatusOK,
			wantInDetails: []string{routableCLI + "/unstamped: unknown_surface"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			database := diagTestDB(t)
			if len(tc.sessions) > 0 {
				seedObservedSessions(t, database, now, tc.sessions)
			}
			got := checkRouteObserved(context.Background(), database, now, tc.policy)
			if got.Name != routeObservedName {
				t.Fatalf("name = %q", got.Name)
			}
			if got.Status != tc.wantStatus {
				t.Fatalf("status = %s, want %s\nmessage: %s\ndetails:\n%s", got.Status, tc.wantStatus, got.Message, strings.Join(got.Details, "\n"))
			}
			for _, want := range tc.wantInMessage {
				if !strings.Contains(got.Message, want) {
					t.Errorf("message %q lacks %q", got.Message, want)
				}
			}
			for _, not := range tc.notInMessage {
				if strings.Contains(got.Message, not) {
					t.Errorf("message %q names %q", got.Message, not)
				}
			}
			joined := strings.Join(got.Details, "\n")
			for _, want := range tc.wantInDetails {
				if !strings.Contains(joined, want) {
					t.Errorf("details lack %q:\n%s", want, joined)
				}
			}
		})
	}
}

func TestRouteObservedNilDB(t *testing.T) {
	if got := checkRouteObserved(context.Background(), nil, time.Now(), nil); got.Status != StatusFail {
		t.Fatalf("status = %s, want fail", got.Status)
	}
}

// TestRouteObservedNamesNoTool pins the capability rule (CLAUDE.md #3): the
// check's source holds no registry tool id as a string literal and reads no
// models.Tool* constant, so it can only branch on capability shape.
func TestRouteObservedNamesNoTool(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "routeobserved.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, id := range integration.Tools() {
		ids[id] = true
	}
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.BasicLit:
			if x.Kind != token.STRING {
				return true
			}
			s, err := strconv.Unquote(x.Value)
			if err != nil {
				return true
			}
			if ids[s] {
				t.Errorf("%s: tool id literal %q in route.observed", fset.Position(x.Pos()), s)
			}
		case *ast.SelectorExpr:
			if pkg, ok := x.X.(*ast.Ident); ok && pkg.Name == "models" && strings.HasPrefix(x.Sel.Name, "Tool") {
				t.Errorf("%s: models.%s in route.observed", fset.Position(x.Pos()), x.Sel.Name)
			}
		}
		return true
	})
}

// TestProxyRoutingGapRetired pins that the name-branched check is gone.
func TestProxyRoutingGapRetired(t *testing.T) {
	matches, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range matches {
		if strings.HasSuffix(m, "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, m, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			if fn, ok := d.(*ast.FuncDecl); ok && fn.Name.Name == "checkProxyRoutingGap" {
				t.Errorf("%s still declares checkProxyRoutingGap", m)
			}
		}
	}
}
