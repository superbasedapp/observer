package dashboard

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/guidance"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// newGuidanceTestServer builds a dashboard over a real temp DB with ONE known
// project root (an actual directory on disk, so the file viewer has something
// to read) and a guidance scan already persisted for it.
func newGuidanceTestServer(t *testing.T) (*Server, *sql.DB, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatalf("openTestDB: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })

	root := t.TempDir()
	st := store.New(database)
	// The project row is what knownProjectRoot validates against — seed it
	// the way real capture does, through Ingest.
	if _, err := st.Ingest(context.Background(), []models.ToolEvent{{
		SourceFile: "f", SourceEventID: "g1", SessionID: "sG",
		ProjectRoot: root, Timestamp: time.Now().UTC().Add(-time.Hour),
		Tool: models.ToolClaudeCode, ActionType: models.ActionReadFile,
		Target: "a.go", Success: true,
	}}, nil, store.IngestOptions{}); err != nil {
		t.Fatalf("Ingest: %v", err)
	}

	// A real CLAUDE.md on disk, plus a guidance row pointing at it.
	if err := os.WriteFile(filepath.Join(root, "CLAUDE.md"),
		[]byte("# Project rules\nexport AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLEKEY123456789\n"), 0o600); err != nil {
		t.Fatalf("write CLAUDE.md: %v", err)
	}
	files := []guidance.File{
		{
			Tool: "claude-code", Kind: guidance.KindInstructions, Scope: guidance.ScopeProject,
			RelPath: "CLAUDE.md", AbsPath: filepath.Join(root, "CLAUDE.md"),
			Name: "CLAUDE.md", SizeBytes: 42, ModTime: time.Now().UTC().Add(-time.Minute),
			ContentHash: "hash-claude",
		},
		{
			Tool: "cursor", Kind: guidance.KindRule, Scope: guidance.ScopeProject,
			RelPath: ".cursor/rules/style.mdc", AbsPath: filepath.Join(root, ".cursor", "rules", "style.mdc"),
			Name: "style", SizeBytes: 11, ModTime: time.Now().UTC().Add(-time.Minute),
			ContentHash: "hash-cursor",
		},
	}
	if _, err := st.UpsertGuidanceScan(context.Background(), root, files, time.Now().UTC()); err != nil {
		t.Fatalf("UpsertGuidanceScan: %v", err)
	}

	s, err := New(Options{DB: database, DBPath: path})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s, database, root
}

// TestGuidanceInventoryEndpoint covers the happy path: the persisted rows come
// back for a known root, with an honest tools_measurable answer per tool.
func TestGuidanceInventoryEndpoint(t *testing.T) {
	s, _, root := newGuidanceTestServer(t)

	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet,
		"/api/projects/guidance?root="+root, nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rr.Code, rr.Body.String())
	}
	var got struct {
		Root            string          `json:"root"`
		ScannedAt       string          `json:"scanned_at"`
		ToolsMeasurable map[string]bool `json:"tools_measurable"`
		Rows            []struct {
			Tool    string `json:"tool"`
			Kind    string `json:"kind"`
			RelPath string `json:"rel_path"`
			Present bool   `json:"present"`
		} `json:"rows"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v (%s)", err, rr.Body.String())
	}
	if got.Root != root {
		t.Errorf("root = %q, want %q", got.Root, root)
	}
	if got.ScannedAt == "" {
		t.Error("scanned_at empty for a root that has been scanned")
	}
	if len(got.Rows) != 2 {
		t.Fatalf("rows = %d, want 2 (%s)", len(got.Rows), rr.Body.String())
	}
	// sortGuidanceRows orders by tool, so claude-code precedes cursor.
	if got.Rows[0].Tool != "claude-code" || got.Rows[1].Tool != "cursor" {
		t.Errorf("row order = %q,%q; want claude-code,cursor", got.Rows[0].Tool, got.Rows[1].Tool)
	}
	// The honesty pin: measurable for claude-code, NOT for cursor — and
	// present for both, because the panel must be able to say "not
	// measurable" rather than render a zero.
	if !got.ToolsMeasurable["claude-code"] {
		t.Error("tools_measurable[claude-code] = false, want true")
	}
	measurable, ok := got.ToolsMeasurable["cursor"]
	if !ok {
		t.Error("tools_measurable is missing the cursor key — a tool present in rows must get an answer")
	}
	if measurable {
		t.Error("tools_measurable[cursor] = true, but no cursor capture names a guidance file")
	}
}

// TestGuidanceUnknownRootRefused is the containment pin: the endpoints are not
// arbitrary-directory readers. A root the store never recorded is a 404 —
// identical for the inventory and the file viewer, so neither is an oracle.
func TestGuidanceUnknownRootRefused(t *testing.T) {
	s, _, _ := newGuidanceTestServer(t)
	other := t.TempDir()
	if err := os.WriteFile(filepath.Join(other, "CLAUDE.md"), []byte("secret"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	cases := []struct {
		name string
		url  string
	}{
		{name: "inventory", url: "/api/projects/guidance?root=" + other},
		{name: "file", url: "/api/projects/guidance/file?root=" + other + "&rel=CLAUDE.md"},
		{name: "empty root", url: "/api/projects/guidance?root="},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, tc.url, nil))
			if rr.Code != http.StatusNotFound {
				t.Fatalf("status = %d, want 404 (body %s)", rr.Code, rr.Body.String())
			}
		})
	}
}

// TestGuidanceFileEndpoint covers the viewer: the body comes back, it is
// scrubbed, and it says so.
func TestGuidanceFileEndpoint(t *testing.T) {
	s, _, root := newGuidanceTestServer(t)

	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet,
		"/api/projects/guidance/file?root="+root+"&rel=CLAUDE.md", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rr.Code, rr.Body.String())
	}
	var got guidanceFileResp
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.RelPath != "CLAUDE.md" {
		t.Errorf("rel_path = %q", got.RelPath)
	}
	if !got.Scrubbed {
		t.Error("scrubbed = false — the viewer has no raw mode")
	}
	if !strings.Contains(got.Content, "# Project rules") {
		t.Errorf("content lost the prose: %q", got.Content)
	}
	if strings.Contains(got.Content, "AKIAIOSFODNN7EXAMPLEKEY123456789") {
		t.Errorf("the secret survived the scrub: %q", got.Content)
	}
}

// TestGuidanceFileTraversalRefused pins that fsview's containment reaches this
// endpoint: a traversal rel never escapes the root.
func TestGuidanceFileTraversalRefused(t *testing.T) {
	s, _, root := newGuidanceTestServer(t)
	for _, rel := range []string{"../escape.md", "/etc/passwd", ""} {
		rel := rel
		t.Run(rel, func(t *testing.T) {
			rr := httptest.NewRecorder()
			s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet,
				"/api/projects/guidance/file?root="+root+"&rel="+rel, nil))
			if rr.Code == http.StatusOK {
				t.Fatalf("traversal %q was served: %s", rel, rr.Body.String())
			}
		})
	}
}

// TestGuidanceSummaryEndpoint pins the roll-up's shape: a bare JSON array.
func TestGuidanceSummaryEndpoint(t *testing.T) {
	s, _, root := newGuidanceTestServer(t)

	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet,
		"/api/projects/guidance/summary", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rr.Code, rr.Body.String())
	}
	var got []struct {
		ProjectRoot string `json:"project_root"`
		Files       int    `json:"files"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode (want a bare array): %v — %s", err, rr.Body.String())
	}
	if len(got) != 1 || got[0].ProjectRoot != root {
		t.Fatalf("summary = %+v, want one entry for %q", got, root)
	}
	if got[0].Files != 2 {
		t.Errorf("files = %d, want 2", got[0].Files)
	}
}

// TestGuidanceMeasurableFor is the table-driven unit over the static
// capability map, including the honest zero value for an unlisted tool.
func TestGuidanceMeasurableFor(t *testing.T) {
	cases := []struct {
		name string
		tool string
		want bool
	}{
		{name: "claude-code has a grounded skill_invoke target", tool: "claude-code", want: true},
		// muse/deepseek/mistral-code/freebuff map a skill call onto
		// skill_invoke, but their TARGETS have never been grounded against a
		// real session. Since the flag now drives a per-file count, claiming
		// them would print a fabricated "never invoked".
		{name: "muse emits skill_invoke but its target is ungrounded", tool: "muse", want: false},
		{name: "mistral-code is ungrounded too", tool: "mistral-code", want: false},
		{name: "cursor has no guidance-naming capture", tool: "cursor", want: false},
		{name: "a tool nobody listed is honestly false", tool: "no-such-tool", want: false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := guidanceMeasurableFor([]store.GuidanceRow{{Tool: tc.tool}})
			if got[tc.tool] != tc.want {
				t.Errorf("measurable(%q) = %v, want %v", tc.tool, got[tc.tool], tc.want)
			}
			if _, ok := got[tc.tool]; !ok {
				t.Errorf("tool %q present in rows but absent from tools_measurable", tc.tool)
			}
		})
	}
}

// TestGuidanceFileUserScopeAnchor pins P1-3: a user-scope row's "~/" path is
// anchored at the operator's HOME, not at the project root. The panel makes
// those rows clickable, and before this they always 404'd.
func TestGuidanceFileUserScopeAnchor(t *testing.T) {
	s, database, root := newGuidanceTestServer(t)

	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(home, ".claude", "CLAUDE.md"),
		[]byte("# Home rules\nPrefer table-driven tests.\n"), 0o600); err != nil {
		t.Fatalf("write home CLAUDE.md: %v", err)
	}
	// The home inventory lives under the sentinel root and is folded into
	// every project's listing.
	if _, err := store.New(database).UpsertGuidanceScan(context.Background(),
		store.GuidanceUserScopeRoot, []guidance.File{{
			Tool: "claude-code", Kind: guidance.KindInstructions, Scope: guidance.ScopeUser,
			RelPath: "~/.claude/CLAUDE.md", AbsPath: filepath.Join(home, ".claude", "CLAUDE.md"),
			Name: "CLAUDE.md", SizeBytes: 12, ModTime: time.Now().UTC(), ContentHash: "hash-home",
		}}, time.Now().UTC()); err != nil {
		t.Fatalf("UpsertGuidanceScan: %v", err)
	}

	// The inventory for the PROJECT carries the home row...
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet,
		"/api/projects/guidance?root="+root, nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("inventory status = %d: %s", rr.Code, rr.Body.String())
	}
	var inv guidanceInventoryResp
	if err := json.Unmarshal(rr.Body.Bytes(), &inv); err != nil {
		t.Fatalf("decode inventory: %v", err)
	}
	var sawUser bool
	for _, row := range inv.Rows {
		if row.RelPath == "~/.claude/CLAUDE.md" {
			sawUser = true
		}
	}
	if !sawUser {
		t.Fatalf("the home-scope row was not folded into the project inventory: %+v", inv.Rows)
	}

	// ...and it is readable through the SAME endpoint.
	for _, tc := range []struct {
		name, rel, want string
	}{
		{name: "user scope", rel: "~/.claude/CLAUDE.md", want: "# Home rules"},
		{name: "project scope", rel: "CLAUDE.md", want: "# Project rules"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet,
				"/api/projects/guidance/file?root="+root+"&rel="+url.QueryEscape(tc.rel), nil))
			if rr.Code != http.StatusOK {
				t.Fatalf("status = %d, body %s", rr.Code, rr.Body.String())
			}
			var got guidanceFileResp
			if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if !strings.Contains(got.Content, tc.want) {
				t.Errorf("content = %q, want it to contain %q", got.Content, tc.want)
			}
		})
	}

	// A "~/" path still cannot climb out of the home directory.
	rr = httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet,
		"/api/projects/guidance/file?root="+root+"&rel="+url.QueryEscape("~/../escape.md"), nil))
	if rr.Code == http.StatusOK {
		t.Errorf("a traversal out of the home anchor was served: %s", rr.Body.String())
	}
}

// TestGuidanceInventoryOmitsAbsPath pins P2-8: the inventory wire carries
// rel_path only — an absolute host path is never handed out.
func TestGuidanceInventoryOmitsAbsPath(t *testing.T) {
	s, _, root := newGuidanceTestServer(t)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet,
		"/api/projects/guidance?root="+root, nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if strings.Contains(body, "abs_path") {
		t.Errorf("the inventory wire still carries abs_path: %s", body)
	}
	if strings.Contains(body, filepath.Join(root, "CLAUDE.md")) {
		t.Errorf("the inventory wire leaked an absolute path: %s", body)
	}
}

// TestKnownProjectRootReturnsCleanedPath pins P2-4: a projects.root_path
// stored with a trailing separator must still resolve to the cleaned root the
// guidance rows are keyed by, or the panel renders empty.
func TestKnownProjectRootReturnsCleanedPath(t *testing.T) {
	s, database, root := newGuidanceTestServer(t)
	if _, err := database.ExecContext(context.Background(),
		`UPDATE projects SET root_path = ? WHERE root_path = ?`, root+"/", root); err != nil {
		t.Fatalf("dirty the root path: %v", err)
	}
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet,
		"/api/projects/guidance?root="+root, nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rr.Code, rr.Body.String())
	}
	var inv guidanceInventoryResp
	if err := json.Unmarshal(rr.Body.Bytes(), &inv); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if inv.Root != root {
		t.Errorf("root = %q, want the cleaned %q", inv.Root, root)
	}
	if len(inv.Rows) == 0 {
		t.Errorf("a trailing-slash project root produced an empty inventory")
	}
}

// TestGuidanceUsageMeasurable is the two-halves capability table: a signal
// exists per KIND, and emitters exist per TOOL. The load-bearing rows are the
// mismatches — a muse SKILL is measurable (muse has a skill_invoke taxonomy
// row) while a muse INSTRUCTIONS file is not (no adapter but claude-code emits
// instructions_loaded), and no tool at all can name an agent/command/rule.
func TestGuidanceUsageMeasurable(t *testing.T) {
	t.Parallel()
	cases := []struct {
		tool, kind string
		want       bool
	}{
		{"claude-code", "skill", true},
		{"claude-code", "instructions", true},
		// muse/deepseek/mistral-code/freebuff emit skill_invoke but their
		// targets are not yet grounded, so they are deliberately NOT in
		// guidanceToolsMeasurable — a count printed off an unverified join
		// would render as a fabricated "never invoked".
		{"muse", "skill", false},
		{"muse", "instructions", false},
		{"mistral-code", "skill", false},
		{"deepseek", "skill", false},
		{"freebuff", "skill", false},
		{"cursor", "skill", false},
		{"cursor", "rule", false},
		{"claude-code", "agent", false},
		{"claude-code", "command", false},
		{"claude-code", "config", false},
		{"unknown-tool", "skill", false},
		{"claude-code", "not-a-kind", false},
	}
	for _, c := range cases {
		if got := guidanceUsageMeasurable(c.tool, c.kind); got != c.want {
			t.Errorf("guidanceUsageMeasurable(%q, %q) = %v, want %v", c.tool, c.kind, got, c.want)
		}
	}
}

// TestGuidanceInventoryUsageJoin is the wave-2 end-to-end: a skill that was
// invoked reports a count, a sibling skill that was not reports
// never_invoked, a CLAUDE.md that the hook loaded reports a load count, and a
// cursor rule — which NO capture signal can name — reports not_measurable
// rather than a zero that reads like disuse.
func TestGuidanceInventoryUsageJoin(t *testing.T) {
	s, database, root := newGuidanceTestServer(t)
	st := store.New(database)
	ctx := context.Background()
	now := time.Now().UTC()

	files := []guidance.File{
		{
			Tool: "claude-code", Kind: guidance.KindInstructions, Scope: guidance.ScopeProject,
			RelPath: "CLAUDE.md", AbsPath: filepath.Join(root, "CLAUDE.md"),
			Name: "CLAUDE.md", SizeBytes: 42, ModTime: now, ContentHash: "hash-claude",
		},
		{
			Tool: "claude-code", Kind: guidance.KindSkill, Scope: guidance.ScopeProject,
			RelPath: ".claude/skills/deploy/SKILL.md",
			AbsPath: filepath.Join(root, ".claude", "skills", "deploy", "SKILL.md"),
			Name:    "deploy", SizeBytes: 10, ModTime: now, ContentHash: "hash-deploy",
		},
		{
			Tool: "claude-code", Kind: guidance.KindSkill, Scope: guidance.ScopeProject,
			RelPath: ".claude/skills/unused/SKILL.md",
			AbsPath: filepath.Join(root, ".claude", "skills", "unused", "SKILL.md"),
			Name:    "unused", SizeBytes: 10, ModTime: now, ContentHash: "hash-unused",
		},
		{
			Tool: "cursor", Kind: guidance.KindRule, Scope: guidance.ScopeProject,
			RelPath: ".cursor/rules/style.mdc",
			AbsPath: filepath.Join(root, ".cursor", "rules", "style.mdc"),
			Name:    "style", SizeBytes: 11, ModTime: now, ContentHash: "hash-cursor",
		},
	}
	if _, err := st.UpsertGuidanceScan(ctx, root, files, now); err != nil {
		t.Fatalf("UpsertGuidanceScan: %v", err)
	}
	if _, err := st.Ingest(ctx, []models.ToolEvent{
		{
			SourceFile: "f", SourceEventID: "sk-1", SessionID: "sG", ProjectRoot: root,
			Timestamp: now.Add(-2 * time.Hour), Tool: models.ToolClaudeCode,
			ActionType: models.ActionSkillInvoke, Target: "deploy", Success: true,
		},
		{
			SourceFile: "f", SourceEventID: "sk-2", SessionID: "sG", ProjectRoot: root,
			Timestamp: now.Add(-time.Hour), Tool: models.ToolClaudeCode,
			ActionType: models.ActionSkillInvoke, Target: "deploy", Success: true,
		},
		{
			SourceFile: "f", SourceEventID: "ld-1", SessionID: "sG", ProjectRoot: root,
			Timestamp: now.Add(-3 * time.Hour), Tool: models.ToolClaudeCode,
			ActionType: models.ActionInstructionsLoaded,
			Target:     filepath.Join(root, "CLAUDE.md"), Success: true,
		},
	}, nil, store.IngestOptions{}); err != nil {
		t.Fatalf("Ingest: %v", err)
	}

	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet,
		"/api/projects/guidance?root="+root, nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rr.Code, rr.Body.String())
	}
	var got struct {
		UsageWindowDays int    `json:"usage_window_days"`
		UsageSince      string `json:"usage_since"`
		Rows            []struct {
			Tool          string `json:"tool"`
			Kind          string `json:"kind"`
			Name          string `json:"name"`
			InvokedCount  int    `json:"invoked_count"`
			LastInvokedAt string `json:"last_invoked_at"`
			LoadedCount   int    `json:"loaded_count"`
			LastLoadedAt  string `json:"last_loaded_at"`
			Usage         string `json:"usage"`
		} `json:"rows"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v (%s)", err, rr.Body.String())
	}
	if got.UsageWindowDays != store.GuidanceUsageWindowDays {
		t.Errorf("usage_window_days = %d, want %d", got.UsageWindowDays, store.GuidanceUsageWindowDays)
	}
	if got.UsageSince == "" {
		t.Error("usage_since empty; the window must be reported")
	}
	byName := map[string]int{}
	for i, r := range got.Rows {
		byName[r.Tool+"/"+r.Kind+"/"+r.Name] = i
	}
	check := func(key, wantUsage string, wantInvoked, wantLoaded int) {
		t.Helper()
		i, ok := byName[key]
		if !ok {
			t.Fatalf("row %q missing (%s)", key, rr.Body.String())
		}
		r := got.Rows[i]
		if r.Usage != wantUsage {
			t.Errorf("%s: usage = %q, want %q", key, r.Usage, wantUsage)
		}
		if r.InvokedCount != wantInvoked {
			t.Errorf("%s: invoked_count = %d, want %d", key, r.InvokedCount, wantInvoked)
		}
		if r.LoadedCount != wantLoaded {
			t.Errorf("%s: loaded_count = %d, want %d", key, r.LoadedCount, wantLoaded)
		}
	}
	check("claude-code/skill/deploy", "invoked", 2, 0)
	check("claude-code/skill/unused", "never_invoked", 0, 0)
	check("claude-code/instructions/CLAUDE.md", "invoked", 0, 1)
	// The honesty pin: a cursor rule has NO capture signal that could name
	// it, so it must never render as never_invoked.
	check("cursor/rule/style", "not_measurable", 0, 0)

	if ts := got.Rows[byName["claude-code/skill/deploy"]].LastInvokedAt; ts == "" {
		t.Error("deploy: last_invoked_at empty for an invoked skill")
	}
	if ts := got.Rows[byName["claude-code/skill/unused"]].LastInvokedAt; ts != "" {
		t.Errorf("unused: last_invoked_at = %q, want omitted", ts)
	}
}

// TestBuildGuidanceInventoryRespUsageFailSoft is the degraded-path pin. The
// inventory is the primary answer: a usage read that times out or errors must
// still yield a complete inventory, every row marked not_measurable, and an
// EXPLICIT usage_unavailable flag so the surface can say "we did not look"
// rather than "there is nothing to see".
func TestBuildGuidanceInventoryRespUsageFailSoft(t *testing.T) {
	t.Parallel()
	rows := []store.GuidanceRow{
		{Tool: "claude-code", Kind: "skill", Name: "deploy", RelPath: ".claude/skills/deploy/SKILL.md"},
		{Tool: "claude-code", Kind: "instructions", Name: "CLAUDE.md", RelPath: "CLAUDE.md"},
		{Tool: "cursor", Kind: "rule", Name: "style", RelPath: ".cursor/rules/style.mdc"},
	}

	cases := []struct {
		name      string
		read      guidanceUsageFn
		wantOK    bool
		wantClass string
	}{
		{
			name: "query failure degrades, never 500s",
			read: func(context.Context, string) (store.GuidanceUsage, error) {
				return store.GuidanceUsage{}, errors.New("no such table: actions")
			},
			wantClass: guidanceUsageErrQuery,
		},
		{
			name: "a slow read is cut off by the handler's own deadline",
			read: func(ctx context.Context, _ string) (store.GuidanceUsage, error) {
				// The real shape: a cold seek that outlives the budget. The
				// fake honours ctx, exactly as database/sql does.
				<-ctx.Done()
				return store.GuidanceUsage{}, ctx.Err()
			},
			wantClass: guidanceUsageErrTimeout,
		},
		{
			name: "the healthy read still reports counts",
			read: func(context.Context, string) (store.GuidanceUsage, error) {
				return store.GuidanceUsage{
					Since: time.Now().UTC().AddDate(0, 0, -store.GuidanceUsageWindowDays),
					Skills: map[string]store.GuidanceUsageStat{
						guidance.SkillKey("claude-code", guidance.KindSkill, "deploy"): {
							Count: 4, Last: time.Now().UTC(),
						},
					},
					Files: map[string]store.GuidanceUsageStat{},
				}, nil
			},
			wantOK: true,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// A short deadline keeps the slow case from waiting out the real
			// 3s budget; readGuidanceUsage takes the tighter of the two.
			ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
			defer cancel()

			resp := buildGuidanceInventoryResp(ctx, "/repo/x", rows, tc.read)

			if len(resp.Rows) != len(rows) {
				t.Fatalf("rows = %d, want the full inventory (%d)", len(resp.Rows), len(rows))
			}
			if resp.UsageUnavailable == tc.wantOK {
				t.Errorf("usage_unavailable = %v, want %v", resp.UsageUnavailable, !tc.wantOK)
			}
			if resp.UsageErrorClass != tc.wantClass {
				t.Errorf("usage_error_class = %q, want %q", resp.UsageErrorClass, tc.wantClass)
			}
			if tc.wantOK {
				if resp.Rows[0].Usage != guidanceUsageInvoked || resp.Rows[0].InvokedCount != 4 {
					t.Errorf("healthy read: row0 = %+v, want invoked x4", resp.Rows[0])
				}
				return
			}
			// The degraded contract: nothing claims disuse.
			for _, r := range resp.Rows {
				if r.Usage != guidanceUsageNotMeasurable {
					t.Errorf("%s/%s: usage = %q, want %q when the usage read failed "+
						"(never_invoked would turn a timeout into a claim about the operator)",
						r.Tool, r.Name, r.Usage, guidanceUsageNotMeasurable)
				}
				if r.InvokedCount != 0 || r.LoadedCount != 0 {
					t.Errorf("%s/%s: counts %d/%d, want zero on a failed read", r.Tool, r.Name, r.InvokedCount, r.LoadedCount)
				}
			}
		})
	}
}

// TestGuidanceInventoryEndpointSurvivesUsageFailure is the route-level
// counterpart: whatever the usage join does, the HTTP status is 200 and the
// inventory is intact. (The healthy path is covered by
// TestGuidanceInventoryUsageJoin; this pins that a bad usage read cannot take
// the panel down.)
func TestGuidanceInventoryEndpointSurvivesUsageFailure(t *testing.T) {
	s, database, root := newGuidanceTestServer(t)
	// Drop the table the usage join reads out from under the handler: the
	// bluntest possible "the usage query failed" without a slow disk.
	if _, err := database.ExecContext(context.Background(), `DROP TABLE actions`); err != nil {
		t.Fatalf("drop actions: %v", err)
	}

	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet,
		"/api/projects/guidance?root="+root, nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (the inventory must survive a usage failure); body %s",
			rr.Code, rr.Body.String())
	}
	var got struct {
		UsageUnavailable bool   `json:"usage_unavailable"`
		UsageErrorClass  string `json:"usage_error_class"`
		Rows             []struct {
			Tool  string `json:"tool"`
			Usage string `json:"usage"`
		} `json:"rows"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v (%s)", err, rr.Body.String())
	}
	if !got.UsageUnavailable {
		t.Error("usage_unavailable = false after the usage query failed")
	}
	if got.UsageErrorClass != "query" {
		t.Errorf("usage_error_class = %q, want query", got.UsageErrorClass)
	}
	if len(got.Rows) != 2 {
		t.Fatalf("rows = %d, want the 2 inventory rows (%s)", len(got.Rows), rr.Body.String())
	}
	for _, r := range got.Rows {
		if r.Usage != "not_measurable" {
			t.Errorf("%s: usage = %q, want not_measurable", r.Tool, r.Usage)
		}
	}
}
