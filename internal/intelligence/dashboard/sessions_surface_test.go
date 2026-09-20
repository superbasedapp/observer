package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// seedSurfaceSessions puts three sessions through the real ingest path
// and stamps two of them through the ONE surface write seam
// (store.SetSessionSurface), so the list reads exactly what the adapters
// would have left behind:
//
//	s-cli  — kind only (cli, no host)
//	s-ide  — kind + host (ide / vscode)
//	s-none — never stamped (the honest unknown)
func seedSurfaceSessions(t *testing.T, s *Server) {
	t.Helper()
	st := store.New(s.db())
	base := time.Now().UTC().Add(-time.Hour)
	for i, id := range []string{"s-cli", "s-ide", "s-none"} {
		if _, err := st.Ingest(context.Background(), []models.ToolEvent{{
			SessionID: id, ProjectRoot: "/repo", Target: "ls",
			ActionType: models.ActionRunCommand, RawToolInput: "ls",
			Tool: models.ToolClaudeCode, SourceFile: "/tmp/" + id + ".jsonl",
			SourceEventID: "ev-" + id, Timestamp: base.Add(time.Duration(i) * time.Minute),
			Success: true,
		}}, nil, store.IngestOptions{}); err != nil {
			t.Fatalf("Ingest %s: %v", id, err)
		}
	}
	for _, sf := range []models.SessionSurface{
		{SessionID: "s-cli", Surface: models.SurfaceCLI},
		{SessionID: "s-ide", Surface: models.SurfaceIDE, SurfaceHost: "vscode"},
	} {
		if changed, err := st.SetSessionSurface(context.Background(), sf); err != nil || !changed {
			t.Fatalf("SetSessionSurface(%+v): changed=%v err=%v", sf, changed, err)
		}
	}
}

// surfaceListRow is the slice of the /api/sessions row this test reads.
// The raw map alongside it is what pins key ABSENCE: an unstamped
// session must omit the keys, not emit "".
type surfaceListRow struct {
	ID          string `json:"id"`
	Surface     string `json:"surface"`
	SurfaceHost string `json:"surface_host"`
}

func fetchSurfaceList(t *testing.T, s *Server, query string) (rows []surfaceListRow, raw []map[string]any, total int) {
	t.Helper()
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/sessions?limit=10"+query, nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /api/sessions%s: status %d body %s", query, rr.Code, rr.Body.String())
	}
	var typed struct {
		Rows  []surfaceListRow `json:"rows"`
		Total int              `json:"total"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &typed); err != nil {
		t.Fatalf("decode typed: %v (%s)", err, rr.Body.String())
	}
	var untyped struct {
		Rows []map[string]any `json:"rows"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &untyped); err != nil {
		t.Fatalf("decode raw: %v", err)
	}
	return typed.Rows, untyped.Rows, typed.Total
}

// TestSessionsListCarriesSurface pins that the list row carries the same
// two capture-surface fields the detail response does — read in the list
// query itself, not a per-row round trip — and that an unstamped session
// OMITS both keys. Absent means unknown; the UI must never see "" and be
// tempted to render a default.
func TestSessionsListCarriesSurface(t *testing.T) {
	t.Parallel()
	s, _ := newLOCServer(t)
	seedSurfaceSessions(t, s)

	rows, raw, total := fetchSurfaceList(t, s, "")
	if total != 3 {
		t.Fatalf("total = %d, want 3", total)
	}
	want := map[string]surfaceListRow{
		"s-cli":  {ID: "s-cli", Surface: "cli"},
		"s-ide":  {ID: "s-ide", Surface: "ide", SurfaceHost: "vscode"},
		"s-none": {ID: "s-none"},
	}
	for _, row := range rows {
		w, ok := want[row.ID]
		if !ok {
			t.Errorf("unexpected row %q", row.ID)
			continue
		}
		if row != w {
			t.Errorf("row %s = %+v, want %+v", row.ID, row, w)
		}
	}
	// Key ABSENCE on the unstamped session and on the host-less stamp.
	for _, m := range raw {
		id, _ := m["id"].(string)
		_, hasSurface := m["surface"]
		_, hasHost := m["surface_host"]
		switch id {
		case "s-none":
			if hasSurface || hasHost {
				t.Errorf("s-none: unstamped session must omit surface/surface_host, got %v", m)
			}
		case "s-cli":
			if hasHost {
				t.Errorf("s-cli: host-less stamp must omit surface_host, got %v", m["surface_host"])
			}
		}
	}
}

// TestSessionsListSurfaceFilter is the table-driven contract for the
// `surface=` / `surface_host=` list filters: exact match on the closed
// kind vocabulary, verbatim (lowercased) match on the open host token,
// AND semantics when both are present, and FAIL-OPEN (no filter, never a
// 400 and never a silent empty page) for anything outside the shape.
func TestSessionsListSurfaceFilter(t *testing.T) {
	t.Parallel()
	s, _ := newLOCServer(t)
	seedSurfaceSessions(t, s)

	cases := []struct {
		name    string
		query   string
		wantIDs []string // nil = every seeded session (fail-open)
	}{
		{name: "kind exact", query: "&surface=ide", wantIDs: []string{"s-ide"}},
		{name: "kind case-insensitive", query: "&surface=CLI", wantIDs: []string{"s-cli"}},
		{name: "kind with no stamped rows", query: "&surface=web", wantIDs: []string{}},
		{name: "kind outside vocabulary fails open", query: "&surface=terminal"},
		{name: "kind blank fails open", query: "&surface=%20"},
		{name: "host exact", query: "&surface_host=vscode", wantIDs: []string{"s-ide"}},
		{name: "host case-insensitive", query: "&surface_host=VSCode", wantIDs: []string{"s-ide"}},
		{name: "host unknown token matches nothing", query: "&surface_host=cursor", wantIDs: []string{}},
		{name: "host with whitespace fails open", query: "&surface_host=vs%20code"},
		{name: "host over length fails open", query: "&surface_host=" + strings.Repeat("x", maxSurfaceHostFilterLen+1)},
		{name: "kind AND host", query: "&surface=ide&surface_host=vscode", wantIDs: []string{"s-ide"}},
		{name: "kind AND host disagree", query: "&surface=cli&surface_host=vscode", wantIDs: []string{}},
		{name: "composes with tool filter", query: "&surface=ide&tool=claude-code", wantIDs: []string{"s-ide"}},
		{name: "composes with a non-matching tool filter", query: "&surface=ide&tool=codex", wantIDs: []string{}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rows, _, total := fetchSurfaceList(t, s, tc.query)
			want := tc.wantIDs
			if want == nil {
				want = []string{"s-cli", "s-ide", "s-none"}
			}
			if total != len(want) {
				t.Errorf("total = %d, want %d (rows %+v)", total, len(want), rows)
			}
			got := make(map[string]bool, len(rows))
			for _, r := range rows {
				got[r.ID] = true
			}
			if len(got) != len(want) {
				t.Errorf("rows = %v, want %v", got, want)
			}
			for _, id := range want {
				if !got[id] {
					t.Errorf("missing %s in %v", id, got)
				}
			}
		})
	}
}
