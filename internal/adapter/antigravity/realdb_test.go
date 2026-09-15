package antigravity

import (
	"os"
	"sort"
	"testing"
)

// TestDumpRealVSCDB is a one-off probe against the user's real
// state.vscdb. Skipped unless ANTIGRAVITY_REAL_VSCDB env var points
// at a file. Used to verify nested-base64 parsing on live data.
func TestDumpRealVSCDB(t *testing.T) {
	path := os.Getenv("ANTIGRAVITY_REAL_VSCDB")
	if path == "" {
		t.Skip("set ANTIGRAVITY_REAL_VSCDB=/path/to/state.vscdb to run")
	}
	entries, err := readTrajectorySummaries(path)
	if err != nil {
		t.Fatalf("readTrajectorySummaries: %v", err)
	}
	withWS, withTitle, withCreated, withModel := 0, 0, 0, 0
	type row struct{ uuid, title, ws, created string }
	var rows []row
	for u, e := range entries {
		if e.workspaceURI != "" {
			withWS++
		}
		if e.title != "" {
			withTitle++
		}
		if !e.created.IsZero() {
			withCreated++
		}
		if e.modelHint != "" {
			withModel++
		}
		rows = append(rows, row{u, e.title, e.workspaceURI, e.created.Format("2006-01-02T15:04:05Z")})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].uuid < rows[j].uuid })
	t.Logf("entries=%d with_workspace=%d with_title=%d with_created=%d with_model=%d",
		len(entries), withWS, withTitle, withCreated, withModel)
	rootHisto := map[string]int{}
	for _, r := range rows {
		root, _, _ := decodeFileURIToRoot(r.ws)
		rootHisto[root]++
	}
	t.Logf("=== resolved project_roots histogram ===")
	for root, n := range rootHisto {
		t.Logf("  %3dx  %s", n, root)
	}
	t.Logf("=== first 6 entries (uri → resolved root) ===")
	for i, r := range rows {
		if i >= 6 {
			break
		}
		root, _, _ := decodeFileURIToRoot(r.ws)
		t.Logf("[%d] %s ws=%q -> %s  title=%q  created=%s",
			i, r.uuid, r.ws, root, r.title, r.created)
	}
	for _, r := range rows {
		if r.uuid == "fb48b020-3513-4298-8ea2-bbce3756bd31" {
			root, _, _ := decodeFileURIToRoot(r.ws)
			t.Logf("FB48 ws=%q -> %s  title=%q  created=%s",
				r.ws, root, r.title, r.created)
		}
	}
}
