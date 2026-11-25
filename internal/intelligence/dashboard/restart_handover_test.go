package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/db"
)

// TestRestartReportsTheHandover (L-168 (ii)): the GET restart report says
// whether the daemon's restart hands its proxy socket over and the digest
// of the command it runs, which `observer service restart` reads; without
// the seam, or without a restart, the report is unchanged.
func TestRestartReportsTheHandover(t *testing.T) {
	for _, tc := range []struct {
		name     string
		restart  func() error
		handover func() (bool, string)
		want     map[string]any
	}{
		{
			"hands over", func() error { return nil }, func() (bool, string) { return true, "abc" },
			map[string]any{"listener_handover": true, "invocation_digest": "abc"},
		},
		{
			"no hand-over, no digest", func() error { return nil }, func() (bool, string) { return false, "" },
			map[string]any{"listener_handover": false},
		},
		{"no seam", func() error { return nil }, nil, map[string]any{}},
		{"no restart in this process", nil, func() (bool, string) { return true, "abc" }, map[string]any{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			database, err := openTestDB(context.Background(), db.Options{Path: filepath.Join(dir, "observer.db")})
			if err != nil {
				t.Fatalf("db.Open: %v", err)
			}
			t.Cleanup(func() { _ = database.Close() })
			s, err := New(Options{DB: database, ConfigPath: filepath.Join(dir, "config.toml"), RestartFunc: tc.restart, RestartHandover: tc.handover})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			rec := restartReq(t, s.Handler(), http.MethodGet, "")
			var m map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
				t.Fatalf("GET body: %v", err)
			}
			for _, k := range []string{"listener_handover", "invocation_digest"} {
				want, wantOK := tc.want[k]
				got, gotOK := m[k]
				if wantOK != gotOK || (wantOK && got != want) {
					t.Errorf("%s = %v (present %v), want %v (present %v): %s", k, got, gotOK, want, wantOK, rec.Body.String())
				}
			}
		})
	}
}
