package dashboard

import (
	"context"
	"testing"
)

// TestAPIStatusNavCounts pins the /api/status counts the sidebar's newer
// badges read: present on the wire, and counting the right thing. The test
// server holds one session whose only action is an hour old (newTestServer):
// active in the last 24 hours, not in the last 15 minutes.
func TestAPIStatusNavCounts(t *testing.T) {
	s, _ := newTestServer(t)
	if _, err := s.db().ExecContext(context.Background(),
		`INSERT INTO plan_accounts (id, provider, source, created_at, updated_at) VALUES ('a1', 'anthropic', 'official', 1, 1)`); err != nil {
		t.Fatal(err)
	}
	got := getStatus(t, s)
	counts, ok := got["counts"].(map[string]any)
	if !ok {
		t.Fatalf("missing counts map: %+v", got)
	}
	cases := []struct {
		key  string
		want float64
	}{
		{"live_sessions", 0},
		{"active_sessions_24h", 1},
		{"project_patterns", 0},
		{"plan_accounts", 1},
		{"benchmark_runs", 0},
		{"projects", 1},
	}
	for _, c := range cases {
		v, ok := counts[c.key].(float64)
		if !ok {
			t.Errorf("counts.%s missing or not a number: %v", c.key, counts[c.key])
			continue
		}
		if v != c.want {
			t.Errorf("counts.%s = %v, want %v", c.key, v, c.want)
		}
	}
}
