package diag

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/proxyroute"
	"github.com/marmutapp/superbased-observer/internal/routeprov"
)

// TestCheckRecordedRoutes is FU-77: a Cline route Observer wrote and
// recorded that a later globalState.json rewrite dropped or changed is a
// WARN naming the route command; a route still in place, or one whose state
// file is gone, is OK; no record is no row. The configured value is never
// printed.
func TestCheckRecordedRoutes(t *testing.T) {
	const foreign = "https://gateway.corp.example/v1"
	state := func(members string) string {
		return "{\n  \"welcomeViewCompleted\": true" + members + ",\n  \"mode\": \"act\"\n}"
	}
	routed := state(",\n  \"actModeApiProvider\": \"openai\"")
	cases := []struct {
		name string
		// noRoute skips the route write (no provenance record).
		noRoute bool
		// after rewrites globalState.json once the route was written;
		// absent removes it; "" leaves the writer's file in place.
		after    string
		absent   bool
		rows     int
		status   Status
		contains []string
		lacks    []string
	}{
		{name: "no record", noRoute: true, rows: 0},
		{name: "recorded and present", rows: 1, status: StatusOK, contains: []string{"still in"}},
		{
			name: "recorded, then dropped by a state rewrite", after: routed, rows: 1, status: StatusWarn,
			contains: []string{"openAiBaseUrl", "is gone from", "observer init --cline --skip-hooks --skip-mcp", "writes its whole settings file back", "ignore this"},
		},
		{
			name: "recorded, then changed to a foreign value", after: state(",\n  \"actModeApiProvider\": \"openai\",\n  \"openAiBaseUrl\": \"" + foreign + "\""),
			rows: 1, status: StatusWarn,
			contains: []string{"now holds another value", "Settings > Connected tools"},
			lacks:    []string{foreign, "gateway.corp"},
		},
		{name: "state file absent", absent: true, rows: 1, status: StatusOK, contains: []string{"is gone", "no route to check"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("CLINE_DIR", "")
			t.Setenv("CLINE_DATA_DIR", "")
			home := t.TempDir()
			path := filepath.Join(home, ".cline", "data", "globalState.json")
			writeState := func(body string) {
				t.Helper()
				if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			writeState(routed)
			if !tc.noRoute {
				reg, err := proxyroute.NewRegistrar(proxyroute.RegisterOptions{ProxyPort: 8820, HomeDir: home, Writer: routeprov.WriterInit})
				if err != nil {
					t.Fatal(err)
				}
				if res := reg.RegisterCline(); !res.Added || res.Error != nil || res.ProvenanceError != nil {
					t.Fatalf("route write = %+v", res)
				}
			}
			switch {
			case tc.absent:
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			case tc.after != "":
				writeState(tc.after)
			}
			checks := checkRecordedRoutes(home)
			if len(checks) != tc.rows {
				t.Fatalf("got %d rows, want %d: %+v", len(checks), tc.rows, checks)
			}
			if tc.rows == 0 {
				return
			}
			c := checks[0]
			if c.Name != "cline.proxy.route_recorded" {
				t.Errorf("name = %q", c.Name)
			}
			if c.Status != tc.status {
				t.Errorf("status %s, want %s: %q", c.Status, tc.status, c.Message)
			}
			text := c.Message + "\n" + strings.Join(c.Details, "\n")
			for _, want := range tc.contains {
				if !strings.Contains(text, want) {
					t.Errorf("%q lacks %q", text, want)
				}
			}
			for _, bad := range tc.lacks {
				if strings.Contains(text, bad) {
					t.Errorf("%q quotes %q", text, bad)
				}
			}
			if got := (Report{Checks: checks}).Filter("cline"); len(got.Checks) != 1 {
				t.Errorf("`observer doctor cline` does not keep the row")
			}
		})
	}
}

// TestCheckRecordedRoutesUnreadableProvenance: a damaged provenance file is
// one WARN row, not a crash and not silence.
func TestCheckRecordedRoutesUnreadableProvenance(t *testing.T) {
	home := t.TempDir()
	p := filepath.Join(home, ".observer", proxyroute.ProvenanceFileName)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	checks := checkRecordedRoutes(home)
	if len(checks) != 1 || checks[0].Name != "proxy.route_recorded" || checks[0].Status != StatusWarn {
		t.Fatalf("got %+v, want one proxy.route_recorded WARN", checks)
	}
}
