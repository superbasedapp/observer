package diag

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/proxyroute"
)

// TestCheckRouteHold: no journal is no row; a journal with held routes is one
// warning naming the tools and the command that puts them back, never the
// route value; an unreadable journal says so.
func TestCheckRouteHold(t *testing.T) {
	home := t.TempDir()
	if got := checkRouteHold(home); len(got) != 0 {
		t.Fatalf("no journal: %+v", got)
	}
	path := filepath.Join(home, ".observer", proxyroute.RouteHoldFileName)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	body := `{"version":1,"port":8820,"routes":[{"tool":"claude-code","config_path":"/h/.claude/settings.json","value":"http://127.0.0.1:8820/t/secret","held_at":"2026-11-23T10:00:00Z"}]}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	got := checkRouteHold(home)
	if len(got) != 1 || got[0].Status != StatusWarn || !strings.Contains(got[0].Message, "claude-code") ||
		!strings.Contains(got[0].Message, "observer service start") {
		t.Fatalf("held: %+v", got)
	}
	// Finding 4: `observer service start` alone fails with no service
	// manager, so the advice names what works everywhere: the daemon puts
	// the routes back itself once its proxy on that port serves.
	if !strings.Contains(got[0].Message, "puts them back itself once its proxy on :8820 serves") ||
		!strings.Contains(got[0].Message, "`observer start`") {
		t.Fatalf("held advice: %s", got[0].Message)
	}
	if strings.Contains(got[0].Message+strings.Join(got[0].Details, " "), "secret") {
		t.Fatal("the route value was printed")
	}
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := checkRouteHold(home); len(got) != 1 || !strings.Contains(got[0].Message, "could not be read") {
		t.Fatalf("unreadable: %+v", got)
	}
}
