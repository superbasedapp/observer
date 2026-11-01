package clinecli

import (
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// TestBuildProcessSeeds covers the candidate-seed emission the SQLite
// path hands up to the store for direct process attribution. Validation
// (liveness + identity) happens in the store; here we only assert which
// rows become candidates.
func TestBuildProcessSeeds(t *testing.T) {
	orig := allHomesFunc
	t.Cleanup(func() { allHomesFunc = orig })
	allHomesFunc = func() []crossmount.HomeRoot {
		return []crossmount.HomeRoot{
			{Path: "/home/me", OS: crossmount.OSLinux, Origin: "native"},
			// Host-native spelling, as crossmount reports it and as the
			// foreign db path below is built.
			{Path: filepath.FromSlash("/mnt/c/Users/me"), OS: crossmount.OSWindows, Origin: "wsl-mnt:c"},
		}
	}

	ended := sql.NullString{String: "2026-07-15T00:00:00.000Z", Valid: true}
	sessions := []sessionRow{
		{ID: "open-1", PID: 4242, CWD: "/home/me/proj"},                  // open → seed
		{ID: "ended-1", PID: 5555, CWD: "/home/me/proj", EndedAt: ended}, // closed → skip
		{ID: "nopid", PID: 0, CWD: "/home/me/proj"},                      // no pid → skip
	}

	// Native db path → seeds emitted for the open session only.
	seeds := buildProcessSeeds(sessions, "/home/me/.cline/data/db/sessions.db")
	if len(seeds) != 1 {
		t.Fatalf("len(seeds) = %d; want 1 (open session only)", len(seeds))
	}
	got := seeds[0]
	want := models.SessionProcessSeed{PID: 4242, SessionID: "open-1", Tool: models.ToolClineCLI, CWD: "/home/me/proj", ExecHint: "cline"}
	if got != want {
		t.Errorf("seed = %+v; want %+v", got, want)
	}

	// Foreign-mount db path → no seeds (the pid is a Windows pid,
	// meaningless on the Linux daemon's /proc).
	foreign := filepath.FromSlash("/mnt/c/Users/me/.cline/data/db/sessions.db")
	if s := buildProcessSeeds(sessions, foreign); s != nil {
		t.Errorf("foreign-mount seeds = %+v; want nil", s)
	}
}
