package opencode

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// TestIsSessionFile_ReleaseChannels pins T-926: upstream names the store
// opencode-<channel>.db for any channel other than latest, dev, beta,
// next and prod (anomalyco/opencode packages/cli/src/database-path.ts),
// so those files and their WAL are watched too; look-alikes and the
// names a default channel never writes are not.
func TestIsSessionFile_ReleaseChannels(t *testing.T) {
	root := t.TempDir()
	a := NewWithOptions(nil, []string{root})
	tests := []struct {
		name string
		want bool
	}{
		{"opencode.db", true},
		{"opencode.db-wal", true},
		{"opencode.db-shm", false},
		{"opencode-stable.db", true},
		{"opencode-local.db", true},
		{"OpenCode-Stable.db-wal", true},
		{"opencode-feat_x-1.2.db", true},
		{"opencode-stable.db-shm", false},
		// The default channels write plain opencode.db, never these.
		{"opencode-dev.db", false},
		{"opencode-Latest.db", false},
		{"opencode-prod.db-wal", false},
		{"opencode-.db", false},
		{"opencode.db.bak", false},
		{"opencode-stable.db.bak", false},
		{"my-opencode-stable.db", false},
		{"opencode stable.db", false},
		{"kilo.db", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := a.IsSessionFile(filepath.Join(root, tt.name)); got != tt.want {
				t.Errorf("IsSessionFile(%s) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
	if a.IsSessionFile(filepath.Join(t.TempDir(), "opencode-stable.db")) {
		t.Error("a channel store outside the watch roots was claimed")
	}
}

func TestResolveDBPath_ReleaseChannels(t *testing.T) {
	dir := filepath.Join("x", "opencode")
	tests := map[string]string{
		"opencode.db-wal":        "opencode.db",
		"opencode.db-shm":        "opencode.db",
		"opencode-stable.db-wal": "opencode-stable.db",
		"opencode-local.db-shm":  "opencode-local.db",
		"opencode-stable.db":     "opencode-stable.db",
		"other.db-wal":           "other.db-wal",
	}
	for in, want := range tests {
		if got := resolveDBPath(filepath.Join(dir, in)); got != filepath.Join(dir, want) {
			t.Errorf("resolveDBPath(%s) = %s, want %s", in, got, want)
		}
	}
}

// TestParseSessionFile_ChannelStore: a store written by a non-default
// channel parses exactly like opencode.db, its rows sourced to its own
// file, and the transcript reader resolves it from the session's hint.
func TestParseSessionFile_ChannelStore(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "opencode-stable.db")
	createDB(t, path, v2DDL, v2Rows)

	a := NewWithOptions(nil, []string{root})
	res, err := a.ParseSessionFile(context.Background(), resolveDBPath(path+"-wal"), 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.ToolEvents) == 0 || len(res.TokenEvents) == 0 {
		t.Fatalf("channel store yielded %d tool / %d token events", len(res.ToolEvents), len(res.TokenEvents))
	}
	for _, ev := range res.ToolEvents {
		if ev.SourceFile != path {
			t.Fatalf("SourceFile = %q, want %q", ev.SourceFile, path)
		}
	}
	msgs, err := a.ReadTranscript(context.Background(), models.Session{ID: "ses_root"}, []string{path})
	if err != nil || len(msgs) == 0 {
		t.Fatalf("ReadTranscript from a channel store: %d messages, err=%v", len(msgs), err)
	}
}

// TestStateDBPath_PrefersDefaultStore: with no usable hint, opencode.db
// wins over a channel store; a root holding only a channel store
// resolves to it.
func TestStateDBPath_PrefersDefaultStore(t *testing.T) {
	root := t.TempDir()
	for _, n := range []string{"opencode-stable.db", "opencode.db", "opencode-local.db", "notes.db"} {
		if err := os.WriteFile(filepath.Join(root, n), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	a := NewWithOptions(nil, []string{root})
	got, err := a.stateDBPath(nil)
	if err != nil || got != filepath.Join(root, "opencode.db") {
		t.Errorf("stateDBPath = %q, %v; want opencode.db", got, err)
	}
	only := t.TempDir()
	if err := os.WriteFile(filepath.Join(only, "opencode-stable.db"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	b := NewWithOptions(nil, []string{only})
	if got, err := b.stateDBPath(nil); err != nil || got != filepath.Join(only, "opencode-stable.db") {
		t.Errorf("stateDBPath = %q, %v; want the channel store", got, err)
	}
	if got := channelStoresIn(root); len(got) != 3 || filepath.Base(got[1]) != "opencode-local.db" {
		t.Errorf("channelStoresIn = %v", got)
	}
}
