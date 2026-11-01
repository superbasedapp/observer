package mcpregister

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/mcp/locate"
)

// TestRemovalKeepsAUsersPreexistingFile pins D-MU9 (live macOS install
// 2026-10-29): Cline's settings file existed as `{"mcpServers": {}}`
// (22 bytes) before init; removing Observer's entry deleted it. A removal
// writes back the user's file byte for byte instead.
func TestRemovalKeepsAUsersPreexistingFile(t *testing.T) {
	r, home := newProvenanceRegistrar(t)
	loc, ok := locate.ForClientEnv("cline", home, nil)
	if !ok {
		t.Fatal("no cline location")
	}
	before := []byte("{\n  \"mcpServers\": {}\n}")
	if len(before) != 22 {
		t.Fatalf("fixture is %d bytes, want the report's 22", len(before))
	}
	mustMkdir(t, filepath.Dir(loc.Path))
	if err := os.WriteFile(loc.Path, before, 0o600); err != nil {
		t.Fatal(err)
	}
	if res := r.Register("cline"); res.Error != nil || !res.Added {
		t.Fatalf("Register = %+v", res)
	}
	if res := r.Unregister("cline"); res.Error != nil || !res.Removed {
		t.Fatalf("Unregister = %+v", res)
	}
	after, err := os.ReadFile(loc.Path)
	if err != nil {
		t.Fatalf("the user's file was deleted: %v", err)
	}
	if !bytes.Equal(after, before) {
		t.Errorf("after removal = %q, want the original %q", after, before)
	}
}

// TestRemovalDeletesOnlyAFileObserverCreated pins the other half: a file
// Observer created (no file before Register) is deleted by the removal, for
// the JSON clients and for codex's TOML.
func TestRemovalDeletesOnlyAFileObserverCreated(t *testing.T) {
	for _, tool := range []string{"cline", "cursor", "codex"} {
		t.Run(tool, func(t *testing.T) {
			r, home := newProvenanceRegistrar(t)
			loc, ok := locate.ForClientEnv(tool, home, nil)
			if !ok {
				t.Fatal("no location")
			}
			mustMkdir(t, filepath.Dir(loc.Path))
			if res := r.Register(tool); res.Error != nil || !res.Added {
				t.Fatalf("Register = %+v", res)
			}
			if res := r.Unregister(tool); res.Error != nil || !res.Removed {
				t.Fatalf("Unregister = %+v", res)
			}
			if _, err := os.Stat(loc.Path); !os.IsNotExist(err) {
				body, _ := os.ReadFile(loc.Path)
				t.Errorf("Observer's own file left behind: %q", body)
			}
		})
	}
}

// TestCodexRemovalKeepsAUsersEmptyConfig: a user's own (empty) config.toml
// stays after Observer's table is cut from it.
func TestCodexRemovalKeepsAUsersEmptyConfig(t *testing.T) {
	r, home := newProvenanceRegistrar(t)
	loc, ok := locate.ForClientEnv("codex", home, nil)
	if !ok {
		t.Fatal("no codex location")
	}
	mustMkdir(t, filepath.Dir(loc.Path))
	if err := os.WriteFile(loc.Path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if res := r.Register("codex"); res.Error != nil || !res.Added {
		t.Fatalf("Register = %+v", res)
	}
	if res := r.Unregister("codex"); res.Error != nil || !res.Removed {
		t.Fatalf("Unregister = %+v", res)
	}
	after, err := os.ReadFile(loc.Path)
	if err != nil {
		t.Fatalf("the user's config.toml was deleted: %v", err)
	}
	if len(bytes.TrimSpace(after)) != 0 {
		t.Errorf("after removal = %q, want empty", after)
	}
}

// newProvenanceRegistrar is newRegistrar with a provenance record outside the
// home (the record is Observer's own state, never a file in the client's
// tree).
func newProvenanceRegistrar(t *testing.T) (*Registrar, string) {
	t.Helper()
	home := t.TempDir()
	r, err := NewRegistrar(RegisterOptions{
		BinaryPath:     "/usr/local/bin/observer",
		HomeDir:        home,
		ProvenancePath: filepath.Join(t.TempDir(), ProvenanceFileName),
	})
	if err != nil {
		t.Fatalf("NewRegistrar: %v", err)
	}
	return r, home
}

// TestRemovalShapeTable pins the removal decision table row by row.
func TestRemovalShapeTable(t *testing.T) {
	cases := []struct {
		name  string
		p     fileProvenance
		known bool
		want  removalShape
	}{
		{"recorded created", fileProvenance{Created: true}, true, shapeDeleteFileWhenEmpty},
		{"recorded key added", fileProvenance{KeyAdded: true}, true, shapeDropObject},
		{"recorded user object", fileProvenance{}, true, shapeKeepEmptyObject},
		// MACUSER merge M2: no record never deletes, whatever the layout.
		{"no record", fileProvenance{}, false, shapeKeepEmptyObject},
	}
	for _, tc := range cases {
		if got := removalShapeFor(tc.p, tc.known); got != tc.want {
			t.Errorf("%s: shape = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestRemovalDropsAnObjectObserverAddedToAUsersFile: a user's file without
// a server object gets Observer's object; the removal takes the object away
// again and keeps the user's other keys.
func TestRemovalDropsAnObjectObserverAddedToAUsersFile(t *testing.T) {
	r, home := newProvenanceRegistrar(t)
	loc, _ := locate.ForClientEnv("cursor", home, nil)
	mustMkdir(t, filepath.Dir(loc.Path))
	before := []byte("{\"theme\": \"dark\"}")
	if err := os.WriteFile(loc.Path, before, 0o600); err != nil {
		t.Fatal(err)
	}
	if res := r.Register("cursor"); res.Error != nil || !res.Added {
		t.Fatalf("Register = %+v", res)
	}
	if res := r.Unregister("cursor"); res.Error != nil || !res.Removed {
		t.Fatalf("Unregister = %+v", res)
	}
	after, err := os.ReadFile(loc.Path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bytes.TrimSpace(after), before) {
		t.Errorf("after = %q, want %q", after, before)
	}
}

// TestRemovalWithoutARecordKeepsTheFile pins MACUSER merge M2, the Mac's
// state exactly: an older build (no provenance records) wrote Observer's
// entry into the user's own cline file, then this build tears it out with
// provenance on but no record for the file. The file survives with the
// user's shape (the 22-byte indented file comes back byte for byte), for
// each layout an older build could have spliced into.
func TestRemovalWithoutARecordKeepsTheFile(t *testing.T) {
	for name, tc := range map[string]struct {
		before    string
		wantBytes bool
	}{
		"indented22": {"{\n  \"mcpServers\": {}\n}", true},
		"compact":    {"{\"mcpServers\":{}}", false},
		"withother":  {"{\n  \"mcpServers\": {},\n  \"x\": 1\n}", false},
	} {
		t.Run(name, func(t *testing.T) {
			home := t.TempDir()
			old, err := NewRegistrar(RegisterOptions{BinaryPath: "/usr/local/bin/observer", HomeDir: home})
			if err != nil {
				t.Fatal(err)
			}
			loc, ok := locate.ForClientEnv("cline", home, nil)
			if !ok {
				t.Fatal("no cline location")
			}
			mustMkdir(t, filepath.Dir(loc.Path))
			if err := os.WriteFile(loc.Path, []byte(tc.before), 0o600); err != nil {
				t.Fatal(err)
			}
			if res := old.Register("cline"); res.Error != nil || !res.Added {
				t.Fatalf("older-build Register = %+v", res)
			}
			r, err := NewRegistrar(RegisterOptions{BinaryPath: "/usr/local/bin/observer", HomeDir: home, ProvenancePath: filepath.Join(t.TempDir(), ProvenanceFileName)})
			if err != nil {
				t.Fatal(err)
			}
			if res := r.Unregister("cline"); res.Error != nil || !res.Removed {
				t.Fatalf("Unregister = %+v", res)
			}
			after, err := os.ReadFile(loc.Path)
			if err != nil {
				t.Fatalf("the user's file was deleted with no provenance record: %v", err)
			}
			if tc.wantBytes && !bytes.Equal(after, []byte(tc.before)) {
				t.Errorf("after = %q, want the original %q", after, tc.before)
			}
			var doc map[string]json.RawMessage
			if err := json.Unmarshal(after, &doc); err != nil {
				t.Fatalf("after = %q: %v", after, err)
			}
			if got := string(bytes.TrimSpace(doc["mcpServers"])); got != "{}" {
				t.Errorf("mcpServers = %q, want the user's empty object kept", got)
			}
			if strings.Contains(tc.before, "\"x\"") && string(doc["x"]) != "1" {
				t.Errorf("the user's other key was lost: %q", after)
			}
		})
	}
}
