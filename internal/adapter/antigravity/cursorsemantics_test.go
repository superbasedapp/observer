package antigravity

import (
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/adapter"
)

// TestCursorSemanticsFor pins that the OSCrypt-encrypted `.pb`
// conversation stores (desktop AND the older CLI layout) declare
// themselves undecodable — zero actions there is the designed
// outcome, not a misroute — while the newer plaintext-protobuf SQLite
// `.db` store keeps ordinary byte-offset semantics.
func TestCursorSemanticsFor(t *testing.T) {
	home := t.TempDir()
	desktop := filepath.Join(home, ".gemini", "antigravity", "conversations")
	cli := filepath.Join(home, ".gemini", "antigravity-cli", "conversations")

	tests := []struct {
		name string
		a    *Adapter
		path string
		want adapter.CursorKind
	}{
		{"desktop .pb is encrypted", NewWithOptions(nil, desktop), filepath.Join(desktop, "a.pb"), adapter.CursorEncrypted},
		{"cli .pb is encrypted", cliAdapterRooted(cli), filepath.Join(cli, "b.pb"), adapter.CursorEncrypted},
		// WAL-mode SQLite: a turn lands in the -wal without growing the
		// main file, so the cursor is a max-mtime watermark (M5).
		{"cli .db is a watermark", cliAdapterRooted(cli), filepath.Join(cli, "c.db"), adapter.CursorWatermark},
		{"cli .db-wal is a watermark", cliAdapterRooted(cli), filepath.Join(cli, "c.db-wal"), adapter.CursorWatermark},
		{"desktop .db (VS Code extension) is a watermark", NewWithOptions(nil, desktop), filepath.Join(desktop, "d.db"), adapter.CursorWatermark},
		// Decoy: an unclaimed shape gets no declaration.
		{"unclaimed", NewWithOptions(nil, desktop), filepath.Join(desktop, "notes.txt"), adapter.CursorByteOffset},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.a.CursorSemanticsFor(tc.path)
			if got.Kind != tc.want {
				t.Errorf("Kind = %v, want %v (IsSessionFile=%v)", got.Kind, tc.want, tc.a.IsSessionFile(tc.path))
			}
		})
	}
}

// cliAdapterRooted builds the agy-CLI variant pointed at a test root
// (there is no exported CLI-with-roots constructor).
func cliAdapterRooted(root string) *Adapter {
	a := NewCLI()
	a.roots = []string{root}
	return a
}
