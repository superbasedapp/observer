package defaults

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/adapter/aiderdesk"
	"github.com/marmutapp/superbased-observer/internal/adapter/codex"
	"github.com/marmutapp/superbased-observer/internal/adapter/geminicodeassist"
	"github.com/marmutapp/superbased-observer/internal/adapter/windsurf"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// TestAdapterIDsOutsideTheCanonicalList pins the wire ids that
// TestAdaptersCanonicalOrder cannot see, in one table (D-612 folded the
// per-package name pins here). A tool id is persisted in every session row
// and shipped on the org wire, so renaming one needs a migration.
//   - windsurf, gemini-code-assist and aider-desk are not in the default
//     registered set, so the canonical list does not pin them.
//   - open-interpreter is a retag of the codex parser: its id must never
//     collapse to the base codex identity, whatever the build registers.
func TestAdapterIDsOutsideTheCanonicalList(t *testing.T) {
	cases := []struct {
		name    string
		got     string
		want    string
		notWant string
	}{
		{"windsurf adapter", windsurf.New().Name(), "windsurf", ""},
		{"windsurf ToolName", windsurf.ToolName, "windsurf", ""},
		{"gemini-code-assist adapter", geminicodeassist.New().Name(), "gemini-code-assist", ""},
		{"gemini-code-assist ToolName", geminicodeassist.ToolName, "gemini-code-assist", ""},
		{"aider-desk adapter", aiderdesk.New(nil).Name(), "aider-desk", ""},
		{"aider-desk ToolName", aiderdesk.ToolName, "aider-desk", ""},
		{"open-interpreter retag", codex.NewOpenInterpreter().Name(), models.ToolOpenInterpreter, models.ToolCodex},
		{"open-interpreter wire id", models.ToolOpenInterpreter, "open-interpreter", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.got != tc.want {
				t.Errorf("got %q, want %q", tc.got, tc.want)
			}
			if tc.notWant != "" && tc.got == tc.notWant {
				t.Errorf("got %q, must not collapse to %q", tc.got, tc.notWant)
			}
		})
	}
}
