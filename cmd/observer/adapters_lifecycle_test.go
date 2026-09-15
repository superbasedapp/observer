package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// TestLifecycleCell pins the matrix cell rendering: the zero value reads
// "active" (never an empty cell), and both non-active statuses are SHOUTED so
// a sunset or dead product cannot be skimmed past. An out-of-vocabulary value
// falls back to "active" — the honest default the zero value already means;
// TestLifecycleVocabularyClosed is what stops such a value existing.
func TestLifecycleCell(t *testing.T) {
	for _, tc := range []struct {
		l    integration.Lifecycle
		want string
	}{
		{integration.LifecycleActive, "active"},
		{integration.LifecycleDeprecated, "DEPRECATED"},
		{integration.LifecycleDead, "DEAD"},
	} {
		if got := lifecycleCell(tc.l); got != tc.want {
			t.Errorf("lifecycleCell(%q) = %q, want %q", string(tc.l), got, tc.want)
		}
	}
}

// TestRenderAdapterMatrixCarriesLifecycleColumn pins that `observer adapters`
// renders a LIFECYCLE column with one cell per row and that the legend
// explains it — the matrix is the generated support grid, so a lifecycle that
// is data in the registry but invisible in the render would leave operators
// reading a dead product as a live one.
func TestRenderAdapterMatrixCarriesLifecycleColumn(t *testing.T) {
	caps := []integration.Capability{
		{Tool: "alive"},
		{Tool: "sunset", Lifecycle: integration.LifecycleDeprecated},
		{Tool: "gone", Lifecycle: integration.LifecycleDead},
	}
	var buf bytes.Buffer
	renderAdapterMatrix(&buf, caps, nil)
	out := buf.String()

	if !strings.Contains(out, "LIFECYCLE") {
		t.Error("matrix header has no LIFECYCLE column")
	}
	for _, want := range []string{"active", "DEPRECATED", "DEAD"} {
		if !strings.Contains(out, want) {
			t.Errorf("matrix output does not carry the %q cell:\n%s", want, out)
		}
	}
	if !strings.Contains(out, "harness") {
		t.Error("matrix legend does not explain the LIFECYCLE column")
	}
	// Capture is never gated on lifecycle: a dead row still renders.
	if !strings.Contains(out, "gone") {
		t.Error("a dead row is missing from the matrix — rows are never hidden, only un-advertised")
	}
}

// TestRenderProductLifecycles pins the trailing block: rowless products are
// rendered with their id, status, servicing adapter and the grounded note
// VERBATIM (wrapped, never truncated), an adapterless product reads as a dash
// rather than an empty column, and an EMPTY table prints nothing at all — an
// empty section header would be noise, not honesty.
func TestRenderProductLifecycles(t *testing.T) {
	t.Run("empty table renders nothing", func(t *testing.T) {
		var buf bytes.Buffer
		renderProductLifecycles(&buf, nil)
		if buf.Len() != 0 {
			t.Errorf("empty product table rendered %q, want nothing", buf.String())
		}
	})

	t.Run("rows render id/status/serviced-by/note", func(t *testing.T) {
		var buf bytes.Buffer
		renderProductLifecycles(&buf, []integration.ProductLifecycle{
			{ID: "retagged", Adapter: "cline", Lifecycle: integration.LifecycleDead, Note: "shut down 2026-04-21; https://example.invalid/announcement"},
			{ID: "orphan", Lifecycle: integration.LifecycleDeprecated, Note: "renamed 2026-06-02; https://example.invalid/rename"},
		})
		out := buf.String()
		for _, want := range []string{
			"product lifecycle",
			"ID", "STATUS", "SERVICED-BY", "NOTE",
			"retagged", "DEAD", "cline", "shut down 2026-04-21",
			"orphan", "DEPRECATED", "—", "renamed 2026-06-02",
		} {
			if !strings.Contains(out, want) {
				t.Errorf("product lifecycle block is missing %q:\n%s", want, out)
			}
		}
	})

	t.Run("the shipped table renders", func(t *testing.T) {
		var buf bytes.Buffer
		renderProductLifecycles(&buf, integration.ProductLifecycles())
		out := buf.String()
		for _, want := range []string{"roo-code", "windsurf", "open-interpreter-python"} {
			if !strings.Contains(out, want) {
				t.Errorf("shipped product lifecycle block is missing %q:\n%s", want, out)
			}
		}
	})
}

// TestWrapNote pins the note wrapper: it breaks on spaces only, never mid
// token — a truncated or split vendor URL would make the grounded evidence
// unusable, which is the whole point of carrying it.
func TestWrapNote(t *testing.T) {
	for _, tc := range []struct {
		name  string
		in    string
		width int
		want  []string
	}{
		{"empty note yields one empty line", "", 10, []string{""}},
		{"whitespace only", "   \n\t ", 10, []string{""}},
		{"short note is one line", "a b c", 10, []string{"a b c"}},
		{"wraps on spaces", "aaa bbb ccc ddd", 7, []string{"aaa bbb", "ccc ddd"}},
		{
			"a token longer than width is emitted whole",
			"see https://example.invalid/a/very/long/path now",
			10,
			[]string{"see", "https://example.invalid/a/very/long/path", "now"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := wrapNote(tc.in, tc.width)
			if len(got) != len(tc.want) {
				t.Fatalf("wrapNote(%q, %d) = %q, want %q", tc.in, tc.width, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("wrapNote line %d = %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}
