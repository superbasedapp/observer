package integration

import (
	"sort"
	"strings"
	"testing"
)

// TestStatusLinesAreRegistryRows pins the status-line column's table: every
// key is a registry tool, the row carries its column, every entry names its
// evidence, a grounded shape names its file, and an audited none says what
// was found instead.
func TestStatusLinesAreRegistryRows(t *testing.T) {
	for tool, s := range statusLines {
		c, ok := For(tool)
		if !ok {
			t.Errorf("statusLines[%q] has no registry row", tool)
			continue
		}
		if c.StatusLine != s {
			t.Errorf("%s: registry row does not carry its StatusLine column", tool)
		}
		if s.Grounding == "" {
			t.Errorf("%s: no grounding", tool)
		}
		switch s.Kind {
		case StatusLineNone:
			if s.Note == "" {
				t.Errorf("%s: audited none without a note", tool)
			}
			if s.File != "" || s.ClaudePayload || s.Writer || s.Exec != "" || s.PlanRateLimits || s.InitFlag != "" {
				t.Errorf("%s: a none row declares a file, payload, exec, writer or init flag", tool)
			}
		case StatusLineSettingsJSON, StatusLineVTCodeTOML:
			if s.File == "" {
				t.Errorf("%s: grounded shape %q without a file", tool, s.Kind)
			}
			if s.Exec != StatusLineExecShell && s.Exec != StatusLineExecScriptPath {
				t.Errorf("%s: grounded shape without a known exec shape (%q)", tool, s.Exec)
			}
		default:
			t.Errorf("%s: unknown status-line kind %q", tool, s.Kind)
		}
	}
}

// TestStatusLineWriterSet pins the tools Observer writes a status line for
// today. Adding a writer means adding its tool here in the same change.
func TestStatusLineWriterSet(t *testing.T) {
	var got []string
	for tool, s := range statusLines {
		if s.Writer {
			got = append(got, tool)
		}
	}
	sort.Strings(got)
	want := []string{"claude-code", "codebuddy", "kimchi", "vtcode"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("status-line writers = %v, want %v", got, want)
	}
	for tool, s := range statusLines {
		switch {
		case s.Writer && s.InitFlag != StatusLineInitClaude && s.InitFlag != StatusLineInitTools:
			t.Errorf("%s: a writer without a known init flag (%q)", tool, s.InitFlag)
		case !s.Writer && s.InitFlag != "":
			t.Errorf("%s: an init flag without a writer", tool)
		}
	}
	if got := StatusLineWriterTools(StatusLineInitTools); strings.Join(got, ",") != "codebuddy,kimchi,vtcode" {
		t.Errorf("StatusLineWriterTools(--statusline-tools) = %v", got)
	}
	if got := StatusLineWriterTools(StatusLineInitClaude); strings.Join(got, ",") != "claude-code" {
		t.Errorf("StatusLineWriterTools(--statusline) = %v", got)
	}
}

// TestStatusLinePlanRateLimitsClaudeOnly pins the plan-meter forward to the
// one host whose payload carries Claude Code's rate_limits: a look-alike
// payload must never be read as Claude's plan.
func TestStatusLinePlanRateLimitsClaudeOnly(t *testing.T) {
	for tool, s := range statusLines {
		if s.PlanRateLimits != (tool == "claude-code") {
			t.Errorf("%s: PlanRateLimits = %v", tool, s.PlanRateLimits)
		}
	}
	if !StatusLineFor("claude-code").PlanRateLimits || StatusLineFor("codebuddy").PlanRateLimits {
		t.Error("StatusLineFor does not carry PlanRateLimits")
	}
	if StatusLineFor("no-such-tool") != (StatusLineSpec{}) {
		t.Error("StatusLineFor(unknown) is not the zero value")
	}
}

// TestStatusLineToolsExcludesNone pins the accessor to grounded shapes only.
func TestStatusLineToolsExcludesNone(t *testing.T) {
	for _, tool := range StatusLineTools() {
		if statusLines[tool].Kind == StatusLineNone {
			t.Errorf("StatusLineTools() lists %s, which has no command", tool)
		}
	}
	if len(StatusLineTools()) == 0 {
		t.Error("StatusLineTools() is empty")
	}
}
