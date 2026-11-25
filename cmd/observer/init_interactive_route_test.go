package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/clientwire"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/proxyroute"
)

// scriptedAnswers is the stdin of an interactive init run that answers each
// consent question by its TEXT rather than by its position: the interactive
// flow writes one question and then reads exactly one line, so each Read
// answers the last question written to out. Every question is recorded.
type scriptedAnswers struct {
	out       *strings.Builder
	answer    func(question string) string
	questions []string
}

// Read answers the most recent "[Y/n]" / "[y/N]" question in the output.
func (s *scriptedAnswers) Read(p []byte) (int, error) {
	text := s.out.String()
	q := text
	if i := strings.LastIndex(q, "\n"); i >= 0 {
		q = q[i+1:]
	}
	q = strings.TrimSpace(q)
	s.questions = append(s.questions, q)
	return copy(p, s.answer(q)+"\n"), nil
}

// TestRunInteractiveInit_QwenCodeNeverOffersCodexRoute pins CMD-02: the
// interactive (zero-flag TTY) init once ran its main route step for every
// routeSupported tool, so qwen-code and kimi-code - whose RouteConfigFile kind
// they share with codex, but whose routes their OWN probe writers apply - were
// offered the CODEX writer under their own name, default yes. A yes created
// ~/.codex/config.toml on a machine with no codex, and re-offered a codex route
// the user had just declined. Batch init never had this defect: both loops
// now share routeWriterFor.
func TestRunInteractiveInit_QwenCodeNeverOffersCodexRoute(t *testing.T) {
	requireComponents(t, "integration.hooks", "integration.mcp-server", "integration.proxy-route")
	cases := []struct {
		name  string
		tool  string   // the config-lane tool under test
		dirs  []string // vendor homes created under HOME
		codex bool     // codex is installed too; its own route is declined
	}{
		{name: "qwen-code without codex", tool: "qwen-code", dirs: []string{".qwen"}},
		{name: "kimi-code without codex", tool: "kimi-code", dirs: []string{".kimi-code"}},
		{name: "qwen-code beside a codex whose route was declined", tool: "qwen-code", dirs: []string{".qwen", ".codex"}, codex: true},
		{name: "kimi-code beside a codex whose route was declined", tool: "kimi-code", dirs: []string{".kimi-code", ".codex"}, codex: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			requireActiveAdapters(t, tc.tool)
			requireAdapter(t, tc.tool)
			if tc.codex {
				requireActiveAdapters(t, "codex")
				requireAdapter(t, "codex")
			}
			home := t.TempDir()
			for _, d := range tc.dirs {
				if err := os.MkdirAll(filepath.Join(home, d), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			codexConfig := filepath.Join(home, ".codex", "config.toml")
			var out strings.Builder
			in := &scriptedAnswers{out: &out, answer: func(q string) string {
				if strings.Contains(q, "route codex through the observer proxy") {
					return "n"
				}
				return "y"
			}}
			if err := runInteractiveInit(&out, in, interactiveInitOptions{
				BinaryPath: filepath.Join(home, "observer"),
				ProxyPort:  18820,
				HomeDir:    home,
			}); err != nil {
				t.Fatalf("runInteractiveInit: %v\noutput:\n%s", err, out.String())
			}
			text := out.String()
			if !strings.Contains(text, tc.tool) {
				t.Fatalf("%s was not detected, so the test proves nothing:\n%s", tc.tool, text)
			}
			if tc.codex && !containsQuestion(in.questions, "route codex through the observer proxy") {
				t.Fatalf("codex's own route was never offered, so the decline proves nothing:\n%s", text)
			}
			// No consent under the config-lane tool's heading may name
			// codex's file.
			section := toolSection(text, tc.tool)
			if strings.Contains(section, ".codex") {
				t.Errorf("%s's consents name codex's config file:\n%s", tc.tool, section)
			}
			raw, err := os.ReadFile(codexConfig)
			switch {
			case !tc.codex && err == nil:
				t.Errorf("codex is not installed but %s was created:\n%s", codexConfig, raw)
			case err == nil && strings.Contains(string(raw), "openai-observer"):
				t.Errorf("the codex route was declined (or codex is absent) but it was written:\n%s", raw)
			}
		})
	}
}

// containsQuestion reports whether any recorded question contains want.
func containsQuestion(questions []string, want string) bool {
	for _, q := range questions {
		if strings.Contains(q, want) {
			return true
		}
	}
	return false
}

// toolSection returns the text the interactive flow printed under tool's own
// heading line (a line that is exactly the tool name), up to the next blank
// line that starts another heading.
func toolSection(text, tool string) string {
	var b strings.Builder
	in := false
	for _, line := range strings.Split(text, "\n") {
		switch {
		case line == tool:
			in = true
		case in && line == "":
			in = false
		}
		if in {
			b.WriteString(line)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// TestRouteWriterFor_LabelsTheToolAsked pins the one dispatch both init loops
// share (CMD-02): for every registry row, and for its "<tool>-windows"
// cross-OS target, routeWriterFor either has no writer or returns one whose
// result is labelled with the tool asked for. A config-lane tool that shares
// codex's route KIND (qwen-code, kimi-code) must therefore get no writer from
// the main step, since its only writer there would be codex's.
func TestRouteWriterFor_LabelsTheToolAsked(t *testing.T) {
	home := t.TempDir()
	reg, err := proxyroute.NewRegistrar(proxyroute.RegisterOptions{ProxyPort: 18820, DryRun: true, HomeDir: home})
	if err != nil {
		t.Fatal(err)
	}
	served := map[string]bool{}
	for _, c := range integration.Capabilities() {
		for _, tool := range []string{c.Tool, c.Tool + clientwire.WindowsSuffix} {
			write, ok := routeWriterFor(reg, tool)
			if !ok {
				continue
			}
			served[tool] = true
			if got := write().Tool; got != tool {
				t.Errorf("routeWriterFor(%q) runs the writer labelled %q", tool, got)
			}
		}
	}
	// The table must still serve the verified routes, and only them.
	for _, tool := range []string{"codex", "claude-code", "codex-windows", "claude-code-windows"} {
		if !served[tool] {
			t.Errorf("routeWriterFor(%q) has no writer, want one", tool)
		}
	}
	for _, tool := range []string{"qwen-code", "kimi-code", "crush", "cline"} {
		if served[tool] {
			t.Errorf("routeWriterFor(%q) has a main-step writer; its own probe writer applies it", tool)
		}
	}
	if _, ok := routeWriterFor(nil, "codex"); ok {
		t.Error("routeWriterFor(nil registrar) returned a writer")
	}
	if entries, err := os.ReadDir(home); err != nil || len(entries) != 0 {
		t.Errorf("a dry-run dispatch wrote into HOME: %v (err=%v)", entries, err)
	}
}

// TestProbeRouteConsent_CallsOnlyUnverifiedRowsUnverified pins the copy half
// of CMD-02: the probe-route step's consent called every tool "NOT yet
// live-verified", including qwen-code, kimi-code and crush, whose registry
// rows carry a verified route (Proxy set). The copy now follows the row's
// shape: "unverified" exactly when Proxy is nil.
func TestProbeRouteConsent_CallsOnlyUnverifiedRowsUnverified(t *testing.T) {
	sawVerified, sawUnverified := false, false
	for _, tool := range probeRouteTools() {
		c, ok := integration.For(tool)
		if !ok {
			t.Fatalf("probe-route tool %q has no registry row", tool)
		}
		intro, question := probeRouteConsent(tool)
		text := strings.Join(intro, "\n") + "\n" + question
		unverified := c.Proxy == nil
		if unverified {
			sawUnverified = true
		} else {
			sawVerified = true
		}
		if got := strings.Contains(text, "NOT yet") || strings.Contains(text, "unverified"); got != unverified {
			t.Errorf("%s (Proxy set: %v): consent calls it unverified = %v:\n%s", tool, !unverified, got, text)
		}
		if !strings.Contains(question, "route "+tool+" ") {
			t.Errorf("%s: question %q does not name the tool", tool, question)
		}
	}
	if !sawVerified || !sawUnverified {
		t.Fatalf("the registry no longer has both probe-route shapes (verified %v, unverified %v); the test proves less than it says", sawVerified, sawUnverified)
	}
}

// TestRunInteractiveInit_VerifiedProbeRouteIsNotCalledUnverified runs the
// interactive flow end to end for qwen-code with a settings.json its own
// writer can route: the consent under its heading must not call the route an
// unverified probe, and a yes writes qwen-code's own file.
func TestRunInteractiveInit_VerifiedProbeRouteIsNotCalledUnverified(t *testing.T) {
	requireComponents(t, "integration.hooks", "integration.mcp-server", "integration.proxy-route")
	requireActiveAdapters(t, "qwen-code")
	requireAdapter(t, "qwen-code")
	home := t.TempDir()
	settings := filepath.Join(home, ".qwen", "settings.json")
	if err := os.MkdirAll(filepath.Dir(settings), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settings, []byte(`{"model":{"baseUrl":"https://api.openai.com/v1"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	in := &scriptedAnswers{out: &out, answer: func(string) string { return "y" }}
	if err := runInteractiveInit(&out, in, interactiveInitOptions{
		BinaryPath: filepath.Join(home, "observer"),
		ProxyPort:  18820,
		HomeDir:    home,
	}); err != nil {
		t.Fatalf("runInteractiveInit: %v\noutput:\n%s", err, out.String())
	}
	if !containsQuestion(in.questions, "route qwen-code through the observer proxy") {
		t.Fatalf("qwen-code's route was never offered, so the test proves nothing:\n%s", out.String())
	}
	if containsQuestion(in.questions, "route qwen-code through the observer proxy (unverified") {
		t.Errorf("qwen-code's verified route was offered as an unverified probe:\n%s", out.String())
	}
	if strings.Contains(out.String(), "NOT yet") {
		t.Errorf("the flow calls a verified route NOT yet live-verified:\n%s", out.String())
	}
	raw, err := os.ReadFile(settings)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "18820") {
		t.Errorf("a yes did not route qwen-code's own settings.json:\n%s", raw)
	}
}
