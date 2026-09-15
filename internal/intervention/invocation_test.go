package intervention

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// dedicatedInvocationSpec returns the composed registry declaration for one
// dedicated-process surface, so these cases exercise the shipped rows rather
// than a hand-written copy of them.
func dedicatedInvocationSpec(t *testing.T, tool string) integration.InvocationSpec {
	t.Helper()
	surfaces, ok := integration.InterventionFor(tool)
	if !ok {
		t.Fatalf("intervention surfaces for %q missing", tool)
	}
	for _, surface := range surfaces {
		if surface.Class == integration.SurfaceDedicatedProcess {
			return surface.Binding.Invocation
		}
	}
	t.Fatalf("tool %q has no dedicated process surface", tool)
	return integration.InvocationSpec{}
}

func TestClassifyInvocationGovernsUndeclaredArgumentsByDefault(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		tool    string
		leading string
		present bool
		want    InvocationClass
	}{
		// A dedicated surface with no per-product verbs: the ordinary CLI
		// shapes that previously escaped governance entirely.
		{name: "bare launch", tool: "claude-code", want: InvocationCLI},
		{name: "resume flag", tool: "claude-code", leading: "--resume", present: true, want: InvocationCLI},
		{name: "run subcommand", tool: "opencode", leading: "run", present: true, want: InvocationCLI},
		{name: "prompt flag", tool: "gemini-cli", leading: "-p", present: true, want: InvocationCLI},
		{name: "bare prompt", tool: "gemini-cli", leading: "fix the bug", present: true, want: InvocationCLI},
		{name: "future subcommand", tool: "goose", leading: "future-mode", present: true, want: InvocationCLI},
		{name: "empty argument", tool: "goose", leading: "", present: true, want: InvocationCLI},

		// The universal non-billable set every dedicated surface inherits.
		{name: "serve", tool: "opencode", leading: "serve", present: true, want: InvocationNonCLI},
		{name: "mcp", tool: "claude-code", leading: "mcp", present: true, want: InvocationNonCLI},
		{name: "acp", tool: "goose", leading: "acp", present: true, want: InvocationNonCLI},
		{name: "login", tool: "opencode", leading: "login", present: true, want: InvocationNonCLI},
		{name: "doctor", tool: "claude-code", leading: "doctor", present: true, want: InvocationNonCLI},
		{name: "update", tool: "gemini-cli", leading: "update", present: true, want: InvocationNonCLI},
		{name: "version flag", tool: "claude-code", leading: "--version", present: true, want: InvocationNonCLI},
		{name: "help flag", tool: "opencode", leading: "--help", present: true, want: InvocationNonCLI},
		{name: "short help flag", tool: "opencode", leading: "-h", present: true, want: InvocationNonCLI},

		// Grounded per-product rows keep their declared behaviour.
		{name: "codex exec", tool: "codex", leading: "exec", present: true, want: InvocationCLI},
		{name: "codex resume", tool: "codex", leading: "resume", present: true, want: InvocationCLI},
		{name: "codex model flag", tool: "codex", leading: "--model", present: true, want: InvocationCLI},
		{name: "codex app server", tool: "codex", leading: "app-server", present: true, want: InvocationNonCLI},
		{name: "codex mcp server", tool: "codex", leading: "mcp-server", present: true, want: InvocationNonCLI},
		{name: "muse exec", tool: "muse", leading: "exec", present: true, want: InvocationCLI},
		{name: "muse resume", tool: "muse", leading: "resume", present: true, want: InvocationCLI},
		{name: "muse session message", tool: "muse", leading: "session-message", present: true, want: InvocationCLI},
		{name: "muse sandbox", tool: "muse", leading: "sandbox", present: true, want: InvocationCLI},
		{name: "muse prompt", tool: "muse", leading: "fix the bug", present: true, want: InvocationCLI},
		{name: "muse export", tool: "muse", leading: "export", present: true, want: InvocationNonCLI},
		{name: "muse version flag", tool: "muse", leading: "-V", present: true, want: InvocationNonCLI},
		{name: "cursor status", tool: "cursor", leading: "status", present: true, want: InvocationNonCLI},
		{name: "cursor agent", tool: "cursor", leading: "agent", present: true, want: InvocationCLI},
		{name: "zcode app server", tool: "zcode", leading: "app-server", present: true, want: InvocationNonCLI},
		{name: "zcode run", tool: "zcode", leading: "run", present: true, want: InvocationCLI},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			spec := dedicatedInvocationSpec(t, tc.tool)
			if got := ClassifyInvocation(spec, tc.leading, tc.present); got != tc.want {
				t.Fatalf("ClassifyInvocation(%s, %q, present=%v) = %q, want %q", tc.tool, tc.leading, tc.present, got, tc.want)
			}
		})
	}
}

func TestClassifyInvocationAbstainsOnlyForDeclaredAmbiguity(t *testing.T) {
	t.Parallel()

	ambiguous := integration.InvocationSpec{
		AllowNoArguments:       true,
		CLILeadingArguments:    []string{"run"},
		NonCLILeadingArguments: []string{"serve"},
		RequireDeclaredCLI:     true,
	}
	contradictory := integration.InvocationSpec{
		AllowNoArguments:       true,
		CLILeadingArguments:    []string{"run"},
		NonCLILeadingArguments: []string{"run"},
	}
	cases := []struct {
		name    string
		spec    integration.InvocationSpec
		leading string
		present bool
		want    InvocationClass
	}{
		{name: "declared-cli surface bare", spec: ambiguous, want: InvocationCLI},
		{name: "declared-cli surface known cli", spec: ambiguous, leading: "run", present: true, want: InvocationCLI},
		{name: "declared-cli surface known service", spec: ambiguous, leading: "serve", present: true, want: InvocationNonCLI},
		{name: "declared-cli surface unknown flag", spec: ambiguous, leading: "--future", present: true, want: InvocationUnclassified},
		{name: "contradictory declaration", spec: contradictory, leading: "run", present: true, want: InvocationUnclassified},
		{
			name: "no argument form declared",
			spec: integration.InvocationSpec{CLILeadingArguments: []string{"run"}, RequireDeclaredCLI: true},
			want: InvocationUnclassified,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := ClassifyInvocation(tc.spec, tc.leading, tc.present); got != tc.want {
				t.Fatalf("ClassifyInvocation(%q, present=%v) = %q, want %q", tc.leading, tc.present, got, tc.want)
			}
		})
	}
}

func TestInvocationSpecAllowsCLI(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		spec integration.InvocationSpec
		want bool
	}{
		{name: "inverted default", spec: integration.InvocationSpec{AllowNoArguments: true}, want: true},
		{name: "inverted without bare form", spec: integration.InvocationSpec{}, want: true},
		{
			name: "declared-cli surface with a cli verb",
			spec: integration.InvocationSpec{RequireDeclaredCLI: true, CLILeadingArguments: []string{"run"}},
			want: true,
		},
		{
			name: "declared-cli surface with no cli form",
			spec: integration.InvocationSpec{RequireDeclaredCLI: true, NonCLILeadingArguments: []string{"serve"}},
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.spec.AllowsCLI(); got != tc.want {
				t.Fatalf("AllowsCLI() = %v, want %v", got, tc.want)
			}
		})
	}
}
