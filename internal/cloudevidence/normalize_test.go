package cloudevidence

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
)

// TestNormalizeActionKindIsMembershipNotShape pins that an action's kind is
// checked for MEMBERSHIP, not for looking plausible. A well-shaped attacker
// value satisfies a shape check by construction, which is why the mix already
// used a table and the action list must use the same one (A2).
func TestNormalizeActionKindIsMembershipNotShape(t *testing.T) {
	cases := []struct{ in, want string }{
		{"run_command", "run_command"},
		{"  READ_FILE ", "read_file"},
		{"payroll.csv", LabelUnclassified},
		{"project-thunderclap", LabelUnclassified},
		{"customer_balance", LabelUnclassified},
		{"", LabelUnclassified},
		{strings.Repeat("a", 300), LabelUnclassified},
	}
	for _, tc := range cases {
		if got := NormalizeActionKind(tc.in); got != tc.want {
			t.Errorf("NormalizeActionKind(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestNormalizeCategoryIsClosed pins the same rule for categories, across all
// four derivations that feed the field: a file extension, a command class, an
// MCP family, and a fixed strategy label.
func TestNormalizeCategoryIsClosed(t *testing.T) {
	cases := []struct{ in, want string }{
		{"go", "go"},
		{"ts", "ts"},
		{"git", "git"},         // a command class
		{"browser", "browser"}, // an MCP family
		{"harness", "harness"}, // a fixed strategy label
		{"test", "test"},       // the outcome-shaped command classes
		{"build", "build"},
		{"shell", "shell"},
		{"acme-merger", LabelOther},
		{"acmemerger", LabelOther},
		{"payroll", LabelOther},
		{"thunderclap", LabelOther},
		{"", LabelOther},
	}
	for _, tc := range cases {
		if got := NormalizeCategory(tc.in); got != tc.want {
			t.Errorf("NormalizeCategory(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestDeriveCategoryUsesTheExtensionAllowList pins the path derivation. The old
// shape check ("short, unaccented alphanumerics") accepted a codename as
// readily as an extension, because there is no shape that separates them.
func TestDeriveCategoryUsesTheExtensionAllowList(t *testing.T) {
	cases := []struct{ path, want string }{
		{"internal/foo/bar.go", "go"},
		{"web/src/App.tsx", "tsx"},
		{"C:\\repo\\docs\\README.md", "md"},
		{"plan.acme-merger", LabelOther},
		{"notes.payroll", LabelOther},
		{"deck.thunderclap", LabelOther},
		{"Makefile", LabelOther},
		{"", LabelOther},
	}
	for _, tc := range cases {
		if got := deriveCategory(tc.path); got != tc.want {
			t.Errorf("deriveCategory(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}

// TestNormalizeModelFamilyIsClosed pins that the local model string is mapped
// onto the closed family vocabulary rather than copied. Every output must be a
// contract member, including for hostile input.
func TestNormalizeModelFamilyIsClosed(t *testing.T) {
	cases := []struct{ in, want string }{
		{"claude-sonnet-5", ModelFamilyClaude},
		{"anthropic/claude-opus-4-8", ModelFamilyClaude},
		{"us.anthropic.claude-3-5-sonnet-20241022-v2:0", ModelFamilyClaude},
		{"opus-4-8-fast", ModelFamilyClaude},
		{"gpt-5.6-terra", ModelFamilyGPT},
		{"openai/gpt-4o-2024-11-20", ModelFamilyGPT},
		{"o3-mini", ModelFamilyOSeries},
		{"gemini-2.5-pro", ModelFamilyGemini},
		{"gemma3:27b", ModelFamilyGemma},
		{"meta-llama/Llama-3.3-70B-Instruct", ModelFamilyLlama},
		{"qwen2.5-coder:32b", ModelFamilyQwen},
		{"mistralai/devstral-small", ModelFamilyMistral},
		{"deepseek-v3", ModelFamilyDeepSeek},
		{"grok-4-fast", ModelFamilyGrok},
		{"kimi-k2", ModelFamilyKimi},
		{"", ModelFamilyUnknown},
		{"   ", ModelFamilyUnknown},
		// The shapes the field actually leaked.
		{"acme-internal-llm-v3", ModelFamilyUnknown},
		{"project-thunderclap-v2", ModelFamilyUnknown},
		{"customer_balance=12345", ModelFamilyUnknown},
		{"/etc/passwd", ModelFamilyUnknown},
	}
	vocab := map[string]bool{}
	for _, f := range cloudcontract.ModelFamilyLabels() {
		vocab[f] = true
	}
	for _, tc := range cases {
		got := NormalizeModelFamily(tc.in)
		if got != tc.want {
			t.Errorf("NormalizeModelFamily(%q) = %q, want %q", tc.in, got, tc.want)
		}
		if !vocab[got] {
			t.Errorf("NormalizeModelFamily(%q) = %q, which is not a contract vocabulary member", tc.in, got)
		}
	}
}

// TestNormalizeModelFamilyNeverEchoesTheModelString is the privacy assertion in
// the form that survives cases nobody thought to enumerate: whatever goes in,
// what comes out is one of ours.
func TestNormalizeModelFamilyNeverEchoesTheModelString(t *testing.T) {
	vocab := map[string]bool{}
	for _, f := range cloudcontract.ModelFamilyLabels() {
		vocab[f] = true
	}
	hostile := []string{
		"acme-holdings-payroll",
		"../../etc/passwd",
		"C:\\models\\secret.gguf",
		strings.Repeat("z", 500),
		"claude\x00injected",
		"gpt-and-a-secret-sk-live-abcdef",
		"\u202eevil",
	}
	for _, in := range hostile {
		got := NormalizeModelFamily(in)
		if !vocab[got] {
			t.Fatalf("NormalizeModelFamily(%q) = %q, which is not a closed-vocabulary label", in, got)
		}
		if strings.Contains(in, got) && got != ModelFamilyUnknown && len(got) > 3 {
			// A label that happens to be a substring of the input is fine (it is
			// OUR constant), but it must never be the input itself.
			if got == in {
				t.Fatalf("NormalizeModelFamily(%q) echoed its input", in)
			}
		}
	}
}
