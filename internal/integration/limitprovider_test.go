package integration

import (
	"sort"
	"testing"
)

// TestLimitProviderCoverage pins the LimitProvider column: every row holds
// the zero value or a known family, exactly the OpenAI-family rows key their
// limit observations as openai, and every other registered tool, like a
// tool with no row, resolves to anthropic. It is the mapping
// sessiongauge.ProviderForTool used to switch on by tool name.
func TestLimitProviderCoverage(t *testing.T) {
	known := map[string]bool{"": true, LimitProviderAnthropic: true, LimitProviderOpenAI: true}
	var openai []string
	for _, tool := range Tools() {
		c, _ := For(tool)
		if !known[c.LimitProvider] {
			t.Errorf("%s: LimitProvider %q is not in the vocabulary", tool, c.LimitProvider)
		}
		switch got := LimitProviderFor(tool); got {
		case LimitProviderOpenAI:
			openai = append(openai, tool)
		case LimitProviderAnthropic:
		default:
			t.Errorf("LimitProviderFor(%s) = %q, want a known family", tool, got)
		}
	}
	sort.Strings(openai)
	want := []string{"codex", "copilot", "copilot-cli"}
	if len(openai) != len(want) {
		t.Fatalf("openai-keyed tools = %v, want %v", openai, want)
	}
	for i := range want {
		if openai[i] != want[i] {
			t.Fatalf("openai-keyed tools = %v, want %v", openai, want)
		}
	}
	if got := LimitProviderFor("no-such-tool"); got != LimitProviderAnthropic {
		t.Errorf("LimitProviderFor(unregistered) = %q, want %q", got, LimitProviderAnthropic)
	}
}
