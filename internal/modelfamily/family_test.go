package modelfamily

import "testing"

func TestStripRouterPrefix(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ in, want string }{
		{"", ""},
		{"auto", ""},
		{"claude-sonnet-4-5", ""},
		{"capi:claude-sonnet-4-5", "claude-sonnet-4-5"},
		{"sweagent-capi:gpt-5", "gpt-5"},
		{"openrouter/anthropic/claude-opus-4", "claude-opus-4"},
		{"capi:openai/gpt-5", "gpt-5"},
		{"provider/", ""},
		{"capi:", ""},
	} {
		if got := StripRouterPrefix(tc.in); got != tc.want {
			t.Errorf("StripRouterPrefix(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
