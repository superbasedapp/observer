package proxy

import (
	"net/url"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// TestChatGPTAccountPathsGoToTheChatGPTUpstream pins the proxy half of D-MU5:
// a codex in a sandbox box points chatgpt_base_url at the proxy's
// /backend-api/, and every account, workspace-routing and model call under
// it must reach the ChatGPT upstream, whatever the auth header looks like,
// while ordinary API paths keep their own upstreams. The box's gateway keeps
// chatgpt.com blocked; this table is the only way those calls leave.
func TestChatGPTAccountPathsGoToTheChatGPTUpstream(t *testing.T) {
	chatgpt, _ := url.Parse("https://chatgpt.com")
	openai, _ := url.Parse("https://api.openai.com")
	anthropic, _ := url.Parse("https://api.anthropic.com")
	p := &Proxy{chatgptURL: chatgpt, openaiURL: openai, anthropicURL: anthropic}
	cases := []struct {
		path        string
		chatgptAuth bool
		want        *url.URL
	}{
		{"/backend-api/accounts/check/v4-2023-04-27", false, chatgpt},
		{"/backend-api/wham/accounts/check", false, chatgpt},
		{"/backend-api/codex/responses", true, chatgpt},
		{"/backend-api/codex/models", false, chatgpt},
		{"/v1/responses", false, openai},
		{"/v1/messages", false, anthropic},
	}
	for _, c := range cases {
		got, _ := p.upstreamForPath(c.path, providerForPath(c.path), c.chatgptAuth, nil, "")
		if got != c.want {
			t.Errorf("%s: upstream = %v, want %v", c.path, got, c.want)
		}
	}
	if providerForPath("/backend-api/accounts/check") != models.ProviderOpenAI {
		t.Error("a /backend-api/ path must classify as OpenAI-side")
	}
}
