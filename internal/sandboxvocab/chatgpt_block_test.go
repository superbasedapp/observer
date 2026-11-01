package sandboxvocab

import "testing"

// TestChatGPTStaysOnTheProviderList pins D-MU5's gateway side: a
// ChatGPT-signed-in codex reaches chatgpt.com through the forwarded proxy
// (chatgpt_base_url), never by the gateway opening the host, so chatgpt.com
// and its subdomains stay refused like every other provider host.
func TestChatGPTStaysOnTheProviderList(t *testing.T) {
	hosts := ModelProviderHosts()
	for _, h := range []string{"chatgpt.com", "ab.chatgpt.com", "CHATGPT.COM."} {
		if !MatchesHost(h, hosts) {
			t.Errorf("%s must stay a provider host", h)
		}
	}
}
