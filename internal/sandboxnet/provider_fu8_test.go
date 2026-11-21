package sandboxnet

import "testing"

// TestProviderBlockFamilies pins lane FU8 (ledger OSH-43): the gateway's
// name rule refuses the family rows (Vertex regional, Bedrock regional)
// and the new host rows, by the one matcher sandboxvocab owns.
func TestProviderBlockFamilies(t *testing.T) {
	b := NewProviderBlock(nil)
	cases := []struct {
		host string
		rule string
	}{
		{"bedrock-runtime.us-east-1.amazonaws.com", RuleModelProviderHost},
		{"europe-west4-aiplatform.googleapis.com", RuleModelProviderHost},
		{"myres.openai.azure.com", RuleModelProviderHost},
		{"api.perplexity.ai", RuleModelProviderHost},
		{"s3.us-east-1.amazonaws.com", ""},
		{"proxy.golang.org", ""},
	}
	for _, c := range cases {
		if got := b.checkTarget(c.host); got != c.rule {
			t.Errorf("checkTarget(%q) = %q, want %q", c.host, got, c.rule)
		}
	}
}
