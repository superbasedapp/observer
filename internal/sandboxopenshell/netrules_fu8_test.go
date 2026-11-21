package sandboxopenshell

import (
	"errors"
	"testing"

	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// TestNetProviderFamiliesRefused pins lane FU8 (ledger OSH-43): an allow
// entry in a provider family, or a wildcard that covers one, refuses the
// compile; an unrelated entry under the same cloud still compiles.
func TestNetProviderFamiliesRefused(t *testing.T) {
	t.Parallel()
	cases := []struct {
		entry   string
		refused bool
	}{
		{"*.amazonaws.com", true},
		{"*.us-east-1.amazonaws.com", true},
		{"bedrock-runtime.us-west-2.amazonaws.com", true},
		{"us-central1-aiplatform.googleapis.com", true},
		{"*.azure.com", true},
		{"myres.openai.azure.com", true},
		{"api.perplexity.ai", true},
		{"api.cerebras.ai", true},
		{"models.github.ai", true},
		{"*.s3.amazonaws.com", false},
		{"s3.us-east-1.amazonaws.com", false},
		{"portal.azure.com", false},
	}
	for _, c := range cases {
		in := netInput()
		in.Hosts = []string{c.entry}
		_, err := CompileNetRules(vocab.TierInternet, in)
		if got := errors.Is(err, ErrNetProviderHost); got != c.refused {
			t.Errorf("%q: err %v, refused %v want %v", c.entry, err, got, c.refused)
		}
	}
}
