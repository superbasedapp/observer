package sandboxvocab

import "testing"

// TestMatchesProviderFamilies pins the closed list's new rows (lane FU8,
// ledger OSH-43): one case per host row and per family pattern, plus the
// near misses each pattern must not catch.
func TestMatchesProviderFamilies(t *testing.T) {
	t.Parallel()
	hosts := ModelProviderHosts()
	cases := []struct {
		host string
		want bool
	}{
		// Vertex regional: <region>-aiplatform.googleapis.com.
		{"us-central1-aiplatform.googleapis.com", true},
		{"europe-west4-aiplatform.googleapis.com", true},
		{"x.us-central1-aiplatform.googleapis.com", true},
		{"-aiplatform.googleapis.com", false},
		{"aiplatform-us.googleapis.com", false},
		{"storage.googleapis.com", false},
		{"prediction.vertexai.goog", true},
		{"123.us-central1-456.prediction.vertexai.goog", true},
		// Bedrock regional: bedrock*.<region>.amazonaws.com.
		{"bedrock-runtime.us-east-1.amazonaws.com", true},
		{"bedrock-runtime-fips.us-gov-west-1.amazonaws.com", true},
		{"bedrock-agent-runtime.ap-southeast-2.amazonaws.com", true},
		{"bedrock.eu-central-1.amazonaws.com", true},
		{"BEDROCK-RUNTIME.US-EAST-1.AMAZONAWS.COM.", true},
		{"vpce-0abc.bedrock-runtime.us-east-1.vpce.amazonaws.com", true},
		{"bedrock-runtime.cn-north-1.amazonaws.com.cn", true},
		{"bedrockish.us-east-1.amazonaws.com", false},
		{"s3.us-east-1.amazonaws.com", false},
		{"bedrock-runtime.s3.amazonaws.com", false},
		{"bedrock-runtime.us-east-1.example.com", false},
		// Azure OpenAI and AI Foundry.
		{"myres.openai.azure.com", true},
		{"myproj.services.ai.azure.com", true},
		{"myres.cognitiveservices.azure.com", true},
		{"models.inference.ai.azure.com", true},
		{"ep.eastus2.models.ai.azure.com", true},
		{"ep.eastus.inference.ml.azure.com", true},
		{"myapp.azurewebsites.net", false},
		{"portal.azure.com", false},
		// Plain hosts.
		{"api.perplexity.ai", true},
		{"api.cerebras.ai", true},
		{"models.github.ai", true},
		{"github.ai", false},
		{"perplexity.ai", false},
		{"", false},
	}
	for _, c := range cases {
		if got := MatchesProvider(c.host, hosts); got != c.want {
			t.Errorf("MatchesProvider(%q) = %v, want %v", c.host, got, c.want)
		}
	}
	// Extra hosts still join the test.
	if !MatchesProvider("llm.corp.example", append(hosts, "corp.example")) {
		t.Error("an extra host must match through MatchesProvider")
	}
}

// TestProviderOverlapFamilies pins the compile-side refusal: an exact entry
// in a family, or a wildcard that covers a provider family, overlaps.
func TestProviderOverlapFamilies(t *testing.T) {
	t.Parallel()
	hosts := ModelProviderHosts()
	cases := []struct {
		entry string
		want  string
	}{
		{"*.amazonaws.com", "bedrock*.<region>.amazonaws.com"},
		{"*.us-east-1.amazonaws.com", "bedrock*.<region>.amazonaws.com"},
		{"*.bedrock-runtime.us-east-1.amazonaws.com", "bedrock*.<region>.amazonaws.com"},
		{"bedrock-runtime.us-east-1.amazonaws.com", "bedrock*.<region>.amazonaws.com"},
		{"*.vpce.amazonaws.com", "bedrock*.<region>.vpce.amazonaws.com"},
		{"*.com", "api.anthropic.com"},
		{"*.amazonaws.com.cn", "bedrock*.<region>.amazonaws.com.cn"},
		{"*.googleapis.com", "generativelanguage.googleapis.com"},
		{"us-central1-aiplatform.googleapis.com", "<region>-aiplatform.googleapis.com"},
		{"*.azure.com", "openai.azure.com"},
		{"*.ai.azure.com", "services.ai.azure.com"},
		{"*.openai.azure.com", "openai.azure.com"},
		{"myres.openai.azure.com", "openai.azure.com"},
		{"*.github.ai", "models.github.ai"},
		{"api.perplexity.ai", "api.perplexity.ai"},
		{"api.cerebras.ai", "api.cerebras.ai"},
		// No overlap.
		{"*.s3.amazonaws.com", ""},
		{"*.s3.us-east-1.amazonaws.com", ""},
		{"s3.us-east-1.amazonaws.com", ""},
		{"storage.googleapis.com", ""},
		{"*.azurewebsites.net", ""},
		{"proxy.golang.org", ""},
		{"*.npmjs.org", ""},
	}
	for _, c := range cases {
		got, hit := ProviderOverlap(c.entry, hosts)
		if hit != (c.want != "") || got != c.want {
			t.Errorf("ProviderOverlap(%q) = %q, %v; want %q", c.entry, got, hit, c.want)
		}
	}
	if got, hit := ProviderOverlap("*.corp.example", append(hosts, "llm.corp.example")); !hit || got != "llm.corp.example" {
		t.Errorf("a wildcard over an extra host = %q, %v", got, hit)
	}
}

// TestProviderPatternNames pins the family rows the refusal can name.
func TestProviderPatternNames(t *testing.T) {
	t.Parallel()
	if got := len(ProviderPatternNames()); got != len(modelProviderPatterns) || got == 0 {
		t.Fatalf("ProviderPatternNames: %d names", got)
	}
}
