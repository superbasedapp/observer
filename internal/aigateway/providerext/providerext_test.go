package providerext

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRegistryLookupAndDefaults(t *testing.T) {
	r := DefaultRegistry()
	if !r.Has(KindBedrock) || !r.Has(KindVertex) {
		t.Fatalf("default registry missing bedrock/vertex: %v", r.Kinds())
	}
	if _, ok := r.Lookup("BEDROCK "); !ok {
		t.Fatal("Lookup is not case/space-insensitive")
	}
	if r.Has("openai_compatible") {
		t.Fatal("registry claims a core kind it should not own")
	}
	if len(r.Kinds()) != 2 {
		t.Fatalf("kinds = %v, want 2", r.Kinds())
	}
}

func TestNewRegistryRejectsDuplicateKind(t *testing.T) {
	if _, err := NewRegistry(NewBedrockAdapter(), NewBedrockAdapter()); err == nil {
		t.Fatal("duplicate kind accepted")
	}
}

func TestBedrockAdapter(t *testing.T) {
	a := NewBedrockAdapter()
	if a.AuthKind() != AuthSigV4 {
		t.Fatalf("auth = %q, want sigv4", a.AuthKind())
	}
	// URL mapping, unary + stream.
	base := "https://bedrock-runtime.us-east-1.amazonaws.com"
	if got := a.BuildURL(base+"/", "anthropic.claude-3", false); got != base+"/model/anthropic.claude-3/invoke" {
		t.Fatalf("unary url = %q", got)
	}
	if got := a.BuildURL(base, "m", true); got != base+"/model/m/invoke-with-response-stream" {
		t.Fatalf("stream url = %q", got)
	}
	// SigV4 requires a signer.
	req := httptest.NewRequest(http.MethodPost, base, nil)
	if err := a.AttachAuth(req, "cred", nil); err == nil {
		t.Fatal("nil signer accepted for sigv4")
	}
	fs := &fakeSigner{}
	if err := a.AttachAuth(req, "cred", fs); err != nil || !fs.called {
		t.Fatalf("signer not invoked: err=%v called=%v", err, fs.called)
	}
	// Usage extraction: Converse camelCase.
	u, ok := a.ExtractUsage([]byte(`{"usage":{"inputTokens":120,"outputTokens":45,"cacheReadInputTokens":8}}`))
	if !ok || u.InputTokens != 120 || u.OutputTokens != 45 || u.CacheReadTokens != 8 {
		t.Fatalf("converse usage = %+v ok=%v", u, ok)
	}
	// Usage extraction: Anthropic-on-Bedrock snake_case.
	u2, ok := a.ExtractUsage([]byte(`{"usage":{"input_tokens":10,"output_tokens":5}}`))
	if !ok || u2.InputTokens != 10 || u2.OutputTokens != 5 {
		t.Fatalf("anthropic-on-bedrock usage = %+v ok=%v", u2, ok)
	}
	// No usage block.
	if _, ok := a.ExtractUsage([]byte(`{"completion":"hi"}`)); ok {
		t.Fatal("reported usage where there is none")
	}
}

func TestVertexAdapter(t *testing.T) {
	a := NewVertexAdapter()
	if a.AuthKind() != AuthOAuthBearer {
		t.Fatalf("auth = %q, want oauth_bearer", a.AuthKind())
	}
	base := "https://us-central1-aiplatform.googleapis.com/v1/projects/p/locations/us-central1/publishers/google"
	if got := a.BuildURL(base, "gemini-2.0", false); got != base+"/models/gemini-2.0:generateContent" {
		t.Fatalf("unary url = %q", got)
	}
	if got := a.BuildURL(base, "gemini-2.0", true); got != base+"/models/gemini-2.0:streamGenerateContent" {
		t.Fatalf("stream url = %q", got)
	}
	req := httptest.NewRequest(http.MethodPost, base, nil)
	if err := a.AttachAuth(req, "ya29.token", nil); err != nil {
		t.Fatalf("AttachAuth: %v", err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer ya29.token" {
		t.Fatalf("auth header = %q", got)
	}
	u, ok := a.ExtractUsage([]byte(`{"usageMetadata":{"promptTokenCount":100,"candidatesTokenCount":30,"cachedContentTokenCount":12}}`))
	if !ok || u.InputTokens != 100 || u.OutputTokens != 30 || u.CacheReadTokens != 12 {
		t.Fatalf("vertex usage = %+v ok=%v", u, ok)
	}
	if _, ok := a.ExtractUsage([]byte(`{}`)); ok {
		t.Fatal("reported usage on empty body")
	}
}

type fakeSigner struct{ called bool }

func (f *fakeSigner) Sign(req *http.Request, cred string) error {
	f.called = true
	if cred == "" {
		return errors.New("empty cred")
	}
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 …")
	return nil
}
