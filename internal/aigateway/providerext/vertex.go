package providerext

import (
	"encoding/json"
	"net/http"
	"strings"
)

// VertexAdapter is the Google Vertex AI native-protocol adapter (HG6 instance
// #2). Vertex speaks the generateContent wire authenticated with a GCP OAuth
// access token — the research lane's recommendation was to prefer Vertex over
// the direct Gemini API for Google upstreams (docs/general_info/
// gateway-vendor-tos-research-2026-08-29.md). It is the closed-vocabulary
// google->"" gap (llmprovider.KindForNodeProvider) that HG6 fills.
type VertexAdapter struct{}

// NewVertexAdapter constructs the adapter.
func NewVertexAdapter() *VertexAdapter { return &VertexAdapter{} }

// Kind is KindVertex.
func (*VertexAdapter) Kind() string { return KindVertex }

// AuthKind is AuthOAuthBearer: Vertex uses a GCP access token as a bearer.
func (*VertexAdapter) AuthKind() AuthKind { return AuthOAuthBearer }

// BuildURL maps to the Vertex publisher model endpoint:
//
//	<base>/models/<model>:generateContent       (unary)
//	<base>/models/<model>:streamGenerateContent (streaming)
//
// base carries the project/location/publisher path the admin configured, e.g.
// https://us-central1-aiplatform.googleapis.com/v1/projects/P/locations/us-central1/publishers/google
func (*VertexAdapter) BuildURL(baseURL, model string, stream bool) string {
	method := ":generateContent"
	if stream {
		method = ":streamGenerateContent"
	}
	return strings.TrimRight(baseURL, "/") + "/models/" + model + method
}

// AttachAuth attaches `Authorization: Bearer <access-token>`. The signer is
// unused (the credential is already a minted GCP access token).
func (*VertexAdapter) AttachAuth(req *http.Request, cred string, _ Signer) error {
	req.Header.Set("Authorization", "Bearer "+cred)
	return nil
}

// vertexUsage matches the Vertex generateContent usageMetadata block.
type vertexUsage struct {
	UsageMetadata struct {
		PromptTokenCount        *int64 `json:"promptTokenCount"`
		CandidatesTokenCount    *int64 `json:"candidatesTokenCount"`
		CachedContentTokenCount *int64 `json:"cachedContentTokenCount"`
	} `json:"usageMetadata"`
}

// ExtractUsage pulls token usage from a Vertex response body. promptTokenCount
// maps to input, candidatesTokenCount to output, cachedContentTokenCount to
// cache-read.
func (*VertexAdapter) ExtractUsage(body []byte) (Usage, bool) {
	var v vertexUsage
	if err := json.Unmarshal(body, &v); err != nil {
		return Usage{}, false
	}
	m := v.UsageMetadata
	if m.PromptTokenCount == nil && m.CandidatesTokenCount == nil && m.CachedContentTokenCount == nil {
		return Usage{}, false
	}
	u := Usage{}
	if m.PromptTokenCount != nil {
		u.InputTokens = *m.PromptTokenCount
	}
	if m.CandidatesTokenCount != nil {
		u.OutputTokens = *m.CandidatesTokenCount
	}
	if m.CachedContentTokenCount != nil {
		u.CacheReadTokens = *m.CachedContentTokenCount
	}
	return u, true
}
