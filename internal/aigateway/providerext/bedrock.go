package providerext

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

// BedrockAdapter is the AWS Bedrock native-protocol adapter (HG6 instance #1).
// Bedrock's runtime speaks its own wire (invoke-model / converse), authenticated
// with AWS Signature V4 — not an OpenAI/Anthropic-compatible bearer — which is
// exactly why it needs a pluggable adapter rather than riding an existing kind.
type BedrockAdapter struct{}

// NewBedrockAdapter constructs the adapter.
func NewBedrockAdapter() *BedrockAdapter { return &BedrockAdapter{} }

// Kind is KindBedrock.
func (*BedrockAdapter) Kind() string { return KindBedrock }

// AuthKind is AuthSigV4: Bedrock requires an AWS SigV4-signed request.
func (*BedrockAdapter) AuthKind() AuthKind { return AuthSigV4 }

// BuildURL maps to the Bedrock runtime invoke path:
//
//	<base>/model/<modelId>/invoke                      (unary)
//	<base>/model/<modelId>/invoke-with-response-stream (streaming)
//
// base is the region-scoped runtime host the admin configured, e.g.
// https://bedrock-runtime.us-east-1.amazonaws.com
func (*BedrockAdapter) BuildURL(baseURL, model string, stream bool) string {
	suffix := "/invoke"
	if stream {
		suffix = "/invoke-with-response-stream"
	}
	return strings.TrimRight(baseURL, "/") + "/model/" + model + suffix
}

// AttachAuth delegates to the injected SigV4 signer (region/service/time bound
// at wiring time). A nil signer is a wiring error — Bedrock cannot be reached
// with a static header.
func (*BedrockAdapter) AttachAuth(req *http.Request, cred string, signer Signer) error {
	if signer == nil {
		return errors.New("providerext.BedrockAdapter.AttachAuth: SigV4 signer is required for bedrock")
	}
	return signer.Sign(req, cred)
}

// bedrockUsage matches BOTH the Bedrock Converse usage block (inputTokens/
// outputTokens) and Anthropic-on-Bedrock (input_tokens/output_tokens). Either
// spelling is accepted; the camelCase Converse names take precedence when both
// are present.
type bedrockUsage struct {
	Usage struct {
		InputTokens       *int64 `json:"inputTokens"`
		OutputTokens      *int64 `json:"outputTokens"`
		InputTokensSnake  *int64 `json:"input_tokens"`
		OutputTokensSnake *int64 `json:"output_tokens"`
		CacheReadTokens   *int64 `json:"cacheReadInputTokens"`
		CacheWriteTokens  *int64 `json:"cacheWriteInputTokens"`
	} `json:"usage"`
}

// ExtractUsage pulls token usage from a Bedrock response body.
func (*BedrockAdapter) ExtractUsage(body []byte) (Usage, bool) {
	var b bedrockUsage
	if err := json.Unmarshal(body, &b); err != nil {
		return Usage{}, false
	}
	u := Usage{}
	got := false
	if b.Usage.InputTokens != nil {
		u.InputTokens = *b.Usage.InputTokens
		got = true
	} else if b.Usage.InputTokensSnake != nil {
		u.InputTokens = *b.Usage.InputTokensSnake
		got = true
	}
	if b.Usage.OutputTokens != nil {
		u.OutputTokens = *b.Usage.OutputTokens
		got = true
	} else if b.Usage.OutputTokensSnake != nil {
		u.OutputTokens = *b.Usage.OutputTokensSnake
		got = true
	}
	if b.Usage.CacheReadTokens != nil {
		u.CacheReadTokens = *b.Usage.CacheReadTokens
		got = true
	}
	if b.Usage.CacheWriteTokens != nil {
		u.CacheWriteTokens = *b.Usage.CacheWriteTokens
		got = true
	}
	return u, got
}
