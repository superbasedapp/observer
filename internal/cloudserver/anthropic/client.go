package anthropic

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	sdk "github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/inference"
)

const (
	// DefaultBaseURL is the Anthropic API origin a route is bound to unless the
	// operator names another (a gateway in front of the API, say).
	DefaultBaseURL = "https://api.anthropic.com"
	// APIVersion is the anthropic-version header value recorded on the route
	// snapshot and sent on every call.
	APIVersion = "2023-06-01"
	// DefaultModel is the operator-ruled model for Cloud Intelligence.
	DefaultModel = "claude-haiku-5-5"
	// ResourcePrefix prefixes the provider resource identifier an Anthropic
	// route is bound to (route_registry.arm_resource_id holds it; the column
	// name is historical, the value is provider-neutral).
	ResourcePrefix = "anthropic:messages:"
	// DefaultEffort is the effort level every call uses unless configured
	// otherwise: enrichment is short structured extraction, and the model's
	// thinking counts against max_tokens.
	DefaultEffort = "low"
	// defaultTimeout bounds one call when neither the request nor the client
	// names a timeout.
	defaultTimeout = 60 * time.Second
	// maxErrorBody bounds the provider error document kept for the ledger.
	maxErrorBody = 1024
)

// ResourceID is the canonical provider resource identifier for a model, the
// value an Anthropic route's binding and the disclosed attestation are keyed
// to (e.g. "anthropic:messages:claude-haiku-5-5").
func ResourceID(model string) string { return ResourcePrefix + strings.TrimSpace(model) }

// Client is the Anthropic provider. The zero value is usable.
type Client struct {
	// HTTPClient carries the call; nil uses a client whose timeout is the
	// request's (or 60s). Tests inject a fake transport here.
	HTTPClient *http.Client
	// Effort is the output_config.effort level ("" means DefaultEffort).
	Effort string
	// DisablePromptCache turns off the cache_control breakpoint on the system
	// prompt.
	DisablePromptCache bool
}

var _ inference.Provider = (*Client)(nil)

// Complete makes ONE bounded Messages API call for the request. It never
// retries and never reads a credential from the environment.
func (c *Client) Complete(ctx context.Context, req inference.Request) (inference.Response, error) {
	if req.Dialect != inference.DialectAnthropicMessages {
		return inference.Response{}, fmt.Errorf("%w: %q", inference.ErrUnsupportedDialect, req.Dialect)
	}
	if strings.TrimSpace(req.APIKey) == "" {
		return inference.Response{}, errors.New("anthropic: no API key on the request (credential absent)")
	}
	params, err := BuildParams(req, c.effort(), !c.DisablePromptCache)
	if err != nil {
		return inference.Response{}, err
	}
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	hc := c.HTTPClient
	if hc == nil {
		// Redirects are never followed: Go forwards a custom X-Api-Key
		// header to a redirect's new host (RB1 sweep finding C4).
		hc = &http.Client{Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}}
	}
	base := strings.TrimRight(strings.TrimSpace(req.Endpoint), "/")
	if base == "" {
		base = DefaultBaseURL
	}
	opts := []option.RequestOption{
		// Ambient credentials and base URLs are never consulted: the key and
		// the origin come from the authorized route snapshot only.
		option.WithoutEnvironmentDefaults(),
		option.WithAPIKey(req.APIKey),
		option.WithBaseURL(base + "/"),
		option.WithHTTPClient(hc),
		option.WithMaxRetries(0),
		option.WithRequestTimeout(timeout),
	}
	if v := strings.TrimSpace(req.APIVersion); v != "" {
		opts = append(opts, option.WithHeader("anthropic-version", v))
	}
	client := sdk.NewClient(opts...)
	msg, err := client.Messages.New(ctx, params)
	if err != nil {
		return inference.Response{}, classify(ctx, err)
	}
	return ParseMessage(msg), nil
}

func (c *Client) effort() string {
	if e := strings.TrimSpace(c.Effort); e != "" {
		return e
	}
	return DefaultEffort
}

// BuildParams builds the Messages API request from the bounded inference
// request. Exported so a test can pin the exact wire shape: the model id from
// the route, max_tokens from the route cap, the system prompt as one cached
// text block, one user turn, output_config with the effort level and the
// strict json_schema format, and NOTHING else (no tools, no sampling
// parameters, no thinking override, no metadata).
func BuildParams(req inference.Request, effort string, cacheSystem bool) (sdk.MessageNewParams, error) {
	model := strings.TrimSpace(req.Deployment)
	if model == "" {
		return sdk.MessageNewParams{}, errors.New("anthropic: route has no model (deployment) id")
	}
	if req.MaxOutputTokens <= 0 {
		return sdk.MessageNewParams{}, errors.New("anthropic: route has no max_output_tokens")
	}
	system := sdk.TextBlockParam{Text: req.System}
	if cacheSystem {
		// The system prompt is the stable, evidence-free prefix (framing plus
		// the closed vocabularies); the per-request evidence follows it in the
		// user turn, so a cache breakpoint here is reused across jobs.
		system.CacheControl = sdk.NewCacheControlEphemeralParam()
	}
	params := sdk.MessageNewParams{
		Model:     model,
		MaxTokens: int64(req.MaxOutputTokens),
		System:    []sdk.TextBlockParam{system},
		Messages:  []sdk.MessageParam{sdk.NewUserMessage(sdk.NewTextBlock(req.User))},
	}
	params.OutputConfig.Effort = sdk.OutputConfigEffort(effort)
	if len(req.Schema) > 0 {
		var schema map[string]any
		if err := json.Unmarshal(req.Schema, &schema); err != nil {
			return sdk.MessageNewParams{}, fmt.Errorf("anthropic: decode output schema: %w", err)
		}
		params.OutputConfig.Format = sdk.JSONOutputFormatParam{Schema: schema}
	}
	return params, nil
}

// ParseMessage turns a Messages API response into the provider-neutral shape:
// the concatenated text blocks (thinking blocks are skipped; their text is
// omitted by default anyway), the per-bucket usage, and a normalized finish
// reason.
func ParseMessage(msg *sdk.Message) inference.Response {
	if msg == nil {
		return inference.Response{}
	}
	var b strings.Builder
	for _, block := range msg.Content {
		if t, ok := block.AsAny().(sdk.TextBlock); ok {
			b.WriteString(t.Text)
		}
	}
	u := inference.Usage{
		Input:      msg.Usage.InputTokens,
		Output:     msg.Usage.OutputTokens,
		CacheRead:  msg.Usage.CacheReadInputTokens,
		CacheWrite: msg.Usage.CacheCreationInputTokens,
	}
	return inference.Response{
		Content:      b.String(),
		TokensIn:     u.PromptTokens(),
		TokensOut:    u.Output,
		Usage:        u,
		Model:        msg.Model,
		FinishReason: finishReason(msg),
	}
}

func finishReason(msg *sdk.Message) string {
	switch msg.StopReason {
	case sdk.StopReasonMaxTokens:
		return inference.FinishLength
	case sdk.StopReasonRefusal:
		if cat := strings.TrimSpace(string(msg.StopDetails.Category)); cat != "" {
			return inference.FinishRefusal + ":" + cat
		}
		return inference.FinishRefusal
	}
	return string(msg.StopReason)
}

// classify maps an SDK error onto the inference sentinels.
func classify(ctx context.Context, err error) error {
	var apiErr *sdk.Error
	if errors.As(err, &apiErr) {
		switch apiErr.StatusCode {
		case http.StatusTooManyRequests, 529: // 529 = Anthropic "overloaded"
			return fmt.Errorf("%w: anthropic status %d", inference.ErrQuota, apiErr.StatusCode)
		}
		return &inference.ProviderError{StatusCode: apiErr.StatusCode, Body: inference.Truncate(apiErr.RawJSON(), maxErrorBody)}
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) || isTimeout(err) {
		return inference.ErrTimeout
	}
	return fmt.Errorf("anthropic: transport: %w", err)
}

func isTimeout(err error) bool {
	var te interface{ Timeout() bool }
	return errors.As(err, &te) && te.Timeout()
}
