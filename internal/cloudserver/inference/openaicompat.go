package inference

import (
	"context"
	"errors"
	"fmt"

	"github.com/marmutapp/superbased-observer/internal/llmwire"
)

// openAICompatibleRequestFor maps the seam's request onto llmwire. The route's
// Deployment is the provider's public model id; Endpoint is the base URL (the
// part before /chat/completions). APIVersion is not used by this dialect.
//
// The request is sent in the model's shape from llmwire's shared
// model-family table (shape.go): a GPT-5 or o-series deployment gets
// max_completion_tokens and its family's reasoning effort (this lane sends no
// temperature on any shape); every other model, gpt-oss-20b included, keeps
// max_tokens, so the shipped route's body is unchanged. The reply cap is NOT
// raised to the shape's minimum: MaxOutputTokens is the worst case the job's
// spend reservation was made against, and a route's cap is chosen per model.
func openAICompatibleRequestFor(req Request) llmwire.Request {
	shape := llmwire.ResolveShape(llmwire.ProfileAuto, "", req.Deployment)
	return shape.Apply(llmwire.Request{
		Model:      req.Deployment,
		System:     req.System,
		Messages:   []llmwire.Message{{Role: llmwire.RoleUser, Content: req.User}},
		MaxTokens:  req.MaxOutputTokens,
		SchemaName: req.SchemaName,
		Schema:     req.Schema,
	})
}

// openAICompatibleResponseFor maps an llmwire reply onto the seam's response.
// Input excludes cache reads (the seam's Usage contract); a server that
// reports no cache split leaves every prompt token in Input. Reasoning tokens
// are already inside completion_tokens, so TokensOut and Usage.Output carry
// the billed completion total.
func openAICompatibleResponseFor(r llmwire.Response) Response {
	u := r.Usage
	return Response{
		Content:      r.Content,
		TokensIn:     u.PromptTokens,
		TokensOut:    u.CompletionTokens,
		Usage:        Usage{Input: u.UncachedPromptTokens(), Output: u.CompletionTokens, CacheRead: min(u.CachedPromptTokens, u.PromptTokens)},
		Model:        r.Model,
		FinishReason: r.FinishReason,
	}
}

// openAICompatibleErrorFor maps llmwire failures onto the seam's sentinels so
// the worker's retry and park decisions never depend on the provider.
func openAICompatibleErrorFor(err error) error {
	var se *llmwire.StatusError
	switch {
	case err == nil:
		return nil
	case errors.Is(err, llmwire.ErrQuota):
		return ErrQuota
	case errors.Is(err, llmwire.ErrTimeout):
		return ErrTimeout
	case errors.As(err, &se):
		return &ProviderError{StatusCode: se.StatusCode, Body: se.Body}
	default:
		return err
	}
}

// OpenAICompatible is the Provider for the openai_compatible dialect (OVH AI
// Endpoints and any OpenAI-compatible server). It holds no HTTP code: the
// llmwire client it wraps owns the transport, over a netguard client.
type OpenAICompatible struct {
	// Client is the llmwire client; required.
	Client *llmwire.Client
}

var _ Provider = (*OpenAICompatible)(nil)

// Complete performs one bounded call. The request's Timeout is applied as a
// context deadline.
func (p *OpenAICompatible) Complete(ctx context.Context, req Request) (Response, error) {
	if p == nil || p.Client == nil {
		return Response{}, errors.New("inference: openai_compatible provider has no llmwire client")
	}
	if req.Dialect != DialectOpenAICompatible && req.Dialect != "" {
		return Response{}, fmt.Errorf("%w: %q", ErrUnsupportedDialect, req.Dialect)
	}
	if req.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, req.Timeout)
		defer cancel()
	}
	res, err := p.Client.Complete(ctx, req.Endpoint, req.APIKey, openAICompatibleRequestFor(req))
	if err != nil {
		return Response{}, openAICompatibleErrorFor(err)
	}
	return openAICompatibleResponseFor(res), nil
}
