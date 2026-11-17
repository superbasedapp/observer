package llmwire

// Usage is the provider-reported token accounting for one call.
//
// PromptTokens and CompletionTokens are the totals the server billed.
// CachedPromptTokens is the part of PromptTokens served from a prompt cache,
// and ReasoningTokens the part of CompletionTokens spent on hidden reasoning;
// both are subsets, never addends.
type Usage struct {
	PromptTokens       int64
	CachedPromptTokens int64
	CompletionTokens   int64
	ReasoningTokens    int64
}

// UncachedPromptTokens is the prompt-side input that was not a cache read,
// the figure pricing tables price as plain input. It never goes negative on a
// server that over-reports cached tokens.
func (u Usage) UncachedPromptTokens() int64 {
	if u.CachedPromptTokens >= u.PromptTokens {
		return 0
	}
	return u.PromptTokens - u.CachedPromptTokens
}

// VisibleCompletionTokens is the completion minus hidden reasoning, clamped
// at zero.
func (u Usage) VisibleCompletionTokens() int64 {
	if u.ReasoningTokens >= u.CompletionTokens {
		return 0
	}
	return u.CompletionTokens - u.ReasoningTokens
}
