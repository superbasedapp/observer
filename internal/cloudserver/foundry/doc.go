// Package foundry is the Azure AI Foundry provider client for the CI-P4
// inference worker (plan §2.3). The ONLY active dialect is chat_completions
// (Azure OpenAI-compatible Chat Completions — stateless by design). The
// responses_store_false dialect is implemented (the request builder FORCES
// store:false and a persistence-indicating response fails the job) but stays
// dark: the route resolver refuses it unless an operator verification record
// exists (enforced by the caller, not here). Every call is bounded, single,
// and non-agentic — no tools, no Batch, no stateful endpoints.
//
// The request/response shapes, the sentinel errors and the Provider seam are
// owned by internal/cloudserver/inference (shared with the Anthropic client);
// the names below are aliases so existing callers keep compiling unchanged.
// AzureClient is ONE implementation of inference.Provider, selected only when
// the process is configured for the foundry provider family.
package foundry
