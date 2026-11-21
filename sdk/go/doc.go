// Package superbased is the superbased SDK for Go: it sends traces from the
// LLM apps and agents you build to superbased over OpenTelemetry (OTLP/HTTP).
//
// It is a thin layer over the official OpenTelemetry Go SDK. Anything it
// sends, a stock OpenTelemetry exporter can send too; the SDK adds the
// attribute names superbased reads, per-request identity, content capture with
// a size limit, the Admit pre-flight check, scores, prompts, experiments, trace
// cost, and the choice of where the data goes (local, online or both).
//
// It behaves like the Python and TypeScript SDKs: the three run the same
// shared behaviour cases (sdk/contract/sdk-behaviour-cases.json).
//
//	ctx := context.Background()
//	if _, err := superbased.Init(ctx, superbased.Options{ServiceName: "support-bot"}); err != nil {
//		log.Fatal(err)
//	}
//	defer superbased.Shutdown(ctx)
//
//	ctx = superbased.PropagateAttributes(ctx, superbased.Attributes{User: "alice", SessionID: "s1"})
//	err := superbased.WithLLMSpan(ctx, "chat", superbased.LLMOptions{Model: "gpt-5-nano", Provider: "openai"},
//		func(ctx context.Context, span trace.Span) error {
//			// call the model
//			return superbased.SetUsage(span, superbased.Usage{InputTokens: superbased.Int(1200), OutputTokens: superbased.Int(80)})
//		})
//
// Never set sbo.emitted_by=observer: that is superbased's own echo-guard
// marker, and a resource carrying it is dropped at ingestion.
package superbased
