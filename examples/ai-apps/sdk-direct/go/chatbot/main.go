// Command chatbot is a three-turn support bot built on the superbased Go SDK
// directly, with no framework. Per turn it:
//
//   - screens the user's message with superbased.Admit before the model runs;
//   - uses a system prompt from the prompt registry (GetPrompt, label
//     production), compiled with a variable, and stamps the LLM span with its
//     name and version (LLMOptions.Prompt);
//   - wraps a raw OpenAI call in a manual LLM span with SetUsage (input,
//     output, cached and reasoning tokens) and the messages and reply;
//   - records a score (concise) and end-user feedback (user_feedback);
//   - reads the turn's trace cost with GetTraceCost once it is ingested;
//   - carries the end user, session and customer tenant on every span.
//
// Create the prompt first (README.md). The OpenAI key comes from
// OPENAI_API_KEY only. Every call uses gpt-5-nano. It writes run.json for
// ../../verify.py.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/superbasedapp/observer/examples/ai-apps/sdk-direct/go/internal/chat"
	superbased "github.com/superbasedapp/observer/sdk/go"
	"go.opentelemetry.io/otel/trace"
)

var turns = []string{
	"Hi! What can you do?",
	"What is your return window?",
	"Tell me about competitor pricing.", // the admission policy refuses this one
}

func env(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

type call struct {
	Kind      string `json:"kind"`
	ID        string `json:"id"`
	Input     int    `json:"input"`
	Output    int    `json:"output"`
	Cached    int    `json:"cached"`
	Reasoning int    `json:"reasoning"`
}

func answer(ctx context.Context, prompt *superbased.Prompt, system string, history []chat.Message, text string) (string, *call, error) {
	messages := append(append([]chat.Message{{Role: "system", Content: system}}, history...), chat.Message{Role: "user", Content: text})
	var reply string
	var usage *call
	// Prompt: <*Prompt> stamps the span with the registry prompt's name and
	// version (sbo.prompt.*); SetContent records the messages actually sent.
	err := superbased.WithLLMSpan(ctx, "chat", superbased.LLMOptions{Model: chat.Model, Provider: "openai", Prompt: prompt},
		func(ctx context.Context, span trace.Span) error {
			superbased.SetContent(span, superbased.Content{Prompt: messages})
			superbased.SetRequestParams(span, superbased.RequestParams{MaxTokens: superbased.Int(400)})
			resp, err := chat.Complete(ctx, messages, 400)
			if err != nil {
				return err
			}
			u := resp.Usage
			usage = &call{"chat", resp.ID, u.PromptTokens, u.CompletionTokens, u.PromptTokensDetails.CachedTokens, u.CompletionTokensDetails.ReasoningTokens}
			reply = resp.Text()
			// InputTokens is the gross input (cache reads are part of it);
			// OutputTokens includes the reasoning tokens.
			return superbased.SetUsage(span, superbased.Usage{
				InputTokens: superbased.Int(usage.Input), OutputTokens: superbased.Int(usage.Output),
				CacheReadTokens: superbased.Int(usage.Cached), ReasoningTokens: superbased.Int(usage.Reasoning),
				FinishReasons: []string{resp.FinishReason()}, ResponseID: resp.ID, ResponseModel: resp.Model, Response: reply,
			})
		})
	return reply, usage, err
}

func main() {
	os.Exit(run())
}

func run() int {
	ctx := context.Background()
	service := env("SUPERBASED_SERVICE_NAME", "sdk-direct-chatbot")
	runID := env("RUN_ID", strconv.FormatInt(time.Now().Unix(), 10))
	if _, err := superbased.Init(ctx, superbased.Options{ServiceName: service, Release: "examples-1"}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer superbased.Shutdown(ctx)

	user, session, tenant := "user-ada", "sd-"+runID, "acme"
	prompt, err := superbased.GetPrompt(ctx, env("PROMPT_NAME", "support-system"), superbased.PromptOptions{
		Fallback: "You are a terse support bot. Answer in one sentence.",
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "prompt: %s v%d label=%q\n", prompt.Name, prompt.Version, prompt.Label)
	system := prompt.Text
	if prompt.Version != 0 {
		if system, err = prompt.CompileText(ctx, map[string]any{"company": "Acme Widgets"}); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
	}

	var traceIDs []string
	calls := []*call{}
	var verdicts, scores []map[string]any
	var history []chat.Message
	ctx = superbased.PropagateAttributes(ctx, superbased.Attributes{User: user, SessionID: session, Tenant: tenant})
	for i, text := range turns {
		n := i + 1
		var tid, reply string
		var v superbased.Verdict
		err := superbased.WithSpan(ctx, fmt.Sprintf("turn-%d", n), superbased.SpanOptions{Kind: superbased.KindAgent},
			func(ctx context.Context, root trace.Span) error {
				tid = superbased.CurrentTraceID(ctx)
				superbased.SetInput(root, text)
				v = superbased.Admit(ctx, text, superbased.AdmitOptions{})
				verdicts = append(verdicts, map[string]any{"turn": n, "decision": v.Decision, "allowed": v.Allowed, "mode": v.Mode,
					"degraded": v.Degraded, "judge_used": v.JudgeUsed})
				if !v.Allowed {
					reply = "Sorry, I can't help with that here."
				} else {
					r, usage, err := answer(ctx, prompt, system, history, text)
					if err != nil {
						return err
					}
					reply = r
					calls = append(calls, usage)
					history = append(history, chat.Message{Role: "user", Content: text}, chat.Message{Role: "assistant", Content: reply})
				}
				superbased.SetOutput(root, reply)
				// A toy evaluator: a support answer should be short.
				r := superbased.Score(ctx, "concise", len(reply) <= 240, superbased.ScoreOptions{Scorer: "length-check", ScorerVersion: "1"})
				scores = append(scores, map[string]any{"turn": n, "ok": r.OK, "errors": r.Errors})
				return nil
			})
		if err != nil {
			fmt.Fprintln(os.Stderr, "turn", n, err)
			return 1
		}
		traceIDs = append(traceIDs, tid)
		fb := superbased.Feedback(ctx, true, superbased.FeedbackOptions{TraceID: tid, Comment: "helpful"})
		scores = append(scores, map[string]any{"turn": n, "feedback_ok": fb.OK, "errors": fb.Errors})
		degraded := ""
		if v.Degraded != "" {
			degraded = ", " + v.Degraded
		}
		fmt.Printf("turn %d: %q -> %q (admit: %s%s)\n", n, text, reply, v.Decision, degraded)
	}

	superbased.Flush(ctx)
	costs := map[string]any{}
	for _, tid := range traceIDs {
		var cost *superbased.TraceCost
		for try := 0; try < 20; try++ { // the cost exists once the spans are ingested
			cost, _ = superbased.GetTraceCost(ctx, tid)
			if cost != nil && len(cost.Spans) > 0 {
				break
			}
			time.Sleep(time.Second)
		}
		if cost != nil {
			costs[tid] = map[string]any{"cost_usd": cost.CostUSD, "label": cost.CostProvenance.Label, "from": cost.Destination}
		} else {
			costs[tid] = nil
		}
		b, _ := json.Marshal(costs[tid])
		fmt.Printf("cost %s: %s\n", tid, b)
	}

	d := superbased.GetDiagnostics()
	record := map[string]any{
		"service": service, "run_id": runID, "user": user, "session": session, "tenant": tenant,
		"prompt": map[string]any{"name": prompt.Name, "version": prompt.Version}, "trace_ids": traceIDs,
		"calls": calls, "verdicts": verdicts, "scores": scores, "costs": costs,
		"diagnostics": map[string]any{"destination": d.Destination, "destinations": d.Destinations, "failed_exports": d.FailedExports,
			"dropped_spans": d.DroppedSpans, "admission_degraded": d.AdmissionDegraded, "admission_last_error": d.AdmissionLastError},
	}
	out, _ := json.MarshalIndent(record, "", "  ")
	if err := os.WriteFile(env("RUN_OUT", "run.json"), out, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	diag, _ := json.Marshal(record["diagnostics"])
	fmt.Fprintln(os.Stderr, string(diag))
	return 0
}
