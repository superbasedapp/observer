// Command experiment runs a small golden set through the same model call the
// chatbot makes and scores each answer with an exact-match evaluator.
// FailUnder 0.5 makes it exit 1 (*superbased.ExperimentGateFailed) when fewer
// than half of the items pass.
//
// On this machine the dataset is created on first use. On the organization
// the dataset must exist first, and the key needs the sdk:eval scope (a CI
// credential).
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/superbasedapp/observer/examples/ai-apps/sdk-direct/go/internal/chat"
	superbased "github.com/superbasedapp/observer/sdk/go"
	"go.opentelemetry.io/otel/trace"
)

func main() {
	os.Exit(run())
}

func task(ctx context.Context, item superbased.Item) (any, error) {
	input := item.Input.(string)
	var out string
	err := superbased.WithLLMSpan(ctx, "answer", superbased.LLMOptions{Model: chat.Model, Provider: "openai", Prompt: input},
		func(ctx context.Context, span trace.Span) error {
			resp, err := chat.Complete(ctx, []chat.Message{{Role: "user", Content: input}}, 300)
			if err != nil {
				return err
			}
			out = strings.TrimRight(strings.TrimSpace(resp.Text()), ".")
			return superbased.SetUsage(span, superbased.Usage{
				InputTokens: superbased.Int(resp.Usage.PromptTokens), OutputTokens: superbased.Int(resp.Usage.CompletionTokens),
				ResponseID: resp.ID, ResponseModel: resp.Model, Response: out,
			})
		})
	return out, err
}

var exactMatch = superbased.EvaluatorFunc("exact_match", func(_ context.Context, in superbased.EvalInput) (any, error) {
	return strings.EqualFold(fmt.Sprint(in.Output), fmt.Sprint(in.Expected)), nil
})

func run() int {
	ctx := context.Background()
	service := os.Getenv("SUPERBASED_SERVICE_NAME")
	if service == "" {
		service = "sdk-direct-evals"
	}
	if _, err := superbased.Init(ctx, superbased.Options{ServiceName: service}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer superbased.Shutdown(ctx)
	dataset := os.Getenv("DATASET_NAME")
	if dataset == "" {
		dataset = "capitals-golden"
	}
	items := []superbased.Item{
		{ID: "fr", Input: "Capital of France? One word.", Expected: "Paris"},
		{ID: "jp", Input: "Capital of Japan? One word.", Expected: "Tokyo"},
	}
	res, err := superbased.RunExperiment(ctx, superbased.ExperimentOptions{
		Dataset: items, Task: task, Evaluators: []superbased.Evaluator{exactMatch},
		DatasetName: dataset, Name: fmt.Sprintf("capitals-%d", time.Now().Unix()), FailUnder: superbased.Float(0.5),
	})
	if res != nil {
		fmt.Println("pass_rate:", res.PassRate(), "scored:", res.Scored(), "runs:", res.Runs)
		fmt.Println("errors:", res.Errors)
		fmt.Println("summary:", res.Summary())
	}
	var gate *superbased.ExperimentGateFailed
	if errors.As(err, &gate) {
		fmt.Fprintln(os.Stderr, gate)
		return 1
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}
