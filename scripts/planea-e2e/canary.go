//go:build ignore

// Dry-run canary for one Go example: no provider call, ever.
//
// The build tag keeps this file out of the repository's root module (it
// imports the Go SDK, a separate module). The runner compiles it INSIDE the
// example's own module through `go build -overlay` (a copy without the tag,
// mapped to a package path in the example that does not exist on disk), so
// it builds against the example's go.mod, go.sum and its `replace` to
// sdk/go, and nothing is written into the example's tree.
//
// It checks that Init resolves a destination and exports one synthetic trace
// (a root AGENT span and one manual LLM span with fixed usage) that verify.py
// then checks on the machine and/or the org. The Go SDK has no instrument():
// the Go examples call the SDK directly. With -admit-probe it also calls
// Admit(<text>) and records the verdict. Provider keys are stripped from the
// environment by the runner.
//
//	canary -service e2e-canary -model gpt-5-nano -provider openai -out run.json
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"time"

	superbased "github.com/superbasedapp/observer/sdk/go"
	"go.opentelemetry.io/otel/trace"
)

const input, output, cached = 1000, 100, 0

func main() {
	os.Exit(run())
}

func run() int {
	service := flag.String("service", "", "service name")
	model := flag.String("model", "", "model on the synthetic LLM span")
	provider := flag.String("provider", "", "provider on the synthetic LLM span")
	out := flag.String("out", "", "run record path")
	probe := flag.String("admit-probe", "", "also call Admit(<text>) and record the verdict")
	flag.Parse()
	if *service == "" || *model == "" || *provider == "" || *out == "" {
		fmt.Fprintln(os.Stderr, "canary: -service, -model, -provider and -out are required")
		return 2
	}

	ctx := context.Background()
	runID := os.Getenv("RUN_ID")
	if runID == "" {
		runID = strconv.FormatInt(time.Now().Unix(), 10)
	}
	if _, err := superbased.Init(ctx, superbased.Options{ServiceName: *service, Release: "planea-e2e-canary"}); err != nil {
		fmt.Fprintln(os.Stderr, "canary: init:", err)
		return 1
	}

	user, session, tenant := "user-ada", "canary-"+runID, "acme"
	var traceIDs []string
	ctx = superbased.PropagateAttributes(ctx, superbased.Attributes{User: user, SessionID: session, Tenant: tenant})
	err := superbased.WithSpan(ctx, "canary-turn", superbased.SpanOptions{Kind: superbased.KindAgent},
		func(ctx context.Context, _ trace.Span) error {
			traceIDs = append(traceIDs, superbased.CurrentTraceID(ctx))
			return superbased.WithLLMSpan(ctx, "canary-chat", superbased.LLMOptions{Model: *model, Provider: *provider},
				func(_ context.Context, span trace.Span) error {
					return superbased.SetUsage(span, superbased.Usage{
						InputTokens: superbased.Int(input), OutputTokens: superbased.Int(output),
						CacheReadTokens: superbased.Int(cached), ResponseModel: *model, Response: "canary",
					})
				})
		})
	if err != nil {
		fmt.Fprintln(os.Stderr, "canary: span:", err)
		return 1
	}
	verdicts := []map[string]any{}
	if *probe != "" {
		v := superbased.Admit(ctx, *probe, superbased.AdmitOptions{})
		verdicts = append(verdicts, map[string]any{"probe": *probe, "decision": v.Decision, "allowed": v.Allowed,
			"mode": v.Mode, "degraded": v.Degraded})
	}
	superbased.Flush(ctx)
	d := superbased.GetDiagnostics()
	record := map[string]any{
		"service": *service, "run_id": runID, "user": user, "session": session, "tenant": tenant,
		"trace_ids":  traceIDs,
		"calls":      []map[string]any{{"kind": "canary", "input": input, "output": output, "cached": cached}},
		"instrument": map[string]string{}, "verdicts": verdicts,
		"diagnostics": map[string]any{"destination": d.Destination, "destination_source": d.DestinationSource,
			"destinations": d.Destinations, "failed_exports": d.FailedExports, "dropped_spans": d.DroppedSpans,
			"warnings": d.Warnings},
	}
	b, _ := json.MarshalIndent(record, "", "  ")
	if err := os.WriteFile(*out, b, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "canary:", err)
		return 1
	}
	superbased.Shutdown(ctx)
	return 0
}
