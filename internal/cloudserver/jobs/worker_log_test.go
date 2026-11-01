package jobs_test

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/jobs"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// scriptedExecutor returns one scripted result per attempt. It persists
// nothing, which is all the worker's own bookkeeping needs.
type scriptedExecutor struct {
	results []jobs.ExecResult
	calls   int
}

func (e *scriptedExecutor) Execute(context.Context, *store.LeasedJob, store.RouteInfo, string, int, func() time.Time, jobs.FinalGate) (jobs.ExecResult, error) {
	r := e.results[min(e.calls, len(e.results)-1)]
	e.calls++
	return r, nil
}

// TestWorkerLogsOneLinePerJob pins T-968: every leased job ends in exactly
// one INFO line naming the job id prefix, route, attempts, final state, reason
// and summed tokens (and the T-967 title fallback), and nothing else: no
// account id, no session text.
func TestWorkerLogsOneLinePerJob(t *testing.T) {
	cases := []struct {
		name    string
		results []jobs.ExecResult
		creds   jobs.CredentialSource
		want    []string
	}{
		{
			name: "retry then success with the title fallback",
			results: []jobs.ExecResult{
				{Outcome: jobs.ExecInvalidOutput, TokensIn: 16841, TokensOut: 103, Detail: "validate: title is required"},
				{Outcome: jobs.ExecSucceeded, TokensIn: 16845, TokensOut: 681, TitleFallback: true},
			},
			creds: jobs.StaticCredentials{Key: "k"},
			want: []string{
				"level=INFO", "job finished", "route_id=session_enrichment.luna.v1", "attempts=2",
				"state=succeeded", "tokens_in=33686", "tokens_out=784", "title_fallback=true",
			},
		},
		{
			name: "budget exhausted fails with its reason",
			results: []jobs.ExecResult{
				{Outcome: jobs.ExecInvalidOutput, TokensIn: 10, TokensOut: 1},
			},
			creds: jobs.StaticCredentials{Key: "k"},
			want:  []string{"attempts=2", "state=failed", "reason=" + store.ReasonProviderInvalidOutput, "tokens_in=20", "title_fallback=false"},
		},
		{
			name:  "parked before any attempt",
			creds: nil, // credential absent: parked at the gate
			want:  []string{"attempts=0", "state=parked", "reason=" + store.ReasonProviderPolicyUnverified, "tokens_in=0"},
		},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, _, acct := setup(t)
			ctx := context.Background()
			now := time.Now()
			sub := submit(t, s, acct, "canon-log-"+string(rune('a'+i)), now)

			var logs bytes.Buffer
			exec := &scriptedExecutor{results: tc.results}
			if len(exec.results) == 0 {
				exec.results = []jobs.ExecResult{{Outcome: jobs.ExecSucceeded}}
			}
			w := jobs.NewWorker(jobs.Config{
				WorkerID: "w1", LeaseFor: time.Hour,
				Logger: slog.New(slog.NewTextHandler(&logs, nil)),
			},
				jobs.NewPGQueue(s), s, verifiedAttestor{}, tc.creds,
				map[string]jobs.Executor{store.FeatureSessionEnrichment: exec})
			if _, err := w.ProcessOnce(ctx, now); err != nil {
				t.Fatalf("ProcessOnce: %v", err)
			}
			out := logs.String()
			if n := strings.Count(out, "job finished"); n != 1 {
				t.Fatalf("%d job lines, want exactly 1:\n%s", n, out)
			}
			for _, want := range append(tc.want, "job="+sub.JobID[:8]) {
				if !strings.Contains(out, want) {
					t.Errorf("log lacks %q:\n%s", want, out)
				}
			}
			if strings.Contains(out, sub.JobID) {
				t.Errorf("the full job id was logged, want only its prefix:\n%s", out)
			}
			if strings.Contains(out, acct) {
				t.Errorf("the account id was logged:\n%s", out)
			}

			// Nothing leased, nothing logged.
			logs.Reset()
			if _, err := w.ProcessOnce(ctx, now); err != nil {
				t.Fatalf("second ProcessOnce: %v", err)
			}
			if logs.Len() != 0 {
				t.Errorf("an empty poll logged:\n%s", logs.String())
			}
		})
	}
}
