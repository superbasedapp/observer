package scrub

import (
	"strconv"
	"strings"
	"testing"
	"time"
)

// piiLatencyBudget is the per-op wall-clock ceiling asserted by the
// benchmarks below. The contract budget (§17.9) is "≤10ms p99 added per
// request"; 8ms leaves headroom under that ceiling while still catching
// a real regression (Go benchmarks have no native per-op assertion
// primitive, so this is measured by hand — see assertDetectBudget).
const piiLatencyBudget = 8 * time.Millisecond

// assertDetectBudget runs DetectSecrets(body) b.N times, measuring wall
// clock by hand (time.Since across the whole loop, divided by b.N) and
// failing the benchmark with b.Fatalf if the mean per-op cost exceeds
// budget. This is the pattern requested for BenchmarkDetectPII and
// retrofitted onto internal/guard's BenchmarkScanProxyRequest /
// BenchmarkScanProxyRequest_MCPOn (contract §4.5 — "today's [benchmarks]
// have none").
func assertDetectBudget(b *testing.B, body string, budget time.Duration) {
	b.Helper()
	b.SetBytes(int64(len(body)))
	start := time.Now()
	for i := 0; i < b.N; i++ {
		DetectSecrets(body)
	}
	elapsed := time.Since(start)
	if b.N == 0 {
		return
	}
	perOp := elapsed / time.Duration(b.N)
	if perOp > budget {
		b.Fatalf("DetectSecrets: %v/op exceeds the §17.9 budget of %v (body %d bytes, %d iterations)", perOp, budget, len(body), b.N)
	}
}

// cleanTextBody builds a ~n-byte body of realistic prose/code-mix text
// carrying no secrets and no PII — the "ordinary request" case the
// §17.9 budget must hold for.
func cleanTextBody(n int) string {
	unit := "func handleRequest(ctx context.Context, req *Request) (*Response, error) {\n" +
		"\t// Ordinary tool-call output: no secrets, no PII, just prose and code.\n" +
		"\tlogger.Info(\"processing request\", \"id\", req.ID, \"path\", req.Path)\n" +
		"\tif err := req.Validate(); err != nil {\n" +
		"\t\treturn nil, fmt.Errorf(\"validate: %w\", err)\n" +
		"\t}\n" +
		"\treturn &Response{Status: \"ok\", Duration: time.Since(start)}, nil\n" +
		"}\n\n"
	return repeatToLen(unit, n)
}

// piiDenseBody builds a ~n-byte body where EVERY line actually produces
// PII candidates: a Luhn+IIN-valid, non-test credit card number, an
// email address, and a context-worded NANP phone number (round-2
// review B4 — the previous digitDenseBody was a 10-digit-run CSV paste
// that never matched ANY detector: credit_card needs 13-19 digits,
// us_ssn needs literal hyphens, and phone_nanp needs a nearby context
// word, so that benchmark measured nothing but the numeric-run
// pre-pass's candidate-collection cost, never the expensive PII
// suppression path (isTestValue/inCodeContext) the O(n·m) bug actually
// lived in). This body is the real worst case: thousands of genuine PII
// candidates spread across the whole body.
func piiDenseBody(n int) string {
	const pan = "4532015112830366" // Luhn+IIN-valid, not a testValues entry
	var b strings.Builder
	b.Grow(n + 256)
	i := 0
	for b.Len() < n {
		b.WriteString("customer ")
		b.WriteString(strconv.Itoa(i))
		b.WriteString(" card ")
		b.WriteString(pan)
		b.WriteString(" email user")
		b.WriteString(strconv.Itoa(i))
		b.WriteString("@example.com call (415) 555-")
		suffix := strconv.Itoa(i % 10000)
		for len(suffix) < 4 {
			suffix = "0" + suffix
		}
		b.WriteString(suffix)
		b.WriteString(" phone\n")
		i++
	}
	s := b.String()
	if len(s) > n {
		s = s[:n]
	}
	return s
}

// BenchmarkDetectPII measures DetectSecrets (which still runs the full
// detection table internally — including every PII row — before
// filtering PII out of the returned findings, so this exercises the
// same PII-suppression code path a real egress scan pays for) over the
// two shapes the contract calls out: a clean 128 KB body, and a 128 KB
// PII-dense body (the real worst case for the suppression path, not
// the vacuous digitDenseBody this replaced). Both must stay inside
// piiLatencyBudget.
//
// Round-2 review B4 measured the OLD detectorMatch/inCodeContext
// (per-candidate O(n) rescan-from-zero) against this SAME piiDenseBody
// shape on this box: 128KB ≈ 26ms/op, 256KB ≈ 44ms/op, 512KB ≈ 98ms/op
// — all well past this 8ms budget (the previous digitDenseBody passed
// trivially because it produced zero PII candidates to suppress).
// AFTER precomputing the fence-span list and applying the
// maxPIIFindings cap inline (short-circuiting the suppression checks
// once reached) this body still cost ≈11ms/op — the residual cost was
// the numeric-run pre-pass (§4.5) still ATTEMPTING all five
// numericCandidate detector regexes against every remaining candidate
// span even after the cap was reached; numericPrepassMatches now
// short-circuits that too. Final measured cost on this box:
// 128KB ≈ 6.8ms/op, comfortably inside the 8ms budget.
func BenchmarkDetectPII(b *testing.B) {
	const size = 128 * 1024

	b.Run("clean_128kb", func(b *testing.B) {
		assertDetectBudget(b, cleanTextBody(size), piiLatencyBudget)
	})
	b.Run("pii_dense_128kb", func(b *testing.B) {
		assertDetectBudget(b, piiDenseBody(size), piiLatencyBudget)
	})
	// Uncapped variant (nit, round-2 re-review): DetectSecrets always
	// passes the built-in defaultDetectOptions(), whose maxFindings is
	// the fixed maxPIIFindings cap — so every case above ALSO measures
	// the cap short-circuit's benefit, never the truly uncapped path a
	// caller with a very high [guard.prompt].max_findings (or
	// MaxFindings<=0, which falls back to the same built-in default)
	// could still hit. This exercises DetectPromptFindings directly
	// with an effectively-uncapped budget over the same PII-dense
	// worst case. Deliberately MEASUREMENT ONLY, no b.Fatalf budget
	// assertion: removing the cap is expected to cost more than the
	// capped budget by design (every candidate pays the full
	// isTestValue/inCodeContext check with no early-exit) — this
	// sub-benchmark exists so `-bench` output makes that cost visible,
	// not to gate it against the capped-path ceiling.
	b.Run("pii_dense_128kb_uncapped", func(b *testing.B) {
		body := piiDenseBody(size)
		opts := PromptDetectOptions{MaxFindings: 1 << 30, SuppressInCode: true}
		b.SetBytes(int64(len(body)))
		for i := 0; i < b.N; i++ {
			DetectPromptFindings(body, opts)
		}
	})
}

// piiLatencyTestCeiling is a deliberately more generous ceiling than
// piiLatencyBudget for TestDetectPII_LatencyRegression (F1, round-2
// review): `go test -race ./...` (what `make test`/CI actually runs)
// never executes `go test -bench`, so BenchmarkDetectPII's budget
// assertion above never runs in CI — it only fires when a developer
// remembers to run benchmarks by hand. This test expresses the SAME
// regression class (the O(n·m) PII-suppression blowup B4 fixed) as an
// ordinary test so CI catches it, using a looser ceiling to avoid
// flaking on a slower/shared CI runner while still catching an
// order-of-magnitude regression like the one B4 fixed (26-98ms/op).
const piiLatencyTestCeiling = 50 * time.Millisecond

// TestDetectPII_LatencyRegression is the CI-visible sibling of
// BenchmarkDetectPII (F1). Skipped under `-short` (a plain wall-clock
// timing assertion is exactly the kind of test `-short` exists to
// skip); otherwise runs a handful of iterations and fails if the mean
// per-call cost exceeds piiLatencyTestCeiling.
func TestDetectPII_LatencyRegression(t *testing.T) {
	if testing.Short() {
		t.Skip("wall-clock latency assertion skipped under -short")
	}
	const size = 128 * 1024
	const iterations = 5

	cases := []struct {
		name string
		body string
	}{
		{"clean_128kb", cleanTextBody(size)},
		{"pii_dense_128kb", piiDenseBody(size)},
	}
	// FIX-3 (round-2 re-review): widen the ceiling under the race
	// detector, which CI actually runs (`go test -race ./...`) and
	// whose per-access instrumentation overhead the plain ceiling's
	// ~7x headroom does not comfortably absorb — see race_on_test.go /
	// race_off_test.go.
	ceiling := piiLatencyTestCeiling * raceLatencyMultiplier
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			start := time.Now()
			for i := 0; i < iterations; i++ {
				DetectSecrets(tc.body)
			}
			perOp := time.Since(start) / iterations
			if perOp > ceiling {
				t.Fatalf("DetectSecrets: %v/op exceeds the CI regression ceiling of %v (body %d bytes)", perOp, ceiling, len(tc.body))
			}
		})
	}
}
