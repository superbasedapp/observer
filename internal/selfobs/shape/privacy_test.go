package shape

import (
	"strings"
	"testing"

	"go.opentelemetry.io/otel/attribute"

	"github.com/marmutapp/superbased-observer/internal/selfobs/run"
)

// TestNoRawPathInRetainedScalars is the B-B5 regression: the free-form
// correlation scalars (sbo.run.id, sbo.run.trace_id) are retained VERBATIM as
// operational metadata by the gateway classify tier at every capture level, so
// a raw filesystem path reaching them leaves the node in the clear. Table-
// driven over the shapes a decision component can plausibly hand the shaper —
// including the exact `observer advise --project <path>` input that produced
// the finding.
func TestNoRawPathInRetainedScalars(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		run     run.DecisionRun
		secrets []string // substrings that must appear in NO emitted value
	}{
		{
			name:    "advise --project posix root",
			run:     run.DecisionRun{RunID: "advisor-30", TraceID: "/home/alice/work/acme-secret-project"},
			secrets: []string{"/home/alice/work/acme-secret-project", "acme-secret-project", "alice"},
		},
		{
			name:    "advise --project windows root",
			run:     run.DecisionRun{RunID: "advisor-7", TraceID: `C:\Users\alice\src\acme`},
			secrets: []string{`C:\Users\alice\src\acme`, "Users", "alice"},
		},
		{
			name:    "home-relative root",
			run:     run.DecisionRun{RunID: "advisor-7", TraceID: "~/src/acme"},
			secrets: []string{"~/src/acme", "src/acme"},
		},
		{
			name:    "path-shaped run id",
			run:     run.DecisionRun{RunID: "/var/lib/observer/run-1", TraceID: "sess-1"},
			secrets: []string{"/var/lib/observer/run-1"},
		},
		{
			name:    "path-shaped dataset name as trace id",
			run:     run.DecisionRun{RunID: "eval-run-3", TraceID: "datasets/prod/golden.jsonl"},
			secrets: []string{"datasets/prod/golden.jsonl", "golden.jsonl"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			m := collect(Attributes(tc.run))

			for _, key := range []string{"sbo.run.id", "sbo.run.trace_id"} {
				got := m[key].AsString()
				if strings.ContainsAny(got, `/\`) {
					t.Errorf("%s = %q contains a path separator", key, got)
				}
				if strings.HasPrefix(got, "~") {
					t.Errorf("%s = %q is home-relative", key, got)
				}
			}

			for _, kv := range Attributes(tc.run) {
				val := renderValue(kv.Value)
				for _, secret := range tc.secrets {
					if strings.Contains(val, secret) {
						t.Errorf("attribute %s = %q leaks %q", kv.Key, val, secret)
					}
				}
			}
		})
	}
}

// TestOpaqueCorrelationIDsSurviveIntact proves the backstop does not destroy
// legitimate correlation: uuid/session/request-shaped ids pass through byte-for-
// byte, so org-side joins on sbo.run.trace_id keep working.
func TestOpaqueCorrelationIDsSurviveIntact(t *testing.T) {
	t.Parallel()

	r := run.DecisionRun{RunID: "req-9f2c", TraceID: "3f2a1c8e-0b7d-4a11-9d2f-6b0c1e5a7d34"}
	m := collect(Attributes(r))

	if got := m["sbo.run.id"].AsString(); got != r.RunID {
		t.Errorf("sbo.run.id = %q, want %q", got, r.RunID)
	}
	if got := m["sbo.run.trace_id"].AsString(); got != r.TraceID {
		t.Errorf("sbo.run.trace_id = %q, want %q", got, r.TraceID)
	}
}

// TestHashedTraceIDIsStableAcrossRuns pins that two runs over the same project
// still correlate after hashing — the property that justified hashing over
// dropping the attribute.
func TestHashedTraceIDIsStableAcrossRuns(t *testing.T) {
	t.Parallel()

	const root = "/home/alice/work/acme"
	a := collect(Attributes(run.DecisionRun{RunID: "advisor-7", TraceID: root}))["sbo.run.trace_id"].AsString()
	b := collect(Attributes(run.DecisionRun{RunID: "advisor-30", TraceID: root}))["sbo.run.trace_id"].AsString()

	if a == "" || a != b {
		t.Fatalf("trace ids for the same project root did not correlate: %q vs %q", a, b)
	}
	if a != run.CorrelationID(root) {
		t.Errorf("sbo.run.trace_id = %q, want run.CorrelationID(root) = %q", a, run.CorrelationID(root))
	}
}

// renderValue flattens any attribute value (scalar or slice) to a single string
// so a leak assertion can scan every emitted value uniformly.
func renderValue(v attribute.Value) string {
	if v.Type() == attribute.STRINGSLICE {
		return strings.Join(v.AsStringSlice(), "\x00")
	}
	// Value.String, not the deprecated Value.Emit (SA1019 since the otel
	// v1.43 -> v1.44 bump). For a STRING value — every case this helper is
	// asked about, since STRINGSLICE is handled above — both return the raw
	// value byte-for-byte, so the leak scan is unchanged.
	return v.String()
}
