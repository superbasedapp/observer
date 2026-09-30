package alignment

import (
	"context"
	"fmt"
)

// EgressGate is an optional capability a Judge may implement (JUDGE-1,
// docs/security.md) to refuse a per-Input grading call — e.g. a
// data-authority / managed-tenancy check on whether in's session content
// may leave the node to wherever this judge is configured to send it.
// Grade consults it, when present, BEFORE building the prompt or ever
// calling Judge, so a refusal never dials out. A refusal is reported as
// an ordinary error — never a fabricated grade, never a silent
// local-heuristic fallback dressed up as tier J — so it reaches the
// caller exactly like judge unavailability already does (an honest
// "not_available" with a reason, cmd/observer's grade handler).
type EgressGate interface {
	// AllowInput reports whether in may be graded by this judge right
	// now. false with a human-readable reason refuses the call.
	AllowInput(in Input) (ok bool, reason string)
}

// Grade builds the prompt for in, calls j once, and parses the reply into a
// Result. It is the one composition point of this package — everything
// else (which judge to use, whether it is even configured, persistence)
// lives at the seams around it (cmd/observer/alignment_wire.go,
// internal/store/promptgrades.go).
func Grade(ctx context.Context, j Judge, in Input) (Result, error) {
	if j == nil {
		return Result{}, fmt.Errorf("alignment.Grade: judge is nil")
	}
	if gate, ok := j.(EgressGate); ok {
		if allowed, reason := gate.AllowInput(in); !allowed {
			return Result{}, fmt.Errorf("alignment.Grade: refused: %s", reason)
		}
	}
	prompt := BuildPrompt(in)
	raw, err := j.Judge(ctx, prompt)
	if err != nil {
		return Result{}, fmt.Errorf("alignment.Grade: judge: %w", err)
	}
	result, err := ParseResult(raw)
	if err != nil {
		return Result{}, fmt.Errorf("alignment.Grade: parse: %w", err)
	}
	return result, nil
}
