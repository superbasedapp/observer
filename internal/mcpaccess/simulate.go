package mcpaccess

import "fmt"

// TargetVerdict is one target's answer in a simulation.
type TargetVerdict struct {
	Target string `json:"target"`
	// Applicable is false for the CEL target on a PDP-owned action.
	Applicable bool   `json:"applicable"`
	Denied     bool   `json:"denied"`
	Effect     Effect `json:"effect,omitempty"`
	Reason     string `json:"reason"`
}

// Simulation is Simulate's result.
type Simulation struct {
	Decision Decision        `json:"decision"`
	Targets  []TargetVerdict `json:"targets"`
	// Agree is true when every applicable target returned the same
	// denied/not-denied outcome and the three PDP targets the same effect.
	Agree bool `json:"agree"`
	// Problems carries the lint warnings of the compiled spec.
	Problems []Problem `json:"problems,omitempty"`
}

// Simulate compiles spec into all four targets, evaluates in on each and
// asserts agreement. The CEL target cannot express ask (the PDP parks an
// ask; the approved retry passes CEL as an allow), so agreement across all
// four is on the DENIED bit; effect agreement is asserted among the three
// PDP targets.
func Simulate(spec Spec, in EvalInput, now int64) (Simulation, error) {
	n, err := Normalize(spec, now)
	if err != nil {
		return Simulation{}, err
	}
	table, _ := CompileNodeTable(spec, now)
	fast, _ := CompileFastPath(spec, now)
	az, _ := CompileAuthZEN(spec, now)
	cel := compileCELNormalized(n)

	nd, fd, ad := table.Evaluate(in), fast.Evaluate(in), az.Decide(in)
	sim := Simulation{Decision: nd, Problems: n.Problems}
	sim.Targets = append(sim.Targets,
		TargetVerdict{Target: "node_table", Applicable: true, Denied: nd.Denied(), Effect: nd.Effect, Reason: nd.Reason},
		TargetVerdict{Target: "fast_path", Applicable: true, Denied: fd.Denied(), Effect: fd.Effect, Reason: fd.Reason},
		TargetVerdict{Target: "authzen", Applicable: true, Denied: ad.Denied(), Effect: ad.Effect, Reason: ad.Reason},
	)
	allowed, reason, ok, cerr := EvaluateCEL(cel, in)
	if cerr != nil {
		return Simulation{}, fmt.Errorf("mcpaccess.Simulate: cel: %w", cerr)
	}
	cv := TargetVerdict{Target: "cel", Applicable: ok, Denied: !allowed, Reason: reason}
	if ok {
		if allowed {
			cv.Effect = EffectAllow
		} else {
			cv.Effect = EffectDeny
		}
	}
	sim.Targets = append(sim.Targets, cv)

	sim.Agree = nd.Effect == fd.Effect && fd.Effect == ad.Effect && nd.MatchedGrant == fd.MatchedGrant && fd.MatchedGrant == ad.MatchedGrant
	if ok && cv.Denied != nd.Denied() {
		sim.Agree = false
	}
	return sim, nil
}
