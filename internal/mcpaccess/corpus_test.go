package mcpaccess

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// corpusFile is one testdata/corpus/*.json document.
type corpusFile struct {
	Name              string      `json:"name"`
	Spec              Spec        `json:"spec"`
	PrincipalDefaults Principal   `json:"principal_defaults"`
	Rows              []corpusRow `json:"rows"`
}

type corpusRow struct {
	Name      string          `json:"name"`
	Principal json.RawMessage `json:"principal,omitempty"`
	Input     EvalInput       `json:"input"`
	Want      Effect          `json:"want"`
	WantGrant string          `json:"want_grant,omitempty"`
}

// principal overlays the row's partial principal onto the corpus defaults.
func (r corpusRow) principal(t *testing.T, def Principal) Principal {
	t.Helper()
	p := def
	// Deep-copy the slices: json.Unmarshal reuses a destination slice's
	// backing array when it has capacity, which would let a same-length
	// override in one row rewrite the defaults every later row sees.
	p.Audience = append([]string(nil), def.Audience...)
	p.Groups = append([]string(nil), def.Groups...)
	if len(r.Principal) == 0 {
		return p
	}
	if err := json.Unmarshal(r.Principal, &p); err != nil {
		t.Fatalf("row %q principal: %v", r.Name, err)
	}
	// A row that sets "groups": [] means NO groups; json.Unmarshal into an
	// existing non-nil slice keeps the default otherwise, which is the
	// overlay semantics every other field has.
	var probe map[string]json.RawMessage
	_ = json.Unmarshal(r.Principal, &probe)
	if raw, ok := probe["groups"]; ok && string(raw) == "[]" {
		p.Groups = nil
	}
	return p
}

func loadCorpus(t *testing.T) []corpusFile {
	t.Helper()
	files, err := filepath.Glob(filepath.Join("testdata", "corpus", "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("corpus glob: %v (%d files)", err, len(files))
	}
	var out []corpusFile
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var c corpusFile
		if err := json.Unmarshal(b, &c); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		out = append(out, c)
	}
	return out
}

// targets compiles the four targets once per spec.
type targets struct {
	table NodeDecisionTable
	fast  FastIndex
	az    AuthZENEvaluator
	cel   CELRuleSet
}

func compileAll(t *testing.T, spec Spec) targets {
	t.Helper()
	table, err := CompileNodeTable(spec, 0)
	if err != nil {
		t.Fatalf("CompileNodeTable: %v", err)
	}
	fast, err := CompileFastPath(spec, 0)
	if err != nil {
		t.Fatalf("CompileFastPath: %v", err)
	}
	az, err := CompileAuthZEN(spec, 0)
	if err != nil {
		t.Fatalf("CompileAuthZEN: %v", err)
	}
	cel, err := CompileCEL(spec, 0)
	if err != nil {
		t.Fatalf("CompileCEL: %v", err)
	}
	if err := ValidateCEL(cel); err != nil {
		t.Fatalf("ValidateCEL: %v", err)
	}
	return targets{table, fast, az, cel}
}

// verdicts evaluates one input on every target and checks they agree with
// each other; it returns the PDP effect + matched grant and the CEL denied
// bit (celOK=false when the action is PDP-owned).
func (tg targets) verdicts(t *testing.T, in EvalInput) (Effect, string, bool, bool) {
	t.Helper()
	nd, fd, ad := tg.table.Evaluate(in), tg.fast.Evaluate(in), tg.az.Decide(in)
	if nd.Effect != fd.Effect || nd.Effect != ad.Effect {
		t.Fatalf("PDP targets disagree: node=%s fast=%s authzen=%s (%s | %s | %s)", nd.Effect, fd.Effect, ad.Effect, nd.Reason, fd.Reason, ad.Reason)
	}
	if nd.MatchedGrant != fd.MatchedGrant || nd.MatchedGrant != ad.MatchedGrant {
		t.Fatalf("PDP targets attribute different grants: node=%q fast=%q authzen=%q", nd.MatchedGrant, fd.MatchedGrant, ad.MatchedGrant)
	}
	// The AuthZEN wire shape must round-trip to the same decision.
	if resp := tg.az.Evaluate(AuthZENRequestFor(in)); resp.Decision == nd.Denied() {
		t.Fatalf("AuthZEN wire evaluate = %v, want denied=%v", resp.Decision, nd.Denied())
	}
	allowed, reason, ok, err := EvaluateCEL(tg.cel, in)
	if err != nil {
		t.Fatalf("EvaluateCEL: %v", err)
	}
	if ok && allowed == nd.Denied() {
		t.Fatalf("CEL disagrees with the PDP targets: cel allowed=%v (%s) pdp=%s (%s)", allowed, reason, nd.Effect, nd.Reason)
	}
	return nd.Effect, nd.MatchedGrant, !allowed, ok
}

// TestCorpusAllTargetsAgree is the conformance corpus: every row's verdict
// on every applicable target equals the expected effect.
func TestCorpusAllTargetsAgree(t *testing.T) {
	for _, c := range loadCorpus(t) {
		t.Run(c.Name, func(t *testing.T) {
			tg := compileAll(t, c.Spec)
			for _, row := range c.Rows {
				t.Run(row.Name, func(t *testing.T) {
					in := row.Input
					in.Principal = row.principal(t, c.PrincipalDefaults)
					eff, grant, celDenied, celOK := tg.verdicts(t, in)
					if eff != row.Want {
						t.Fatalf("effect %s, want %s", eff, row.Want)
					}
					if grant != row.WantGrant {
						t.Fatalf("matched grant %q, want %q", grant, row.WantGrant)
					}
					if celOK != CELApplicable(in.Action) {
						t.Fatalf("cel applicable=%v, want %v", celOK, CELApplicable(in.Action))
					}
					if celOK && celDenied != (row.Want == EffectDeny) {
						t.Fatalf("cel denied=%v, want %v", celDenied, row.Want == EffectDeny)
					}
					sim, err := Simulate(c.Spec, in, 0)
					if err != nil || !sim.Agree || sim.Decision.Effect != row.Want {
						t.Fatalf("Simulate = %+v, %v", sim, err)
					}
				})
			}
		})
	}
}

// TestCorpusMutationProofs flips ONE grant and proves all four targets flip
// identically on the rows that grant decides: allow -> deny, deny -> allow,
// and enabled -> disabled (which must fall through to the sentinel or to
// the next matching grant, never keep the old verdict by accident).
func TestCorpusMutationProofs(t *testing.T) {
	flips := []struct {
		name string
		mut  func(g *Grant)
	}{
		{"allow<->deny", func(g *Grant) {
			switch g.Effect {
			case EffectAllow:
				g.Effect = EffectDeny
			case EffectDeny:
				g.Effect = EffectAllow
			case EffectAsk:
				g.Effect = EffectDeny
			}
		}},
		{"disable", func(g *Grant) { g.Enabled = false }},
	}
	for _, c := range loadCorpus(t) {
		base := compileAll(t, c.Spec)
		for gi, g := range c.Spec.Grants {
			if !g.Enabled {
				continue
			}
			for _, fl := range flips {
				t.Run(c.Name+"/"+g.ID+"/"+fl.name, func(t *testing.T) {
					mutated := c.Spec
					mutated.Grants = append([]Grant(nil), c.Spec.Grants...)
					mg := mutated.Grants[gi]
					fl.mut(&mg)
					mutated.Grants[gi] = mg
					// A deny grant with a floor is refused (condition_on_deny);
					// that refusal must come from EVERY compiler identically.
					if mg.Effect == EffectDeny && (mg.Conditions.RequiresCredAssurance != "" || mg.Conditions.RequiresClientAttestation != "") {
						assertAllCompilersRefuse(t, mutated, CodeConditionOnDeny)
						return
					}
					mt := compileAll(t, mutated)
					flipped := 0
					for _, row := range c.Rows {
						in := row.Input
						in.Principal = row.principal(t, c.PrincipalDefaults)
						be, bg, bcel, bok := base.verdicts(t, in)
						me, mgrant, mcel, mok := mt.verdicts(t, in)
						if bok != mok {
							t.Fatalf("%s: CEL applicability changed", row.Name)
						}
						if be == me && bg == mgrant {
							if bok && bcel != mcel {
								t.Fatalf("%s: CEL flipped while the PDP verdict did not", row.Name)
							}
							continue
						}
						flipped++
						if bg != g.ID && mgrant != g.ID {
							t.Fatalf("%s: verdict changed (%s->%s) but neither side attributes the mutated grant %s (%q->%q)", row.Name, be, me, g.ID, bg, mgrant)
						}
						if bok && (bcel == mcel) != ((be == EffectDeny) == (me == EffectDeny)) {
							t.Fatalf("%s: CEL denied %v->%v but PDP %s->%s", row.Name, bcel, mcel, be, me)
						}
					}
					t.Logf("%d row(s) flipped identically across all targets", flipped)
				})
			}
		}
	}
}

func assertAllCompilersRefuse(t *testing.T, spec Spec, code string) {
	t.Helper()
	check := func(name string, err error) {
		t.Helper()
		var le *LintError
		if !errors.As(err, &le) || !Has(le.Problems, code) {
			t.Fatalf("%s: err = %v, want *LintError with %s", name, err, code)
		}
	}
	_, e1 := CompileCEL(spec, 0)
	check("CompileCEL", e1)
	_, e2 := CompileNodeTable(spec, 0)
	check("CompileNodeTable", e2)
	_, e3 := CompileAuthZEN(spec, 0)
	check("CompileAuthZEN", e3)
	_, e4 := CompileFastPath(spec, 0)
	check("CompileFastPath", e4)
	_, e5 := Simulate(spec, EvalInput{}, 0)
	check("Simulate", e5)
}

// TestVisibleMaskFollowsCallVerdicts: tools/list visibility is exactly the
// set of tools the same principal may call or ask.
func TestVisibleMaskFollowsCallVerdicts(t *testing.T) {
	c := loadCorpus(t)[0] // basic
	if c.Spec.Grants[0].ID != "g-allow-ci" {
		for _, cc := range loadCorpus(t) {
			if len(cc.Spec.Grants) > 0 && cc.Spec.Grants[0].ID == "g-allow-ci" {
				c = cc
			}
		}
	}
	fast, err := CompileFastPath(c.Spec, 0)
	if err != nil {
		t.Fatal(err)
	}
	p := c.PrincipalDefaults
	p.Groups = []string{"release-eng"}
	got := fast.Visible(p, "vs-gh", ActionCall, "gh", []string{"create_issue", "delete_repo", "merge_pr", "force_push", "sbo_echo"})
	want := []string{"create_issue", "merge_pr", "force_push"}
	if len(got) != len(want) {
		t.Fatalf("visible = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("visible = %v, want %v", got, want)
		}
	}
}
