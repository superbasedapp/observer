package policy

// PER-EVALUATION MEMO (demo bug #14, R3-5).
//
// One Evaluate asks every row of the table about the same command units, and
// a dozen path rows (sensitive files, shell profiles, persistence, git hooks,
// the observer's own config, consent records, hook switches) each derived the
// same facts about each unit before judging it against their own table: the
// directories the unit can run in (unitAnchors), its path operands
// (sensitivePathTokens) and, per resolved path, the split forms a path table
// is matched against. Those facts are pure functions of the event, the
// engine's configuration and the unit, all fixed for one MatchContext, so
// deriving them once answers every row with what it derived for itself. On a
// week's replay that repetition was about a fifth of the CPU left after the
// matcher-first ordering (engine.go applyRule).
//
// The memo lives on the MatchContext (one per evaluation, never shared across
// goroutines) and is keyed by the unit's address in the context's own Cmds,
// so a unit a matcher builds on the fly (a parsed script body, a temporary
// Command) is never memoized: it is derived every time, as before. Callers
// must treat the memoized slices as read-only; they always were shared
// read-only values within one matcher.

// evalMemo is one evaluation's memoized derivations.
type evalMemo struct {
	units map[*Command]*unitFacts
	// forms is pathFormSegs(pathMatchForms(p, Cfg.Home)) per resolved path.
	forms map[string][][]string
}

// unitFacts are one unit's memoized derivations.
type unitFacts struct {
	anchors   []deleteAnchor
	anchorsOK bool
	tokens    []pathToken
	tokensOK  bool
}

// memo returns the context's memo, creating it on first use.
func (ctx *MatchContext) memo() *evalMemo {
	if ctx.evalMemo == nil {
		ctx.evalMemo = &evalMemo{}
	}
	return ctx.evalMemo
}

// unitFactsFor returns cmd's memo entry, or nil when cmd is not one of the
// context's own units (the derivation then runs unmemoized).
func (ctx *MatchContext) unitFactsFor(cmd *Command) *unitFacts {
	if cmd == nil {
		return nil
	}
	own := false
	for i := range ctx.Cmds {
		if &ctx.Cmds[i] == cmd {
			own = true
			break
		}
	}
	if !own {
		return nil
	}
	m := ctx.memo()
	if m.units == nil {
		m.units = make(map[*Command]*unitFacts, len(ctx.Cmds))
	}
	f := m.units[cmd]
	if f == nil {
		f = &unitFacts{}
		m.units[cmd] = f
	}
	return f
}

// unitAnchors returns the distinct anchors a unit can run with
// (deriveUnitAnchors). It is the ONE entry the delete and path rules use,
// memoized per unit of the evaluation.
func unitAnchors(ctx *MatchContext, cmd *Command) []deleteAnchor {
	f := ctx.unitFactsFor(cmd)
	if f == nil {
		return deriveUnitAnchors(ctx, cmd)
	}
	if !f.anchorsOK {
		f.anchors, f.anchorsOK = deriveUnitAnchors(ctx, cmd), true
	}
	return f.anchors
}

// sensitivePathTokensMemo is sensitivePathTokens, memoized per unit of the
// evaluation.
func sensitivePathTokensMemo(ctx *MatchContext, cmd *Command) []pathToken {
	f := ctx.unitFactsFor(cmd)
	if f == nil {
		return sensitivePathTokens(cmd)
	}
	if !f.tokensOK {
		f.tokens, f.tokensOK = sensitivePathTokens(cmd), true
	}
	return f.tokens
}

// homePathFormSegs is pathFormSegs(pathMatchForms(p, ctx.Cfg.Home)),
// memoized per path for the evaluation.
func homePathFormSegs(ctx *MatchContext, p string) [][]string {
	m := ctx.memo()
	if v, ok := m.forms[p]; ok {
		return v
	}
	v := pathFormSegs(pathMatchForms(p, ctx.Cfg.Home))
	if m.forms == nil {
		m.forms = map[string][][]string{}
	}
	m.forms[p] = v
	return v
}

// homePathPatternMatch is pathPatternMatch(p, ctx.Cfg.Home, pats) over the
// evaluation's memoized forms of p.
func homePathPatternMatch(ctx *MatchContext, p string, pats []pathPattern) (string, bool) {
	if p == "" || len(pats) == 0 {
		return "", false
	}
	return matchPathFormSegs(homePathFormSegs(ctx, p), pats)
}
