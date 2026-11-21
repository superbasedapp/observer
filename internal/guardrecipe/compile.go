package guardrecipe

import (
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
)

// CatalogRule is one built-in rule as the compiler needs it: the guard
// layer hands these in from policy.Catalog() (one entry per rule ID, its
// strictest row), so this package never imports the engine.
type CatalogRule struct {
	ID       string
	Category string
	// Observe and Enforce are the rule's catalog decisions ("allow", "flag",
	// "ask", "deny").
	Observe string
	Enforce string
	// Integrity marks the guard's own integrity rules (R-160 and its
	// siblings): no layer below the org may weaken or disable them, so the
	// compiler never emits a cap, a disable or a lowering decision for one.
	Integrity bool
	// ModuleRule marks a rule pack row of a module this node runs (not a
	// built-in): a recipe pack naming it is judged tighten-only like any
	// rule, but project-scope mode emulation leaves it alone.
	ModuleRule bool
}

// Selection is what a person picked: one level (optional), any packs, a
// scope.
type Selection struct {
	Level string
	Packs []string
	Scope Scope
	// FloorMode is the organization's [guard] mode floor on a managed node
	// ("" none, "observe", "enforce"): a project-scope level never emulates
	// a mode below it.
	FloorMode string
}

// Origin labels which part of a selection emitted a row.
type Origin string

// Row origins.
const (
	// OriginMode is a project-scope row emulating the level's mode.
	OriginMode Origin = "mode"
	// OriginLevel is a level (or a recipe it extends) row.
	OriginLevel Origin = "level"
	// OriginPack is a pack (or a recipe it extends) row.
	OriginPack Origin = "pack"
)

// EmittedOverride is one [[override]] row of a compiled file.
type EmittedOverride struct {
	OverrideRow
	// Recipe is the recipe that contributed the row ("" for mode rows).
	Recipe string
	Origin Origin
	// Kept is set on a pack row whose decision a stricter recipe row before
	// it kept: the file carries it as a comment (and the row's enforce
	// flag, when it sets one).
	Kept string
}

// Compiled is the result of Compile: the file to write and what it does.
type Compiled struct {
	// Text is the recipe policy file.
	Text []byte
	// Meta is its header (AppliedAt / AppliedVia / Previous as passed in).
	Meta Meta
	// Mode and PromptMode are what a global apply writes to [guard] mode and
	// [guard.prompt] mode ("" = leave as is). Always "" at project scope.
	Mode       string
	PromptMode string
	// Overrides are the emitted [[override]] rows in file order.
	Overrides []EmittedOverride
	// Disable is the emitted top-level disable list (project scope, mode
	// off only).
	Disable []string
	// RuleIDs are the emitted [[rule]] ids.
	RuleIDs []string
	// Advice and Inputs are the union over the selected recipes.
	Advice []string
	Inputs []string
	// Problems are pack rows that could only lower a rule (tighten.go):
	// they are not written, and an apply is refused while any is present.
	Problems []string
	// ModeNote explains a project-scope mode the organization's floor
	// keeps the compile from holding ("" when none).
	ModeNote string
}

// emulatedCategories are the catalog categories a project-scope level
// emulates its mode over. Budget and usage-limit rows are left out on
// purpose: their decisions are governed by [guard.budget] (and on a
// managed node by the organization), not by a strictness level.
var emulatedCategories = map[string]bool{
	"destructive": true, "boundary": true, "secrets": true, "exfil": true,
	"posture": true, "mcp": true, "injection": true, "taint": true,
	"anomaly": true, "pii": true,
}

// decisionRank orders the decision vocabulary.
var decisionRank = map[string]int{"allow": 0, "flag": 1, "ask": 2, "deny": 3}

// resolveSelection looks up the selected level and packs in set, refusing a
// name that is not in the catalog or is of the other kind, and records them
// on meta (a repeated pack counts once).
func resolveSelection(set *Set, sel Selection, meta *Meta) (*Recipe, []*Recipe, error) {
	meta.Level, meta.Packs = nil, nil
	var level *Recipe
	if sel.Level != "" {
		r, ok := set.Get(sel.Level)
		if !ok {
			return nil, nil, fmt.Errorf("guardrecipe.Compile: level %q is not in the catalog", sel.Level)
		}
		if r.Kind != KindLevel {
			return nil, nil, fmt.Errorf("guardrecipe.Compile: %q is a %s, not a level", sel.Level, r.Kind)
		}
		level = r
		meta.Level = &Ref{Name: r.Name, Version: r.Version}
	}
	var packs []*Recipe
	seenPack := map[string]bool{}
	for _, name := range sel.Packs {
		if seenPack[name] {
			continue
		}
		seenPack[name] = true
		r, ok := set.Get(name)
		if !ok {
			return nil, nil, fmt.Errorf("guardrecipe.Compile: pack %q is not in the catalog", name)
		}
		if r.Kind != KindPack {
			return nil, nil, fmt.Errorf("guardrecipe.Compile: %q is a %s, not a pack", name, r.Kind)
		}
		packs = append(packs, r)
		meta.Packs = append(meta.Packs, Ref{Name: r.Name, Version: r.Version})
	}
	return level, packs, nil
}

// Compile turns a selection into one recipe policy file. meta carries the
// apply-time fields (AppliedAt, AppliedVia, ProjectRoot, Previous); the
// selection fields of the header are filled in here. cat is the built-in
// rule catalog (needed for project-scope mode emulation; global scope reads
// it only to refuse a lowering row on an integrity rule).
func Compile(set *Set, sel Selection, cat []CatalogRule, meta Meta) (*Compiled, error) {
	if !ValidScope(sel.Scope) {
		return nil, fmt.Errorf("guardrecipe.Compile: scope %q not in {global, project}", sel.Scope)
	}
	if sel.Level == "" && len(sel.Packs) == 0 {
		return nil, errors.New("guardrecipe.Compile: nothing selected (choose a level, a pack, or both)")
	}
	integrity := map[string]bool{}
	for _, c := range cat {
		if c.Integrity {
			integrity[c.ID] = true
		}
	}

	out := &Compiled{}
	meta.Scope = sel.Scope
	level, packs, err := resolveSelection(set, sel, &meta)
	if err != nil {
		return nil, err
	}

	// The selected recipes, in fold order: the level's chain, then each
	// pack's chain. Rule definitions keep first-wins on a repeated id.
	type link struct {
		r      *Recipe
		origin Origin
	}
	var links []link
	collect := func(r *Recipe, origin Origin) error {
		chain, err := set.chain(r)
		if err != nil {
			return err
		}
		for _, c := range chain {
			links = append(links, link{c, origin})
		}
		return nil
	}
	if level != nil {
		if err := collect(level, OriginLevel); err != nil {
			return nil, err
		}
	}
	for _, p := range packs {
		if err := collect(p, OriginPack); err != nil {
			return nil, err
		}
	}
	var ruleRows []map[string]any
	ruleSeen := map[string]bool{}
	st := newStances(cat)
	for _, l := range links {
		for _, rr := range l.r.Rules {
			id := RuleID(rr)
			if ruleSeen[id] {
				continue
			}
			ruleSeen[id] = true
			ruleRows = append(ruleRows, rr)
			out.RuleIDs = append(out.RuleIDs, id)
			st.define(rr)
		}
		out.Advice = appendUnique(out.Advice, l.r.Advice...)
		out.Inputs = appendUnique(out.Inputs, l.r.Inputs...)
	}

	// A level's rows fold in last-wins (a level may lower a rule, an
	// integrity rule excepted); a pack's rows join tighten-only
	// (tighten.go).
	var rows []EmittedOverride
	for _, l := range links {
		for _, ov := range l.r.Overrides {
			if integrity[ov.Rule] && lowers(ov, cat) {
				return nil, fmt.Errorf("guardrecipe.Compile: recipe %s lowers %s, an integrity rule no recipe may weaken", l.r.Name, ov.Rule)
			}
			if l.origin != OriginPack {
				st.apply(ov)
				rows = append(rows, EmittedOverride{OverrideRow: ov, Recipe: l.r.Name, Origin: l.origin})
				continue
			}
			row, kept, problem := st.tighten(l.r.Name, ov)
			if problem != "" {
				out.Problems = append(out.Problems, problem)
			}
			rows = append(rows, EmittedOverride{OverrideRow: row, Recipe: l.r.Name, Origin: l.origin, Kept: kept})
		}
	}

	// Project scope cannot carry the mode, so it is emulated on every
	// catalog rule the selection does not name, never below the
	// organization's mode floor; global scope writes it.
	var modeRows []EmittedOverride
	if level != nil {
		if sel.Scope == ScopeGlobal {
			out.Mode, out.PromptMode = level.Mode, level.PromptMode
			meta.Mode, meta.PromptMode = level.Mode, level.PromptMode
		} else {
			named := map[string]bool{}
			for _, r := range rows {
				named[r.Rule] = true
			}
			mode, note := emulatedMode(level.Mode, sel.FloorMode)
			out.ModeNote = note
			modeRows, out.Disable = emulateMode(mode, cat, named)
		}
	}
	modeRows = append(modeRows, rows...)
	out.Overrides = modeRows
	out.Meta = meta
	out.Text = render(out, level, packs, ruleRows)
	return out, nil
}

// floorEmulation is how a project-scope level's mode is emulated under the
// organization's [guard] mode floor on a managed node (sweep finding CFG-2:
// a project recipe must not hold a mode the floor forbids machine-wide).
// Walked top-down, first match wins; no match emulates the level's mode.
// emulate "" writes no mode rows at all.
var floorEmulation = []struct {
	floor, level, emulate, note string
}{
	{"enforce", "off", "", "Your organization keeps the mode at enforce, so the level's \"off\" is not held in this project: no rule is switched off."},
	{"enforce", "observe", "", "Your organization keeps the mode at enforce, so the level's \"observe\" is not held in this project: no rule is capped at flag."},
	{"observe", "off", "observe", "Your organization keeps the guard on (observe at least), so the level's \"off\" is held as observe in this project: rules are capped at flag, none is switched off."},
}

// emulatedMode returns the mode a project-scope level is emulated as under
// floor, and the note that explains a difference ("" when none).
func emulatedMode(level, floor string) (string, string) {
	for _, r := range floorEmulation {
		if r.floor == floor && r.level == level {
			return r.emulate, r.note
		}
	}
	return level, ""
}

// lowers reports whether an override row would weaken the rule it names
// against the catalog: a cap (enforce = false), or a decision below the
// rule's catalog enforce decision.
func lowers(ov OverrideRow, cat []CatalogRule) bool {
	if ov.Enforce != nil && !*ov.Enforce {
		return true
	}
	if ov.Decision == "" {
		return false
	}
	for _, c := range cat {
		if c.ID == ov.Rule {
			return decisionRank[ov.Decision] < decisionRank[c.Enforce]
		}
	}
	return false
}

// emulateMode returns the project-scope rows that make a level's mode hold
// in one project whatever the machine-wide mode is: off disables every
// emulated, non-integrity rule; observe caps every one that could block;
// enforce marks enforced every one whose enforce decision is stricter than
// its observe decision. Rules the selection names are left to their rows.
func emulateMode(mode string, cat []CatalogRule, named map[string]bool) ([]EmittedOverride, []string) {
	var rows []EmittedOverride
	var disable []string
	ids := make([]CatalogRule, 0, len(cat))
	for _, c := range cat {
		if emulatedCategories[c.Category] && !named[c.ID] && !c.ModuleRule {
			ids = append(ids, c)
		}
	}
	sort.SliceStable(ids, func(i, j int) bool { return ids[i].ID < ids[j].ID })
	f, t := false, true
	for _, c := range ids {
		switch mode {
		case "off":
			if !c.Integrity {
				disable = append(disable, c.ID)
			}
		case "observe":
			if !c.Integrity && decisionRank[c.Enforce] > decisionRank["flag"] {
				rows = append(rows, EmittedOverride{OverrideRow: OverrideRow{Rule: c.ID, Enforce: &f}, Origin: OriginMode})
			}
		case "enforce":
			if decisionRank[c.Enforce] > decisionRank[c.Observe] {
				rows = append(rows, EmittedOverride{OverrideRow: OverrideRow{Rule: c.ID, Enforce: &t}, Origin: OriginMode})
			}
		}
	}
	return rows, disable
}

// appendUnique appends the strings of add that dst does not hold yet.
func appendUnique(dst []string, add ...string) []string {
	for _, a := range add {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		if !slices.Contains(dst, a) {
			dst = append(dst, a)
		}
	}
	return dst
}
