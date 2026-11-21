// Package guardrecipe is the PURE half of guard recipes
// (docs/guard-recipes.md; plan docs/plans/profile-guard-recipes-repo-grouping-plan-2026-11-07.md
// section 3): quick-setup policy presets on two axes, composed.
//
//   - A LEVEL (one per scope) is a strictness preset: none, loose, balanced,
//     strict, lockdown. It carries the guard mode and the [guard.prompt]
//     mode it implies, plus [[override]] / [[rule]] rows.
//   - A PACK (any number) is a function preset: frontend, backend and
//     database, devops and infra, networking, data and ML, regulated. It
//     carries rows only.
//
// A recipe is a TOML file in the guard policy-file vocabulary
// (internal/guard/policyfile.go: [[override]] and [[rule]]) plus a few
// metadata keys. The catalog is the embedded set (catalog/*.toml) plus the
// user's own recipes in the guard-recipes directory beside the user policy
// file; a user recipe never shadows a built-in name.
//
// Compile turns a selection (level, packs, scope) into ONE policy file: the
// managed recipe file the guard folds into the user layer (scope global) or
// the trusted per-project layer (scope project), BEFORE that layer's own
// file so the person's own edits win over the recipe. Effective policy is
// therefore: built-ins, level rows, pack rows, the person's own edits, and
// the org floor over all of it (escalate-only, internal/guard/merge.go). A
// level's rows fold in last-wins; a pack's rows join tighten-only
// (tighten.go): the stricter decision, the enforce flags OR-ed, and a pack
// row that could only lower a rule is a Compiled.Problem, never a row. The
// file starts with a machine-readable header line (Meta) naming what was
// applied and what the apply replaced, so a remove can restore it.
//
// Project scope cannot carry a mode (the mode is machine-wide), so a
// level's mode is emulated there with explicit rows: `disable` for mode off,
// `enforce = false` caps for mode observe and `enforce = true` for mode
// enforce, on every catalog rule the level and packs do not name, and never
// below the organization's mode floor (Selection.FloorMode, floorEmulation).
// Global scope writes the mode itself and needs none of them.
//
// The package does no I/O and imports no Observer package: the built-in
// rule catalog arrives as data (CatalogRule), and the compiled file is
// checked by the guard's own lint at the I/O boundary
// (internal/guardrecipesvc), so the policy grammar keeps one owner.
package guardrecipe
