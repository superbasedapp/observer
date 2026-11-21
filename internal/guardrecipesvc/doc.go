// Package guardrecipesvc is the I/O half of guard recipes
// (docs/guard-recipes.md): it reads the catalog (the embedded recipes and the
// person's own in the guard-recipes directory), previews a selection against
// the real guard (the rule decisions it changes, the guard's own lint, the
// load issues it would raise), and applies or removes one: the ONE writer of
// the managed recipe files (internal/guard/recipelayer.go names their paths)
// and of [guard] level, [guard] mode and [guard.prompt] mode on apply and
// remove. The pure half (parse, compile, header) is internal/guardrecipe.
//
// The CLI (`observer guard recipe`) and the dashboard's Recipes card both
// call it, so the preview a person reads and the write they confirm come
// from the same code. Neither surface is agent-reachable: R-165 denies an
// agent's `observer guard recipe apply|remove|save|delete` and its writes to
// the /api/guard/recipes routes (internal/policy/rules_selfapproval.go), and
// the files themselves sit inside R-160's ~/.observer deny surface.
package guardrecipesvc
