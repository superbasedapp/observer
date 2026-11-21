// Package complexity is the pure, table-driven cyclomatic-complexity
// counter of the code-intelligence index (docs/codeintel/parsing.md
// "Complexity"; the Projects page's complexity metric,
// docs/projects-page.md "Quality metrics"; plan
// docs/plans/os-and-ci-vulnerability-scanning-plan-2026-11-04.md section
// 14.10, item 8, M3L-4).
//
// A function's complexity is its decision points + 1 (McCabe). A decision
// point is one row of the per-language rule table in rules.go: a grammar
// node kind and the anonymous token inside it whose position marks the
// decision (an `if`, a loop keyword, a non-default case arm, a catch, a
// short-circuit operator, a ternary). The table is DATA: the tree-sitter
// backend compiles a language's rows into one query (Query), and the go/ast
// backend looks Go's rows up by AST type and token (GoDecision). Count then
// attributes every decision position to the innermost function or method
// whose exact byte span contains it.
//
// Only an exact-span backend counts (go/ast and tree-sitter): a heuristic
// span cannot say which function a decision belongs to, so a heuristic file
// gets no figure (Node.Complexity stays 0, persisted as NULL), never zero.
// A language with no rows gets no figure either.
//
// What is deliberately not counted, per row notes in rules.go: `else`
// (the branch was counted at its `if`), a default or else arm of a switch
// when the grammar tells it apart, Rust's unconditional `loop`, and the
// error-propagation operators (`?` in Rust, `try` in Swift). Closures and
// lambdas are not nodes of the index, so their decisions count toward the
// enclosing function, as gocyclo does.
//
// It is PURE (CLAUDE.md module rule 1, pinned by
// internal/codeintel/imports_test.go): no SQL, HTTP, fsnotify or file I/O.
package complexity
