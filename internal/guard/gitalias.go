package guard

// GitAliasLookup returns the git aliases in force for a directory (alias
// name, lowercased, to its expansion) and whether any alias table covers
// that directory. The cmd composition wires it to the per-project alias
// table the daemon precomputes (internal/gitalias); guard never runs git
// and never reads that file itself. A lookup must not block: it is called
// on the hook's reply path.
type GitAliasLookup func(dir string) (aliases map[string]string, ok bool)

// SetGitAliasLookup wires the alias table the R-112 to R-114 rows read
// (policy.Config.GitAliases), so `git ci` is judged as the `commit
// --no-verify` it runs. Nil leaves the rows to aliases defined on the
// command line itself. Safe to call after construction: every engine
// reads the lookup through gitAliasesFor at evaluation time.
func (g *Guard) SetGitAliasLookup(fn GitAliasLookup) {
	if fn == nil {
		g.gitAliases.Store(nil)
		return
	}
	g.gitAliases.Store(&fn)
}

// gitAliasesFor is the policy.Config.GitAliases every engine this guard
// builds carries.
func (g *Guard) gitAliasesFor(dir string) (map[string]string, bool) {
	fn := g.gitAliases.Load()
	if fn == nil {
		return nil, false
	}
	return (*fn)(dir)
}
