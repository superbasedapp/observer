package sectrust

import (
	"strings"
	"sync"

	"github.com/marmutapp/superbased-observer/internal/agentconfig"
)

// The developer's own files (lane SEC-TRUSTFIX, plans decision log P-016).
// Some table files are where the developer, their tools and git keep the
// developer's own settings: a project-local scope file of the agent-config
// catalogue (.claude/settings.local.json and siblings, gitignored by the
// vendor), the repository's .git/config (git writes it on `git push -u`,
// `git remote add` and the like) and the dotenv files. They stay judged,
// because a planted repository can still ship them (an archive or a copy
// carries .git/config; a repository can force-commit a local file), but
// every reason found in one carries a digest the developer can accept,
// unless its code is Fixed. So the developer's own setting asks once, and
// asks again only when it changes; it never refuses or asks forever.

// ownRow is one row of the own-file table: the rule a group of table paths
// follows.
type ownRow struct {
	// match reports whether a path-table row (its Rel) is in the group.
	match func(rel string) bool
	// why is the rule's reason, for the doc and the tests.
	why string
}

// ownRepositoryFiles are the repository rows that hold the developer's own
// settings (agentconfig.RepositoryFiles ids repo/git-config, repo/dotenv,
// repo/dotenv-local, repo/gemini-dotenv).
var ownRepositoryFiles = map[string]bool{".git/config": true, ".env": true, ".env.local": true, ".gemini/.env": true}

// ownRows is the ordered own-file table; the first matching row decides.
var ownRows = []ownRow{
	{
		match: func(rel string) bool { return ownRepositoryFiles[rel] },
		why:   "git and the developer write .git/config, and the dotenv files hold the developer's own variables",
	},
	{
		match: func(rel string) bool { return localScopePaths()[rel] },
		why:   "a project-local scope file of the agent-config catalogue is the developer's own (the vendor gitignores it, and the tool writes it, for example a permission grant)",
	},
}

var (
	localOnce  sync.Once
	localPaths map[string]bool
)

// localScopePaths are the root-relative paths of the catalogue's project
// local rows that no project-shared row also names.
func localScopePaths() map[string]bool {
	localOnce.Do(func() {
		local, shared := map[string]bool{}, map[string]bool{}
		for _, f := range agentconfig.Files() {
			rel, ok := strings.CutPrefix(f.Paths.Linux, "<project>/")
			if !ok {
				continue
			}
			rel = strings.ReplaceAll(rel, "**/", "")
			switch f.Scope {
			case agentconfig.ScopeProjectLocal:
				local[rel] = true
			case agentconfig.ScopeProjectShared:
				shared[rel] = true
			}
		}
		for rel := range shared {
			delete(local, rel)
		}
		localPaths = local
	})
	return localPaths
}

// ownTableRow reports whether a path-table row (its root-relative Rel) is
// one of the developer's own files.
func ownTableRow(rel string) bool {
	for _, r := range ownRows {
		if r.match(rel) {
			return true
		}
	}
	return false
}

// ownFile reports whether a file path, relative to the repository root and
// possibly under a nested root, is one of the developer's own files.
func ownFile(rel string) bool {
	for {
		if ownTableRow(rel) {
			return true
		}
		_, rest, ok := strings.Cut(rel, "/")
		if !ok {
			return false
		}
		rel = rest
	}
}

// OwnFile reports whether a file path relative to the repository root is
// one of the developer's own files (the own-file table): the config
// baseline grades its changes by that.
func OwnFile(rel string) bool { return ownFile(rel) }
