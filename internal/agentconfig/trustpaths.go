package agentconfig

import (
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/marmutapp/superbased-observer/internal/hookdisable"
)

// TrustClass says how the repository trust check reads one path of the
// trust path table (security pillar plan section 5.1 item 2). The
// vocabulary is closed and names a PARSING shape, never a tool.
type TrustClass string

// The closed TrustClass vocabulary.
const (
	// TrustStructured is a settings, MCP, hooks or permissions file: parsed
	// (JSON with comments, TOML or YAML) and judged key by key.
	TrustStructured TrustClass = "structured"
	// TrustCode is a plugin or hook script the agent loads and runs: judged
	// by its content digest only, never parsed.
	TrustCode TrustClass = "code"
	// TrustProse is an instruction, rule, skill, agent or command file:
	// judged for hidden Unicode only.
	TrustProse TrustClass = "prose"
	// TrustEnv is a dotenv file: judged by variable name (and, in memory
	// only, a few values such as a base URL).
	TrustEnv TrustClass = "env"
	// TrustGitConfig is a repository's .git/config: judged by key.
	TrustGitConfig TrustClass = "gitconfig"
	// TrustGitAttributes is a .gitattributes file: the filter, diff and
	// merge drivers it names.
	TrustGitAttributes TrustClass = "gitattributes"
	// TrustTasks is a VS Code tasks.json: tasks that run when the folder
	// opens.
	TrustTasks TrustClass = "tasks"
	// TrustConfigDir is a configuration directory: the directory itself and
	// its direct children are checked for symlinks that leave the root.
	TrustConfigDir TrustClass = "config_dir"
)

// RepositoryFile is a repository file that is not one tool's own
// configuration but changes what an agent launched in the repository runs
// or where it sends traffic (plan section 5.1 item 2, the "extra rows" the
// JSP-7 spike moved into this package so the catalogue stays the one owner
// of the path table).
type RepositoryFile struct {
	// ID is "repo/<name>", unique.
	ID string
	// Rel is the slash-separated path relative to a root.
	Rel   string
	Class TrustClass
	// RepoRootOnly marks a file that is read at the repository root only
	// (.git/config has no meaning in a subdirectory).
	RepoRootOnly bool
	Grounding    Grounding
	Note         string
}

// jsp7 is the grounding of the rows the JSP-7 spike measured.
func jsp7(what string) Grounding {
	return Grounding{Kind: GroundSource, Source: "docs/plans/spikes/JSP-7-repository-trust-2026-10.md: " + what, Date: "2026-10-20"}
}

// repositoryFiles is the extra-row table, in reading order.
var repositoryFiles = []RepositoryFile{
	{
		ID: "repo/dotenv", Rel: ".env", Class: TrustEnv, Grounding: jsp7("fixture 04 (CVE-2025-61260, CODEX_HOME) and fixture 18 (OBSERVER_BIN)"),
		Note: "Agents and their launchers load it into the environment. Only variable names are judged; values never leave memory.",
	},
	{
		ID: "repo/dotenv-local", Rel: ".env.local", Class: TrustEnv, Grounding: jsp7("plan section 5.1 .env keys"),
		Note: "The local spelling of .env.",
	},
	{
		ID: "repo/gemini-dotenv", Rel: ".gemini/.env", Class: TrustEnv, Grounding: jsp7("gemini-cli loads .gemini/.env"),
		Note: "Also a catalogue row (gemini-cli/project-env), which marks it never shown or edited.",
	},
	{
		ID: "repo/git-config", Rel: ".git/config", Class: TrustGitConfig, RepoRootOnly: true,
		Grounding: jsp7("fixture 05 (CVE-2026-19592, core.fsmonitor) and fixture 17 (filter driver)"),
		Note:      "Its rules fire only on a tree that arrived by archive, copy or an agent's edit: a fresh git clone writes its own .git/config.",
	},
	{
		ID: "repo/gitattributes", Rel: ".gitattributes", Class: TrustGitAttributes, Grounding: jsp7("fixture 17 (a .gitattributes driver defined in .git/config)"),
		Note: "A driver it names matters only when .git/config defines it.",
	},
	{
		ID: "repo/vscode-tasks", Rel: ".vscode/tasks.json", Class: TrustTasks, Grounding: jsp7("fixture 16 (a folder-open task)"),
		Note: "A task with runOptions.runOn = folderOpen runs when the editor opens the folder.",
	},
}

// RepositoryFiles returns the extra-row table (a copy).
func RepositoryFiles() []RepositoryFile {
	return append([]RepositoryFile(nil), repositoryFiles...)
}

// TrustPath is one row of the repository trust path table: a path read at
// each root the check visits (the repository root, the launch directory
// and the directories between them; no walk).
type TrustPath struct {
	// Rel is slash-separated and relative to a root. A trailing "/" names a
	// directory whose entries are read; a "*" segment is a one-level glob.
	Rel   string
	Class TrustClass
	// RepoRootOnly: read at the repository root only.
	RepoRootOnly bool
	// Sources are the ids of the rows the path came from (Files rows,
	// hookdisable switches, repository rows), sorted.
	Sources []string
}

var (
	trustOnce     sync.Once
	trustCompiled []TrustPath
)

// TrustPaths returns the repository trust path table: every project-shared
// and project-local Files row, the project rows of hookdisable.Switches,
// the repository rows, and one config-directory row for every leading
// dot-directory those paths name. A "**/" glob keeps only its root-level
// instance, because a "**" glob needs a walk. Sorted by Rel; compiled once.
func TrustPaths() []TrustPath {
	trustOnce.Do(func() { trustCompiled = compileTrustPaths(nil) })
	out := make([]TrustPath, len(trustCompiled))
	for i, p := range trustCompiled {
		p.Sources = append([]string(nil), p.Sources...)
		out[i] = p
	}
	return out
}

// trustClassFor is the class a Files row is read as; ok is false for a row
// the trust check does not read (tool state: credentials and caches).
func trustClassFor(f FileRow) (TrustClass, bool) {
	switch {
	case f.Kind == KindToolState:
		return "", false
	case f.Kind == KindInstructions, f.Kind == KindRule, f.Kind == KindSkill, f.Kind == KindAgent, f.Kind == KindCommand:
		return TrustProse, true
	case f.Format == FormatScript, f.Format == FormatCrushrc:
		// Code the tool loads (a plugin, a crushrc whose $(...) runs at
		// load): judged by digest, never parsed.
		return TrustCode, true
	default:
		return TrustStructured, true
	}
}

// compileTrustPaths assembles the table; extra are conditional repository
// rows whose condition holds (TrustPathsWith), nil for the default table.
func compileTrustPaths(extra []RepositoryFile) []TrustPath {
	byRel := map[string]*TrustPath{}
	var order []string
	add := func(rel string, class TrustClass, rootOnly bool, source string) {
		if p, ok := byRel[rel]; ok {
			if !slices.Contains(p.Sources, source) {
				p.Sources = append(p.Sources, source)
			}
			return
		}
		byRel[rel] = &TrustPath{Rel: rel, Class: class, RepoRootOnly: rootOnly, Sources: []string{source}}
		order = append(order, rel)
	}
	for _, f := range filesTable() {
		if f.Scope != ScopeProjectShared && f.Scope != ScopeProjectLocal {
			continue
		}
		class, ok := trustClassFor(f)
		if !ok {
			continue
		}
		rel, ok := strings.CutPrefix(f.Paths.Linux, "<project>/")
		if !ok {
			continue // a project-local file kept under the home directory
		}
		add(strings.ReplaceAll(rel, "**/", ""), class, false, f.ID)
	}
	for _, s := range hookdisable.Switches {
		if s.Scope == hookdisable.ScopeProject {
			add(s.ProjectRel, TrustStructured, false, "hookdisable:"+s.ID)
		}
	}
	for _, r := range append(append([]RepositoryFile(nil), repositoryFiles...), extra...) {
		add(r.Rel, r.Class, r.RepoRootOnly, r.ID)
	}
	// One config-directory row per leading dot-directory (".git" is git's
	// own and never a symlink target the agent follows).
	for _, rel := range append([]string(nil), order...) {
		first, rest, ok := strings.Cut(rel, "/")
		if !ok || rest == "" || !strings.HasPrefix(first, ".") || first == ".git" {
			continue
		}
		add(first+"/", TrustConfigDir, false, "dir:"+first)
	}
	out := make([]TrustPath, 0, len(byRel))
	for _, rel := range order {
		p := *byRel[rel]
		sort.Strings(p.Sources)
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Rel < out[j].Rel })
	return out
}

// TrustUserPaths returns the user-scope half of the config baseline's path
// table for one machine (security pillar plan section 5.1 item 1): every
// user-scope Files row the trust check would read (never tool state, which
// holds credentials and caches), resolved for e and made relative to
// e.Home, in the TrustPath shape the check reads against a root at the home
// directory. A row that does not resolve on e's OS, resolves outside the
// home directory, names a token the env cannot expand (the VS Code user
// directory), or needs a walk ("**") is left out. Sorted by Rel.
func TrustUserPaths(e PathEnv) []TrustPath {
	home := strings.TrimRight(e.native(e.Home), `/\`)
	if home == "" {
		return nil
	}
	byRel := map[string]*TrustPath{}
	for _, f := range filesTable() {
		if f.Scope != ScopeUser {
			continue
		}
		class, ok := trustClassFor(f)
		if !ok {
			continue
		}
		rp := ResolvePath(f, e)
		if rp.Status != PathResolved && rp.Status != PathGlob && rp.Status != PathDirectory {
			continue
		}
		rel, ok := e.underHome(home, rp.Path)
		if !ok || strings.Contains(rel, "**") {
			continue
		}
		if rp.Status == PathDirectory && !strings.HasSuffix(rel, "/") {
			rel += "/"
		}
		if p, ok := byRel[rel]; ok {
			if !slices.Contains(p.Sources, f.ID) {
				p.Sources = append(p.Sources, f.ID)
			}
			continue
		}
		byRel[rel] = &TrustPath{Rel: rel, Class: class, Sources: []string{f.ID}}
	}
	out := make([]TrustPath, 0, len(byRel))
	for _, p := range byRel {
		sort.Strings(p.Sources)
		out = append(out, *p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Rel < out[j].Rel })
	return out
}

// underHome returns p relative to home, slash-separated, when p is inside
// home (case-insensitively on Windows, whose paths are).
func (e PathEnv) underHome(home, p string) (string, bool) {
	sep := "/"
	if e.windows() {
		sep = `\`
	}
	if len(p) <= len(home)+1 || p[len(home):len(home)+1] != sep {
		return "", false
	}
	prefix := p[:len(home)]
	if prefix != home && (!e.windows() || !strings.EqualFold(prefix, home)) {
		return "", false
	}
	return strings.ReplaceAll(p[len(home)+1:], `\`, "/"), true
}
