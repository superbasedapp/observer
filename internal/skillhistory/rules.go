package skillhistory

import (
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/guidance"
)

// skillPattern is one KindSkill discovery row reduced to the shape this
// package needs: a skill directory is Prefix + <one segment>, and its
// version file is that directory + "/" + File.
type skillPattern struct {
	Tool   string
	Scope  string
	Prefix string // e.g. ".claude/skills/" or "~/.claude/skills/"
	File   string // e.g. "SKILL.md"
}

// skillPatterns walks the discovery table and keeps every KindSkill row
// whose glob has the "<prefix>*/<file>" shape. A row of any other shape is
// ignored (it cannot name a skill directory), never guessed at.
func skillPatterns(rules []guidance.Rule) []skillPattern {
	var out []skillPattern
	for _, r := range rules {
		if r.Kind != guidance.KindSkill {
			continue
		}
		i := strings.Index(r.Glob, "*")
		if i < 0 || strings.Contains(r.Glob, "**") || strings.Count(r.Glob, "*") != 1 {
			continue
		}
		prefix, rest := r.Glob[:i], r.Glob[i+1:]
		if !strings.HasSuffix(prefix, "/") || !strings.HasPrefix(rest, "/") || strings.Contains(rest[1:], "/") {
			continue
		}
		out = append(out, skillPattern{Tool: r.Tool, Scope: string(r.Scope), Prefix: prefix, File: rest[1:]})
	}
	return out
}

// dirMatch is what one path resolves to against the skill patterns.
type dirMatch struct {
	Scope     string
	Dir       string // prefix + name, no trailing slash, original case
	IsVersion bool   // the path is the directory's version file (SKILL.md)
	File      string // the version file name the pattern declares
	Tools     []string
}

// matchSkillPath resolves a project-relative (or "~/"-prefixed) path to
// the skill directory it lives in, if any, and the tools whose discovery
// row reads that directory. ok=false when no pattern claims the path.
func matchSkillPath(rel string, patterns []skillPattern) (dirMatch, bool) {
	return matchSkillPathFold(rel, patterns, false)
}

// matchSkillPathFold is matchSkillPath with an optional case-insensitive
// prefix comparison for PROJECT-scope patterns (a checkout on a
// case-insensitive filesystem, core.ignorecase=true, may record
// ".Claude/Skills/..."). The returned Dir keeps the path's own case.
func matchSkillPathFold(rel string, patterns []skillPattern, foldProject bool) (dirMatch, bool) {
	var m dirMatch
	found := false
	for _, p := range patterns {
		fold := foldProject && p.Scope == ScopeProject
		if len(rel) < len(p.Prefix) {
			continue
		}
		if fold && !strings.EqualFold(rel[:len(p.Prefix)], p.Prefix) {
			continue
		}
		if !fold && !strings.HasPrefix(rel, p.Prefix) {
			continue
		}
		tail := rel[len(p.Prefix):]
		seg, after, hasAfter := strings.Cut(tail, "/")
		if seg == "" || !hasAfter || after == "" {
			continue
		}
		dir := rel[:len(p.Prefix)] + seg
		if found && (m.Dir != dir || m.Scope != p.Scope) {
			continue
		}
		m.Scope, m.Dir, m.File = p.Scope, dir, p.File
		if strings.EqualFold(after, p.File) {
			m.IsVersion = true
		}
		m.Tools = appendUnique(m.Tools, p.Tool)
		found = true
	}
	sort.Strings(m.Tools)
	return m, found
}

// DirPattern is one skill-directory convention a tool reads: a skill is
// Prefix + <name> + "/" + File. Prefix is project-relative, or "~/"-prefixed
// for user scope.
type DirPattern struct {
	Scope  string
	Prefix string
	File   string
}

// DirPatterns returns the skill-directory conventions tool reads, from the
// discovery table (the KindSkill rows). The hook uses it to find an
// invoked skill's file without hard-coding where a tool keeps skills.
func DirPatterns(rules []guidance.Rule, tool string) []DirPattern {
	var out []DirPattern
	for _, p := range skillPatterns(rules) {
		if p.Tool == tool {
			out = append(out, DirPattern{Scope: p.Scope, Prefix: p.Prefix, File: p.File})
		}
	}
	return out
}

// Pathspecs returns the literal project-scope directory pathspecs that
// cover every skill directory the discovery table knows about (e.g.
// ".claude/skills"). They are literal, never glob magic, so git can use
// its changed-path filters and no pathspec parsing surprise applies. The
// git step passes them to ls-tree and the status porcelain.
func Pathspecs(rules []guidance.Rule) []string {
	var out []string
	for _, p := range skillPatterns(rules) {
		if p.Scope != ScopeProject {
			continue
		}
		out = appendUnique(out, strings.TrimSuffix(p.Prefix, "/"))
	}
	sort.Strings(out)
	return out
}

// IsSkillPath reports whether a project-relative path lives under a
// project-scope skill directory. The store seam uses it to filter the
// commit timeline down to skill files.
func IsSkillPath(rel string, rules []guidance.Rule) bool {
	m, ok := matchSkillPath(rel, skillPatterns(rules))
	return ok && m.Scope == ScopeProject
}

// ToolsReading returns the tools whose discovery row reads the skill
// directory holding rel (sorted), or nil.
func ToolsReading(rel string, rules []guidance.Rule) []string {
	m, ok := matchSkillPath(rel, skillPatterns(rules))
	if !ok {
		return nil
	}
	return m.Tools
}

func appendUnique(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}
