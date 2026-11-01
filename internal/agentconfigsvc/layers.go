package agentconfigsvc

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/agentconfig"
	"github.com/marmutapp/superbased-observer/internal/integration"
)

// The effective-layer pass (surface-gap Wave 4, lane w4-layers): the I/O
// half of agentconfig.EvaluateLayers. It reads every file the families
// name, the user, system and managed files once and each project's files
// once per project, resolving each path through the service's one path
// environment (Service.env, Relocate on), so a relocation variable
// (CLAUDE_CONFIG_DIR, CODEBUDDY_CONFIG_DIR, ...) moves the file read here
// exactly as it moves the tool's, and exactly as it moves the file the
// editor saves. The usual read rules hold: a PrivNever file is never opened
// (the catalogue's credential stores), every read is size-capped, and no
// value leaves this function: a file is decoded only to be classified.
//
// The runtime layers come from the injected environment (Options.Getenv,
// never os.Getenv here): the route variable a registry row names
// (ProxyRoute.EnvVar), the config document it carries
// (ProxyRoute.ConfigContentEnv), and, for a row whose tool loads .env files
// itself (ProxyRoute.DotenvOverride), whether such a file sets one of the
// row's keys, read by NAME only (agentconfig.DotenvKeysPresent).

// LayerMaxProjects bounds the projects one pass reads (the same bound the
// hook-switch scan uses, store.RecentProjectRoots' cap).
const LayerMaxProjects = 64

// LayerOptions are the inputs of one effective-layer pass.
type LayerOptions struct {
	// Projects are the project directories to evaluate, most recent first;
	// at most LayerMaxProjects distinct non-empty ones are read.
	Projects []string
	// OwnHookCommand recognises Observer's own hook commands
	// (internal/hook.IsObserverHookCommand); nil sees none.
	OwnHookCommand func(command string) bool
	// Tools restricts the pass to these tools (nil: every family's tool).
	Tools []string
	// Runtime are runtime trees the caller's own reader already read, key
	// names only (an OS preferences domain: internal/hook.PolicyDomainLayers,
	// FU-105). A tree whose tool has no family in the pass is dropped.
	Runtime []agentconfig.RuntimeTree
}

// LayerReport is one pass's findings and the files they name.
type LayerReport struct {
	Findings []agentconfig.LayerFinding
	paths    map[string]string
}

// Path returns the local path of the file a finding's winning source names
// ("" for a runtime layer). It is node-local and never leaves the node.
func (r LayerReport) Path(f agentconfig.LayerFinding) string {
	if f.Winning.FileID == "" {
		return ""
	}
	if p, ok := r.paths[layerPathKey(f.Project, f.Winning.FileID)]; ok {
		return p
	}
	return r.paths[layerPathKey("", f.Winning.FileID)]
}

func layerPathKey(project, fileID string) string { return project + "\x00" + fileID }

// EffectiveLayers runs every effective-layer family over the files this
// node can read.
func (s *Service) EffectiveLayers(ctx context.Context, o LayerOptions) (LayerReport, error) {
	fams := layerFamilies(o.Tools)
	projects := boundedProjects(o.Projects)
	rep := LayerReport{paths: map[string]string{}}
	var files []agentconfig.LayerFile
	read := map[string]bool{}
	for _, row := range agentconfig.Files() {
		if ctx.Err() != nil {
			return rep, ctx.Err()
		}
		if !familyWants(fams, row) {
			continue
		}
		scopes := []string{""}
		if row.Scope == agentconfig.ScopeProjectShared || row.Scope == agentconfig.ScopeProjectLocal {
			scopes = projects
		}
		for _, p := range scopes {
			if read[layerPathKey(p, row.ID)] {
				continue
			}
			read[layerPathKey(p, row.ID)] = true
			lf, path, ok := s.layerFile(row, p)
			if !ok {
				continue
			}
			rep.paths[layerPathKey(p, row.ID)] = path
			files = append(files, lf)
		}
	}
	findings, err := agentconfig.EvaluateLayers(agentconfig.LayerInput{
		Files: files, Runtime: mergeRuntime(append(s.runtimeTrees(fams, projects), callerTrees(fams, o.Runtime)...)), Projects: projects,
		Classify: agentconfig.ClassifyContext{OwnHookCommand: o.OwnHookCommand}, Families: fams,
	})
	if err != nil {
		return rep, err
	}
	rep.Findings = findings
	return rep, nil
}

// callerTrees keeps the caller-read trees whose tool has a family in fams
// (a copy of each tree, so the merge never writes into the caller's map).
func callerTrees(fams []agentconfig.Family, in []agentconfig.RuntimeTree) []agentconfig.RuntimeTree {
	tools := map[string]bool{}
	for _, f := range fams {
		tools[f.Tool] = true
	}
	var out []agentconfig.RuntimeTree
	for _, rt := range in {
		if !tools[rt.Tool] || rt.Tree == nil {
			continue
		}
		cp := rt
		cp.Tree = map[string]any{}
		mergeInto(cp.Tree, rt.Tree)
		out = append(out, cp)
	}
	return out
}

// layerFamilies picks the families of tools (all when tools is nil).
func layerFamilies(tools []string) []agentconfig.Family {
	all := agentconfig.Families()
	if tools == nil {
		return all
	}
	want := map[string]bool{}
	for _, t := range tools {
		want[t] = true
	}
	var out []agentconfig.Family
	for _, f := range all {
		if want[f.Tool] {
			out = append(out, f)
		}
	}
	return out
}

func familyWants(fams []agentconfig.Family, row agentconfig.FileRow) bool {
	for _, f := range fams {
		if f.Tool == row.Tool && f.Shape == row.Shape {
			return true
		}
	}
	return false
}

func boundedProjects(ps []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range ps {
		if p == "" {
			continue
		}
		c := filepath.Clean(p)
		if seen[c] {
			continue
		}
		seen[c] = true
		out = append(out, c)
		if len(out) == LayerMaxProjects {
			break
		}
	}
	return out
}

// layerFile reads one row at one project (never a PrivNever file) and
// decodes it; ok is false when nothing was observed (absent, never read,
// unresolvable, unreadable or not decodable).
func (s *Service) layerFile(row agentconfig.FileRow, project string) (agentconfig.LayerFile, string, bool) {
	snap := s.snapshot(row, s.env(project))
	if snap.State != agentconfig.FilePresent {
		return agentconfig.LayerFile{}, "", false
	}
	tree := agentconfig.DecodeTree(row, snap.Bytes)
	if tree == nil {
		return agentconfig.LayerFile{}, "", false
	}
	return agentconfig.LayerFile{Row: row, Project: project, Tree: tree}, snap.Resolved.Path, true
}

// runtimeTrees builds the runtime layers of the families' tools from the
// injected environment and the tools' own .env files.
func (s *Service) runtimeTrees(fams []agentconfig.Family, projects []string) []agentconfig.RuntimeTree {
	var out []agentconfig.RuntimeTree
	for _, f := range fams {
		c, ok := integration.For(f.Tool)
		if !ok || c.Proxy == nil {
			continue
		}
		p := c.Proxy
		if _, ranked := f.RuntimeRanks[agentconfig.RuntimeLaunchEnv]; ranked && p.EnvVar != "" {
			if v := s.o.Getenv(p.EnvVar); strings.TrimSpace(v) != "" {
				if tree := familyTree(f, p.EnvVar, v); tree != nil {
					out = append(out, agentconfig.RuntimeTree{Tool: f.Tool, Layer: agentconfig.RuntimeLaunchEnv, Tree: tree})
				}
			}
		}
		if _, ranked := f.RuntimeRanks[agentconfig.RuntimeConfigContent]; ranked && p.ConfigContentEnv != "" {
			if v := s.o.Getenv(p.ConfigContentEnv); strings.TrimSpace(v) != "" {
				var tree map[string]any
				if json.Unmarshal([]byte(v), &tree) == nil && tree != nil {
					out = append(out, agentconfig.RuntimeTree{Tool: f.Tool, Layer: agentconfig.RuntimeConfigContent, Tree: tree})
				}
			}
		}
		if _, ranked := f.RuntimeRanks[agentconfig.RuntimeDotenv]; ranked && p.DotenvOverride != nil {
			out = append(out, s.dotenvTrees(f, *p.DotenvOverride, projects)...)
		}
	}
	return mergeRuntime(out)
}

// mergeRuntime folds the trees of one (tool, layer, project) into one, so
// two families of a tool read the same source (the evaluator takes one tree
// per layer).
func mergeRuntime(in []agentconfig.RuntimeTree) []agentconfig.RuntimeTree {
	var out []agentconfig.RuntimeTree
	at := map[string]int{}
	for _, rt := range in {
		k := rt.Tool + "\x00" + string(rt.Layer) + "\x00" + rt.Project
		if i, ok := at[k]; ok {
			mergeInto(out[i].Tree, rt.Tree)
			continue
		}
		at[k] = len(out)
		out = append(out, rt)
	}
	return out
}

// mergeInto copies src into dst, recursing into maps both hold; an
// existing leaf is kept.
func mergeInto(dst, src map[string]any) {
	for k, v := range src {
		dm, dok := dst[k].(map[string]any)
		sm, sok := v.(map[string]any)
		switch {
		case dok && sok:
			mergeInto(dm, sm)
		case dst[k] == nil:
			dst[k] = v
		}
	}
}

// familyTree places one launch-environment value at the family's key: as
// the member named by the variable for a map family that observes it, at
// the key itself for an exact family.
func familyTree(f agentconfig.Family, name string, v any) map[string]any {
	key := append(agentconfig.KeyPath(nil), f.Key...)
	if len(f.Members) > 0 {
		found := false
		for _, m := range f.Members {
			found = found || m == name
		}
		if !found {
			return nil
		}
		key = append(key, name)
	}
	return nestTree(key, v)
}

func nestTree(key agentconfig.KeyPath, v any) map[string]any {
	if len(key) == 0 {
		return nil
	}
	root := map[string]any{}
	cur := root
	for _, k := range key[:len(key)-1] {
		next := map[string]any{}
		cur[k] = next
		cur = next
	}
	cur[key[len(key)-1]] = v
	return root
}

// dotenvTrees reads the tool's own .env files by key name and returns a
// dotenv tree (KeyPresent at the family's key) for the home level and for
// each project whose own .env sets a key.
func (s *Service) dotenvTrees(f agentconfig.Family, d integration.DotenvOverride, projects []string) []agentconfig.RuntimeTree {
	set := func(project string, rel []string) bool {
		for _, r := range rel {
			path := s.dotenvPath(r, project)
			if path == "" || (strings.HasPrefix(r, "<project>/") && projectLinkEscapes(path, project)) {
				continue
			}
			b, present, err := s.readFile(path)
			if err != nil || !present {
				continue
			}
			if len(agentconfig.DotenvKeysPresent(b, d.Keys)) > 0 {
				return true
			}
		}
		return false
	}
	var home, proj []string
	for _, r := range d.Files {
		if strings.HasPrefix(r, "<project>/") {
			proj = append(proj, r)
		} else {
			home = append(home, r)
		}
	}
	var out []agentconfig.RuntimeTree
	if set("", home) {
		out = append(out, agentconfig.RuntimeTree{Tool: f.Tool, Layer: agentconfig.RuntimeDotenv, Tree: nestTree(f.Key, agentconfig.KeyPresent{})})
	}
	for _, p := range projects {
		if set(p, proj) {
			out = append(out, agentconfig.RuntimeTree{Tool: f.Tool, Layer: agentconfig.RuntimeDotenv, Project: p, Tree: nestTree(f.Key, agentconfig.KeyPresent{})})
		}
	}
	return out
}

// dotenvPath resolves a "~/" or "<project>/" dotenv file name.
func (s *Service) dotenvPath(rel, project string) string {
	switch {
	case strings.HasPrefix(rel, "~/"):
		if s.o.Home == "" {
			return ""
		}
		return filepath.Join(s.o.Home, filepath.FromSlash(strings.TrimPrefix(rel, "~/")))
	case strings.HasPrefix(rel, "<project>/"):
		if project == "" {
			return ""
		}
		return filepath.Join(project, filepath.FromSlash(strings.TrimPrefix(rel, "<project>/")))
	}
	return ""
}
