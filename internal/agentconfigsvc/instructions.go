package agentconfigsvc

import (
	"context"
	"path/filepath"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/agentconfig"
	"github.com/marmutapp/superbased-observer/internal/guidance"
)

// Instruction files (plan section 5.1 "Instructions and skills"): the
// guidance inventory per tool, user and project scope, editable through
// the same preview / save pipeline as settings files (Markdown engine,
// front-matter lint).

// InstructionFile is one instruction / skill / agent / command / rule file.
type InstructionFile struct {
	FileID string               `json:"file_id"`
	Tool   string               `json:"tool"`
	Kind   agentconfig.FileKind `json:"kind"`
	Scope  agentconfig.Scope    `json:"scope"`
	// Glob is the row's pattern (as the catalogue spells it).
	Glob   string `json:"glob"`
	Path   string `json:"path"`
	Exists bool   `json:"exists"`
	Name   string `json:"name,omitempty"`
	Desc   string `json:"description,omitempty"`
	Size   int64  `json:"size,omitempty"`
	// NewName: a glob row with one "*" segment, so a new file can be made
	// by naming it (a new skill or agent).
	NewName  bool   `json:"new_name,omitempty"`
	ParseErr string `json:"parse_error,omitempty"`
	Tracked  bool   `json:"tracked,omitempty"`
	// relocatedID is the catalogue's home-relative spelling of a user file
	// a relocation variable moved ("~/.claude/skills/x/SKILL.md" for
	// $CLAUDE_CONFIG_DIR/skills/x/SKILL.md, FU-142): the managed
	// inventory's file id, which names no local path. "" for every other
	// file.
	relocatedID string
}

func instructionRows(tool string) []agentconfig.FileRow {
	var out []agentconfig.FileRow
	for _, f := range agentconfig.Files() {
		if f.Tool != tool {
			continue
		}
		switch f.Kind {
		case agentconfig.KindInstructions, agentconfig.KindSkill, agentconfig.KindAgent, agentconfig.KindCommand, agentconfig.KindRule:
			out = append(out, f)
		}
	}
	return out
}

// Instructions lists a tool's instruction-family files at user scope and,
// with a project, at project scope. Existing files come from the guidance
// scanner (containment-checked, depth-capped); a fixed-name file that does
// not exist yet is listed so it can be created.
func (s *Service) Instructions(ctx context.Context, tool, project string) ([]InstructionFile, error) {
	if !knownTool(tool) {
		return nil, ErrUnknownTool
	}
	rows := instructionRows(tool)
	env := s.env(project)
	var found []guidance.File
	opts := guidance.DefaultOptions()
	opts.Tools = []string{tool}
	opts.UserHome = s.o.Home
	// The user-scope rows a relocation variable moves are scanned where the
	// tool reads them (FU-142); the scan keeps the home layout, so each
	// file keeps its "~/" identity, and a variable holding a relative value
	// leaves those rows with no file at all (never the home default).
	moves := s.userAnchorMoves(rows, env)
	var userFS relocatedFS
	if s.o.Home != "" {
		o := opts
		o.UserScopeOnly, o.IncludeUserScope = true, true
		userFS = newRelocatedFS(s.o.Home, moves)
		var fsys guidance.FS = userFS
		if len(moves) == 0 {
			fsys = guidance.OSFS(s.o.Home)
		}
		if res, err := guidance.Scan(ctx, s.o.Home, fsys, o); err == nil {
			found = append(found, res.Files...)
		}
	}
	if project != "" {
		o := opts
		o.IncludeUserScope = false
		if res, err := guidance.Scan(ctx, project, guidance.OSFSProject(project), o); err == nil {
			found = append(found, res.Files...)
		}
	}
	var out []InstructionFile
	seen := map[string]bool{}
	for _, gf := range found {
		row, ok := matchInstructionRow(rows, gf)
		if !ok {
			continue
		}
		p, relocatedID := gf.AbsPath, ""
		if gf.Scope == guidance.ScopeUser && len(moves) > 0 {
			_, moved, mi := userFS.route(gf.AbsPath)
			if mi >= 0 {
				if !moves[mi].rows[row.ID] {
					// Under a moved anchor, but this row does not follow
					// the variable: not a file the tool reads there.
					continue
				}
				p, relocatedID = moved, gf.RelPath
			}
		}
		if seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, InstructionFile{
			FileID: row.ID, Tool: tool, Kind: row.Kind, Scope: row.Scope, Glob: row.Paths.Linux, Path: p, Exists: true,
			Name: gf.Name, Desc: gf.Description, Size: gf.SizeBytes, ParseErr: gf.ParseErr,
			Tracked: agentconfig.IsTracked(row), relocatedID: relocatedID,
		})
	}
	for _, row := range rows {
		rp := agentconfig.ResolvePath(row, env)
		switch rp.Status {
		case agentconfig.PathResolved:
			if seen[rp.Path] {
				continue
			}
			seen[rp.Path] = true
			_, present, _ := s.readFileInfo(rp.Path)
			relocatedID := ""
			if rp.RelocatedBy != "" && row.Scope == agentconfig.ScopeUser && strings.HasPrefix(row.Paths.Linux, "~/") {
				relocatedID = row.Paths.Linux
			}
			out = append(out, InstructionFile{
				FileID: row.ID, Tool: tool, Kind: row.Kind, Scope: row.Scope, Glob: row.Paths.Linux, Path: rp.Path,
				Exists: present, Tracked: agentconfig.IsTracked(row), relocatedID: relocatedID,
			})
		case agentconfig.PathGlob:
			if strings.Count(row.Paths.Linux, "*") == 1 && !strings.Contains(row.Paths.Linux, "**") {
				out = append(out, InstructionFile{
					FileID: row.ID, Tool: tool, Kind: row.Kind, Scope: row.Scope, Glob: row.Paths.Linux, Path: rp.Path,
					NewName: true, Tracked: agentconfig.IsTracked(row),
				})
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Scope != b.Scope {
			return a.Scope == agentconfig.ScopeUser
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.Path < b.Path
	})
	return out, nil
}

// readFileInfo reports existence without reading content.
func (s *Service) readFileInfo(path string) (int64, bool, error) {
	fi, err := statRegular(path)
	if err != nil || fi == nil {
		return 0, false, err
	}
	return fi.Size(), true, nil
}

// matchInstructionRow finds the catalogue row a scanned file belongs to.
func matchInstructionRow(rows []agentconfig.FileRow, gf guidance.File) (agentconfig.FileRow, bool) {
	rel := filepath.ToSlash(gf.RelPath)
	for _, r := range rows {
		raw := r.Paths.Linux
		switch {
		case gf.Scope == guidance.ScopeUser && strings.HasPrefix(raw, "~/"):
			if agentconfig.MatchGlob(strings.TrimPrefix(raw, "~/"), strings.TrimPrefix(rel, "~/")) {
				return r, true
			}
		case gf.Scope == guidance.ScopeProject && strings.HasPrefix(raw, "<project>/"):
			if agentconfig.MatchGlob(strings.TrimPrefix(raw, "<project>/"), rel) {
				return r, true
			}
		}
	}
	return agentconfig.FileRow{}, false
}

// NewInstructionPath names the file a new skill / agent of a glob row would
// be, replacing the row's one "*" with name.
func (s *Service) NewInstructionPath(t Target, name string) (string, error) {
	row, ok := fileRow(t.FileID)
	if !ok || row.Tool != t.Tool {
		return "", ErrUnknownFile
	}
	name = strings.TrimSpace(name)
	if name == "" || strings.ContainsAny(name, `/\*?[`) || name == "." || name == ".." {
		return "", ErrBadTarget
	}
	raw := row.Paths.Linux
	if strings.Count(raw, "*") != 1 || strings.Contains(raw, "**") {
		return "", ErrBadTarget
	}
	tmp := row
	tmp.Paths = agentconfig.OSPaths{Linux: strings.Replace(raw, "*", name, 1), Darwin: strings.Replace(raw, "*", name, 1), Windows: strings.Replace(raw, "*", name, 1)}
	rp := agentconfig.ResolvePath(tmp, s.env(t.Project))
	if rp.Status != agentconfig.PathResolved {
		return "", ErrBadTarget
	}
	return rp.Path, nil
}
