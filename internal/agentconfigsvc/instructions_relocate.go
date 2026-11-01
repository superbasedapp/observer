package agentconfigsvc

import (
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/agentconfig"
	"github.com/marmutapp/superbased-observer/internal/guidance"
)

// Relocated instruction files (FU-142). Claude Code reads its user
// CLAUDE.md, skills, agents and commands from $CLAUDE_CONFIG_DIR when the
// variable is set, so those catalogue rows carry the same relocation rule as
// its settings. The three paths of the service that walk under a home
// directory follow it here: the user-scope guidance scan behind
// Instructions (and so the managed inventory's instruction rows), a glob
// target (matchGlobTarget), and the inventory's home-relative file id.

// anchorMove is one relocated anchor of a tool's user-scope instruction
// rows, in the guidance scanner's forward-slash spelling: from is the anchor
// under the home ("<home>/.claude"), to the directory the variable names, ""
// when the variable holds a relative value (nothing there can be named).
type anchorMove struct {
	from, to string
	// rows are the ids of the rows the move applies to.
	rows map[string]bool
}

// userAnchorMoves resolves, for the user-scope rows of rows, every anchor a
// relocation variable moves under env.
func (s *Service) userAnchorMoves(rows []agentconfig.FileRow, env agentconfig.PathEnv) []anchorMove {
	if s.o.Home == "" {
		return nil
	}
	var out []anchorMove
	for _, row := range rows {
		if row.Scope != agentconfig.ScopeUser {
			continue
		}
		m, ok := agentconfig.RelocatedAnchor(row, env)
		if !ok || !strings.HasPrefix(m.Anchor, "~/") {
			continue
		}
		// The scanner's own spelling of the home (guidance normalizes the
		// root by separators and trailing slashes only), so a scanned path
		// under the anchor matches it byte for byte.
		from := slashPath(strings.TrimSpace(s.o.Home)) + "/" + strings.TrimPrefix(m.Anchor, "~/")
		to := ""
		if !m.Unresolved {
			to = slashPath(m.Dir)
		}
		found := false
		for i := range out {
			if out[i].from == from && out[i].to == to {
				out[i].rows[row.ID] = true
				found = true
			}
		}
		if !found {
			out = append(out, anchorMove{from: from, to: to, rows: map[string]bool{row.ID: true}})
		}
	}
	return out
}

// slashPath is p in the guidance scanner's spelling (forward slashes, no
// trailing separator).
func slashPath(p string) string {
	p = strings.ReplaceAll(p, `\`, "/")
	for len(p) > 1 && strings.HasSuffix(p, "/") {
		p = strings.TrimSuffix(p, "/")
	}
	return p
}

// under reports whether p is dir itself or below it, and the remainder.
func under(p, dir string) (string, bool) {
	if p == dir {
		return "", true
	}
	if strings.HasPrefix(p, dir+"/") {
		return p[len(dir):], true
	}
	return "", false
}

// relocatedFS is the user-scope scan's file system with the moved anchors
// mapped: a path under a move's from is read under its to, through a
// guidance.OSFS confined to that directory, and a move whose variable holds
// a relative value reads nothing there. Every other path is the home's own
// confined file system. The scan keeps seeing the catalogue's home layout,
// so a file keeps its "~/"-relative identity.
type relocatedFS struct {
	home  guidance.FS
	moves []anchorMove
	dirs  []guidance.FS
}

func newRelocatedFS(home string, moves []anchorMove) relocatedFS {
	r := relocatedFS{home: guidance.OSFS(home), moves: moves}
	for _, m := range moves {
		var d guidance.FS = noFS{}
		if m.to != "" {
			d = guidance.OSFS(filepath.FromSlash(m.to))
		}
		r.dirs = append(r.dirs, d)
	}
	return r
}

// route returns the file system and path a scanned path is read through,
// and the move that mapped it (-1 for none).
func (r relocatedFS) route(p string) (guidance.FS, string, int) {
	sp := slashPath(p)
	for i, m := range r.moves {
		if rest, ok := under(sp, m.from); ok {
			return r.dirs[i], m.to + rest, i
		}
	}
	return r.home, p, -1
}

func (r relocatedFS) Glob(pattern string) ([]string, error) {
	fsys, p, _ := r.route(pattern)
	return fsys.Glob(p)
}

func (r relocatedFS) ReadDir(p string) ([]fs.DirEntry, error) {
	fsys, q, _ := r.route(p)
	return fsys.ReadDir(q)
}

func (r relocatedFS) Stat(p string) (fs.FileInfo, error) {
	fsys, q, _ := r.route(p)
	return fsys.Stat(q)
}

func (r relocatedFS) ReadFile(p string) ([]byte, error) {
	fsys, q, _ := r.route(p)
	return fsys.ReadFile(q)
}

// noFS is a file system with nothing in it.
type noFS struct{}

func (noFS) Glob(string) ([]string, error)         { return nil, nil }
func (noFS) ReadDir(string) ([]fs.DirEntry, error) { return nil, fs.ErrNotExist }
func (noFS) Stat(string) (fs.FileInfo, error)      { return nil, fs.ErrNotExist }
func (noFS) ReadFile(string) ([]byte, error)       { return nil, fs.ErrNotExist }

// relocatedGlobAnchor is matchGlobTarget's anchor and pattern for a
// user-scope glob row a relocation variable moves: the directory the
// variable names and the row's pattern below its anchor. ok is false when no
// variable moves the row (the home anchors it, as before).
func (s *Service) relocatedGlobAnchor(row agentconfig.FileRow, project string) (anchor, pat string, ok bool) {
	m, moved := agentconfig.RelocatedAnchor(row, s.env(project))
	if !moved || m.Unresolved {
		return "", "", false
	}
	rest, cut := strings.CutPrefix(row.Paths.Linux, m.Anchor+"/")
	if !cut {
		return "", "", false
	}
	return m.Dir, rest, true
}
