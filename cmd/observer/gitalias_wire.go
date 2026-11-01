package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/gitalias"
	"github.com/marmutapp/superbased-observer/internal/gitview"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// The git alias table (R-112 to R-114, D-761): the daemon is the ONE writer
// of guard-git-aliases.json beside the database; the hook and the daemon's
// own guard read it through fileGitAliasLookup, so the hook never runs git.

// gitAliasInterval is how often the daemon refreshes the table. A project
// whose git config files did not change since the last pass is not asked
// again.
const gitAliasInterval = 5 * time.Minute

// gitAliasMaxAge is how long a project's aliases are trusted without a
// fresh read even when the config file times did not move: a linked
// worktree's aliases live in the main repository's config, and an
// include.path file is outside the stamp too.
const gitAliasMaxAge = time.Hour

// gitAliasTimeout bounds one `git config` call.
const gitAliasTimeout = 2 * time.Second

// gitAliasOutputCap bounds one `git config` call's output.
const gitAliasOutputCap = 256 << 10

// gitAliasCache remembers one project's aliases and the config file times
// they were read at.
type gitAliasCache struct {
	stamp   string
	readAt  time.Time
	aliases map[string]string
}

// gitConfigStamp is the modification times of the config files a
// project's aliases come from (its own, the user's two global files), so
// an unchanged project is not asked again. "" when the root is not a
// directory.
func gitConfigStamp(root, home string) string {
	if fi, err := os.Stat(root); err != nil || !fi.IsDir() {
		return ""
	}
	var b bytes.Buffer
	for _, p := range []string{
		filepath.Join(root, ".git", "config"),
		filepath.Join(home, ".gitconfig"),
		filepath.Join(home, ".config", "git", "config"),
	} {
		if fi, err := os.Stat(p); err == nil {
			b.WriteString(fi.ModTime().UTC().Format(time.RFC3339Nano))
		}
		b.WriteByte('|')
	}
	return b.String()
}

// readProjectAliases asks git for one project's aliases through gitview's
// read-only envelope (no hooks, no fsmonitor, no pager, no prompts). A
// project with no aliases (git exits 1) has an empty set.
func readProjectAliases(ctx context.Context, root string) (map[string]string, bool) {
	out, _, err := gitview.RunReadOnlyTimeout(ctx, root, gitAliasOutputCap, gitAliasTimeout,
		"config", "-z", "--get-regexp", `^alias\.`)
	if err != nil {
		var ge *gitview.GitError
		if errors.As(err, &ge) && ge.ExitCode == 1 {
			return map[string]string{}, true
		}
		return nil, false
	}
	return gitalias.ParseConfigList(out), true
}

// gitAliasRefresher builds the table from the observed projects; it is
// owned by gitAliasLoop.
type gitAliasRefresher struct {
	home  string
	cache map[string]gitAliasCache
	// last is the encoding of the last table written (WrittenAt zeroed).
	last []byte
}

// refresh recomputes the table for roots and writes it when it changed.
func (r *gitAliasRefresher) refresh(ctx context.Context, path string, roots []string, now time.Time) (bool, error) {
	next := make(map[string]gitAliasCache, len(roots))
	t := gitalias.Table{}
	for _, root := range roots {
		if len(t.Projects) >= gitalias.MaxProjects || ctx.Err() != nil {
			break
		}
		stamp := gitConfigStamp(root, r.home)
		if stamp == "" {
			continue
		}
		c, ok := r.cache[root]
		if !ok || c.stamp != stamp || now.Sub(c.readAt) >= gitAliasMaxAge {
			aliases, read := readProjectAliases(ctx, root)
			if !read {
				continue
			}
			c = gitAliasCache{stamp: stamp, readAt: now, aliases: aliases}
		}
		next[root] = c
		// A project with no aliases is listed too, so a repository nested
		// inside another is not judged by the outer one's aliases.
		t.Projects = append(t.Projects, gitalias.Project{Root: root, Aliases: c.aliases})
	}
	r.cache = next
	semantic, err := gitalias.Encode(t)
	if err != nil {
		return false, err
	}
	if r.last != nil && bytes.Equal(semantic, r.last) {
		return false, nil
	}
	t.WrittenAt = now.UTC()
	if err := gitalias.Write(path, t); err != nil {
		return false, err
	}
	r.last = semantic
	return true, nil
}

// gitAliasLoop is the daemon's alias table owner: refresh at start, then
// every gitAliasInterval. P1 like every sibling loop: never propagates an
// error.
func gitAliasLoop(ctx context.Context, configPath string) {
	cfg, database, cleanup, err := loadConfigAndDB(ctx, configPath)
	if err != nil {
		return
	}
	defer cleanup()
	logger := newLogger(cfg.Observer.LogLevel)
	st := store.New(database)
	home, _ := os.UserHomeDir()
	path := gitalias.Path(cfg.Observer.DBPath)
	r := &gitAliasRefresher{home: home}
	tick := func() {
		roots, err := st.ProjectRoots(ctx)
		if err != nil {
			logger.Warn("guard git aliases: project roots unavailable", "err", err)
			return
		}
		changed, err := r.refresh(ctx, path, roots, time.Now())
		if err != nil {
			logger.Warn("guard git aliases: publish failed", "err", err)
			return
		}
		if changed {
			logger.Debug("guard git aliases: published", "path", path)
		}
	}
	tick()
	t := time.NewTicker(gitAliasInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			tick()
		}
	}
}

// fileGitAliasLookup returns the guard's alias lookup over the table file
// at path. The table is read on first use and again only when the file's
// modification time changes; any read failure means "no table".
func fileGitAliasLookup(path string, logger *slog.Logger) guard.GitAliasLookup {
	if path == "" {
		return nil
	}
	var (
		mu    sync.Mutex
		mod   time.Time
		table *gitalias.Table
		read  bool
	)
	return func(dir string) (map[string]string, bool) {
		mu.Lock()
		defer mu.Unlock()
		fi, err := os.Stat(path)
		if err != nil {
			table, read = nil, false
			return nil, false
		}
		if !read || !fi.ModTime().Equal(mod) {
			t, lerr := gitalias.Load(path)
			if lerr != nil && logger != nil {
				logger.Warn("guard git aliases: table unreadable", "err", lerr)
			}
			table, mod, read = t, fi.ModTime(), true
		}
		return table.Lookup(dir)
	}
}
