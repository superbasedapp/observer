package cortexcode

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

const (
	// conversationsDir is the store directory under the cortex data home.
	conversationsDir = "conversations"
	// historySuffix names the append-only message log.
	historySuffix = ".history.jsonl"
	// metaSuffix names the whole-file session metadata document.
	metaSuffix = ".json"
	// placeholderRoot is the synthetic project root used when the
	// session's metadata (the only statement of its cwd) is unreadable.
	placeholderRoot = "[cortex-code]"
)

// layout is the store file shape a path matches.
type layout int

const (
	layoutNone layout = iota
	// layoutHistory is conversations/<id>.history.jsonl.
	layoutHistory
	// layoutMeta is conversations/<id>.json.
	layoutMeta
)

// Adapter parses the Cortex Code conversation store. See the package doc
// for the two-file layout, the gross-of-cache token semantics and the
// off-limits file list.
type Adapter struct {
	scrubber *scrub.Scrubber
	roots    []string
	// logs memoizes the parsed tail of each data home's coco.log
	// (cocolog.go), shared by every parse of that home's sessions.
	logs *logCache
}

// New returns an adapter with the default scrubber and the platform-default
// cross-mount watch roots.
func New() *Adapter {
	return &Adapter{scrubber: scrub.New(), roots: defaultRoots(), logs: &logCache{}}
}

// NewWithOptions customizes the scrubber and/or watch roots for tests. A
// nil scrubber falls back to scrub.New(); no roots falls back to the
// platform defaults.
func NewWithOptions(s *scrub.Scrubber, roots ...string) *Adapter {
	if s == nil {
		s = scrub.New()
	}
	if len(roots) == 0 {
		roots = defaultRoots()
	}
	return &Adapter{scrubber: s, roots: roots, logs: &logCache{}}
}

// Name implements adapter.Adapter.
func (*Adapter) Name() string { return models.ToolCortexCode }

// WatchPaths implements adapter.Adapter.
func (a *Adapter) WatchPaths() []string { return a.roots }

// defaultRoots returns the conversations directory for every candidate
// cortex data home:
//
//   - $CORTEX_HOME/conversations and $SNOWFLAKE_HOME/cortex/conversations
//     when this process carries those overrides (both read off the v1.2.18
//     bundle's storage-root resolver; only meaningful for THIS process's
//     env, so they are not resolved per cross-mount home);
//   - <home>/.snowflake/cortex/conversations under every
//     cross-mount-resolved $HOME. Cortex uses the same layout on Linux,
//     macOS and native Windows (%USERPROFILE%\.snowflake), so a WSL2
//     observer reads a Windows-side store at /mnt/c/Users/<u>/.snowflake
//     and vice versa with no OS branching.
//
// The root is the conversations directory, never the data home: the home
// also holds connection credentials and caches this adapter must not
// watch. Duplicate and empty candidates are dropped.
func defaultRoots() []string {
	seen := map[string]bool{}
	var roots []string
	add := func(p string) {
		if p == "" {
			return
		}
		p = filepath.Clean(p)
		if seen[p] {
			return
		}
		seen[p] = true
		roots = append(roots, p)
	}
	if ch := envPath("CORTEX_HOME"); ch != "" {
		add(filepath.Join(ch, conversationsDir))
	}
	if sh := envPath("SNOWFLAKE_HOME"); sh != "" {
		add(filepath.Join(sh, "cortex", conversationsDir))
	}
	for _, h := range crossmount.AllHomes() {
		if h.Path == "" {
			continue
		}
		add(filepath.Join(h.Path, ".snowflake", "cortex", conversationsDir))
	}
	return roots
}

// envPath returns an absolute form of the named env var's path value, or
// "" when unset. A relative value is resolved the way the vendor resolves
// it (against the process cwd).
func envPath(name string) string {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return ""
	}
	if abs, err := filepath.Abs(v); err == nil {
		return abs
	}
	return v
}

// IsSessionFile implements adapter.Adapter. A path qualifies only when it
// is under one of this adapter's watch roots AND has one of the two store
// shapes (classifyLayout).
func (a *Adapter) IsSessionFile(path string) bool {
	if classifyLayout(path) == layoutNone {
		return false
	}
	return adapter.UnderAnyWatchRoot(path, a.WatchPaths())
}

// classifyLayout returns the store shape of path, independent of watch
// roots: a `<stem>.history.jsonl` or `<stem>.json` file directly inside a
// `conversations` directory, where the stem carries no dot. The no-dot
// rule rejects the vendor's `<id>.back.<n>.json` backups and any other
// dotted sidecar; `.last-session` fails the suffix tests.
func classifyLayout(path string) layout {
	slashed := strings.ReplaceAll(path, `\`, "/")
	if !strings.EqualFold(filepath.Base(filepath.Dir(filepath.FromSlash(slashed))), conversationsDir) {
		return layoutNone
	}
	base := slashed[strings.LastIndex(slashed, "/")+1:]
	lower := strings.ToLower(base)
	switch {
	case strings.HasSuffix(lower, historySuffix):
		if validStem(base[:len(base)-len(historySuffix)]) {
			return layoutHistory
		}
	case strings.HasSuffix(lower, metaSuffix):
		if validStem(base[:len(base)-len(metaSuffix)]) {
			return layoutMeta
		}
	}
	return layoutNone
}

// validStem reports whether a file stem can be a session id: non-empty and
// dot-free.
func validStem(stem string) bool {
	return stem != "" && !strings.Contains(stem, ".")
}

// sessionIDFromPath returns the canonical session id — the file stem, the
// id `cortex --resume <id>` accepts.
func sessionIDFromPath(path string) string {
	base := filepath.Base(filepath.FromSlash(strings.ReplaceAll(path, `\`, "/")))
	lower := strings.ToLower(base)
	switch {
	case strings.HasSuffix(lower, historySuffix):
		return base[:len(base)-len(historySuffix)]
	case strings.HasSuffix(lower, metaSuffix):
		return base[:len(base)-len(metaSuffix)]
	}
	return base
}

// metaPathFor returns the metadata sibling of a history log.
func metaPathFor(historyPath string) string {
	return strings.TrimSuffix(historyPath, historySuffix) + metaSuffix
}

// historyPathFor returns the history log of the session a store path (the
// history log itself or its metadata sibling) belongs to.
func historyPathFor(storePath string) string {
	if classifyLayout(storePath) == layoutMeta {
		return strings.TrimSuffix(storePath, metaSuffix) + historySuffix
	}
	return storePath
}

// historyExists reports whether the session behind storePath has a history
// log on disk, i.e. ever recorded a message.
func historyExists(storePath string) bool {
	info, err := os.Stat(historyPathFor(storePath))
	return err == nil && !info.IsDir()
}

// CursorSemanticsFor implements adapter.CursorSemantics. The history log
// is an append-only byte-offset stream that the parser seeks into; the
// metadata document is rewritten whole on every turn, carries only the
// session-cumulative token rows (never an action) and can shrink, so its
// cursor (the file size) may rewind.
func (a *Adapter) CursorSemanticsFor(path string) adapter.FileCursorSemantics {
	switch classifyLayout(path) {
	case layoutHistory:
		return adapter.FileCursorSemantics{
			Kind:              adapter.CursorByteOffset,
			StreamsFromCursor: true,
		}
	case layoutMeta:
		return adapter.FileCursorSemantics{
			Kind:              adapter.CursorNoActions,
			Detail:            "Cortex Code session metadata: rewritten whole each turn, carries only session-cumulative token usage",
			RewindsOnTruncate: true,
		}
	}
	return adapter.FileCursorSemantics{}
}

// ParseSessionFile implements adapter.Adapter. It dispatches on the file's
// store shape: the metadata document yields the session-level token rows
// and lineage; anything else is parsed as a history log (so a fixture or a
// copied store outside a canonical root keeps working; IsSessionFile stays
// strict).
func (a *Adapter) ParseSessionFile(ctx context.Context, path string, fromOffset int64) (adapter.ParseResult, error) {
	if classifyLayout(path) == layoutMeta {
		return a.parseMeta(ctx, path, fromOffset)
	}
	return a.parseHistory(ctx, path, fromOffset)
}

// resolveProjectRoot turns the session's raw working directory into a
// project root, translating a foreign-OS path first (a Windows session read
// by a WSL observer, or the reverse) so git resolution never runs against
// a meaningless path.
func resolveProjectRoot(rawCWD string) (root, branch string, id git.Identity) {
	cwd := strings.TrimSpace(rawCWD)
	if cwd == "" {
		return placeholderRoot, "", git.Identity{}
	}
	cwd = crossmount.TranslateForeignPath(cwd)
	identity, err := git.ResolveIdentity(cwd, git.IdentityOptions{})
	if err != nil {
		return cwd, "", git.Identity{}
	}
	return identity.Root, identity.Branch, identity
}
