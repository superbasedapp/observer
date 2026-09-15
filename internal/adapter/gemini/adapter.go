package gemini

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/platform/pathnorm"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

// Adapter parses Gemini CLI session files under
// ~/.gemini/tmp/<project_hash>/chats/. Two on-disk formats are
// supported (the adapter dispatches on extension):
//
//   - .json — legacy single-object format. Full file is rewritten
//     on every turn; cursor is the file size (forward-only) and the
//     adapter performs idempotent full re-reads. Per-turn dedup is
//     handled by the store via (source_file, source_event_id).
//   - .jsonl — append-only event-record format proposed by issue
//     #15292. Cursor is byte offset; lines are streamed.
type Adapter struct {
	scrubber *scrub.Scrubber
	roots    []string
}

// New returns an adapter with platform-default cross-mount roots.
func New() *Adapter {
	return &Adapter{scrubber: scrub.New(), roots: defaultRoots()}
}

// NewWithOptions customizes scrubber and/or roots for tests.
func NewWithOptions(s *scrub.Scrubber, roots ...string) *Adapter {
	if s == nil {
		s = scrub.New()
	}
	if len(roots) == 0 {
		roots = defaultRoots()
	}
	return &Adapter{scrubber: s, roots: roots}
}

// Name implements adapter.Adapter.
func (*Adapter) Name() string { return models.ToolGeminiCLI }

// WatchPaths implements adapter.Adapter.
func (a *Adapter) WatchPaths() []string { return a.roots }

// IsSessionFile implements adapter.Adapter.
//
// Matches `.gemini/tmp/<hash>/chats/session-...{.json,.jsonl}` and
// nothing else. Subagent nested sessions at deeper paths
// (`chats/<parent_id>/session-*`) are explicitly rejected — that's a
// deferred feature, and silently swallowing them under the parent
// session's tool ID would cause data attribution bugs we'd discover
// late. Logs a warning at parse time so the rejection is visible.
func (a *Adapter) IsSessionFile(path string) bool {
	if classifyPath(path) == classifyOther {
		return false
	}
	return adapter.UnderAnyWatchRoot(path, a.WatchPaths())
}

type pathKind int

const (
	classifyOther pathKind = iota
	classifyLegacyJSON
	classifyJSONL
	classifySubagent
)

func classifyPath(path string) pathKind {
	lower := strings.ReplaceAll(strings.ToLower(path), `\`, "/")
	if !strings.Contains(lower, "/.gemini/tmp/") {
		return classifyOther
	}
	if !strings.Contains(lower, "/chats/") {
		return classifyOther
	}
	base := filepath.Base(lower)
	if !strings.HasPrefix(base, "session-") {
		return classifyOther
	}
	// Reject subagent nested sessions at deeper paths
	// (chats/<parent_id>/session-*). Detect by counting path segments
	// between "/chats/" and the basename — exactly one means flat
	// chats/session-*; more means nested.
	idx := strings.Index(lower, "/chats/")
	tail := lower[idx+len("/chats/"):]
	if strings.Count(tail, "/") > 0 {
		return classifySubagent
	}
	switch {
	case strings.HasSuffix(base, ".jsonl"):
		return classifyJSONL
	case strings.HasSuffix(base, ".json"):
		return classifyLegacyJSON
	}
	return classifyOther
}

// ParseSessionFile implements adapter.Adapter. Dispatches on extension.
//
// Legacy JSON: ignores fromOffset semantics on content (re-reads in
// full every call) and returns NewOffset = current file size so the
// watcher's MAX-monotonic cursor advances. Per-turn dedup downstream
// guarantees idempotence.
//
// JSONL: streams from fromOffset, returns NewOffset = bytes consumed.
func (a *Adapter) ParseSessionFile(ctx context.Context, path string, fromOffset int64) (adapter.ParseResult, error) {
	kind := classifyPath(path)
	switch kind {
	case classifyOther:
		return adapter.ParseResult{}, fmt.Errorf("gemini.ParseSessionFile: %s does not match any known session shape", path)
	case classifySubagent:
		// Reject + warn rather than silently capture under the parent's
		// session ID. When subagent capture lands as a real feature, this
		// branch turns into proper handling.
		return adapter.ParseResult{
			NewOffset: fromOffset,
			Warnings:  []string{fmt.Sprintf("gemini: subagent session at unexpected depth, ignored: %s", path)},
		}, nil
	}

	fi, statErr := os.Stat(path)
	if statErr != nil {
		return adapter.ParseResult{}, fmt.Errorf("gemini.ParseSessionFile: stat: %w", statErr)
	}

	switch kind {
	case classifyLegacyJSON:
		return a.parseLegacy(ctx, path, fi, fromOffset)
	case classifyJSONL:
		return a.parseJSONL(ctx, path, fi, fromOffset)
	}
	return adapter.ParseResult{}, errors.New("gemini.ParseSessionFile: unreachable")
}

// projectHashFromPath extracts the <hash> segment from
// .../.gemini/tmp/<hash>/chats/session-... — used as the project key
// fallback when no tool-call cwd is available.
func projectHashFromPath(path string) string {
	lower := strings.ReplaceAll(strings.ToLower(path), `\`, "/")
	idx := strings.Index(lower, "/.gemini/tmp/")
	if idx < 0 {
		return ""
	}
	tail := strings.ReplaceAll(path, `\`, "/")[idx+len("/.gemini/tmp/"):]
	end := strings.Index(tail, "/chats/")
	if end < 0 {
		return ""
	}
	return tail[:end]
}

// resolveProjectRoot picks a project root for a session, applying the
// fallback chain documented in the package doc:
//
//  1. tool-call cwd from any captured turn (caller passes via cwdHint).
//  2. the CLI's own `.project_root` sidecar, under either
//     ~/.gemini/tmp/<key>/ or ~/.gemini/history/<key>/ (plain text = the
//     real cwd; both written by the live CLI).
//  3. ~/.gemini/projects.json, whose {root: key} map inverts to the same
//     answer — used only when the sidecar is missing/unreadable, and
//     skipped when two roots share a key (ambiguous).
//  4. ~/.gemini/history/<key>/.git/config worktree path (best-effort).
//  5. synthetic key "[gemini-cli:<key>]".
//
// Tiers 2+3 exist because the live session JSONL carries NO cwd at all,
// so tier 1 never fires and every gemini session used to land on the
// synthetic key — unjoinable to a real repo (WP-T6 finding G1,
// secondary).
//
// Returns the chosen root; never empty. remote is the normalized git
// "origin" remote when the winning tier ran git.Resolve (tiers 1-3);
// tiers 4-5 never touch git.Resolve so remote is "" for those — an
// honest gap rather than a fabricated value.
func resolveProjectRoot(sessionPath, cwdHint string) (root, remote string, id git.Identity) {
	// Normalize before resolving so a Windows-side Gemini CLI session
	// (whose cwd is captured as `C:\…` or `file:///D:/…`) doesn't get
	// fed to git.Resolve as a relative path. Without this, the
	// observer's own CWD gets prepended and the walk-up lands on
	// observer's own .git in the worst case
	// (memory [[feedback_foreign_path_git_resolve]]).
	cwdHint = pathnorm.Normalize(cwdHint)
	if cwdHint != "" {
		if identity, err := git.ResolveIdentity(cwdHint, git.IdentityOptions{}); err == nil {
			// identity.Remote is already NormalizeRemote'd.
			return identity.Root, identity.Remote, identity
		}
		return cwdHint, "", git.Identity{}
	}
	hash := projectHashFromPath(sessionPath)
	if hash != "" {
		if root, remote, id := readRecordedProjectRoot(sessionPath, hash); root != "" {
			return root, remote, id
		}
		if root := readShadowGitWorktree(sessionPath, hash); root != "" {
			return root, "", git.Identity{}
		}
		return "[gemini-cli:" + hash + "]", "", git.Identity{}
	}
	return "[gemini-cli]", "", git.Identity{}
}

// readRecordedProjectRoot reads the project root the Gemini CLI itself
// recorded for this project key, trying the `.project_root` sidecars
// first and the projects.json reverse map second. Returns ("", "", zero)
// when neither is present/usable.
func readRecordedProjectRoot(sessionPath, key string) (root, remote string, id git.Identity) {
	home := geminiHomeFromSessionPath(sessionPath)
	if home == "" || key == "" {
		return "", "", git.Identity{}
	}
	for _, sidecar := range []string{
		filepath.Join(home, "tmp", key, ".project_root"),
		filepath.Join(home, "history", key, ".project_root"),
	} {
		body, err := os.ReadFile(sidecar)
		if err != nil {
			continue
		}
		if root, remote, id := resolveRecordedRoot(string(body)); root != "" {
			return root, remote, id
		}
	}
	return resolveRecordedRoot(lookupProjectsJSON(filepath.Join(home, "projects.json"), key))
}

// lookupProjectsJSON inverts ~/.gemini/projects.json — which maps
// {"<project root>": "<key>"} — back to the root for one key. Returns ""
// when the file is missing/unparseable, when no entry matches, or when
// TWO roots claim the same key: an ambiguous answer is worse than the
// honest synthetic fallback.
func lookupProjectsJSON(path, key string) string {
	body, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	var doc struct {
		Projects map[string]string `json:"projects"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return ""
	}
	var match string
	for root, name := range doc.Projects {
		if name != key {
			continue
		}
		if match != "" && match != root {
			return ""
		}
		match = root
	}
	return match
}

// resolveRecordedRoot normalizes a root the CLI recorded on disk and,
// when that path actually exists on this host, promotes it to its git
// root. The stat gate comes BEFORE git.Resolve deliberately: resolving a
// path that isn't mounted here (a Windows-side session read from WSL,
// say) would walk up from a non-existent directory. A recorded-but-
// unmounted root is still returned verbatim — it is real information,
// unlike the synthetic key. remote is only populated when git.Resolve
// actually ran.
func resolveRecordedRoot(raw string) (root, remote string, id git.Identity) {
	p := pathnorm.Normalize(strings.TrimSpace(raw))
	if p == "" {
		return "", "", git.Identity{}
	}
	if _, err := os.Stat(p); err != nil {
		return p, "", git.Identity{}
	}
	if identity, err := git.ResolveIdentity(p, git.IdentityOptions{}); err == nil {
		// identity.Remote is already NormalizeRemote'd.
		return identity.Root, identity.Remote, identity
	}
	return p, "", git.Identity{}
}

// geminiHomeFromSessionPath walks up from a session file to the
// enclosing `.gemini` directory (handles cross-mount paths like
// /mnt/c/Users/<u>/.gemini/...). Returns "" when the path isn't under
// one.
func geminiHomeFromSessionPath(sessionPath string) string {
	cur := filepath.Dir(sessionPath)
	for cur != "" && cur != filepath.Dir(cur) {
		base := filepath.Base(cur)
		if base == ".gemini" {
			return cur
		}
		if base == "tmp" && filepath.Base(filepath.Dir(cur)) == ".gemini" {
			return filepath.Dir(cur)
		}
		cur = filepath.Dir(cur)
	}
	if filepath.Base(cur) == ".gemini" {
		return cur
	}
	return ""
}

// readShadowGitWorktree opens ~/.gemini/history/<hash>/.git/config and
// looks for a `[core] worktree = ...` setting that points at the
// original project root. Returns the resolved path or "" if not
// present / unparseable. Tolerates missing dirs and config files.
func readShadowGitWorktree(sessionPath, hash string) string {
	cur := geminiHomeFromSessionPath(sessionPath)
	if cur == "" {
		return ""
	}
	configPath := filepath.Join(cur, "history", hash, ".git", "config")
	body, err := os.ReadFile(configPath)
	if err != nil {
		return ""
	}
	var inCore bool
	for _, line := range strings.Split(string(body), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") {
			inCore = trimmed == "[core]"
			continue
		}
		if !inCore {
			continue
		}
		if !strings.HasPrefix(trimmed, "worktree") {
			continue
		}
		eq := strings.Index(trimmed, "=")
		if eq < 0 {
			continue
		}
		root := strings.TrimSpace(trimmed[eq+1:])
		if root == "" {
			continue
		}
		return root
	}
	return ""
}

// defaultRoots returns ~/.gemini/tmp under every cross-mount-resolved
// $HOME so observer in WSL2 picks up sessions on /mnt/c/Users/<u>/.gemini
// (and vice versa for native-Windows observer with WSL distros).
func defaultRoots() []string {
	var roots []string
	for _, h := range crossmount.AllHomes() {
		roots = append(roots, filepath.Join(h.Path, ".gemini", "tmp"))
	}
	return roots
}
