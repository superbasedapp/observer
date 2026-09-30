package config

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/BurntSushi/toml"
)

// This file implements R3 — per-project compression overrides
// (usability arc §2.3): a repo-local <root>/.observer/config.toml
// whose ALLOW-LISTED keys overlay the resolved profile parameters for
// traffic attributed to that project (via the pidbridge session CWD).
//
// SECURITY POSTURE: project files are world-authored (anyone who can
// commit to a repo writes them), so the allow-list is enforced BY
// CONSTRUCTION — the file parses into a narrow struct holding only
// [profiles] and [compression]; db_path, upstreams, hook commands and
// every other daemon-level key simply do not exist in the parse
// target and cannot take effect. On top of that, conversation.enabled
// stays pinned: it is AND-guarded — a project can turn compression OFF
// for its traffic, never ON (the master switch is the operator's).

// ProjectOverlayFilename is the repo-local override file looked up
// under a project root.
const ProjectOverlayFilename = ".observer/config.toml"

// projectOverlayDoc is the allow-listed parse target for a project
// override file. Keys outside [profiles] / [compression] are ignored
// by construction.
type projectOverlayDoc struct {
	Profiles    ProfilesConfig    `toml:"profiles"`
	Compression CompressionConfig `toml:"compression"`
}

// FindProjectRoot walks upward from dir looking for the directory
// that contains ProjectOverlayFilename. Returns "" when none exists.
// Bounded at 32 levels; never errors (probing is best-effort).
//
// Two candidates are skipped (the walk continues past them):
//   - the user's home directory — ~/.observer/config.toml is the
//     daemon's MASTER config, not a project overlay; without this
//     rule every session with a cwd under home would treat home as a
//     "project" and re-apply master keys over resolved profile
//     parameters (wrong layering);
//   - excludeFile (when non-empty) — the resolved master config path,
//     covering custom --config locations the same way.
func FindProjectRoot(dir, excludeFile string) string {
	home, _ := os.UserHomeDir()
	if excludeFile != "" {
		excludeFile = filepath.Clean(excludeFile)
	}
	cur := filepath.Clean(dir)
	for range 32 {
		if cur == "" || cur == "." {
			return ""
		}
		cand := filepath.Join(cur, ProjectOverlayFilename)
		if (home == "" || cur != home) && (excludeFile == "" || cand != excludeFile) {
			if fi, err := os.Stat(cand); err == nil && !fi.IsDir() {
				return cur
			}
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return ""
		}
		cur = parent
	}
	return ""
}

// ProjectOverlays is the daemon's lazy, mtime-cached view of project
// override files. One instance lives beside the proxy's profile
// router; lookups stat the file and re-read only when (mtime, size)
// changed. A file that fails to parse is treated as absent (warn-once
// via the Warnf hook) so a malformed repo file can never disturb
// resolution.
type ProjectOverlays struct {
	// Warnf, when non-nil, receives one line per (root, mtime) whose
	// file failed to parse.
	Warnf func(format string, args ...any)

	mu      sync.Mutex
	entries map[string]projectOverlayEntry
}

type projectOverlayEntry struct {
	modTimeNano int64
	size        int64
	raw         []byte
	valid       bool
	warned      bool
}

// NewProjectOverlays returns an empty cache.
func NewProjectOverlays() *ProjectOverlays {
	return &ProjectOverlays{entries: map[string]projectOverlayEntry{}}
}

// Lookup returns the raw override file for root plus a stamp that
// changes whenever the file content generation changes (mtime+size) —
// callers fold the stamp into cache keys so edits apply to new
// sessions without a restart. ok=false when the file is absent or
// invalid.
func (c *ProjectOverlays) Lookup(root string) (raw []byte, stamp string, ok bool) {
	if root == "" {
		return nil, "", false
	}
	path := filepath.Join(root, ProjectOverlayFilename)
	fi, err := os.Stat(path)
	if err != nil || fi.IsDir() {
		return nil, "", false
	}
	mod, size := fi.ModTime().UnixNano(), fi.Size()

	c.mu.Lock()
	defer c.mu.Unlock()
	if e, hit := c.entries[root]; hit && e.modTimeNano == mod && e.size == size {
		if !e.valid {
			return nil, "", false
		}
		return e.raw, stampOf(mod, size), true
	}
	body, err := os.ReadFile(path)
	entry := projectOverlayEntry{modTimeNano: mod, size: size}
	if err == nil {
		var probe projectOverlayDoc
		if _, perr := toml.Decode(string(body), &probe); perr == nil {
			entry.raw = body
			entry.valid = true
		} else if c.Warnf != nil {
			c.Warnf("project override %s does not parse; ignoring until fixed: %v", path, perr)
			entry.warned = true
		}
	}
	c.entries[root] = entry
	if !entry.valid {
		return nil, "", false
	}
	return entry.raw, stampOf(mod, size), true
}

func stampOf(modNano, size int64) string {
	return strconv.FormatInt(modNano, 10) + "." + strconv.FormatInt(size, 10)
}

// ProjectProfiles returns global with the project file's [profiles]
// keys partial-merged over it (project assignment wins where set).
// The global value is never mutated — maps are cloned before the
// merge.
func ProjectProfiles(global ProfilesConfig, raw []byte) ProfilesConfig {
	doc := projectOverlayDoc{Profiles: cloneProfiles(global)}
	if err := toml.Unmarshal(raw, &doc); err != nil {
		return global
	}
	return doc.Profiles
}

// ProjectCompression overlays the project file's [compression] keys
// on base (the already-resolved profile parameters), enforcing the
// pinned guard: conversation.enabled can only be turned OFF by a
// project, never on.
func ProjectCompression(base CompressionConfig, raw []byte) (CompressionConfig, error) {
	doc := projectOverlayDoc{Compression: base}
	if err := toml.Unmarshal(raw, &doc); err != nil {
		return base, fmt.Errorf("config: project overlay: %w", err)
	}
	out := doc.Compression
	out.Conversation.Enabled = base.Conversation.Enabled && out.Conversation.Enabled
	return out, nil
}

func cloneProfiles(pc ProfilesConfig) ProfilesConfig {
	out := ProfilesConfig{Default: pc.Default}
	if pc.ByProvider != nil {
		out.ByProvider = maps.Clone(pc.ByProvider)
	}
	if pc.ByTool != nil {
		out.ByTool = maps.Clone(pc.ByTool)
	}
	return out
}
