package guard

import "sync"

// REPLAY FILESYSTEM MEMO (demo bug #14, 2026-11-10).
//
// The policy engine asks the filesystem three questions while it judges an
// action: where does this path really point (ResolveLinks, R-1xx destructive
// rows), what does this hook-switch file hold (R-162), and what does this SQL
// script hold (R-125/R-126). On the live hook path each question is asked once
// per call, which is cheap. A REPLAY asks them once per CAPTURED action, and a
// week of history is tens of thousands of actions that name the same few
// hundred paths: on the 2026-11-10 demo node (WSL, /mnt/c paths over 9p) the
// 7-day recipe replay spent most of its 582 s in filepath.EvalSymlinks.
//
// A replay judges history against the filesystem as it is NOW (it cannot see
// it as it was), so answering every repeat of a path with the first answer is
// the same answer the replay would get by asking again - only without the
// syscalls. The memo is therefore offered to replays only (Options.ReplayFS);
// the live guard keeps asking, because a symlink can change between two live
// calls and a stale answer there would be a wrong verdict.
//
// Bounded: past replayFSMaxEntries distinct keys a lookup is answered but not
// stored, so a pathological corpus costs the old speed, never unbounded memory.

// replayFSMaxEntries bounds each of the memo's three maps.
const replayFSMaxEntries = 16384

// replayFSMaxFileBytes bounds the total bytes of file contents the memo keeps.
// Hook-switch and SQL files are already read bounded (64 KiB and 1 MiB);
// this caps the sum over every distinct file.
const replayFSMaxFileBytes = 32 << 20

// ReplayFS memoizes the policy engine's filesystem lookups for one replay.
// One value may be shared by every guard a replay builds (the as-is guard and
// a recipe's before/after pair judge the same captured actions against the same
// filesystem). It is safe for concurrent use. The zero value is not usable;
// call NewReplayFS.
type ReplayFS struct {
	mu        sync.Mutex
	links     map[string]string
	hookFiles map[string]memoFile
	sqlFiles  map[string]memoFile
	fileBytes int
}

type memoFile struct {
	b  []byte
	ok bool
}

// NewReplayFS returns an empty memo for one replay.
func NewReplayFS() *ReplayFS {
	return &ReplayFS{
		links:     map[string]string{},
		hookFiles: map[string]memoFile{},
		sqlFiles:  map[string]memoFile{},
	}
}

// resolveLinks memoizes resolve.
func (m *ReplayFS) resolveLinks(resolve func(string) string) func(string) string {
	return func(p string) string {
		m.mu.Lock()
		if v, ok := m.links[p]; ok {
			m.mu.Unlock()
			return v
		}
		m.mu.Unlock()
		v := resolve(p)
		m.mu.Lock()
		if len(m.links) < replayFSMaxEntries {
			m.links[p] = v
		}
		m.mu.Unlock()
		return v
	}
}

// readFile memoizes one of the bounded file readers into the given map.
func (m *ReplayFS) readFile(which func(*ReplayFS) map[string]memoFile, read func(string) ([]byte, bool)) func(string) ([]byte, bool) {
	return func(p string) ([]byte, bool) {
		m.mu.Lock()
		if v, ok := which(m)[p]; ok {
			m.mu.Unlock()
			return v.b, v.ok
		}
		m.mu.Unlock()
		b, ok := read(p)
		m.mu.Lock()
		cache := which(m)
		if len(cache) < replayFSMaxEntries && m.fileBytes+len(b) <= replayFSMaxFileBytes {
			cache[p] = memoFile{b: b, ok: ok}
			m.fileBytes += len(b)
		}
		m.mu.Unlock()
		return b, ok
	}
}

// fsReaders is the policy engine's filesystem seam for one guard: the live
// readers, or the replay memo over them.
type fsReaders struct {
	resolveLinks func(string) string
	hookFile     func(string) ([]byte, bool)
	sqlFile      func(string) ([]byte, bool)
}

// fsSeam returns the guard's filesystem seam, the live readers for a Guard
// built without New (its zero fs).
func (g *Guard) fsSeam() fsReaders {
	if g.fs.resolveLinks == nil {
		return newFSReaders(nil)
	}
	return g.fs
}

// newFSReaders composes the seam. A nil memo is the live guard, byte-identical
// to the readers before the memo existed.
func newFSReaders(memo *ReplayFS) fsReaders {
	live := fsReaders{resolveLinks: resolveExistingLinks, hookFile: readHookSwitchFile, sqlFile: readSQLFileBounded}
	if memo == nil {
		return live
	}
	return fsReaders{
		resolveLinks: memo.resolveLinks(live.resolveLinks),
		hookFile:     memo.readFile(func(m *ReplayFS) map[string]memoFile { return m.hookFiles }, live.hookFile),
		sqlFile:      memo.readFile(func(m *ReplayFS) map[string]memoFile { return m.sqlFiles }, live.sqlFile),
	}
}
