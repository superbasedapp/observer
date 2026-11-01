//go:build !sbo_omit_security && !sbo_omit_security_scan_opengrep

package main

import (
	"os"
	"sync"

	"github.com/marmutapp/superbased-observer/internal/extrun"
	extrunhost "github.com/marmutapp/superbased-observer/internal/extrun/host"
)

// security_opengrep_digest.go caches the engine binary's sha256 for the
// reads that only report or decide (lane SEC-G2 audit finding 2): the
// daemon loop's presence check every 15 s, the Code rules card's GET (which
// hashed it twice) and the Scanners GET each hashed the whole binary, about
// 47 MB. A cached digest is reused only while the file's size, modification
// time, mode and file identity (device and inode; volume serial and file
// index on Windows) all match what they were when it was hashed; a change in
// any of them hashes again. A file that changed while it was being hashed is
// not cached. A scan never reads this cache: its runner hashes the program
// again just before it starts it (extrun), and the driver decides on that.

// codeDigestKey is what a cached digest is valid for.
type codeDigestKey struct {
	size  int64
	modNS int64
	mode  os.FileMode
	id    string
}

type codeDigestEntry struct {
	key codeDigestKey
	sum string
	n   int64
}

// codeDigestCache is the process's one digest cache (one owner of the
// state), keyed by path.
type codeDigestCache struct {
	mu sync.Mutex
	m  map[string]codeDigestEntry
}

// codeDigests is the cache the inspector and the install plan read through.
var codeDigests = &codeDigestCache{m: map[string]codeDigestEntry{}}

// keyOf stats path; ok is false when it cannot be keyed (then nothing is
// cached and every read hashes).
func (c *codeDigestCache) keyOf(path string, stat func(string) (os.FileInfo, error)) (codeDigestKey, bool) {
	fi, err := stat(path)
	if err != nil {
		return codeDigestKey{}, false
	}
	id, ok := codeFileID(path, fi)
	if !ok {
		return codeDigestKey{}, false
	}
	return codeDigestKey{size: fi.Size(), modNS: fi.ModTime().UnixNano(), mode: fi.Mode(), id: id}, true
}

// digest returns path's digest from the cache when its key still matches,
// otherwise from hash, caching the result when the key did not move while
// hash ran.
func (c *codeDigestCache) digest(path string, stat func(string) (os.FileInfo, error), hash func() (string, int64, error)) (string, int64, error) {
	before, ok := c.keyOf(path, stat)
	if ok {
		c.mu.Lock()
		e, hit := c.m[path]
		c.mu.Unlock()
		if hit && e.key == before {
			return e.sum, e.n, nil
		}
	}
	sum, n, err := hash()
	if err != nil || !ok {
		return sum, n, err
	}
	if after, ok := c.keyOf(path, stat); ok && after == before {
		c.mu.Lock()
		c.m[path] = codeDigestEntry{key: before, sum: sum, n: n}
		c.mu.Unlock()
	}
	return sum, n, nil
}

// codeCachedHash wraps a runner's Hash with the cache. The runner hashes
// the resolved real path, so the key follows links (os.Stat).
func codeCachedHash(c *codeDigestCache, h func(string) (string, error)) func(string) (string, error) {
	return func(path string) (string, error) {
		sum, _, err := c.digest(path, os.Stat, func() (string, int64, error) {
			s, err := h(path)
			return s, 0, err
		})
		return sum, err
	}
}

// codeInspectRunner is the inspector's unisolated runner with its Hash
// read through the cache (it starts nothing; Probe and Inspect only).
func codeInspectRunner() *extrun.Runner {
	r := extrunhost.NewRunner(extrunhost.Options{})
	if r.Hash != nil {
		r.Hash = codeCachedHash(codeDigests, r.Hash)
	}
	return r
}

// cachedRegularFileDigest is hashRegularFile through the cache (os.Lstat:
// a link put in place of the file changes the mode and the identity).
func cachedRegularFileDigest(path string, limit int64) (string, error) {
	sum, _, err := codeDigests.digest(path, os.Lstat, func() (string, int64, error) { return hashRegularFile(path, limit) })
	return sum, err
}
