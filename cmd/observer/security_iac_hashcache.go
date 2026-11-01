//go:build !sbo_omit_security

package main

import (
	"os"
	"sync"
	"time"
)

// security_iac_hashcache.go is the IaC engines' probe hash cache (audit
// finding F5 of lane GATES-SEC): the daemon's 15 s loop resolves each
// selected engine, and hashing a 100 MB binary every pass is wasted work
// when nothing changed. The resolve step hashes through this cache, keyed
// by path, size and modification time; any change of the three rehashes.
// The exec-time digest check in internal/extrun never goes through it: a
// binary swapped under the same size and time is still refused when it is
// started (digest_mismatch).

// iacProbeHashes is the process's one cache (one owner: this file).
var iacProbeHashes = &iacHashCache{}

// iacHashCacheMax bounds the cache (a handful of engine paths in practice).
const iacHashCacheMax = 64

type iacHashEntry struct {
	size  int64
	mtime time.Time
	sum   string
}

type iacHashCache struct {
	mu sync.Mutex
	m  map[string]iacHashEntry
}

// hash wraps raw with the cache; stat reads the file's size and time.
func (c *iacHashCache) hash(raw func(string) (string, error), stat func(string) (os.FileInfo, error)) func(string) (string, error) {
	if raw == nil {
		return nil
	}
	return func(path string) (string, error) {
		fi, err := stat(path)
		if err != nil {
			return raw(path)
		}
		c.mu.Lock()
		e, ok := c.m[path]
		c.mu.Unlock()
		if ok && e.size == fi.Size() && e.mtime.Equal(fi.ModTime()) {
			return e.sum, nil
		}
		sum, err := raw(path)
		if err != nil {
			return "", err
		}
		c.mu.Lock()
		if c.m == nil || len(c.m) >= iacHashCacheMax {
			c.m = map[string]iacHashEntry{}
		}
		c.m[path] = iacHashEntry{size: fi.Size(), mtime: fi.ModTime(), sum: sum}
		c.mu.Unlock()
		return sum, nil
	}
}
