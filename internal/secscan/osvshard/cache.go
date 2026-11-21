package osvshard

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// DefaultCacheBytes caps the cache when Cache.MaxBytes is 0: every language
// set together is about 98 MiB of shards (RM-1, 2026-11-04), and a first
// scan of this repository took 8.1 MB, so 256 MiB keeps several projects'
// shards across ecosystems.
const DefaultCacheBytes = 256 << 20

// CacheDirName is the cache's directory name in the security directory
// (~/.observer/security/osv-shards/, plan section 13.3).
const CacheDirName = "osv-shards"

// Cache is the node-local store of verified shard objects, laid out as the
// shard bucket is (<Set>/index/<sha256>.json, <Set>/obj/<sha256>.json.gz),
// keyed by digest. An object is written only after it verified and is
// verified again on every read, so a file changed on disk is a miss, never
// a wrong answer. The zero value (no Dir) caches nothing.
type Cache struct {
	// Dir is the cache directory; "" disables the cache.
	Dir string
	// MaxBytes caps the directory; 0 means DefaultCacheBytes.
	MaxBytes int64
	// Now is the clock for the least-recently-used stamps (tests).
	Now func() time.Time
}

func (c Cache) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c Cache) max() int64 {
	if c.MaxBytes > 0 {
		return c.MaxBytes
	}
	return DefaultCacheBytes
}

// path maps an object path (osvshardkey.IndexPath or ShardPath, always
// "<Set>/<index|obj>/<sha256>.<ext>" with a validated set and digest) to
// its file.
func (c Cache) path(rel string) (string, bool) {
	if c.Dir == "" || rel == "" || strings.Contains(rel, "..") || strings.ContainsAny(rel, `\:`) || strings.HasPrefix(rel, "/") {
		return "", false
	}
	return filepath.Join(c.Dir, filepath.FromSlash(rel)), true
}

// get returns the cached object at rel when its size and sha256 match;
// a hit is stamped as recently used.
func (c Cache) get(rel, sum string, size int64) ([]byte, bool) {
	p, ok := c.path(rel)
	if !ok {
		return nil, false
	}
	fi, err := os.Stat(p)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() != size {
		return nil, false
	}
	b, err := os.ReadFile(p) //nolint:gosec // G304: a file of the node's own cache directory
	if err != nil || int64(len(b)) != size || hashOf(b) != sum {
		return nil, false
	}
	now := c.now()
	_ = os.Chtimes(p, now, now)
	return b, true
}

// put stores a verified object (best effort: a cache that cannot be
// written only costs a fetch next time).
func (c Cache) put(rel string, data []byte) error {
	p, ok := c.path(rel)
	if !ok {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(p), ".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	_, werr := tmp.Write(data)
	if cerr := tmp.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = os.Rename(name, p)
	}
	if werr != nil {
		_ = os.Remove(name)
		return werr
	}
	now := c.now()
	_ = os.Chtimes(p, now, now)
	return nil
}

// Trim removes the least recently used objects until the directory is
// under its cap (and every stray temp file). It never removes anything
// outside Dir.
func (c Cache) Trim() error {
	if c.Dir == "" {
		return nil
	}
	type obj struct {
		path string
		size int64
		at   time.Time
	}
	var objs []obj
	var total int64
	err := filepath.WalkDir(c.Dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		if d.IsDir() {
			return nil
		}
		fi, err := d.Info()
		if err != nil || !fi.Mode().IsRegular() {
			return nil
		}
		if strings.HasPrefix(d.Name(), ".tmp-") && c.now().Sub(fi.ModTime()) > time.Hour {
			_ = os.Remove(p) //nolint:gosec // G122: p is a regular file (checked above) WalkDir found in the node's own cache directory; WalkDir follows no symlink, and a raced replacement only loses a stale temp file.
			return nil
		}
		objs = append(objs, obj{path: p, size: fi.Size(), at: fi.ModTime()})
		total += fi.Size()
		return nil
	})
	if err != nil {
		return fmt.Errorf("osvshard.Cache.Trim: %w", err)
	}
	sort.Slice(objs, func(i, j int) bool {
		if !objs[i].at.Equal(objs[j].at) {
			return objs[i].at.Before(objs[j].at)
		}
		return objs[i].path < objs[j].path
	})
	for _, o := range objs {
		if total <= c.max() {
			break
		}
		if err := os.Remove(o.path); err == nil {
			total -= o.size
		}
	}
	return nil
}

// Bytes is the cache's size on disk.
func (c Cache) Bytes() int64 {
	var total int64
	if c.Dir == "" {
		return 0
	}
	_ = filepath.WalkDir(c.Dir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if fi, err := d.Info(); err == nil && fi.Mode().IsRegular() {
			total += fi.Size()
		}
		return nil
	})
	return total
}

func hashOf(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
