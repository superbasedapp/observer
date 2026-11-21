//go:build !sbo_omit_security && !sbo_omit_security_scan_opengrep

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/secscan"
	"github.com/marmutapp/superbased-observer/internal/secscan/opengrep"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// security_opengrep_taintcache.go is the intrafile taint pass's I/O on the
// node: its result cache (one file, this file its only writer) and the
// project-file stat the pass plans its targets with.

// codeTaintCacheFile is the cache's file name under the scanner root
// (codeScanRoot): beside the engine's own cache and the pack copies, a
// regenerable cache that never enters the database, so it can never reach
// the org push.
const codeTaintCacheFile = "taint-cache.json"

// codeTaintCacheMaxBytes caps the cache file read back: a larger file is
// treated as empty (the pass re-runs every file and rewrites it pruned).
const codeTaintCacheMaxBytes = 64 << 20

// codeTaintCacheStore is the cache file (opengrep.TaintCacheStore).
type codeTaintCacheStore struct{ path string }

func (c codeTaintCacheStore) Load() (opengrep.TaintCache, error) {
	var out opengrep.TaintCache
	b, err := readCappedFile(c.path, codeTaintCacheMaxBytes)
	if errors.Is(err, fs.ErrNotExist) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return opengrep.TaintCache{}, err
	}
	return out, nil
}

func (c codeTaintCacheStore) Save(tc opengrep.TaintCache) error {
	b, err := json.Marshal(tc)
	if err != nil {
		return err
	}
	if len(b) > codeTaintCacheMaxBytes {
		// Never write a file the next load would refuse: keep none.
		_ = os.Remove(c.path)
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(c.path), 0o700); err != nil {
		return err
	}
	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, c.path)
}

// codeLstat is the pass's file stat: the size and whether the path itself
// is a regular file (a symlink is never followed).
func codeLstat(path string) (int64, bool, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return 0, false, err
	}
	return fi.Size(), fi.Mode().IsRegular(), nil
}

// codeTaintConfig is the pass's configuration from [security.scan.opengrep].
func codeTaintConfig(oc config.SecurityOpengrepConfig) opengrep.TaintConfig {
	return opengrep.TaintConfig{
		Mode: oc.TaintPass, BudgetSeconds: oc.TaintPassBudgetSeconds, Jobs: oc.TaintPassJobs, MemoryMiB: oc.TaintPassMemoryMiB,
	}
}

// codeLastTaintPass is the taint pass of the driver's newest run that
// recorded one (a full scan: no other scan runs it), in words, with the
// scan's time; ok is false when none did.
func codeLastTaintPass(ctx context.Context, st *store.Store) (string, time.Time, bool) {
	if st == nil {
		return "", time.Time{}, false
	}
	r, ok, err := st.SecLatestRunWithPasses(ctx, opengrep.DriverID)
	if err != nil || !ok || len(r.Passes) == 0 {
		return "", time.Time{}, false
	}
	var passes []secscan.PassStatus
	if json.Unmarshal(r.Passes, &passes) != nil {
		return "", time.Time{}, false
	}
	p, ok := opengrep.TaintPassOf(secscan.Coverage{Passes: passes})
	if !ok {
		return "", time.Time{}, false
	}
	return opengrep.TaintStatusWords(p), r.StartedAt, true
}
