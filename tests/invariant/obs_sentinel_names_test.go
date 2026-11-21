// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 SuperBased

package invariant

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// TestEveryNodeObsTableIsNamedInTheSentinel: every table the machine's obs
// subsystem creates (internal/obs/store/migrations) is NODE-LOCAL and must be
// named in forbiddenCacheTables, so orgpush.go can never carry its name in a
// string literal. The obs_ prefix alone is not checked by
// TestSelectUnpushedSinceExcludesCacheTables (review finding R-C23: the
// saved views and alert state tables of obs 0020 / 0021 were missing).
func TestEveryNodeObsTableIsNamedInTheSentinel(t *testing.T) {
	t.Parallel()
	skipInPublicTree(t, repoRoot(t), "internal/obs (the node obs store and its migrations)")
	files, err := filepath.Glob(filepath.Join("..", "..", "internal", "obs", "store", "migrations", "*.sql"))
	if err != nil || len(files) == 0 {
		t.Fatalf("glob obs migrations: %v (%d files)", err, len(files))
	}
	named := map[string]bool{}
	for _, n := range forbiddenCacheTables {
		named[n] = true
	}
	create := regexp.MustCompile(`(?i)CREATE TABLE (?:IF NOT EXISTS )?(obs_[a-z0-9_]+)`)
	for _, f := range files {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range create.FindAllStringSubmatch(string(src), -1) {
			if !named[m[1]] {
				t.Errorf("%s creates node-local table %q, which is missing from forbiddenCacheTables", filepath.Base(f), m[1])
			}
		}
	}
}
