package latencygate

import (
	"bufio"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// EnvSkip is the variable the CI test shards set to skip the latency tests;
// ci.yml's latency step runs them instead.
const EnvSkip = "SBO_SKIP_LATENCY_TESTS"

// ListFile is the module-relative path of the list of latency tests, one
// "<module-relative package> TAB <top-level test name>" per line.
const ListFile = "scripts/ci/latency-tests.txt"

// Gate is called first in a wall-clock latency test. It fails the test when
// the list does not name it, and skips it under -short or when EnvSkip is 1.
func Gate(t testing.TB) {
	t.Helper()
	_, caller, _, ok := runtime.Caller(1)
	if ok {
		if root, found := moduleRoot(); found {
			if pkg, err := filepath.Rel(root, filepath.Dir(caller)); err == nil {
				name, _, _ := strings.Cut(t.Name(), "/")
				listed, err := Listed(filepath.Join(root, filepath.FromSlash(ListFile)), filepath.ToSlash(pkg), name)
				if err != nil {
					t.Fatalf("latencygate: %v", err)
				}
				if !listed {
					t.Fatalf("latencygate: %s in %s is not listed in %s; ci.yml's latency step runs only listed tests, so add the line \"%s\\t%s\"",
						name, filepath.ToSlash(pkg), ListFile, filepath.ToSlash(pkg), name)
				}
			}
		}
	}
	if testing.Short() {
		t.Skip("wall-clock latency assertion skipped under -short")
	}
	if os.Getenv(EnvSkip) == "1" {
		t.Skip("wall-clock latency assertion skipped in a loaded test shard (" + EnvSkip + "=1); ci.yml's latency step runs it")
	}
}

// Listed reports whether the list file names the test in the package.
func Listed(listPath, pkg, test string) (bool, error) {
	f, err := os.Open(listPath) //nolint:gosec // G304: a fixed path under the module root
	if err != nil {
		return false, err
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p, n, ok := strings.Cut(line, "\t")
		if ok && strings.TrimSpace(p) == pkg && strings.TrimSpace(n) == test {
			return true, nil
		}
	}
	return false, sc.Err()
}

// moduleRoot finds the module root from this file's own path. A binary
// built with -trimpath carries no absolute path; the listing check is then
// skipped, never failed.
func moduleRoot() (string, bool) {
	_, self, _, ok := runtime.Caller(0)
	if !ok || !filepath.IsAbs(self) {
		return "", false
	}
	root := filepath.Join(filepath.Dir(self), "..", "..", "..")
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		return "", false
	}
	if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(ListFile))); err != nil {
		return "", false
	}
	return root, true
}
