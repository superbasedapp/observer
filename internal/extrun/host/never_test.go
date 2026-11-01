package host

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestNeverAddressSpaceOrNprocLimits pins two JSP-12 findings in the source:
// RLIMIT_AS is never a cap (a Go program cannot even start under 512 MiB of
// address space) and RLIMIT_NPROC is never a cap (it counts every process
// and thread the user owns, and is ignored for root). No non-test file of
// the runner may name either.
func TestNeverAddressSpaceOrNprocLimits(t *testing.T) {
	t.Parallel()
	bad := regexp.MustCompile(`RLIMIT_(AS|NPROC)\b`)
	for _, dir := range []string{".", ".."} {
		files, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			data, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			for _, line := range strings.Split(string(data), "\n") {
				code, _, _ := strings.Cut(line, "//")
				if bad.MatchString(code) {
					t.Errorf("%s uses %s", f, bad.FindString(code))
				}
			}
		}
	}
}
