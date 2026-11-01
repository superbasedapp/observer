package sectrust

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"
)

// corpusRuns is how many warm runs TestTrustCorpus times per repository.
const corpusRuns = 5

// TestTrustCorpus is the measuring harness for the JSP-7 50-repository run
// and its owed Windows and macOS halves (security pillar plan section 5.1,
// revision 2.5; scripts/sectrust-timing.sh). It runs only when
// SECTRUST_CORPUS names a directory of repository clones (one per
// subdirectory) and is otherwise skipped: it is a measurement, not a gate.
// It writes one TSV row per repository to SECTRUST_CORPUS_OUT (default:
// trust-corpus.tsv in the test's temporary directory, logged).
func TestTrustCorpus(t *testing.T) {
	dir := os.Getenv("SECTRUST_CORPUS")
	if dir == "" {
		t.Skip("SECTRUST_CORPUS is not set: the corpus timing harness runs only on request (scripts/sectrust-timing.sh)")
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	out := os.Getenv("SECTRUST_CORPUS_OUT")
	if out == "" {
		out = filepath.Join(t.TempDir(), "trust-corpus.tsv")
	}
	var b strings.Builder
	b.WriteString("repo\tverdict\tcodes\tdigests\tfiles_read\tbytes_read\tmedian_us\tmax_us\n")
	verdicts := map[Verdict]int{}
	var medians []time.Duration
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		root := filepath.Join(dir, e.Name())
		var times []time.Duration
		var res Result
		for i := 0; i < corpusRuns; i++ {
			t0 := time.Now()
			res, err = Check(context.Background(), OSFS(root), Request{})
			times = append(times, time.Since(t0))
			if err != nil {
				t.Fatalf("%s: %v", e.Name(), err)
			}
		}
		slices.Sort(times)
		median := times[len(times)/2]
		medians = append(medians, median)
		verdicts[res.Verdict]++
		fmt.Fprintf(&b, "%s\t%s\t%s\t%d\t%d\t%d\t%d\t%d\n", e.Name(), res.Verdict, strings.Join(res.Codes(), ","),
			len(res.Digests()), res.FilesRead, res.BytesRead, median.Microseconds(), times[len(times)-1].Microseconds())
	}
	if err := os.WriteFile(out, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	sort.Slice(medians, func(i, j int) bool { return medians[i] < medians[j] })
	if len(medians) > 0 {
		t.Logf("%d repositories: clean %d, flagged %d, untrusted %d; median of medians %v, p90 %v, max %v; rows in %s",
			len(medians), verdicts[VerdictClean], verdicts[VerdictFlagged], verdicts[VerdictUntrusted],
			medians[len(medians)/2], medians[len(medians)*9/10], medians[len(medians)-1], out)
	}
}

// BenchmarkCheckFixtures times one check over each JSP-7 fixture shape (the
// fixtures' half of the timing run).
func BenchmarkCheckFixtures(b *testing.B) {
	for _, tc := range jsp7Fixtures {
		b.Run(tc.name, func(b *testing.B) {
			root := buildForBench(b, tc.fx)
			fsys := OSFS(root)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := Check(context.Background(), fsys, Request{LaunchRel: tc.launch}); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// buildForBench writes a fixture for a benchmark (symlink fixtures are
// written without their links on a host that cannot make them).
func buildForBench(b *testing.B, f fixture) string {
	b.Helper()
	root := filepath.Join(b.TempDir(), "repo")
	if err := os.MkdirAll(filepath.Join(root, ".git"), 0o755); err != nil {
		b.Fatal(err)
	}
	for rel, body := range f.files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			b.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			b.Fatal(err)
		}
	}
	for link, target := range f.links {
		p := filepath.Join(root, filepath.FromSlash(link))
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		_ = os.Symlink(filepath.FromSlash(target), p)
	}
	return root
}
