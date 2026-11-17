package cvss4

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// readTSV reads a testdata file: tab-separated columns, '#' lines and blank
// lines skipped.
func readTSV(t *testing.T, name string) [][]string {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer func() { _ = f.Close() }()
	var rows [][]string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		rows = append(rows, strings.Split(line, "\t"))
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	if len(rows) == 0 {
		t.Fatalf("fixture %s has no rows", name)
	}
	return rows
}

// selectionOf reads a full CVSS 4.0 vector, threat, environmental and
// supplemental metrics included, into the calculator's selection: every
// metric the vector does not mention is "X". Test code only; the scorer's
// public surface accepts base vectors alone.
func selectionOf(t *testing.T, vector string) selection {
	t.Helper()
	if !strings.HasPrefix(vector, Prefix) {
		t.Fatalf("not a 4.0 vector: %q", vector)
	}
	s := selection{}
	for _, k := range knownMetricKeys {
		s[k] = "X"
	}
	for _, part := range strings.Split(vector[len(Prefix):], "/") {
		k, v, ok := strings.Cut(part, ":")
		if !ok {
			t.Fatalf("bad part %q in %q", part, vector)
		}
		s[k] = v
	}
	return s
}
