package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/seccorpus"
)

// repo is one row of corpus/repos.tsv.
type repo struct {
	URL    string
	Commit string
}

// dir is the clone's directory name under the scratch root.
func (r repo) dir() string {
	s := strings.TrimPrefix(r.URL, "https://github.com/")
	return strings.NewReplacer("/", "__", ":", "_").Replace(s)
}

// readRepos reads repos.tsv: URL, a tab, the full commit id; # comments.
func readRepos(path string) ([]repo, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []repo
	for i, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		f := strings.Split(l, "\t")
		if len(f) != 2 {
			return nil, fmt.Errorf("%s:%d: want URL<TAB>commit", path, i+1)
		}
		r := repo{URL: f[0], Commit: f[1]}
		probe := seccorpus.Finding{Repo: r.URL, Commit: r.Commit, Path: "x", Line: 1, Rule: "x"}
		if err := probe.Validate(); err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, i+1, err)
		}
		out = append(out, r)
	}
	return out, nil
}

// writeJSONL writes one JSON object per line.
func writeJSONL[T any](path string, rows []T) error {
	b, err := marshalJSONL(rows)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

// marshalJSONL renders one JSON object per line.
func marshalJSONL[T any](rows []T) ([]byte, error) {
	var buf bytes.Buffer
	for _, r := range rows {
		b, err := json.Marshal(r)
		if err != nil {
			return nil, err
		}
		buf.Write(b)
		buf.WriteByte('\n')
	}
	return buf.Bytes(), nil
}

// readJSONL reads one JSON object per line, strictly.
func readJSONL[T any](path string) ([]T, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseJSONL[T](path, b, 0)
}

// parseJSONL decodes one JSON object per line of b, strictly; name and
// the line offset only label errors.
func parseJSONL[T any](name string, b []byte, offset int) ([]T, error) {
	var out []T
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for n := offset + 1; sc.Scan(); n++ {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var v T
		dec := json.NewDecoder(bytes.NewReader(line))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&v); err != nil {
			return nil, fmt.Errorf("%s:%d: %w", name, n, err)
		}
		out = append(out, v)
	}
	return out, sc.Err()
}

// writeJSON writes an indented JSON file.
func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

// readJSON reads a JSON file strictly.
func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

// jsonIndent is the manifest's on-disk form: two-space indent, newline.
func jsonIndent(v any) ([]byte, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}
