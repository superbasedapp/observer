package agentconfig

import (
	"bytes"
	"strings"
)

// KeyPresent is the value a boundary puts in a runtime tree for a key it saw
// set in a credential-bearing file (a .env file) without reading the value.
// A URL family classes it ClassSet.
type KeyPresent struct{}

// DotenvKeysPresent reports which of keys a .env document sets, by name
// only: `KEY=...` or `export KEY=...` on its own line, comments and blank
// lines skipped. An empty value counts as set (the tool loads it and it
// overrides the variable). No value is returned, kept or compared: a .env
// file holds credentials (surface-gap CLI-6, CLI-7). The result keeps the
// order of keys.
func DotenvKeysPresent(b []byte, keys []string) []string {
	want := map[string]bool{}
	for _, k := range keys {
		want[k] = true
	}
	set := map[string]bool{}
	for _, line := range bytes.Split(b, []byte("\n")) {
		s := strings.TrimSpace(string(bytes.TrimPrefix(line, []byte("\xef\xbb\xbf"))))
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		s = strings.TrimPrefix(s, "export ")
		i := strings.IndexByte(s, '=')
		if i <= 0 {
			continue
		}
		if name := strings.TrimSpace(s[:i]); want[name] {
			set[name] = true
		}
	}
	var out []string
	for _, k := range keys {
		if set[k] {
			out = append(out, k)
			delete(set, k)
		}
	}
	return out
}
