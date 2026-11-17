package secassess

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"testing"
)

// webTableKeys returns the keys of an object literal the web declares as
// `export const NAME: ... = { key: "...", ... };`, in source order.
func webTableKeys(t *testing.T, src, name string) []string {
	t.Helper()
	body := regexp.MustCompile(`(?s)export const ` + name + `[^=]*= \{\r?\n(.*?)\r?\n\};`).FindStringSubmatch(src)
	if body == nil {
		t.Fatalf("the web has no table %s", name)
	}
	var keys []string
	for _, m := range regexp.MustCompile(`(?m)^  ([a-z_]+): `).FindAllStringSubmatch(body[1], -1) {
		keys = append(keys, m[1])
	}
	return keys
}

// TestEvidenceWordsMatchTheWeb: the closed lists the helper's evidence is made
// of (the reasons a finding reads No log and the codes a helper refuses a
// request under) are the keys of the web's sentence tables, in the same order,
// so a code either side adds without the other fails here by name.
func TestEvidenceWordsMatchTheWeb(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "web", "src", "lib", "secAssessModel.ts"))
	if err != nil {
		t.Fatal(err)
	}
	src := string(data)
	for _, c := range []struct {
		table string
		want  []string
	}{
		{"EVIDENCE_REASON_WORDS", EvidenceReasons},
		{"REFUSED_WORDS", ProbeRefusals()},
	} {
		got := webTableKeys(t, src, c.table)
		if !slices.Equal(got, c.want) {
			t.Errorf("%s keys\n  web: %v\n   Go: %v", c.table, got, c.want)
		}
	}
}
