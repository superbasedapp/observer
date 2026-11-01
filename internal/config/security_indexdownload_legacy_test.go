package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestIndexDownloadLegacyStrings is lane sec-deps4 audit finding 8: a
// config written while index_download was a string still loads, the old
// "on" words reading true and the "off" words false, in every spelling of
// the key; the bool form and an absent key are untouched, and a word
// outside the table still fails to load.
func TestIndexDownloadLegacyStrings(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cases := []struct {
		name string
		body string
		want bool
		ok   bool
	}{
		{"always", "[security.deps]\nindex_download = \"always\"\n", true, true},
		{"on", "[security.deps]\nindex_download = \"on\"\n", true, true},
		{"true as a string", "[security.deps]\nindex_download = \"true\"\n", true, true},
		{"never", "[security.deps]\nindex_download = \"never\"\n", false, true},
		{"off, single quotes", "[security.deps]\nindex_download = 'off'\n", false, true},
		{"false as a string", "[security.deps]\nindex_download = \"false\"\n", false, true},
		{"after_consent", "[security.deps]\nindex_download = \"after_consent\"\n", false, true},
		{"mixed case", "[security.deps]\nindex_download = \"Always\"\n", true, true},
		{"dotted under [security]", "[security]\ndeps.index_download = \"never\"\n", false, true},
		{"dotted at the top", "security.deps.index_download = \"off\"\n", false, true},
		{"bool true", "[security.deps]\nindex_download = true\n", true, true},
		{"bool false", "[security.deps]\nindex_download = false\n", false, true},
		{"absent", "[security.deps]\nonline = true\n", true, true},
		{"unknown word", "[security.deps]\nindex_download = \"sometimes\"\n", false, false},
	}
	for i, c := range cases {
		p := filepath.Join(dir, "c"+string(rune('a'+i))+".toml")
		if err := os.WriteFile(p, []byte(c.body), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, err := Load(LoadOptions{GlobalPath: p})
		if (err == nil) != c.ok {
			t.Errorf("%s: load err %v", c.name, err)
			continue
		}
		if c.ok && cfg.Security.Deps.IndexDownload != c.want {
			t.Errorf("%s: index_download %v, want %v", c.name, cfg.Security.Deps.IndexDownload, c.want)
		}
	}
	// Nothing but the key changes: a string elsewhere that mentions it stays.
	in := "[security.deps]\nindex_download = \"always\"\n# index_download = \"never\" was the old spelling\n"
	want := "[security.deps]\nindex_download = true\n# index_download = \"never\" was the old spelling\n"
	if got := string(normalizeLegacyIndexDownload([]byte(in))); got != want {
		t.Errorf("rewrite:\n%s\nwant:\n%s", got, want)
	}
}
