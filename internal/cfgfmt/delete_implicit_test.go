package cfgfmt

import (
	"testing"
)

// TestTOMLDeleteImplicitParent pins the surgical delete of a table whose
// parent is implicit (live proof 2026-10-21: removing Observer's last
// [hooks.state."<path>:<event>:0:0"] record failed under ForbidReserialize
// because the expected tree kept an empty hooks.state that no TOML line can
// spell). Every row runs with ForbidReserialize: the edit must be byte
// surgical, keep every other byte, and never fall back.
func TestTOMLDeleteImplicitParent(t *testing.T) {
	// TOML basic strings: the backslashes are escaped, as tomlString writes.
	const win = `"C:\\Users\\op\\.codex\\hooks.json:pre_tool_use:0:0"`
	const winStop = `"C:\\Users\\op\\.codex\\hooks.json:stop:0:0"`
	winKey := `C:\Users\op\.codex\hooks.json:pre_tool_use:0:0`
	cases := []struct {
		name string
		in   string
		del  []Path
		want string
	}{
		{
			name: "last-table-only-child",
			in:   "model = \"x\"\n\n[hooks.state.\"a:pre:0:0\"]\ntrusted_hash = \"sha256:1\"\n",
			del:  []Path{{"hooks", "state", "a:pre:0:0"}},
			want: "model = \"x\"\n",
		},
		{
			name: "every-table-one-by-one",
			in: "model = \"x\"\n\n[hooks.state.\"a:pre:0:0\"]\ntrusted_hash = \"sha256:1\"\n\n" +
				"[hooks.state.\"a:post:0:0\"]\ntrusted_hash = \"sha256:2\"\n\n[hooks.state.\"a:stop:0:0\"]\ntrusted_hash = \"sha256:3\"\n",
			del:  []Path{{"hooks", "state", "a:post:0:0"}, {"hooks", "state", "a:pre:0:0"}, {"hooks", "state", "a:stop:0:0"}},
			want: "model = \"x\"\n",
		},
		{
			name: "middle-table-keeps-neighbours",
			in: "[hooks.state.\"a:pre:0:0\"]\ntrusted_hash = \"sha256:1\"\n\n[hooks.state.\"a:post:0:0\"]\ntrusted_hash = \"sha256:2\"\n\n" +
				"[hooks.state.\"a:stop:0:0\"]\ntrusted_hash = \"sha256:3\"\n",
			del:  []Path{{"hooks", "state", "a:post:0:0"}},
			want: "[hooks.state.\"a:pre:0:0\"]\ntrusted_hash = \"sha256:1\"\n\n[hooks.state.\"a:stop:0:0\"]\ntrusted_hash = \"sha256:3\"\n",
		},
		{
			name: "user-record-stays",
			in: "[hooks.state.\"user:pre:0:0\"]\ntrusted_hash = \"sha256:users-own\"\n\n" +
				"[hooks.state.\"a:pre:0:0\"]\ntrusted_hash = \"sha256:1\"\n",
			del:  []Path{{"hooks", "state", "a:pre:0:0"}},
			want: "[hooks.state.\"user:pre:0:0\"]\ntrusted_hash = \"sha256:users-own\"\n",
		},
		{
			name: "windows-keys-crlf",
			in:   "model = \"x\"\r\n\r\n[hooks.state." + win + "]\r\ntrusted_hash = \"sha256:1\"\r\n\r\n[hooks.state." + winStop + "]\r\ntrusted_hash = \"sha256:2\"\r\n",
			del:  []Path{{"hooks", "state", winKey}, {"hooks", "state", `C:\Users\op\.codex\hooks.json:stop:0:0`}},
			want: "model = \"x\"\r\n",
		},
		{
			name: "windows-literal-key",
			in:   "[hooks.state.'" + winKey + "']\ntrusted_hash = \"sha256:1\"\n",
			del:  []Path{{"hooks", "state", winKey}},
			want: "",
		},
		{
			name: "comments-around",
			in: "# top comment\nmodel = \"x\"\n\n# about a section\n[features]\nhooks = true # inline\n\n" +
				"# observer trust record\n[hooks.state.\"a:pre:0:0\"]\ntrusted_hash = \"sha256:1\"\n# trailing note\n\n[tui]\ntheme = \"dark\"\n",
			del: []Path{{"hooks", "state", "a:pre:0:0"}},
			want: "# top comment\nmodel = \"x\"\n\n# about a section\n[features]\nhooks = true # inline\n\n" +
				"# trailing note\n\n[tui]\ntheme = \"dark\"\n",
		},
		{
			name: "explicit-parent-header-kept",
			in:   "[hooks.state]\n\n[hooks.state.\"a:pre:0:0\"]\ntrusted_hash = \"sha256:1\"\n",
			del:  []Path{{"hooks", "state", "a:pre:0:0"}},
			want: "[hooks.state]\n",
		},
		{
			name: "explicit-grandparent-with-keys-kept",
			in:   "[hooks]\nenabled = true\n\n[hooks.state.\"a:pre:0:0\"]\ntrusted_hash = \"sha256:1\"\n",
			del:  []Path{{"hooks", "state", "a:pre:0:0"}},
			want: "[hooks]\nenabled = true\n",
		},
		{
			name: "dotted-keys-under-explicit-header",
			in:   "[hooks]\nstate.\"a:pre:0:0\".trusted_hash = \"sha256:1\"\n",
			del:  []Path{{"hooks", "state", "a:pre:0:0"}},
			want: "[hooks]\n",
		},
		{
			name: "leaf-key-then-empty-table",
			in:   "a = 1\n\n[hooks.state.\"a:pre:0:0\"]\ntrusted_hash = \"sha256:1\"\n",
			del:  []Path{{"hooks", "state", "a:pre:0:0", "trusted_hash"}},
			want: "a = 1\n\n[hooks.state.\"a:pre:0:0\"]\n",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, err := ParseWith(FormatTOML, []byte(c.in), Options{ForbidReserialize: true})
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			for _, p := range c.del {
				found, err := d.Delete(p)
				if err != nil || !found {
					t.Fatalf("delete %s: found=%v err=%v", p, found, err)
				}
			}
			if got := string(d.Bytes()); got != c.want {
				t.Fatalf("got:\n%q\nwant:\n%q", got, c.want)
			}
			if len(d.Disclosures()) > 0 {
				t.Fatalf("disclosures = %v, want a surgical edit", d.Disclosures())
			}
			if _, err := Parse(FormatTOML, d.Bytes()); err != nil {
				t.Fatalf("output does not re-parse: %v", err)
			}
		})
	}
}

// TestTOMLSetThenDeleteRoundTrip: deleting the [hooks.state] records a Set
// appended restores the original file byte for byte (the Codex trust
// register / unregister pair), comments and CRLF included. (A missing
// final newline is not in the table: Set itself terminates the old last
// line, see toml-no-eol-insert.)
func TestTOMLSetThenDeleteRoundTrip(t *testing.T) {
	keys := []string{"/h/.codex/hooks.json:pre_tool_use:0:0", "/h/.codex/hooks.json:stop:0:0"}
	for _, in := range []string{
		"",
		"model = \"x\"\n",
		"# top\r\nmodel = \"x\"\r\n\r\n[features]\r\nhooks = true # keep\r\n",
		"[hooks.state.\"user:pre:0:0\"]\ntrusted_hash = \"sha256:users-own\"\n",
	} {
		d, err := ParseWith(FormatTOML, []byte(in), Options{ForbidReserialize: true})
		if err != nil {
			t.Fatalf("%q: parse: %v", in, err)
		}
		for _, k := range keys {
			if err := d.Set(Path{"hooks", "state", k, "trusted_hash"}, "sha256:obs"); err != nil {
				t.Fatalf("%q: set: %v", in, err)
			}
		}
		for _, k := range keys {
			if _, err := d.Delete(Path{"hooks", "state", k}); err != nil {
				t.Fatalf("%q: delete: %v", in, err)
			}
		}
		if got := string(d.Bytes()); got != in {
			t.Errorf("round trip changed the file:\n got %q\nwant %q", got, in)
		}
	}
}
