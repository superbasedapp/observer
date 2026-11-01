package credfile

import (
	"errors"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cfgfmt"
)

const yamlWithSecret = `# personal settings
web_search:
  api_key: sk-live-SECRET  # keep me
pool:
  default_agent_server: local
hooks: {}
`

// TestSetYAMLMember pins the member editor: a new key lands beside its
// siblings with every other byte (the secret and both comments) intact, a
// new parent mapping is created, removal cuts only the member, an absent
// removal is a no-op, an alias on the path is refused, and no
// error quotes the file.
func TestSetYAMLMember(t *testing.T) {
	out, err := SetYAMLMember([]byte(yamlWithSecret), []string{"pool", "api_url"}, "http://127.0.0.1:8820/v1", true)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, keep := range []string{"# personal settings", "api_key: sk-live-SECRET  # keep me", "default_agent_server: local", "api_url: http://127.0.0.1:8820/v1"} {
		if !strings.Contains(s, keep) {
			t.Errorf("result lost or lacks %q:\n%s", keep, s)
		}
	}
	back, err := SetYAMLMember(out, []string{"pool", "api_url"}, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if string(back) != yamlWithSecret {
		t.Errorf("set then remove is not byte-identical:\n%s", back)
	}
	same, err := SetYAMLMember([]byte(yamlWithSecret), []string{"pool", "absent"}, nil, false)
	if err != nil || string(same) != yamlWithSecret {
		t.Errorf("absent removal changed the file (%v)", err)
	}
	created, err := SetYAMLMember([]byte(yamlWithSecret), []string{"model", "provider"}, "observer", true)
	if err != nil {
		t.Fatal(err)
	}
	if v, ok, _ := MemberValue(cfgfmt.FormatYAML, created, []string{"model", "provider"}); !ok || v != "observer" {
		t.Errorf("new parent mapping: got %v %v", v, ok)
	}
	aliased := yamlWithSecret + "base: &b\n  x: 1\nother: *b\n"
	_, err = SetYAMLMember([]byte(aliased), []string{"other", "x"}, "y", true)
	if err == nil {
		t.Fatal("an edit through an alias was not refused")
	}
	if strings.Contains(err.Error(), "SECRET") {
		t.Errorf("error quotes the file: %v", err)
	}
	if _, err := SetYAMLMember([]byte("a: [unclosed\n  sk-SECRET"), []string{"a"}, "b", true); !errors.Is(err, ErrPatch) || strings.Contains(err.Error(), "SECRET") {
		t.Errorf("a broken file: err = %v, want the withheld ErrPatch", err)
	}
}

// TestSetMemberTOMLAndJSON runs the same editor over TOML and JSON.
func TestSetMemberTOMLAndJSON(t *testing.T) {
	toml := "# top\nmodel_provider = \"x\"\n[profiles.default]\napi_key = \"SECRET\"\n"
	out, err := SetMember(cfgfmt.FormatTOML, []byte(toml), []string{"profiles", "default", "api_endpoint"}, "http://127.0.0.1:8820/v1", true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `api_key = "SECRET"`) || !strings.Contains(string(out), "# top") {
		t.Errorf("TOML edit lost bytes:\n%s", out)
	}
	js := `{"a": 1, "secret": "SECRET", "n": {"k": true}}`
	out, err = SetMember(cfgfmt.FormatJSON, []byte(js), []string{"n", "base"}, "u", true)
	if err != nil {
		t.Fatal(err)
	}
	if v, ok, _ := MemberValue(cfgfmt.FormatJSON, out, []string{"n", "base"}); !ok || v != "u" {
		t.Errorf("JSON member = %v %v", v, ok)
	}
	if !strings.Contains(string(out), `"secret": "SECRET"`) {
		t.Errorf("JSON edit lost bytes: %s", out)
	}
}
