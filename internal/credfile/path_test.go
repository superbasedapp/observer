package credfile

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// providersFixture is a Cline-shaped providers.json: two providers, each with
// a fake key, deliberately not in sorted key order and with mixed spacing so
// a re-serialization would show.
const providersFixture = "{\n" +
	"  \"version\": 1,\n" +
	"  \"providers\": {\n" +
	"    \"zed-provider\": {\"settings\": {\"apiKey\": \"" + fake + "\"}},\n" +
	"    \"openai-compatible\": {\n" +
	"      \"settings\": {\n" +
	"        \"apiKey\": \"" + fake + "\",\n" +
	"        \"baseUrl\": \"https://api.openai.com/v1\"\n" +
	"      },\n" +
	"      \"tokenSource\": \"manual\"\n" +
	"    }\n" +
	"  },\n" +
	"  \"lastUsedProvider\":   \"openai-compatible\"\n" +
	"}\n"

func TestSetObjectPath(t *testing.T) {
	path := []string{"providers", "openai-compatible", "settings", "baseUrl"}
	cases := []struct {
		name    string
		orig    string
		path    []string
		value   string
		present bool
		want    string
	}{
		{
			"replace a nested value, every sibling keeps its bytes", providersFixture, path, `"http://127.0.0.1:8820/v1"`, true,
			strings.Replace(providersFixture, "https://api.openai.com/v1", "http://127.0.0.1:8820/v1", 1),
		},
		{
			"remove a nested value", providersFixture, path, ``, false,
			strings.Replace(providersFixture, ",\n        \"baseUrl\": \"https://api.openai.com/v1\"", "", 1),
		},
		{"equal value is a no-op", providersFixture, path, `"https://api.openai.com/v1"`, true, providersFixture},
		{"absent removal is a no-op", providersFixture, []string{"providers", "nope", "settings", "baseUrl"}, ``, false, providersFixture},
		{
			"a missing intermediate is created", "{\n  \"a\": 1\n}\n",
			[]string{"b", "c"},
			`"x"`, true,
			"{\n  \"a\": 1,\n  \"b\": {\n    \"c\": \"x\"\n  }\n}\n",
		},
		{"a top-level member", "{\n  \"a\": 1\n}\n", []string{"a"}, `2`, true, "{\n  \"a\": 2\n}\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := SetObjectPath([]byte(tc.orig), tc.path, json.RawMessage(tc.value), tc.present)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tc.want {
				t.Errorf("got\n%s\nwant\n%s", got, tc.want)
			}
			if strings.Count(string(got), fake) != strings.Count(tc.orig, fake) {
				t.Errorf("a fake key was lost or duplicated")
			}
		})
	}
	for _, bad := range []struct{ name, orig string }{
		{"a step that is not an object", `{"providers": {"openai-compatible": {"settings": null}}}`},
		{"a step that is an array", `{"providers": []}`},
		{"not an object", `[1]`},
		{"does not parse", `{"providers": `},
	} {
		if _, err := SetObjectPath([]byte(bad.orig), path, json.RawMessage(`"x"`), true); !errors.Is(err, ErrPatch) {
			t.Errorf("%s: err = %v, want ErrPatch", bad.name, err)
		}
	}
	if _, err := SetObjectPath([]byte(`{}`), nil, json.RawMessage(`1`), true); !errors.Is(err, ErrPatch) {
		t.Errorf("empty path: err = %v, want ErrPatch", err)
	}
}

func TestObjectMembersReturnsOnlyTheNamedMembers(t *testing.T) {
	got, err := ObjectMembers([]byte(providersFixture), "lastUsedProvider", "absent")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || string(got["lastUsedProvider"]) != `"openai-compatible"` {
		t.Errorf("got %v", got)
	}
	for _, v := range got {
		if strings.Contains(string(v), fake) {
			t.Error("a member-only read returned a key")
		}
	}
	v, ok, err := ObjectPath([]byte(providersFixture), []string{"providers", "openai-compatible", "settings", "baseUrl"})
	if err != nil || !ok || string(v) != `"https://api.openai.com/v1"` {
		t.Errorf("ObjectPath = %s, %v, %v", v, ok, err)
	}
	if _, ok, err := ObjectPath([]byte(providersFixture), []string{"providers", "missing", "settings"}); ok || err != nil {
		t.Errorf("missing path = %v, %v", ok, err)
	}
	if _, _, err := ObjectPath([]byte(`[1]`), []string{"a"}); !errors.Is(err, ErrPatch) {
		t.Errorf("non-object = %v, want ErrPatch", err)
	}
}

func TestObjectKeys(t *testing.T) {
	got, err := ObjectKeys([]byte(providersFixture))
	if err != nil || strings.Join(got, ",") != "version,providers,lastUsedProvider" {
		t.Errorf("ObjectKeys = %v, %v", got, err)
	}
	if _, err := ObjectKeys([]byte(`null`)); !errors.Is(err, ErrPatch) {
		t.Errorf("null = %v, want ErrPatch", err)
	}
	if !IsObject([]byte(" {}")) || IsObject([]byte("null")) || IsObject(nil) {
		t.Error("IsObject")
	}
}
