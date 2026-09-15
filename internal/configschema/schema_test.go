package configschema

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
)

func mustLeaf(t *testing.T, path string) Leaf {
	t.Helper()
	l, ok := Lookup(path)
	if !ok {
		t.Fatalf("Lookup(%q): not found", path)
	}
	return l
}

func TestParseValue(t *testing.T) {
	cases := []struct {
		path string
		raw  string
		want any
		err  string
	}{
		{"observer.hooks.auto_register", `true`, true, ""},
		{"observer.hooks.auto_register", `"false"`, false, ""},
		{"observer.hooks.auto_register", `"yes"`, nil, "wants true/false"},
		{"observer.hooks.auto_register", `1`, nil, "wants a bool"},
		{"terminal.max_concurrent", `12`, int64(12), ""},
		{"terminal.max_concurrent", `"12"`, int64(12), ""},
		{"terminal.max_concurrent", `12.5`, nil, "wants an integer"},
		{"terminal.max_concurrent", `"abc"`, nil, "wants an integer"},
		{"compression.conversation.target_ratio", `0.25`, 0.25, ""},
		{"compression.conversation.target_ratio", `"0.5"`, 0.5, ""},
		{"compression.conversation.target_ratio", `"NaN"`, nil, "wants a number"},
		{"observer.log_level", `"warn"`, "warn", ""},
		{"observer.log_level", `7`, nil, "wants a string"},
		{"terminal.launch.allowed_tools", `["claude","codex"]`, []string{"claude", "codex"}, ""},
		{"terminal.launch.allowed_tools", `"claude, codex,,"`, []string{"claude", "codex"}, ""},
		{"terminal.launch.allowed_tools", `""`, []string{}, ""},
		{"terminal.launch.allowed_tools", `[1]`, nil, "wants a string"},
		{"profiles.by_tool", `{"cline":"codex-safe"}`, map[string]string{"cline": "codex-safe"}, ""},
		{"profiles.by_tool", `{"cline":1}`, nil, "wants a string"},
		{"profiles.by_tool", `"x"`, nil, "wants a string_map"},
		{"intelligence.pricing.models", `{}`, nil, "not writable"},
		{"observer.log_level", `{not json`, nil, "not valid JSON"},
	}
	for _, c := range cases {
		got, err := ParseValue(mustLeaf(t, c.path), json.RawMessage(c.raw))
		if c.err != "" {
			if err == nil || !strings.Contains(err.Error(), c.err) {
				t.Errorf("ParseValue(%s, %s) err = %v; want containing %q", c.path, c.raw, err, c.err)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseValue(%s, %s): %v", c.path, c.raw, err)
			continue
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("ParseValue(%s, %s) = %#v; want %#v", c.path, c.raw, got, c.want)
		}
	}
}

func TestValidateLeaf(t *testing.T) {
	cases := []struct {
		path string
		v    any
		err  string
	}{
		{"observer.log_level", "warn", ""},
		{"observer.log_level", "loud", `not in {debug, info, warn, error}`},
		{"digest.send_hour", int64(23), ""},
		{"digest.send_hour", int64(24), "must be <= 23"},
		{"digest.send_hour", int64(-1), "must be >= 0"},
		{"compression.conversation.target_ratio", 0.5, ""},
		{"compression.conversation.target_ratio", 1.5, "must be <= 1"},
		{"browser.granularity_ceiling", "", ""},
		{"browser.granularity_ceiling", "everything", "not in {usage_only, redacted, full}"},
		{"terminal.max_concurrent", int64(3), ""},
	}
	for _, c := range cases {
		err := ValidateLeaf(mustLeaf(t, c.path), c.v)
		if c.err == "" && err != nil {
			t.Errorf("ValidateLeaf(%s, %v): unexpected %v", c.path, c.v, err)
		}
		if c.err != "" && (err == nil || !strings.Contains(err.Error(), c.err)) {
			t.Errorf("ValidateLeaf(%s, %v) = %v; want containing %q", c.path, c.v, err, c.err)
		}
	}
}

func TestSetGetAndChangedLeaves(t *testing.T) {
	a := config.Default()
	b := config.Default()
	if got := ChangedLeaves(&a, &b); len(got) != 0 {
		t.Fatalf("identical configs differ: %v", got)
	}
	sets := []struct {
		path string
		raw  string
	}{
		{"terminal.max_concurrent", `7`},
		{"observer.log_level", `"debug"`},
		{"observer.hooks.auto_register", `false`},
		{"compression.conversation.target_ratio", `0.33`},
		{"terminal.launch.allowed_tools", `["claude"]`},
		{"profiles.by_tool", `{"cline":"codex-safe"}`},
	}
	for _, s := range sets {
		leaf := mustLeaf(t, s.path)
		v, err := ParseValue(leaf, json.RawMessage(s.raw))
		if err != nil {
			t.Fatalf("parse %s: %v", s.path, err)
		}
		if err := Set(&b, leaf, v); err != nil {
			t.Fatalf("set %s: %v", s.path, err)
		}
		if got := Get(&b, leaf); !reflect.DeepEqual(got, coerce(got, v)) {
			t.Errorf("Get(%s) = %#v after Set(%#v)", s.path, got, v)
		}
	}
	if b.Terminal.MaxConcurrent != 7 || b.Observer.LogLevel != "debug" || b.Observer.Hooks.AutoRegister ||
		b.Compression.Conversation.TargetRatio != 0.33 || !reflect.DeepEqual(b.Terminal.Launch.AllowedTools, []string{"claude"}) ||
		b.Profiles.ByTool["cline"] != "codex-safe" {
		t.Fatalf("Set did not land on the struct: %+v", b.Terminal)
	}
	got := ChangedLeaves(&a, &b)
	want := []string{
		"observer.log_level", "observer.hooks.auto_register", "compression.conversation.target_ratio",
		"terminal.launch.allowed_tools", "terminal.max_concurrent", "profiles.by_tool",
	}
	// ChangedLeaves is in schema (walk) order; compare as sets.
	if len(got) != len(want) {
		t.Fatalf("ChangedLeaves = %v; want %v", got, want)
	}
	for _, w := range want {
		if !contains(got, w) {
			t.Errorf("ChangedLeaves missing %s (got %v)", w, got)
		}
	}
	if err := Set(&b, mustLeaf(t, "intelligence.pricing.models"), map[string]string{}); err == nil {
		t.Error("Set on a table leaf must refuse")
	}
}

// coerce widens the parsed int64 to whatever int width the field has so
// DeepEqual compares like with like.
func coerce(got, v any) any {
	if n, ok := v.(int64); ok {
		return reflect.ValueOf(n).Convert(reflect.TypeOf(got)).Interface()
	}
	return v
}

func TestTOMLScalar(t *testing.T) {
	cases := []struct {
		path string
		v    any
		want string
		ok   bool
	}{
		{"observer.hooks.auto_register", true, "true", true},
		{"terminal.max_concurrent", int64(12), "12", true},
		{"compression.conversation.target_ratio", 0.5, "0.5", true},
		{"compression.conversation.target_ratio", 1.0, "1.0", true},
		{"compression.conversation.target_ratio", 1e21, "1e+21", true},
		{"observer.log_level", "warn", `"warn"`, true},
		{"observer.log_level", `a "quoted" # not a comment`, `"a \"quoted\" # not a comment"`, true},
		{"observer.log_level", "multi\nline\ttab\\", `"multi\nline\ttab\\"`, true},
		{"observer.log_level", "nul\x00byte", "\"nul\\u0000byte\"", true},
		{"observer.log_level", "bad\xffutf8", "\"bad�utf8\"", true},
		{"observer.log_level", "unicode ✓ ok", `"unicode ✓ ok"`, true},
		{"terminal.launch.allowed_tools", []string{"a"}, "", false},
		{"profiles.by_tool", map[string]string{}, "", false},
	}
	for _, c := range cases {
		got, ok := TOMLScalar(mustLeaf(t, c.path), c.v)
		if ok != c.ok || got != c.want {
			t.Errorf("TOMLScalar(%s, %#v) = %q,%v; want %q,%v", c.path, c.v, got, ok, c.want, c.ok)
		}
	}
	for _, s := range []string{`"`, "\\", "\n", "\r", "\x7f", "\x1b[31m"} {
		q := QuoteTOMLString(s)
		if strings.ContainsAny(q, "\n\r") || len(q) < 2 || q[0] != '"' || q[len(q)-1] != '"' {
			t.Errorf("QuoteTOMLString(%q) = %q is not a single-line basic string", s, q)
		}
	}
}

func TestDescribeIsSerializable(t *testing.T) {
	d := Describe()
	if d.SchemaVersion != SchemaVersion || len(d.Leaves) == 0 || len(d.Tables) == 0 || len(d.Blocks) == 0 {
		t.Fatalf("Describe() incomplete: %+v", d)
	}
	body, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), `"index"`) {
		t.Error("the reflect index chain must not serialize")
	}
}
