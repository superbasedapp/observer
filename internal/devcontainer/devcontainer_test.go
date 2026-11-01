package devcontainer

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

func TestPackageImports_Bounded(t *testing.T) {
	t.Parallel()
	importpin.Check(t, importpin.Spec{
		Forbidden:  []string{"database/sql", "net/http", "net", "os", "os/exec", "syscall", "github.com/fsnotify/fsnotify"},
		StdlibOnly: true,
		Reason:     "the devcontainer reader is pure and built into every install",
	})
}

func TestParseDevcontainer(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, in, ignored, err string
	}{
		{"comments and trailing commas", "{\n // c\n \"image\": \"x\",\n \"initializeCommand\": \"sh i\",\n \"runArgs\": [\"--privileged\"],\n}", "initializeCommand,runArgs", ""},
		{"nothing ignored", `{"image":"x"}`, "", ""},
		{"not json", `{`, "", "devcontainer.json"},
		{"containerEnv not a string map", `{"containerEnv": 1, "initializeCommand": "x"}`, "", "containerEnv"},
		{"over the cap", `{"a":"` + strings.Repeat("x", MaxBytes) + `"}`, "", "over"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f, err := ParseDevcontainer([]byte(c.in))
			if c.err != "" {
				if err == nil || !strings.Contains(err.Error(), c.err) {
					t.Fatalf("err %v, want %q", err, c.err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.Join(f.Ignored, ","); got != c.ignored {
				t.Fatalf("ignored %q, want %q", got, c.ignored)
			}
		})
	}
	f, _ := ParseDevcontainer([]byte(`{"initializeCommand": [ "a",  "b" ]}`))
	if f.IgnoredRaw["initializeCommand"] != `["a","b"]` {
		t.Fatalf("raw %q", f.IgnoredRaw["initializeCommand"])
	}
}

func TestStripJSONCKeepsStrings(t *testing.T) {
	t.Parallel()
	in := `{"a": "// not a comment", "b": "/* nor this */", "c": [1, 2,],}`
	if got := string(StripJSONC([]byte(in))); got != `{"a": "// not a comment", "b": "/* nor this */", "c": [1, 2]}` {
		t.Fatalf("got %s", got)
	}
}
