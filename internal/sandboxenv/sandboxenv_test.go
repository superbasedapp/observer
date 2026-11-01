package sandboxenv

import (
	"reflect"
	"strings"
	"testing"
)

// parent is a launching environment with the leaks the WINFIX2 audit named
// (finding 1): another service's token, a cloud key, the launching agent
// session's own variables and a canary.
var parent = []string{
	"PATH=/usr/bin", "HOME=/home/u", "TERM=xterm-256color", "LANG=C.UTF-8",
	"GITHUB_TOKEN=gh-dummy", "AWS_SECRET_ACCESS_KEY=aws-dummy", "CLAUDECODE=1",
	"CLAUDE_CODE_OAUTH_TOKEN=oauth-dummy", "SBO_CANARY_SECRET=canary-dummy",
	"ANTHROPIC_API_KEY=provider-dummy", "SSH_AUTH_SOCK=/tmp/agent.sock",
	"OBSERVER_DAEMON_CHILD=1", "TMPDIR=/tmp/run", "=C:=C:\\x", "BARE",
}

func names(env []string) []string {
	var out []string
	for _, kv := range env {
		k, _, _ := strings.Cut(kv, "=")
		out = append(out, k)
	}
	return out
}

func TestFilterIsAnAllowList(t *testing.T) {
	cases := []struct {
		name string
		spec Spec
		want []string
	}{
		{"base only", Spec{GOOS: "linux"}, []string{"PATH", "HOME", "TERM", "LANG", "TMPDIR"}},
		{"provider name", Spec{GOOS: "linux", Extra: []string{"ANTHROPIC_API_KEY"}}, []string{"PATH", "HOME", "TERM", "LANG", "ANTHROPIC_API_KEY", "TMPDIR"}},
		{"observer's own", Spec{GOOS: "linux", Observer: []string{"OBSERVER_DAEMON_CHILD"}}, []string{"PATH", "HOME", "TERM", "LANG", "OBSERVER_DAEMON_CHILD", "TMPDIR"}},
		{"pass_env opt-in", Spec{GOOS: "linux", Extra: []string{"GITHUB_TOKEN"}}, []string{"PATH", "HOME", "TERM", "LANG", "GITHUB_TOKEN", "TMPDIR"}},
		{"windows has no TMPDIR", Spec{GOOS: "windows"}, []string{"PATH", "HOME", "TERM", "LANG"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := names(Filter(parent, tc.spec))
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("Filter = %v, want %v", got, tc.want)
			}
			for _, kv := range Filter(parent, tc.spec) {
				if strings.Contains(kv, "canary-dummy") || strings.Contains(kv, "aws-dummy") || strings.Contains(kv, "oauth-dummy") {
					t.Fatalf("a secret crossed: %q", kv)
				}
			}
		})
	}
}

func TestFilterWindowsIsCaseInsensitive(t *testing.T) {
	env := []string{"Path=C:\\Windows", "SYSTEMROOT=C:\\Windows", "windir=C:\\Windows", "ProgramFiles(x86)=C:\\P", "Gh_Token=x", "anthropic_api_key=k"}
	got := names(Filter(env, Spec{GOOS: "windows", Extra: []string{"ANTHROPIC_API_KEY"}}))
	want := []string{"Path", "SYSTEMROOT", "windir", "ProgramFiles(x86)", "anthropic_api_key"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Filter = %v, want %v", got, want)
	}
	// On POSIX the comparison is exact.
	if got := names(Filter([]string{"path=/x"}, Spec{GOOS: "linux"})); len(got) != 0 {
		t.Fatalf("a lower-case path crossed on linux: %v", got)
	}
}

func TestDroppedNamesOnly(t *testing.T) {
	got := Dropped(parent, Spec{GOOS: "linux"})
	want := []string{"ANTHROPIC_API_KEY", "AWS_SECRET_ACCESS_KEY", "CLAUDECODE", "CLAUDE_CODE_OAUTH_TOKEN", "GITHUB_TOKEN", "OBSERVER_DAEMON_CHILD", "SBO_CANARY_SECRET", "SSH_AUTH_SOCK"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Dropped = %v, want %v", got, want)
	}
}

func TestBaseTableHasNoCredential(t *testing.T) {
	for _, r := range baseTable {
		u := strings.ToUpper(r.Name)
		for _, bad := range []string{"KEY", "TOKEN", "SECRET", "PASSWORD", "AUTH", "SOCK", "PROXY"} {
			if strings.Contains(u, bad) {
				t.Errorf("base row %s looks like a credential or a socket", r.Name)
			}
		}
		if r.Why == "" {
			t.Errorf("base row %s has no reason", r.Name)
		}
	}
	for _, goos := range []string{"linux", "darwin", "windows"} {
		if len(Base(goos)) == 0 {
			t.Errorf("no base rows for %s", goos)
		}
	}
}

func TestValidName(t *testing.T) {
	for _, ok := range []string{"GITHUB_TOKEN", "_X", "a1"} {
		if err := ValidName(ok); err != nil {
			t.Errorf("ValidName(%q) = %v", ok, err)
		}
	}
	for _, bad := range []string{"", "1X", "A-B", "A=B", "A B", "OBSERVER_SANDBOX", "observer_x", strings.Repeat("A", 129)} {
		if ValidName(bad) == nil {
			t.Errorf("ValidName(%q) accepted", bad)
		}
	}
}

func TestEncodeDecode(t *testing.T) {
	v := Encode([]string{"B", "A", "B", "OBSERVER_X", "bad name", " C "})
	if v != "A,B,C" {
		t.Fatalf("Encode = %q", v)
	}
	if got := Decode(v + ",OBSERVER_Y,,1z"); !reflect.DeepEqual(got, []string{"A", "B", "C"}) {
		t.Fatalf("Decode = %v", got)
	}
	if Encode(nil) != "" || len(Decode("")) != 0 {
		t.Fatal("empty round trip")
	}
}

func TestLookupLastWins(t *testing.T) {
	env := []string{"A=1", "a=2", "A=3"}
	if v, ok := Lookup(env, "linux", "A"); !ok || v != "3" {
		t.Fatalf("linux Lookup = %q %v", v, ok)
	}
	if v, ok := Lookup([]string{"A=1", "a=2"}, "windows", "A"); !ok || v != "2" {
		t.Fatalf("windows Lookup = %q %v", v, ok)
	}
}
