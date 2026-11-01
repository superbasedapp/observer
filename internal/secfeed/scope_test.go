package secfeed

import (
	"context"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// TestInstallDirs: every directory an install reads its configuration from
// is named (lane SEC-D1FIX2 milestone 1a), and one it cannot resolve makes
// the scope unknown.
func TestInstallDirs(t *testing.T) {
	base := filepath.FromSlash("/w/repo")
	j := func(p ...string) string { return filepath.Join(append([]string{base}, p...)...) }
	for _, tc := range []struct {
		cmd     string
		want    []string
		unknown bool
	}{
		{"npm i left-pad", nil, false},
		{"cd frontend && npm i @corp/x", []string{j("frontend")}, false},
		{"cd frontend && cd web && npm i x", []string{j("frontend", "web")}, false},
		{"npm --prefix app install x", []string{j("app")}, false},
		{"npm install x --prefix=app", []string{j("app")}, false},
		{"pnpm -C pkgs/ui add x", []string{j("pkgs", "ui")}, false},
		{"yarn --cwd web add x", []string{j("web")}, false},
		{"pnpm --dir web add x", []string{j("web")}, false},
		{"cargo add serde --manifest-path crates/a/Cargo.toml", []string{j("crates", "a")}, false},
		{"uv add --directory svc requests", []string{j("svc")}, false},
		{"composer -d lib require a/b", []string{j("lib")}, false},
		{"cd $DIR && npm i x", nil, true},
		{"cd - && npm i x", nil, true},
		{"cd && npm i x", nil, true},
		{"popd && npm i x", nil, true},
		{"npm --prefix ~/x i y", nil, true},
		{"cd other && ls", nil, false},
	} {
		t.Run(tc.cmd, func(t *testing.T) {
			got, unknown := InstallDirs(&policy.Event{Kind: policy.KindShellExec, Target: tc.cmd}, base)
			if unknown != tc.unknown || !slices.Equal(got, tc.want) {
				t.Errorf("got %v unknown=%v, want %v unknown=%v", got, unknown, tc.want, tc.unknown)
			}
		})
	}
	if _, unknown := InstallDirs(&policy.Event{Kind: policy.KindShellExec, Target: "cd web && npm i x"}, ""); !unknown {
		t.Error("a relative directory with no base is unknown")
	}
}

// TestScopePublic: no project root, an unresolved directory or a relative
// one is a scope with nothing public.
func TestScopePublic(t *testing.T) {
	abs := filepath.FromSlash("/w/repo")
	for _, tc := range []struct {
		s    Scope
		want bool
	}{
		{Scope{}, false},
		{Scope{ProjectRoot: abs}, true},
		{Scope{ProjectRoot: abs, Unknown: true}, false},
		{Scope{ProjectRoot: abs, Dirs: []string{"rel"}}, false},
		{Scope{ProjectRoot: abs, Dirs: []string{abs + string(filepath.Separator) + ".." + string(filepath.Separator) + "x"}}, false},
	} {
		if got := tc.s.Public(); got != tc.want {
			t.Errorf("%+v: %v", tc.s, got)
		}
	}
}

// TestScopeEnv: only the source-naming variables cross, never a
// credential, and a URL's credentials are replaced by a marker that still
// reads as not the public default.
func TestScopeEnv(t *testing.T) {
	got := ScopeEnv([]string{
		"GOPRIVATE=corp.example/*", "npm_config_registry=https://npm.corp.example/",
		"NPM_CONFIG__AUTH=c2VjcmV0", "NPM_CONFIG_//npm.corp.example/:_authToken=abc",
		"PIP_INDEX_URL=https://user:pass@pypi.org/simple", "UV_INDEX=corp=https://u:p@uv.corp.example/simple",
		"CARGO_REGISTRIES_CORP_TOKEN=x", "CARGO_REGISTRIES_CORP_INDEX=https://c.example/index",
		"HOME=/home/a", "PATH=/bin", "GOFLAGS=-mod=mod", "VIRTUAL_ENV=/v",
	})
	for _, k := range []string{"NPM_CONFIG__AUTH", "NPM_CONFIG_//NPM.CORP.EXAMPLE/:_AUTHTOKEN", "CARGO_REGISTRIES_CORP_TOKEN", "HOME", "PATH"} {
		if _, ok := got[k]; ok {
			t.Errorf("%s crossed", k)
		}
	}
	for _, k := range []string{"GOPRIVATE", "NPM_CONFIG_REGISTRY", "CARGO_REGISTRIES_CORP_INDEX", "GOFLAGS", "VIRTUAL_ENV"} {
		if got[k] == "" {
			t.Errorf("%s did not cross: %v", k, got)
		}
	}
	if v := got["PIP_INDEX_URL"]; strings.Contains(v, "pass") || IsPublicDefault(EcoPyPI, v) {
		t.Errorf("PIP_INDEX_URL %q", v)
	}
	if v := got["UV_INDEX"]; strings.Contains(v, "u:p") || !strings.HasPrefix(v, "corp=") {
		t.Errorf("UV_INDEX %q", v)
	}
}

// TestAllPublic: a name is public only when every classifier says so.
func TestAllPublic(t *testing.T) {
	yes := func(InstallSpec) bool { return true }
	no := func(InstallSpec) bool { return false }
	sp := ParseSpec(EcoNpm, "x")
	if AllPublic() != nil || AllPublic(yes, nil) != nil {
		t.Error("none or a nil classifier is nothing public")
	}
	if !AllPublic(yes, yes)(sp) || AllPublic(yes, no)(sp) {
		t.Error("conjunction")
	}
}

// TestYarn1AndBunfig: Yarn 1's .yarnrc and Bun's bunfig.toml name
// registries (lane SEC-D1FIX2 milestone 1b).
func TestYarn1AndBunfig(t *testing.T) {
	reg, scopes := ParseYarn1rc([]byte("# c\nregistry \"https://npm.corp.example/\"\n\"@corp:registry\" \"https://corp.example/\"\n"))
	if reg != "https://npm.corp.example/" || scopes["@corp"] != "https://corp.example/" {
		t.Errorf("yarn1 %q %v", reg, scopes)
	}
	reg, scopes, ok := ParseBunfig([]byte("[install]\nregistry = { url = \"https://b.example/\", token = \"t\" }\n[install.scopes]\ncorp = \"https://corp.example/\"\n"))
	if !ok || reg != "https://b.example/" || scopes["@corp"] != "https://corp.example/" {
		t.Errorf("bunfig %q %v %v", reg, scopes, ok)
	}
	if _, _, ok := ParseBunfig([]byte("[install\n")); ok {
		t.Error("a bunfig that does not parse is not ok")
	}
	for _, tc := range []struct {
		files map[ConfigFile][]byte
		name  string
	}{
		{map[ConfigFile][]byte{ConfYarn1Project: []byte("registry https://npm.corp.example/\n")}, "left-pad"},
		{map[ConfigFile][]byte{ConfYarn1User: []byte("\"@corp:registry\" \"https://corp.example/\"\n")}, "@corp/x"},
		{map[ConfigFile][]byte{ConfBunfigProject: []byte("[install]\nregistry = \"https://b.example/\"\n")}, "left-pad"},
		{map[ConfigFile][]byte{ConfBunfigUser: []byte("[install\n")}, "left-pad"},
		{map[ConfigFile][]byte{ConfPipGlobal: []byte("[global]\nindex-url = https://pypi.corp.example/simple\n")}, "py:requests"},
		{map[ConfigFile][]byte{ConfPipVenv: []byte("[global]\nextra-index-url = https://pypi.corp.example/simple\n")}, "py:requests"},
		{map[ConfigFile][]byte{ConfUVUserXDG: []byte("index-url = \"https://pypi.corp.example/simple\"\n")}, "py:requests"},
		// A private index an earlier layer names stays private when a later
		// layer names the public one (more private, never less).
		{map[ConfigFile][]byte{ConfPipGlobal: []byte("[global]\nindex-url = https://pypi.corp.example/simple\n"), ConfPipUser: []byte("[global]\nindex-url = https://pypi.org/simple\n")}, "py:requests"},
	} {
		eco, name := EcoNpm, tc.name
		if n, ok := strings.CutPrefix(name, "py:"); ok {
			eco, name = EcoPyPI, n
		}
		c := NewClassifier(BuildPrivConfig(PrivConfigInput{Files: tc.files}))
		if c(ParseSpec(eco, name)) {
			t.Errorf("%v: %s public", tc.files, tc.name)
		}
	}
}

// TestServiceConfirmed: an ask reports the names it classified public for
// the scope, a prefetch reports nothing, and a scope with no project root
// classifies nothing public.
func TestServiceConfirmed(t *testing.T) {
	var confirmed []string
	s := NewService(ServiceOptions{
		Classify:  func(Scope) Classifier { return func(sp InstallSpec) bool { return sp.Name != "@corp/x" } },
		Confirmed: func(_ Scope, specs []InstallSpec) { confirmed = append(confirmed, specs[0].Name) },
	})
	root := Scope{ProjectRoot: filepath.FromSlash("/r")}
	got := s.Answer(context.Background(), Scope{}, []InstallSpec{ParseSpec(EcoNpm, "left-pad")})
	if !got[0].Private || len(confirmed) != 0 {
		t.Errorf("no project root: %+v %v", got, confirmed)
	}
	s.Answer(context.Background(), root, []InstallSpec{ParseSpec(EcoNpm, "@corp/x"), ParseSpec(EcoNpm, "left-pad")})
	s.Prefetch(context.Background(), root, []InstallSpec{ParseSpec(EcoNpm, "react")})
	if !slices.Equal(confirmed, []string{"left-pad"}) {
		t.Errorf("confirmed %v", confirmed)
	}
}
