package secfeed

import "testing"

func TestBuildPrivConfig(t *testing.T) {
	env := map[string]string{"GOPRIVATE": "github.com/corp/*", "PIP_EXTRA_INDEX_URL": "https://x.corp/simple"}
	cfg := BuildPrivConfig(PrivConfigInput{
		Files: map[ConfigFile][]byte{
			ConfNpmrcUser:    []byte("registry=https://registry.npmjs.org/\n@corp:registry=https://npm.corp.example/\n"),
			ConfNpmrcProject: []byte("# project\n@team:registry = https://npm.pkg.github.com/\n"),
			ConfPipUser:      []byte("[global]\nindex-url = https://pypi.org/simple\nextra-index-url =\n    https://a.corp/simple\n"),
			ConfPyproject:    []byte("[[tool.poetry.source]]\nname = \"corp\"\nurl = \"https://p.corp/simple\"\n"),
			ConfCargoUser:    []byte("[source.crates-io]\nreplace-with = \"mirror\"\n"),
			ConfNuGetProject: []byte(`<configuration><packageSources><clear/><add key="corp" value="https://n.corp/v3/index.json"/></packageSources></configuration>`),
		},
		Env: func(k string) string { return env[k] },
	})
	if cfg.NpmRegistry != "https://registry.npmjs.org/" || cfg.NpmScopeRegistries["@corp"] == "" || cfg.NpmScopeRegistries["@team"] == "" {
		t.Errorf("npm %+v", cfg)
	}
	if len(cfg.PipExtraIndexURLs) != 3 || cfg.PipIndexURL != "https://pypi.org/simple" {
		t.Errorf("pip %+v", cfg.PipExtraIndexURLs)
	}
	if cfg.GoPrivate == "" || cfg.CargoReplaceCratesIO != "mirror" {
		t.Errorf("go/cargo %+v", cfg)
	}
	if _, ok := cfg.NuGetSources["nuget.org"]; ok || cfg.NuGetSources["corp"] == "" {
		t.Errorf("nuget clear: %+v", cfg.NuGetSources)
	}
	pub := NewClassifier(cfg)
	cases := map[string]struct {
		spec InstallSpec
		want bool
	}{
		"public npm":     {ParseSpec(EcoNpm, "left-pad"), true},
		"scoped private": {ParseSpec(EcoNpm, "@corp/ui"), false},
		"pip extra":      {ParseSpec(EcoPyPI, "requests"), false},
		"go private":     {ParseSpec(EcoGo, "github.com/corp/x"), false},
		"go public":      {ParseSpec(EcoGo, "github.com/spf13/cobra"), true},
		"cargo replaced": {ParseSpec(EcoCargo, "serde"), false},
		"rubygems":       {ParseSpec(EcoRubyGems, "rails"), false},
		"invalid":        {ParseSpec(EcoNpm, "github:u/r"), false},
	}
	for name, c := range cases {
		if got := pub(c.spec); got != c.want {
			t.Errorf("%s: %v, want %v", name, got, c.want)
		}
	}
	if def := BuildPrivConfig(PrivConfigInput{}); !NewClassifier(def)(ParseSpec(EcoNuGet, "Newtonsoft.Json")) {
		t.Error("NuGet defaults are public")
	}
	if ParseCargoReplace([]byte("not = = toml")) == "" {
		t.Error("an unreadable cargo config must read as replaced")
	}
}

// TestPrivConfigSources is milestone 1b: each configuration source a
// developer really uses makes a name private, and a file that cannot be
// read or parsed makes its ecosystem private, never public.
func TestPrivConfigSources(t *testing.T) {
	npm, pypi, goMod := ParseSpec(EcoNpm, "left-pad"), ParseSpec(EcoPyPI, "requests"), ParseSpec(EcoGo, "github.com/corp/x")
	cases := []struct {
		name string
		in   PrivConfigInput
		spec InstallSpec
		want bool
	}{
		{"defaults npm", PrivConfigInput{}, npm, true},
		{"defaults pypi", PrivConfigInput{}, pypi, true},
		{"defaults go", PrivConfigInput{}, goMod, true},
		{"go env file GOPRIVATE", PrivConfigInput{Files: map[ConfigFile][]byte{ConfGoEnv: []byte("GOPRIVATE=github.com/corp\n")}}, goMod, false},
		{"go env file GONOSUMDB", PrivConfigInput{Files: map[ConfigFile][]byte{ConfGoEnv: []byte("GONOSUMDB=github.com/corp/*\n")}}, goMod, false},
		{"go env file GONOPROXY", PrivConfigInput{Files: map[ConfigFile][]byte{ConfGoEnv: []byte("GONOPROXY=github.com/corp\n")}}, goMod, false},
		{"go env file GOPROXY", PrivConfigInput{Files: map[ConfigFile][]byte{ConfGoEnv: []byte("GOPROXY=https://goproxy.corp.example\n")}}, ParseSpec(EcoGo, "github.com/spf13/cobra"), false},
		{"go env variable wins", PrivConfigInput{Files: map[ConfigFile][]byte{ConfGoEnv: []byte("GOPROXY=https://proxy.golang.org\n")}, Env: envOf("GOPROXY", "https://corp.example")}, ParseSpec(EcoGo, "github.com/spf13/cobra"), false},
		{"yarnrc registry", PrivConfigInput{Files: map[ConfigFile][]byte{ConfYarnrcProject: []byte("npmRegistryServer: \"https://npm.corp.example\"\n")}}, npm, false},
		{"yarnrc yarnpkg default", PrivConfigInput{Files: map[ConfigFile][]byte{ConfYarnrcProject: []byte("npmRegistryServer: \"https://registry.yarnpkg.com\"\n")}}, npm, true},
		{"yarnrc scope", PrivConfigInput{Files: map[ConfigFile][]byte{ConfYarnrcUser: []byte("npmScopes:\n  corp:\n    npmRegistryServer: https://npm.corp.example\n")}}, ParseSpec(EcoNpm, "@corp/ui"), false},
		{"yarnrc scope leaves others", PrivConfigInput{Files: map[ConfigFile][]byte{ConfYarnrcUser: []byte("npmScopes:\n  corp:\n    npmRegistryServer: https://npm.corp.example\n")}}, npm, true},
		{"yarnrc unparseable", PrivConfigInput{Files: map[ConfigFile][]byte{ConfYarnrcProject: []byte("npmScopes: [unclosed\n  - : :\n")}}, npm, false},
		{"global npmrc", PrivConfigInput{Files: map[ConfigFile][]byte{ConfNpmrcGlobal: []byte("registry=https://artifactory.corp.example/api/npm/\n")}}, npm, false},
		{"user npmrc over global", PrivConfigInput{Files: map[ConfigFile][]byte{ConfNpmrcGlobal: []byte("registry=https://artifactory.corp.example/\n"), ConfNpmrcUser: []byte("registry=https://registry.npmjs.org/\n")}}, npm, true},
		{"NPM_CONFIG_REGISTRY", PrivConfigInput{Env: envOf("NPM_CONFIG_REGISTRY", "https://npm.corp.example")}, npm, false},
		{"npm_config_registry", PrivConfigInput{Env: envOf("npm_config_registry", "https://npm.corp.example")}, npm, false},
		{"npm_config scoped", PrivConfigInput{Environ: func() []string { return []string{"npm_config_@corp:registry=https://npm.corp.example"} }}, ParseSpec(EcoNpm, "@corp/ui"), false},
		{"uv.toml index-url", PrivConfigInput{Files: map[ConfigFile][]byte{ConfUVUser: []byte("index-url = \"https://pypi.corp.example/simple\"\n")}}, pypi, false},
		{"uv.toml [[index]]", PrivConfigInput{Files: map[ConfigFile][]byte{ConfUVProject: []byte("[[index]]\nname = \"corp\"\nurl = \"https://pypi.corp.example/simple\"\n")}}, pypi, false},
		{"uv.toml unparseable", PrivConfigInput{Files: map[ConfigFile][]byte{ConfUVProject: []byte("index-url = = \n")}}, pypi, false},
		{"pyproject tool.uv.index", PrivConfigInput{Files: map[ConfigFile][]byte{ConfPyproject: []byte("[[tool.uv.index]]\nname = \"corp\"\nurl = \"https://pypi.corp.example/simple\"\n")}}, pypi, false},
		{"pyproject tool.uv extra-index-url", PrivConfigInput{Files: map[ConfigFile][]byte{ConfPyproject: []byte("[tool.uv]\nextra-index-url = [\"https://pypi.corp.example/simple\"]\n")}}, pypi, false},
		{"pyproject unparseable", PrivConfigInput{Files: map[ConfigFile][]byte{ConfPyproject: []byte("[tool.poetry\n")}}, pypi, false},
		{"requirements --index-url", PrivConfigInput{Files: map[ConfigFile][]byte{ConfRequirements: []byte("--index-url https://pypi.corp.example/simple\nrequests\n")}}, pypi, false},
		{"requirements --extra-index-url=", PrivConfigInput{Files: map[ConfigFile][]byte{ConfRequirements: []byte("--extra-index-url=https://pypi.corp.example/simple\n")}}, pypi, false},
		{"requirements -i", PrivConfigInput{Files: map[ConfigFile][]byte{ConfRequirements: []byte("-i https://pypi.corp.example/simple\n")}}, pypi, false},
		{"requirements public index", PrivConfigInput{Files: map[ConfigFile][]byte{ConfRequirements: []byte("-i https://pypi.org/simple\nrequests==2\n")}}, pypi, true},
		{"UV_INDEX_URL", PrivConfigInput{Env: envOf("UV_INDEX_URL", "https://pypi.corp.example/simple")}, pypi, false},
		{"UV_INDEX name=url", PrivConfigInput{Env: envOf("UV_INDEX", "corp=https://pypi.corp.example/simple")}, pypi, false},
		{"unreadable npmrc", PrivConfigInput{Unreadable: map[ConfigFile]bool{ConfNpmrcUser: true}}, npm, false},
		{"unreadable goenv", PrivConfigInput{Unreadable: map[ConfigFile]bool{ConfGoEnv: true}}, ParseSpec(EcoGo, "github.com/spf13/cobra"), false},
		{"unreadable npmrc leaves pypi", PrivConfigInput{Unreadable: map[ConfigFile]bool{ConfNpmrcUser: true}}, pypi, true},
		{"oversized pip.conf", PrivConfigInput{Files: map[ConfigFile][]byte{ConfPipUser: make([]byte, maxConfigFileBytes+1)}}, pypi, false},
		{"cargo registry.default", PrivConfigInput{Files: map[ConfigFile][]byte{ConfCargoUser: []byte("[registry]\ndefault = \"corp\"\n")}}, ParseSpec(EcoCargo, "serde"), false},
		{"CARGO_REGISTRY_DEFAULT", PrivConfigInput{Env: envOf("CARGO_REGISTRY_DEFAULT", "corp")}, ParseSpec(EcoCargo, "serde"), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := NewClassifier(BuildPrivConfig(c.in))(c.spec); got != c.want {
				t.Errorf("public = %v, want %v", got, c.want)
			}
		})
	}
	// A spec the command made private stays private.
	sp := ParseSpec(EcoNpm, "left-pad")
	sp.Private = true
	if NewClassifier(BuildPrivConfig(PrivConfigInput{}))(sp) {
		t.Error("a command-private spec is public")
	}
}

func envOf(kv ...string) func(string) string {
	m := map[string]string{}
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i]] = kv[i+1]
	}
	return func(k string) string { return m[k] }
}
