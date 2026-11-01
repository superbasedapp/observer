package secfeed

import (
	"fmt"
	"strings"
	"testing"
)

// The JSP-11 prototype's tables, ported unchanged in substance.

func TestIsPublicDefault(t *testing.T) {
	rows := []struct {
		eco  Ecosystem
		addr string
		want bool
	}{
		{EcoNpm, "https://registry.npmjs.org/", true},
		{EcoNpm, "https://registry.npmjs.org", true},
		{EcoNpm, "https://REGISTRY.NPMJS.ORG./", true},
		{EcoNpm, "https://registry.npmjs.org:443/", true},
		{EcoNpm, "http://registry.npmjs.org/", false},
		{EcoNpm, "https://registry.npmjs.org:8443/", false},
		{EcoNpm, "https://user:tok@registry.npmjs.org/", false},
		{EcoNpm, "https://registry.npmjs.org.evil.example/", false},
		{EcoNpm, "https://registry.npmjs.org@evil.example/", false},
		{EcoNpm, "https://registry.npmjs.com/", false},
		{EcoNpm, "https://npm.pkg.github.com/", false},
		{EcoNpm, "http://localhost:4873/", false},
		{EcoNpm, "https://10.0.0.5/npm/", false},
		{EcoNpm, "https://[::1]/", false},
		{EcoNpm, "https://registry.npmjs.org​/", false},
		{EcoNpm, "https://xn--rgistry-npmjs-gmb.org/", false},
		{EcoNpm, "registry.npmjs.org", false},
		{EcoPyPI, "https://pypi.org/simple", true},
		{EcoPyPI, "https://pypi.org/simple/", true},
		{EcoPyPI, "https://test.pypi.org/simple/", false},
		{EcoPyPI, "https://pypi.corp.example/simple/", false},
		{EcoPyPI, "https://pypi.org/simple/../../evil", false},
		{EcoGo, "https://proxy.golang.org", true},
		{EcoGo, "https://goproxy.io", false},
		{EcoGo, "https://proxy.golang.org.cn", false},
		{EcoNuGet, "https://api.nuget.org/v3/index.json", true},
		{EcoNuGet, "https://pkgs.dev.azure.com/corp/_packaging/feed/nuget/v3/index.json", false},
	}
	for _, r := range rows {
		if got := IsPublicDefault(r.eco, r.addr); got != r.want {
			t.Errorf("IsPublicDefault(%s, %q) = %v, want %v", r.eco, r.addr, got, r.want)
		}
	}
}

func TestClassifyNames(t *testing.T) {
	none := PrivConfig{}
	npmScoped := PrivConfig{NpmScopeRegistries: map[string]string{"@corp": "https://npm.pkg.github.com/"}}
	npmMirror := PrivConfig{NpmRegistry: "https://artifactory.corp.example/api/npm/npm-remote/"}
	pipPrivate := PrivConfig{PipIndexURL: "https://pypi.corp.example/simple"}
	pipExtra := PrivConfig{PipExtraIndexURLs: []string{"https://ci:secret@pypi.corp.example/simple"}}
	goPriv := PrivConfig{GoPrivate: "github.com/corp/*,*.corp.example"}
	goOff := PrivConfig{GoProxy: "off"}
	goDirect := PrivConfig{GoProxy: "direct"}
	goCorpProxy := PrivConfig{GoProxy: "https://athens.corp.example,https://proxy.golang.org,direct"}
	cargoReplaced := PrivConfig{CargoReplaceCratesIO: "corp-mirror"}
	nugetTwo := PrivConfig{NuGetSources: map[string]string{"nuget.org": "https://api.nuget.org/v3/index.json", "corp": "https://pkgs.corp.example/v3/index.json"}}
	nugetMapped := PrivConfig{NuGetSources: nugetTwo.NuGetSources, NuGetMapping: map[string]string{"Corp.*": "corp", "*": "nuget.org"}}
	org := PrivConfig{OrgPrivate: map[Ecosystem][]string{EcoNpm: {"@acme"}, EcoPyPI: {"acme-*"}, EcoGo: {"git.acme.example"}}}

	rows := []struct {
		eco     Ecosystem
		spec    string
		cfg     PrivConfig
		cfgName string
		want    PrivVerdict
	}{
		{EcoNpm, "left-pad", none, "defaults", PrivPublic},
		{EcoNpm, "left-pad@1.3.0", none, "defaults", PrivPublic},
		{EcoNpm, "@types/node@20", none, "defaults", PrivPublic},
		{EcoNpm, "@corp/ui", npmScoped, "@corp scope registry", PrivPrivate},
		{EcoNpm, "@types/node", npmScoped, "@corp scope registry", PrivPublic},
		{EcoNpm, "left-pad", npmMirror, "registry= a corporate mirror", PrivPrivate},
		{EcoNpm, "@acme/core", org, "org private scope @acme", PrivPrivate},
		{EcoNpm, "npm:left-pad@1", none, "defaults (alias)", PrivPublic},
		{EcoNpm, "github:user/repo", none, "defaults", PrivInvalid},
		{EcoNpm, "user/repo", none, "defaults", PrivInvalid},
		{EcoNpm, "git+https://github.com/u/r.git", none, "defaults", PrivInvalid},
		{EcoNpm, "https://evil.example/pkg.tgz", none, "defaults", PrivInvalid},
		{EcoNpm, "file:../local", none, "defaults", PrivInvalid},
		{EcoNpm, "./vendor/pkg", none, "defaults", PrivInvalid},
		{EcoNpm, "Left-Pad", none, "defaults", PrivInvalid},
		{EcoNpm, "left pad", none, "defaults", PrivInvalid},
		{EcoNpm, "left-pad\nevil", none, "defaults", PrivInvalid},
		{EcoPyPI, "requests", none, "defaults", PrivPublic},
		{EcoPyPI, "Requests_Toolbelt==1.0", none, "defaults", PrivPublic},
		{EcoPyPI, "requests[socks]>=2", none, "defaults", PrivPublic},
		{EcoPyPI, "requests", pipPrivate, "index-url private", PrivPrivate},
		{EcoPyPI, "requests", pipExtra, "extra-index-url private", PrivPrivate},
		{EcoPyPI, "acme-billing", org, "org private acme-*", PrivPrivate},
		{EcoPyPI, "pkg @ https://x.example/p.whl", none, "defaults", PrivInvalid},
		{EcoPyPI, "./dist/pkg.whl", none, "defaults", PrivInvalid},
		{EcoPyPI, "-r requirements.txt", none, "defaults", PrivInvalid},
		{EcoGo, "github.com/spf13/cobra@v1.8.0", none, "defaults", PrivPublic},
		{EcoGo, "github.com/corp/secret", goPriv, "GOPRIVATE github.com/corp/*", PrivPrivate},
		{EcoGo, "git.corp.example/x/y", goPriv, "GOPRIVATE *.corp.example", PrivPrivate},
		{EcoGo, "github.com/spf13/cobra", goPriv, "GOPRIVATE set, other path", PrivPublic},
		{EcoGo, "github.com/spf13/cobra", goOff, "GOPROXY=off", PrivPrivate},
		{EcoGo, "github.com/spf13/cobra", goDirect, "GOPROXY=direct", PrivPrivate},
		{EcoGo, "github.com/spf13/cobra", goCorpProxy, "GOPROXY corporate first", PrivPrivate},
		{EcoGo, "git.acme.example/svc", org, "org private", PrivPrivate},
		{EcoGo, "mycorp/internal", none, "defaults (no dot)", PrivInvalid},
		{EcoCargo, "serde", none, "defaults", PrivPublic},
		{EcoCargo, "serde@1.0", none, "defaults", PrivPublic},
		{EcoCargo, "serde", cargoReplaced, "crates-io replaced", PrivPrivate},
		{EcoCargo, "--git https://x", none, "defaults", PrivInvalid},
		{EcoNuGet, "Newtonsoft.Json", none, "defaults", PrivPublic},
		{EcoNuGet, "Newtonsoft.Json", nugetTwo, "two sources, no mapping", PrivPrivate},
		{EcoNuGet, "Corp.Billing", nugetMapped, "mapping Corp.* -> corp", PrivPrivate},
		{EcoNuGet, "Newtonsoft.Json", nugetMapped, "mapping * -> nuget.org", PrivPublic},
		{"maven", "org.apache:commons", none, "defaults", PrivPrivate},
	}
	var lines []string
	lines = append(lines, fmt.Sprintf("%-7s | %-34s | %-30s | %-8s | %s", "eco", "spec", "config", "verdict", "reason"))
	fails := 0
	for _, r := range rows {
		got := Classify(r.eco, r.spec, r.cfg)
		mark := ""
		if got.Verdict != r.want {
			mark = "  <-- want " + string(r.want)
			fails++
		}
		if strings.Contains(got.Reason, "secret") {
			t.Errorf("a credential reached the reason: %q", got.Reason)
		}
		lines = append(lines, fmt.Sprintf("%-7s | %-34q | %-30s | %-8s | %s%s", r.eco, r.spec, r.cfgName, got.Verdict, got.Reason, mark))
	}
	lines = append(lines, fmt.Sprintf("rows %d, mismatches %d", len(rows), fails))
	for _, l := range lines {
		t.Log(l)
	}
	if fails > 0 {
		t.Fail()
	}
}
