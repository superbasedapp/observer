package cloudsession

import (
	"strings"
	"testing"
)

func TestNpmURLs(t *testing.T) {
	if got, want := NpmMetadataURL(DefaultNpmRegistry, "x64", "v1.36.0"), "https://registry.npmjs.org/@superbased%2Fobserver-linux-x64/1.36.0"; got != want {
		t.Errorf("metadata URL = %s, want %s", got, want)
	}
	if got, want := NpmTarballURL(DefaultNpmRegistry+"/", "arm64", "v1.36.0"), "https://registry.npmjs.org/@superbased/observer-linux-arm64/-/observer-linux-arm64-1.36.0.tgz"; got != want {
		t.Errorf("tarball URL = %s, want %s", got, want)
	}
}

func TestIntegritySHA512Hex(t *testing.T) {
	h, err := IntegritySHA512Hex(testPins[0].Integrity)
	if err != nil || len(h) != 128 {
		t.Fatalf("hex = %q, %v", h, err)
	}
	for _, bad := range []string{"", "sha1-AAAA", "sha512-!!", "sha512-AAAA", testPins[0].Integrity + " " + testPins[1].Integrity} {
		if _, err := IntegritySHA512Hex(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// TestParseNpmVersionMetadata: the pin is read only from the document of
// the exact package and version, served from the computed tarball URL.
func TestParseNpmVersionMetadata(t *testing.T) {
	doc := func(name, version, tarball, integrity string) []byte {
		return []byte(`{"name":"` + name + `","version":"` + version + `","dist":{"tarball":"` + tarball + `","integrity":"` + integrity + `","shasum":"abc"}}`)
	}
	tb := NpmTarballURL(DefaultNpmRegistry, "x64", "v1.36.0")
	good := doc("@superbased/observer-linux-x64", "1.36.0", tb, testPins[0].Integrity)
	p, err := ParseNpmVersionMetadata(good, DefaultNpmRegistry, "x64", "v1.36.0")
	if err != nil || p.Arch != "x64" || p.Integrity != testPins[0].Integrity {
		t.Fatalf("pin = %+v, %v", p, err)
	}
	cases := map[string][]byte{
		"other package": doc("@superbased/observer-linux-arm64", "1.36.0", tb, testPins[0].Integrity),
		"other version": doc("@superbased/observer-linux-x64", "1.35.0", tb, testPins[0].Integrity),
		"other tarball": doc("@superbased/observer-linux-x64", "1.36.0", "https://evil.example/x.tgz", testPins[0].Integrity),
		"sha1 only":     doc("@superbased/observer-linux-x64", "1.36.0", tb, "sha1-AAAA"),
		"not JSON":      []byte("<html>"),
	}
	for name, body := range cases {
		if _, err := ParseNpmVersionMetadata(body, DefaultNpmRegistry, "x64", "v1.36.0"); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// TestSetupScriptSources: the default script installs from npm with the
// pinned sha512 and no GitHub URL; the release script keeps the vendor
// signature path.
func TestSetupScriptSources(t *testing.T) {
	npm := renderSetupScript(testOpts("claude-code"))
	x64, _ := IntegritySHA512Hex(testPins[0].Integrity)
	for _, want := range []string{"SOURCE=npm", "REGISTRY=https://registry.npmjs.org", "NPM_SHA512_X64=" + x64, "sha512sum", "package/bin/observer.sig"} {
		if !strings.Contains(npm, want) {
			t.Errorf("npm script lacks %q", want)
		}
	}
	if strings.Contains(npm, "github.com") || strings.Contains(npm, "SHA256SUMS") {
		t.Error("the npm script reaches for release assets")
	}
	o := testOpts("claude-code")
	o.InstallSource = InstallRelease
	rel := renderSetupScript(o)
	for _, want := range []string{"SOURCE=release", "BASE_URL=" + DefaultReleaseBaseURL, "SHA256SUMS", "need_verifier"} {
		if !strings.Contains(rel, want) {
			t.Errorf("release script lacks %q", want)
		}
	}
	if strings.Contains(rel, "registry.npmjs.org") {
		t.Error("the release script reaches for npm")
	}
}

// TestEgressStep: the claude-code plan names the hosts to allow; copilot,
// whose sandbox egress is not allow-listed by default, gets no such step.
func TestEgressStep(t *testing.T) {
	p, err := PlanInit(testOpts("claude-code"), memRepo{}.read)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(p.Manual, "\n")
	for _, want := range []string{"registry.npmjs.org", "org.example.com", "403 at CONNECT", "Allowed domains", "Allow package managers"} {
		if !strings.Contains(joined, want) {
			t.Errorf("manual steps lack %q:\n%s", want, joined)
		}
	}
	o := testOpts("claude-code")
	o.InstallSource = InstallRelease
	p, _ = PlanInit(o, memRepo{}.read)
	if !strings.Contains(strings.Join(p.Manual, "\n"), "github.com") {
		t.Error("the release install does not name the release host")
	}
	p, _ = PlanInit(testOpts("copilot"), memRepo{}.read)
	if strings.Contains(strings.Join(p.Manual, "\n"), "403 at CONNECT") {
		t.Error("copilot got the Claude Code network-level step")
	}
}
