package sandboxoci

import (
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"path"
	"strings"
	"testing"
)

// installscripts_integrity_test.go: ruling P-142 (the LEFT-SBX merge's
// audit finding 6). A script that installs more packages counts as pinned
// only when every fetched artifact is pinned by its registry integrity.

func integrityOf(b string) string {
	s := sha512.Sum512([]byte(b))
	return "sha512-" + base64.StdEncoding.EncodeToString(s[:])
}

func TestPackagePinFlagRoundTrip(t *testing.T) {
	t.Parallel()
	p := PackagePin{Name: "@v/tool-linux-x64", Version: "1.2.3", Integrity: integrityOf("t")}
	got, err := ParsePackagePinFlag(p.Flag())
	if err != nil || got != p {
		t.Fatalf("round trip: %+v %v", got, err)
	}
	for _, bad := range []string{
		"tool@1.2.3", "@1.2.3=" + p.Integrity, "tool@1.2.3=sha256-abc",
		"../x@1.2.3=" + p.Integrity, "tool@latest=" + p.Integrity, "tool@1.2.3=sha512-short==",
	} {
		if _, err := ParsePackagePinFlag(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	rel, raw, err := IntegrityContentPath(p.Integrity)
	h := hex.EncodeToString(raw)
	if err != nil || rel != path.Join("content-v2", "sha512", h[:2], h[2:4], h[4:]) || len(raw) != 64 {
		t.Fatalf("content path %q %v", rel, err)
	}
}

func TestDecideInstallScriptsFetchingNeedsIntegrity(t *testing.T) {
	t.Parallel()
	h := shaOf("script")
	pk := PackagePin{Name: "tool", Version: "1.0.0", Integrity: integrityOf("t")}
	withPkgs := ScriptPin{Tool: "opencode", Version: "1.0.0", SHA256: h, Source: PinSourceBuiltin, Packages: []PackagePin{pk}}
	bare := ScriptPin{Tool: "opencode", Version: "1.0.1", SHA256: h, Source: PinSourceUser}
	fetching := []string{"opencode"}
	cases := []struct {
		name, version string
		pol           ScriptPolicy
		code          string
		pkgs          int
	}{
		{"builtin pin carries the integrity", "1.0.0", ScriptPolicy{Pins: []ScriptPin{withPkgs}, Fetching: fetching}, "", 1},
		{"a script hash alone does not pin what it fetches", "1.0.1", ScriptPolicy{Pins: []ScriptPin{withPkgs, bare}, Fetching: fetching}, VerdictInstallScriptsUnpinned, 0},
		{"a tool that fetches nothing needs no integrity", "1.0.1", ScriptPolicy{Pins: []ScriptPin{bare}}, "", 0},
	}
	for _, c := range cases {
		d, err := DecideInstallScripts("opencode", c.version, true, c.pol)
		switch {
		case c.code == "" && err != nil:
			t.Errorf("%s: refused %v", c.name, err)
		case c.code != "" && (err == nil || !strings.HasPrefix(err.Error(), c.code) || !strings.Contains(err.Error(), "integrity")):
			t.Errorf("%s: %v, want %s naming the integrity", c.name, err, c.code)
		case len(d.Packages) != c.pkgs:
			t.Errorf("%s: %d packages, want %d", c.name, len(d.Packages), c.pkgs)
		}
	}
	if got := FloorScriptPolicy(ScriptPolicy{Fetching: fetching}, ScriptPolicy{}); len(got.Fetching) != 1 {
		t.Errorf("the floor dropped the fetching tools: %+v", got)
	}
}

func TestCheckFetchedPackages(t *testing.T) {
	t.Parallel()
	pins := []PackagePin{
		{Name: "tool", Version: "1.0.0", Integrity: integrityOf("main")},
		{Name: "tool-linux-x64", Version: "1.0.0", Integrity: integrityOf("x64")},
		{Name: "tool-linux-arm64", Version: "1.0.0", Integrity: integrityOf("arm64")},
	}
	facts := func(installed map[string]string, cached map[string]bool, required ...string) PackageFacts {
		return PackageFacts{
			Name: "tool", Version: "1.0.0", Required: required, Optional: []string{"tool-linux-arm64", "tool-linux-x64"},
			Installed: func(n string) (string, bool, error) { v, ok := installed[n]; return v, ok, nil },
			Cached:    func(i string) (bool, error) { return cached[i], nil },
		}
	}
	allCached := map[string]bool{}
	for _, p := range pins {
		allCached[p.Integrity] = true
	}
	ok := map[string]string{"tool-linux-x64": "1.0.0"}
	if err := CheckFetchedPackages(facts(ok, allCached), pins); err != nil {
		t.Fatalf("pinned install refused: %v", err)
	}
	if err := CheckFetchedPackages(facts(nil, nil), nil); err != nil {
		t.Fatalf("no pins checks nothing: %v", err)
	}
	missMain := map[string]bool{pins[1].Integrity: true}
	missX64 := map[string]bool{pins[0].Integrity: true}
	cases := []struct {
		name string
		f    PackageFacts
		want string
	}{
		{"main tarball not the pinned one", facts(ok, missMain), "tool@1.0.0"},
		{"platform tarball not the pinned one", facts(ok, missX64), "tool-linux-x64@1.0.0"},
		{"platform at another version", facts(map[string]string{"tool-linux-x64": "1.0.1"}, allCached), "the pin names 1.0.0"},
		{"none placed: the script would fetch", facts(map[string]string{}, allCached), "would fetch one itself"},
		{"unpinned required dependency", facts(ok, allCached, "left-pad"), "left-pad"},
	}
	for _, c := range cases {
		err := CheckFetchedPackages(c.f, pins)
		if err == nil || !strings.HasPrefix(err.Error(), VerdictInstallPackageUnpinned) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %s naming %q", c.name, err, VerdictInstallPackageUnpinned, c.want)
		}
	}
	extra := facts(map[string]string{"tool-linux-x64": "1.0.0", "tool-linux-x64-musl": "1.0.0"}, allCached)
	extra.Optional = append(extra.Optional, "tool-linux-x64-musl")
	if err := CheckFetchedPackages(extra, pins); err == nil || !strings.Contains(err.Error(), "tool-linux-x64-musl") {
		t.Errorf("an installed optional package no pin names: %v", err)
	}
	if _, err := ParsePackageFacts([]byte(`{"name":"tool","version":"1.0.0","optionalDependencies":{"../../etc":"1.0.0"}}`)); err == nil {
		t.Error("a dependency name that is a path was accepted")
	}
	f, err := ParsePackageFacts([]byte(`{"name":"tool","version":"1.0.0","dependencies":{"b":"1"},"optionalDependencies":{"a":"1","b":"1"}}`))
	if err != nil || f.Name != "tool" || len(f.Required) != 1 || len(f.Optional) != 1 || f.Optional[0] != "a" {
		t.Fatalf("facts %+v %v", f, err)
	}
}

func TestBuildInstallCreateCarriesPackagePins(t *testing.T) {
	t.Parallel()
	p := testInstallPlan()
	p.Source.NeedsScripts = true
	p.Source.ScriptSHA256 = []string{shaOf("s")}
	pk := PackagePin{Name: "tool-linux-x64", Version: "1.0.0", Integrity: integrityOf("x")}
	p.Source.ScriptPackages = []PackagePin{pk}
	_, body, err := BuildInstallCreate(p)
	if err != nil || !strings.Contains(strings.Join(body.Entrypoint, " "), PackageIntegrityFlag+" "+pk.Flag()+" -- npm install") {
		t.Fatalf("entrypoint %q %v", body.Entrypoint, err)
	}
	p.Source.ScriptPackages = []PackagePin{{Name: "tool", Version: "1.0.0", Integrity: "sha1-x"}}
	if _, _, err := BuildInstallCreate(p); err == nil {
		t.Fatal("a malformed integrity was accepted")
	}
}
