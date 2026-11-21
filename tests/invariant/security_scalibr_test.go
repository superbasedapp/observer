package invariant

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// security_scalibr_test.go pins the OSV-SCALIBR boundary (security pillar
// plan section 8.4, spike JSP-9b, ledger SECP-19):
//
//   - internal/secscan/scalibrfacade is the only module package that
//     imports github.com/google/osv-scalibr;
//   - the facade imports single extractor packages and the walker, never
//     the top-level scalibr package, extractor/filesystem/list, or any
//     container, OS-package, image or secret extractor.
//
// The binary-level halves (the omit tag links zero SCALIBR packages, no
// container or image module in any binary, the Google client modules the
// walker links reached only through the facade) are in
// security_scalibr_binary_test.go.

const (
	scalibrModule = "github.com/google/osv-scalibr"
	scalibrFacade = "internal/secscan/scalibrfacade"
)

// scalibrForbidden are the SCALIBR packages (and package prefixes) the
// facade may never import: they bring the container, image, OS-package and
// secret extractors.
var scalibrForbidden = []string{
	scalibrModule, // scalibr.go imports artifact/image
	scalibrModule + "/extractor/filesystem/list", // every extractor
	scalibrModule + "/extractor/standalone",      // live-host extractors
	scalibrModule + "/artifact/image",            // container images
	scalibrModule + "/extractor/filesystem/containers",
	scalibrModule + "/extractor/filesystem/os",
	scalibrModule + "/extractor/filesystem/secrets",
	scalibrModule + "/veles",
	scalibrModule + "/detector",
}

// scalibrOSAllowed are the OS package extractors phase OS-2 route A links
// (component security.scan.os, plan 6.6.1), exceptions to the forbidden
// extractor/filesystem/os prefix: the three package databases, their
// metadata and os-release. Nothing else under os/ (no live-host, kernel or
// image code), and none of them under sbo_omit_security_scan_os
// (TestScalibrOSOmitTagLinksNoOSExtractor).
var scalibrOSAllowed = map[string]bool{
	scalibrModule + "/extractor/filesystem/os/dpkg":          true,
	scalibrModule + "/extractor/filesystem/os/dpkg/metadata": true,
	scalibrModule + "/extractor/filesystem/os/apk":           true,
	scalibrModule + "/extractor/filesystem/os/apk/metadata":  true,
	scalibrModule + "/extractor/filesystem/os/rpm":           true,
	scalibrModule + "/extractor/filesystem/os/rpm/metadata":  true,
	scalibrModule + "/extractor/filesystem/os/osrelease":     true,
}

// moduleImports lists every module package of the root module with its
// direct imports, for the given build tags.
func moduleImports(t *testing.T, tags string) map[string][]string {
	t.Helper()
	args := []string{"list", "-f", "{{.ImportPath}} {{join .Imports \" \"}}"}
	if tags != "" {
		args = append(args, "-tags", tags)
	}
	args = append(args, "./...")
	cmd := exec.Command("go", args...)
	cmd.Dir = filepath.Join("..", "..")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go list ./...: %v\n%s", err, out)
	}
	m := map[string][]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		m[strings.TrimPrefix(f[0], modulePath)] = f[1:]
	}
	return m
}

func TestScalibrImportedOnlyByFacade(t *testing.T) {
	toolchainTest(t)
	pkgs := moduleImports(t, "")
	facadeImports, ok := pkgs[scalibrFacade]
	if !ok {
		t.Fatalf("%s is not in the module; the guard would be vacuous", scalibrFacade)
	}
	linked := 0
	for rel, imps := range pkgs {
		for _, imp := range imps {
			if imp != scalibrModule && !strings.HasPrefix(imp, scalibrModule+"/") {
				continue
			}
			if rel != scalibrFacade {
				t.Errorf("%s imports %s: only %s may import OSV-SCALIBR", rel, imp, scalibrFacade)
			}
		}
	}
	for _, imp := range facadeImports {
		if !strings.HasPrefix(imp, scalibrModule) {
			continue
		}
		linked++
		if scalibrOSAllowed[imp] {
			continue
		}
		for _, bad := range scalibrForbidden {
			if imp == bad || (bad != scalibrModule && strings.HasPrefix(imp, bad+"/")) {
				t.Errorf("%s imports %s, which brings container, image, OS-package or secret code", scalibrFacade, imp)
			}
		}
	}
	if linked == 0 {
		t.Fatalf("%s imports no SCALIBR package; the guard would be vacuous", scalibrFacade)
	}
}

// TestScalibrOSOmitTagLinksNoOSExtractor: with security.scan.os omitted the
// facade imports nothing under extractor/filesystem/os.
func TestScalibrOSOmitTagLinksNoOSExtractor(t *testing.T) {
	toolchainTest(t)
	pkgs := moduleImports(t, "sbo_omit_security_scan_os")
	imps, ok := pkgs[scalibrFacade]
	if !ok {
		t.Fatalf("%s missing under sbo_omit_security_scan_os", scalibrFacade)
	}
	for _, imp := range imps {
		if strings.HasPrefix(imp, scalibrModule+"/extractor/filesystem/os") {
			t.Errorf("%s imports %s with sbo_omit_security_scan_os", scalibrFacade, imp)
		}
	}
}

// TestScalibrStubImportsNothing: with the omit tag the facade's API is the
// stub, which imports no SCALIBR package.
func TestScalibrStubImportsNothing(t *testing.T) {
	toolchainTest(t)
	pkgs := moduleImports(t, "sbo_omit_security_scan_scalibr")
	imps, ok := pkgs[scalibrFacade]
	if !ok {
		t.Fatalf("%s missing under the omit tag: the stub API must stay", scalibrFacade)
	}
	for rel, list := range pkgs {
		for _, imp := range list {
			if strings.HasPrefix(imp, scalibrModule) {
				t.Errorf("with sbo_omit_security_scan_scalibr, %s still imports %s", rel, imp)
			}
		}
	}
	_ = imps
}

// scalibrArtifactExtractors are the four artifact extractors of plan
// section 14.6 (M3L-2 item 4): Go build info, Java archives, Python wheels
// and eggs, and cargo auditable. They sit under extractor/filesystem/
// language, outside every forbidden prefix; this list closes them, so a
// fifth artifact reader (a container or disk-image one) is a reviewed
// change here, not a silent import.
var scalibrArtifactExtractors = []string{
	scalibrModule + "/extractor/filesystem/language/golang/gobinary",
	scalibrModule + "/extractor/filesystem/language/java/archive",
	scalibrModule + "/extractor/filesystem/language/python/wheelegg",
	scalibrModule + "/extractor/filesystem/language/rust/cargoauditable",
}

// TestScalibrArtifactExtractorsLinkNothingForbidden: the facade imports
// the four artifact extractors, and what they add to the facade's closure
// (their closure minus that of the facade's other SCALIBR imports, which
// already bring the walker's own shared packages) holds no forbidden SCALIBR
// package and no container or image module; go-rustaudit is the one new
// module they bring.
func TestScalibrArtifactExtractorsLinkNothingForbidden(t *testing.T) {
	toolchainTest(t)
	pkgs := moduleImports(t, "")
	imps := map[string]bool{}
	var others []string
	for _, imp := range pkgs[scalibrFacade] {
		imps[imp] = true
	}
	artifact := map[string]bool{}
	for _, x := range scalibrArtifactExtractors {
		artifact[x] = true
		if !imps[x] {
			t.Errorf("%s does not import %s; the artifact extractors' guard would be vacuous", scalibrFacade, x)
		}
	}
	for imp := range imps {
		if strings.HasPrefix(imp, scalibrModule) && !artifact[imp] {
			others = append(others, imp)
		}
	}
	base := map[string]bool{}
	for _, p := range listDeps(t, others) {
		base[p] = true
	}
	rustaudit := false
	added := 0
	for _, p := range listDeps(t, scalibrArtifactExtractors) {
		if base[p] {
			continue
		}
		added++
		if p == "github.com/rust-secure-code/go-rustaudit" {
			rustaudit = true
		}
		if scalibrOSAllowed[p] {
			continue
		}
		for _, bad := range scalibrForbidden {
			if bad != scalibrModule && (p == bad || strings.HasPrefix(p, bad+"/")) {
				t.Errorf("an artifact extractor adds %s to the facade's closure", p)
			}
		}
		for _, m := range containerModules {
			if p == m || strings.HasPrefix(p, m+"/") {
				t.Errorf("an artifact extractor adds the container module package %s", p)
			}
		}
	}
	if added == 0 || !rustaudit {
		t.Errorf("the artifact extractors add %d packages and go-rustaudit %v; update the notices (docs/dependency-scanning-notices.md) if cargoauditable no longer links it", added, rustaudit)
	}
}

// listDeps is `go list -deps` over pkgs.
func listDeps(t *testing.T, pkgs []string) []string {
	t.Helper()
	cmd := exec.Command("go", append([]string{"list", "-deps"}, pkgs...)...)
	cmd.Dir = filepath.Join("..", "..")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps: %v\n%s", err, out)
	}
	var res []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		res = append(res, strings.TrimSpace(line))
	}
	return res
}
