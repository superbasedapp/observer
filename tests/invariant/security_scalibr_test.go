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
