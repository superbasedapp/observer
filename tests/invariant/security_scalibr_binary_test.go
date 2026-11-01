package invariant

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// security_scalibr_binary_test.go is the binary half of the OSV-SCALIBR
// boundary (security plan section 8.4, spike JSP-9b, plans decision log
// P-019, ledger SECP-19):
//
//   - TestScalibrOmitTagLinksNothing: the node binary with
//     sbo_omit_security_scan_scalibr links zero osv-scalibr packages while
//     its real driver code (depdriver, scalibrchild) stays in and imports
//     only the facade's stub API; without the tag it links them, so the
//     check is not vacuous.
//   - TestScalibrNoContainerModulesInAnyBinary: no container or image
//     module (containerd, moby, the docker CLI, go-containerregistry,
//     compose-go, buildkit) in the closure of any shipped binary on any
//     platform, SCALIBR's extractors included.
//   - TestScalibrGoogleClientsOnlyThroughFacade: the Google client and OSV
//     API modules the walker and matchers link (oauth2/google,
//     compute/metadata, osv.dev bindings, deps.dev) leave the node binary
//     with the omit tag; nothing but SCALIBR reaches them.

// scalibrBinaryClosure lists the packages of ./cmd/<bin> for goos and tags.
func scalibrBinaryClosure(t *testing.T, cmdPath, goos, tags string) []string {
	t.Helper()
	args := []string{"list", "-deps"}
	if tags != "" {
		args = append(args, "-tags", tags)
	}
	args = append(args, "./"+cmdPath)
	cmd := exec.Command("go", args...)
	cmd.Dir = repoRoot(t)
	cmd.Env = append(os.Environ(), "GOOS="+goos, "CGO_ENABLED=0")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps %s (GOOS=%s tags=%q): %v\n%s", cmdPath, goos, tags, err, out)
	}
	return strings.Split(strings.TrimSpace(string(out)), "\n")
}

func countPrefix(pkgs []string, prefix string) int {
	n := 0
	for _, p := range pkgs {
		if p == prefix || strings.HasPrefix(p, prefix+"/") {
			n++
		}
	}
	return n
}

func TestScalibrOmitTagLinksNothing(t *testing.T) {
	toolchainTest(t)
	for _, goos := range []string{"linux", "windows", "darwin"} {
		linked := scalibrBinaryClosure(t, "cmd/observer", goos, "")
		if countPrefix(linked, scalibrModule) == 0 {
			t.Fatalf("GOOS=%s: the default node binary links no osv-scalibr package; the omit-tag check would be vacuous", goos)
		}
		omitted := scalibrBinaryClosure(t, "cmd/observer", goos, "sbo_omit_security_scan_scalibr")
		if n := countPrefix(omitted, scalibrModule); n != 0 {
			t.Errorf("GOOS=%s: with sbo_omit_security_scan_scalibr the node binary still links %d osv-scalibr packages", goos, n)
		}
		for _, must := range []string{modulePath + scalibrFacade, modulePath + "internal/secscan/depdriver", modulePath + "internal/secscan/scalibrchild"} {
			found := false
			for _, p := range omitted {
				if p == must {
					found = true
				}
			}
			if !found {
				t.Errorf("GOOS=%s: %s left the omit build; the driver must stay and use only the stub API", goos, must)
			}
		}
	}
}

// containerModules are the container and image modules SCALIBR's go.mod
// requires and that must never be linked.
var containerModules = []string{
	"github.com/containerd",
	"github.com/docker/docker",
	"github.com/docker/cli",
	"github.com/docker/distribution",
	"github.com/moby",
	"github.com/google/go-containerregistry",
	"github.com/compose-spec/compose-go",
	"github.com/opencontainers/image-spec",
}

func TestScalibrNoContainerModulesInAnyBinary(t *testing.T) {
	toolchainTest(t)
	bins := []string{"cmd/observer", "cmd/observer-org"}
	for _, bin := range bins {
		if _, err := os.Stat(filepath.Join(repoRoot(t), filepath.FromSlash(bin))); err != nil {
			continue
		}
		for _, goos := range []string{"linux", "windows", "darwin"} {
			pkgs := scalibrBinaryClosure(t, bin, goos, "")
			for _, m := range containerModules {
				if n := countPrefix(pkgs, m); n != 0 {
					t.Errorf("%s (GOOS=%s) links %d packages of %s: no container or image module may reach a binary", bin, goos, n, m)
				}
			}
		}
	}
}

// scalibrOnlyModules are reached in the node binary only through SCALIBR.
var scalibrOnlyModules = []string{
	"golang.org/x/oauth2/google",
	"cloud.google.com/go/compute/metadata",
	"osv.dev/bindings/go",
	"deps.dev/api",
	"github.com/diskfs/go-diskfs",
	"github.com/go-git/go-git/v5",
}

func TestScalibrGoogleClientsOnlyThroughFacade(t *testing.T) {
	toolchainTest(t)
	linked := scalibrBinaryClosure(t, "cmd/observer", "linux", "")
	omitted := scalibrBinaryClosure(t, "cmd/observer", "linux", "sbo_omit_security_scan_scalibr")
	seen := 0
	for _, m := range scalibrOnlyModules {
		if countPrefix(linked, m) > 0 {
			seen++
		}
		if n := countPrefix(omitted, m); n != 0 {
			t.Errorf("%s stays in the node binary without SCALIBR (%d packages): something else reaches it; give it a lane row or remove the import", m, n)
		}
	}
	if seen == 0 {
		t.Fatal("none of the SCALIBR-only modules is in the default binary; the check would be vacuous")
	}
}
