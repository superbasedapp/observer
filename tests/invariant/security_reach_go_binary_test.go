package invariant

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/components"
)

// security_reach_go_binary_test.go is the binary half of the Go symbol
// check's boundary (OS and CI vulnerability scanning plan section 14.5 item
// 3b, spike RG-0 G5, ledger SECP-51): golang.org/x/vuln is linked only
// through internal/secreachgovuln, and it brings golang.org/x/tools and
// golang.org/x/telemetry, which the node binary links nowhere else.
//
//   - TestReachGoOmitTagLinksNothing: with sbo_omit_security_reach_go (and
//     with sbo_omit_security, and in every distro that compiles
//     security.reach.go out) the node binary links no package of the three
//     modules on linux, windows and darwin, while the driver code
//     (secreachgovuln's stub, the scan child) stays in; without the tag it
//     links x/vuln, so the check is not vacuous.
//   - TestReachGoVulnImportedOnlyByFacade: no package of ours but
//     internal/secreachgovuln imports golang.org/x/vuln directly.

// reachGoModules are the modules the symbol check alone brings.
var reachGoModules = []string{"golang.org/x/vuln", "golang.org/x/tools", "golang.org/x/telemetry"}

const reachGoFacade = "internal/secreachgovuln"

func TestReachGoOmitTagLinksNothing(t *testing.T) {
	toolchainTest(t)
	tagSets := []string{"sbo_omit_security_reach_go", "sbo_omit_security"}
	for _, d := range []components.Distro{components.DistroMinimal, components.DistroDeveloper, components.DistroManaged} {
		tags := components.DistroTags(d)
		for _, tag := range tags {
			if tag == "sbo_omit_security_reach_go" {
				tagSets = append(tagSets, strings.Join(tags, ","))
				break
			}
		}
	}
	for _, goos := range []string{"linux", "windows", "darwin"} {
		linked := scalibrBinaryClosure(t, "cmd/observer", goos, "")
		if countPrefix(linked, "golang.org/x/vuln") == 0 {
			t.Fatalf("GOOS=%s: the default node binary links no golang.org/x/vuln package; the omit-tag check would be vacuous", goos)
		}
		for _, tags := range tagSets {
			omitted := scalibrBinaryClosure(t, "cmd/observer", goos, tags)
			for _, m := range reachGoModules {
				if n := countPrefix(omitted, m); n != 0 {
					t.Errorf("GOOS=%s tags=%s: the node binary still links %d packages of %s", goos, shortTags(tags), n, m)
				}
			}
			if strings.Contains(tags, "sbo_omit_security,") || tags == "sbo_omit_security" {
				continue // the whole module is out, the facade with it
			}
			found := false
			for _, p := range omitted {
				found = found || p == modulePath+reachGoFacade
			}
			if !found {
				t.Errorf("GOOS=%s tags=%s: %s left the omit build; the scan child must keep its stub API", goos, shortTags(tags), reachGoFacade)
			}
		}
	}
}

func shortTags(tags string) string {
	if len(tags) > 80 {
		return tags[:80] + "..."
	}
	return tags
}

func TestReachGoVulnImportedOnlyByFacade(t *testing.T) {
	toolchainTest(t)
	for _, goos := range []string{"linux", "windows", "darwin"} {
		g := goListDeps(t, "cmd/observer", goos, "")
		for full, p := range g.pkgs {
			if !strings.HasPrefix(full, modulePath) || full == modulePath+reachGoFacade {
				continue
			}
			for _, imp := range p.imports {
				if imp == "golang.org/x/vuln" || strings.HasPrefix(imp, "golang.org/x/vuln/") {
					t.Errorf("GOOS=%s: %s imports %s; only %s may link golang.org/x/vuln", goos, full, imp, reachGoFacade)
				}
			}
		}
	}
}
