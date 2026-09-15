package invariant

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// intel_import_boundary_test.go pins INV-2 of the org-served cloud-intelligence
// arc (docs/plans/org-served-cloud-intelligence-plan-2026-09-10.md §2.6 / §4):
//
//	The org intelligence rail is reachable only through internal/orgclient. No
//	package under internal/cloudserver, and no personal-plane network package,
//	may be imported by internal/orgserver or by the node's org rail
//	(internal/orgclient). internal/cloudcontract and internal/cloudevidence ARE
//	allowed on both sides — they are pure.
//
// It is a sibling of cloud_egress_test.go's TestCloudClientIsolatedToConsentGateway
// and uses the same import-graph technique (go list). cloud_egress_test.go stays
// exactly as written: that pin governs the PERSONAL network lane inside the node;
// this one governs plane separation between the org side and the personal
// cloud-service / network packages. modulePath is shared from
// edge_boundary_test.go (same package).

// intelForbiddenForOrgSide are the packages neither internal/orgserver nor the
// node's org rail (internal/orgclient) may transitively link: the personal
// network/credential lane AND the whole hosted personal cloud service. A server
// importing the node's outbound client/credential store, or either org side
// importing the separate hosted cloud binary's packages, is a plane-separation
// smell. Matched as a package OR any subpackage.
var intelForbiddenForOrgSide = []string{
	"internal/cloudclient",
	"internal/cloudpop",
	"internal/cloudcred",
	"internal/cloudgateway",
	"internal/cloudserver",
}

// intelOrgSideEntryPatterns are the org-side package trees whose full transitive
// closure must be clean of intelForbiddenForOrgSide.
var intelOrgSideEntryPatterns = []string{
	"./internal/orgserver/...",
	"./internal/orgclient/...",
}

// presentEntryPatterns narrows patterns to those whose package tree actually
// exists under repoRoot.
//
// internal/orgserver is Enterprise-only and is stripped from the public release
// tree, while internal/orgclient stays public by design. Passing a pattern for
// an absent directory makes `go list` exit non-zero and fail the whole sentinel,
// so the guard would be unrunnable on the public tree exactly where it still has
// something real to say: that the node's org rail links no personal-plane
// network package. Resolving the patterns first keeps one test honest on both
// trees - the full closure privately, the orgclient half publicly.
func presentEntryPatterns(repoRoot string, patterns []string) []string {
	var present []string
	for _, p := range patterns {
		dir := strings.TrimSuffix(strings.TrimPrefix(p, "./"), "/...")
		if _, err := os.Stat(filepath.Join(repoRoot, dir)); err == nil {
			present = append(present, p)
		}
	}
	return present
}

// TestINV2_OrgSideDoesNotLinkPersonalCloud is INV-2 half (a): the transitive
// dependency closure of the org server and the node's org rail contains none of
// the personal network/credential packages nor any hosted-cloud-service package.
// Only internal/cloudcontract and internal/cloudevidence (both pure) are shared,
// and they are checked by half (b) to be free of node/server I/O.
func TestINV2_OrgSideDoesNotLinkPersonalCloud(t *testing.T) {
	repoRoot := filepath.Join("..", "..")
	patterns := presentEntryPatterns(repoRoot, intelOrgSideEntryPatterns)
	if len(patterns) == 0 {
		t.Skip("no org-side package tree present in this checkout")
	}
	wantOrgServer := false
	for _, p := range patterns {
		if strings.HasPrefix(p, "./internal/orgserver") {
			wantOrgServer = true
		}
	}
	args := append([]string{"list", "-deps"}, patterns...)
	cmd := exec.Command("go", args...)
	cmd.Dir = repoRoot
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps %v failed: %v\n%s", patterns, err, out)
	}

	var sawOrgServer, count int
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		pkg := strings.TrimSpace(line)
		if !strings.HasPrefix(pkg, modulePath) {
			continue // stdlib / third-party
		}
		count++
		rel := strings.TrimPrefix(pkg, modulePath)
		if strings.HasPrefix(rel, "internal/orgserver") {
			sawOrgServer++
		}
		if bad, hit := matchesIntelPkg(rel, intelForbiddenForOrgSide); hit {
			t.Errorf("an org-side package transitively imports %q — INV-2: the org rail is reached "+
				"ONLY through internal/orgclient with the enrolment identity; no personal-plane network "+
				"package and no internal/cloudserver package may be linked by internal/orgserver or "+
				"internal/orgclient. Reuse internal/cloudcontract / internal/cloudevidence (pure) instead.", bad)
		}
	}
	// Non-vacuous: the closure must be substantial and actually include orgserver
	// packages, so a typo'd pattern can't make this pass silently.
	if count == 0 || (wantOrgServer && sawOrgServer == 0) {
		t.Fatalf("go list -deps %v returned an unexpectedly empty/orgserver-less module closure "+
			"(count=%d sawOrgServer=%d wantOrgServer=%v) — the INV-2 guard would be vacuous",
			patterns, count, sawOrgServer, wantOrgServer)
	}
}

// intelPureShared are the two pure packages allowed on BOTH the personal and the
// org side. Their DIRECT internal imports must stay within intelPureAllowedInternal
// so importing them can never drag node or server I/O onto the org side.
var intelPureShared = []string{
	"./internal/cloudcontract/...",
	"./internal/cloudevidence/...",
}

// intelPureAllowedInternal is the exact set of internal packages the pure shared
// packages may DIRECTLY import — read from their current import sets: the two
// pure packages themselves, plus internal/scrub and internal/dataauthority
// (themselves pure). Anything else — store, orgserver, a network package — would
// break "importable by both sides".
var intelPureAllowedInternal = map[string]bool{
	"internal/cloudcontract": true,
	"internal/cloudevidence": true,
	"internal/dataauthority": true,
	"internal/scrub":         true,
}

// TestINV2_PureSharedPackagesStayImportableByBothSides is INV-2 half (b): every
// package under internal/cloudcontract and internal/cloudevidence directly
// imports only packages in intelPureAllowedInternal (plus stdlib/third-party),
// so both the personal node and the org server can import them without pulling
// in any node/server I/O. This is the standing guard behind "the ONLY change
// either needs is the authority predicate" (§1.3).
func TestINV2_PureSharedPackagesStayImportableByBothSides(t *testing.T) {
	repoRoot := filepath.Join("..", "..")
	args := append([]string{"list", "-e", "-f", "{{.ImportPath}}{{range .Imports}} {{.}}{{end}}"}, intelPureShared...)
	cmd := exec.Command("go", args...)
	cmd.Dir = repoRoot
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go list %v failed: %v\n%s", intelPureShared, err, out)
	}

	var pkgs int
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) == 0 {
			continue
		}
		importer := fields[0]
		if !strings.HasPrefix(importer, modulePath) {
			continue
		}
		pkgs++
		for _, imp := range fields[1:] {
			if !strings.HasPrefix(imp, modulePath) {
				continue // stdlib / third-party
			}
			impRel := strings.TrimPrefix(imp, modulePath)
			if !intelPureAllowedInternal[impRel] {
				t.Errorf("pure shared package %q directly imports internal package %q — INV-2 (b): "+
					"internal/cloudcontract and internal/cloudevidence must import only %v so they stay "+
					"importable by BOTH the personal node and the org server without dragging node/server I/O.",
					strings.TrimPrefix(importer, modulePath), impRel, sortedKeys(intelPureAllowedInternal))
			}
		}
	}
	if pkgs == 0 {
		t.Fatalf("go list %v matched no module packages — the INV-2 (b) guard would be vacuous", intelPureShared)
	}
}

// forbiddenIOImport is one entry in the pure-package I/O deny-list (finding 12).
// Most entries match themselves OR any subpackage; `exact` entries match only
// their exact path, which is how "net" (raw sockets) is forbidden WITHOUT
// catching the pure, already-used net/url.
type forbiddenIOImport struct {
	path  string
	exact bool
}

// matches reports whether import path imp is denied by this entry.
func (f forbiddenIOImport) matches(imp string) bool {
	if f.exact {
		return imp == f.path
	}
	return imp == f.path || strings.HasPrefix(imp, f.path+"/")
}

// intelPureForbiddenIO is the explicit allow-list's complement: the I/O packages
// the pure shared packages (internal/cloudcontract, internal/cloudevidence, and
// anything they import) must NEVER pull in, so they stay importable by BOTH the
// personal node and the org server with no network / SQL / subprocess / fs-watch
// dependency (finding 12). Table-driven: a new forbidden family is one row.
var intelPureForbiddenIO = []forbiddenIOImport{
	{path: "net/http"},                     // HTTP client/server
	{path: "net", exact: true},             // raw sockets (exact: net/url is pure and allowed)
	{path: "database/sql"},                 // SQL
	{path: "os/exec"},                      // subprocess
	{path: "github.com/fsnotify/fsnotify"}, // filesystem watching
	{path: "github.com/marmutapp/superbased-observer/internal/store"}, // node I/O store
}

// firstForbiddenIO returns the first deny-list entry that matches imp, or nil.
func firstForbiddenIO(imp string) *forbiddenIOImport {
	for i := range intelPureForbiddenIO {
		if intelPureForbiddenIO[i].matches(imp) {
			return &intelPureForbiddenIO[i]
		}
	}
	return nil
}

// TestINV2_PureSharedPackagesForbidIO is INV-2 half (c) (finding 12): the
// existing half (b) checked only INTERNAL imports against an allow-list and
// ignored stdlib/third-party. This one scans EVERY direct import of the pure
// shared packages against an explicit I/O deny-list, so a newly-added net/http,
// database/sql, os/exec or fsnotify dependency on the pure side fails loudly —
// the property that keeps cloudcontract/cloudevidence importable by both planes.
func TestINV2_PureSharedPackagesForbidIO(t *testing.T) {
	repoRoot := filepath.Join("..", "..")
	args := append([]string{"list", "-e", "-f", "{{.ImportPath}}{{range .Imports}} {{.}}{{end}}"}, intelPureShared...)
	cmd := exec.Command("go", args...)
	cmd.Dir = repoRoot
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go list %v failed: %v\n%s", intelPureShared, err, out)
	}

	var pkgs int
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) == 0 {
			continue
		}
		importer := fields[0]
		if !strings.HasPrefix(importer, modulePath) {
			continue
		}
		pkgs++
		for _, imp := range fields[1:] {
			if f := firstForbiddenIO(imp); f != nil {
				t.Errorf("pure shared package %q imports forbidden I/O package %q — INV-2 (c): "+
					"internal/cloudcontract and internal/cloudevidence (and their imports) must stay free of "+
					"net/http, net, database/sql, os/exec, fsnotify and the node store so they remain importable "+
					"by BOTH the personal node and the org server (finding 12).",
					strings.TrimPrefix(importer, modulePath), imp)
			}
		}
	}
	if pkgs == 0 {
		t.Fatalf("go list %v matched no module packages — the INV-2 (c) guard would be vacuous", intelPureShared)
	}
}

// TestINV2_ForbiddenIOMatcherCatchesPlantedImports proves the deny-list matcher
// would catch a planted net/http (and friends) import, WITHOUT committing an
// actual planted import to the tree (finding 12's "plant then remove"): it feeds
// the matcher the exact import paths a violation would introduce and asserts it
// flags each, while the legitimately-used pure imports pass.
func TestINV2_ForbiddenIOMatcherCatchesPlantedImports(t *testing.T) {
	mustCatch := []string{
		"net/http",
		"net/http/httptest",
		"net",
		"database/sql",
		"os/exec",
		"github.com/fsnotify/fsnotify",
		"github.com/marmutapp/superbased-observer/internal/store",
	}
	for _, imp := range mustCatch {
		if firstForbiddenIO(imp) == nil {
			t.Errorf("deny-list failed to catch a planted forbidden import %q — the guard would be vacuous", imp)
		}
	}
	mustAllow := []string{
		"net/url", // pure; used by cloudcontract.safetext.go
		"fmt",
		"encoding/json",
		"github.com/marmutapp/superbased-observer/internal/scrub",
		"github.com/marmutapp/superbased-observer/internal/dataauthority",
		"golang.org/x/text/unicode/norm",
	}
	for _, imp := range mustAllow {
		if f := firstForbiddenIO(imp); f != nil {
			t.Errorf("deny-list wrongly flagged legitimate import %q (matched %q)", imp, f.path)
		}
	}
}

// matchesIntelPkg reports whether module-relative rel is one of pkgs or a
// subpackage of one.
func matchesIntelPkg(rel string, pkgs []string) (string, bool) {
	for _, p := range pkgs {
		if rel == p || strings.HasPrefix(rel, p+"/") {
			return p, true
		}
	}
	return "", false
}

// sortedKeys returns the map keys sorted, for a stable failure message.
func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	// small n; insertion sort keeps the helper dependency-free
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1] > out[j]; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}
