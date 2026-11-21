package invariant

import (
	"go/parser"
	"go/scanner"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// openshell_boundary_test.go is the OpenShell row's boundary (OpenShell
// build plan 05 section 2, lane O1A): OpenShell is one pluggable sandbox
// component, so selection, posture, guard and the UI read the row's
// capability fields, never its name. Three rules over the Go source:
//
//  1. the name openshell, in any case (a string such as the label
//     "OpenShell", an import path, an identifier, an omit tag in a build
//     constraint), appears in production code only in the backend id
//     constant and row, the pure planner, the driver files, the component
//     row and the config block. Comments are prose and are not scanned
//     (other lanes cite "OpenShell build plan 05" in theirs); docs are not
//     Go; test files may name the row to test it;
//  2. only the driver files (cmd/observer/terminal_sandbox_openshell*.go)
//     import internal/sandboxopenshell, besides the package itself;
//  3. the id constant sandboxbackend.BackendOpenShell is named in production
//     code only by the registry, the planner, the driver files and the
//     files openShellIDFiles names.

// openShellLiteralFiles are the production files rule 1 allows, as
// repository-relative slash paths; a trailing "/" allows a directory, a
// trailing "*" a file-name prefix.
var openShellLiteralFiles = []string{
	"internal/sandboxbackend/registry.go",
	"internal/sandboxbackend/types.go",
	"internal/sandboxopenshell/",
	"cmd/observer/terminal_sandbox_openshell*",
	"internal/components/catalog_node.go",
	"internal/config/sandbox_openshell.go",
	"internal/config/config.go",
	"internal/config/component_sections.go",
	"internal/configschema/annotations.go",
	// The Settings card's editor of [terminal.sandbox.openshell] (lane O4):
	// it names the config block, as config.go and annotations.go do.
	"internal/intelligence/dashboard/terminal_sandbox_config_gatewayrow.go",
	// The org-hosted OpenShell gateway's control half (tracker F-019, lane
	// G2; g1-design.md section 11.1's boundary token): the pure core, the
	// contract file and its body-field hunk, the issuer, the control
	// service, the server wiring pair and its hunks, the config block, the
	// control-store twin, the audit actions, the retention row, the
	// component row and the observer-org verbs.
	"internal/openshellorg/",
	"internal/orgcontract/openshellorg.go",
	"internal/orgcontract/sandboxpolicy.go",
	"internal/orgserver/openshellctl/",
	"internal/orgserver/openshellidp/",
	"internal/orgserver/server_openshell*",
	"internal/orgserver/server.go",
	"internal/orgserver/server_runtime.go",
	"internal/orgserver/config/openshell.go",
	"internal/orgserver/config/config.go",
	"internal/orgserver/controlstore/schema_gen.go",
	"internal/orgserver/controlstore/schema.go",
	"internal/orgserver/rollup/audit.go",
	// The device-approval page's form route in the cross-site table (live
	// finding F-L3-3, lane FX1): the table is the one owner of those rows.
	"internal/orgserver/auth/crosssite.go",
	"internal/orgserver/retention/aged_rows.go",
	// The tenancy manifest (plan 07 M3-0.2): one row per org table, the
	// OpenShell tables included; it names tables, never the capability.
	"internal/orgserver/tenancy/tables.go",
	// The org-bound object store's namespace table (plan 07 M5.7): the
	// OpenShell collect tree is one storage namespace; it names a key
	// layout, never the capability.
	"internal/orgserver/orgobj/rules.go",
	// The background-loop classification (plan 07 M4.1): one row per loop,
	// the OpenShell worker included; it names a loop, never the capability.
	"internal/orgserver/periodic/loops.go",
	// The retention hold path inventory (plan 07 M7a.4): one row per prune
	// path, the OpenShell box prune included; it names a path, never the
	// capability.
	"internal/orgserver/retention/holdpaths.go",
	// The pooled route inventory (plan 07 wave 10 L2): one row per mounted
	// route, the OpenShell agent and admin routes included, each pattern
	// spelt exactly as mounted so TestEveryRouteHasAPooledRow matches it; it
	// names routes, never the capability.
	"internal/orgserver/pooledroutes/routes.go",
	"internal/components/catalog_server.go",
	// The grandfathered Reach set (plan 06 18.3.3): one key per catalog
	// component id that existed at catalog version 4, the OpenShell rows
	// included; it names component ids, never the capability.
	"internal/components/reach.go",
	// The entitlements gate table (plan 07 M7b.1): one row per server
	// catalog component id, the OpenShell row included, keyed by the
	// component id (no second key space); it names a component id, never
	// the capability.
	"internal/entitlements/capability.go",
	// The plain-language network lane table `observer privacy` prints
	// (Getting started v2, internal/netlanes): one row per lane, the
	// sandboxes row naming the org-hosted sandbox's egress lane id
	// (sandbox.remote.openshell-org, declared in egress_lanes_test.go) and
	// the provider in words; it names a lane, never the capability.
	"internal/netlanes/netlanes.go",
	"cmd/observer-org/openshell*",
	"cmd/observer-org/components_build_no_openshell.go",
	"cmd/observer-org/main.go",
	"internal/orgserver/sandboxmanaged/provider.go",
	"internal/orgserver/sandboxmanaged/store.go",
	// The org-hosted gateway's front, gateway client and sync (lane G3,
	// g1-design.md 11.3): the validating front and its front-only boot path,
	// the gateway client and its test fake, the sync, reaper, drain and
	// collect with their admin routes, the server seam file, the CLI verbs,
	// the doctor and preflight rows, and the role vocabulary's front role.
	"internal/orgserver/openshellfront/",
	"internal/orgserver/openshellgw/",
	"internal/orgserver/roles/roles.go",
	"cmd/observer-org/serve_openshellfront*",
	"cmd/observer-org/doctor_openshell*",
	"cmd/observer-org/preflight_openshell*",
	"cmd/observer-org/supportbundle_openshell*",
	"cmd/observer-org/doctor.go",
	"cmd/observer-org/preflight.go",
	"cmd/observer-org/supportbundle.go",
	"internal/orgserver/db/pgmigrations/gen/controlshadow/manifest.go",
	"internal/orgserver/chat/admin_orgshell.go",
	// The org gateway's live-check probe (lane G5, G-L1 and G-L2): its own
	// module against the tagged SDK, never linked into a product binary.
	"scripts/sandbox/g-l2/",
	// The org gateway's deployment (lane G5): the planner's axis id
	// ("openshell", design 2.3) and its renderer, and the exported bundle's
	// row for the sandbox host bundle (deploy/observer-openshell). They name
	// deployment files and an axis, never a sandbox row or its id.
	"deploy/catalog/resolve.go",
	// Lane GF2: the planner's openshell axis and module variables, never a sandbox row.
	"deploy/catalog/render/openshell*",
	"deploy/catalog/bom_openshell*",
	"internal/orgserver/deploybundle/bundle.go",
	// The org-hosted gateway's node side (tracker F-019, lane G4;
	// g1-design.md section 11.4): the node's SDK wire client (the only node
	// importer of the OpenShell module), the vendor row and its capability
	// flags, the transport and probe files of the pure core (covered by the
	// directory above), the org client's agent routes, the node driver,
	// login, hold and guest verbs, and the node config hunk of the two keys.
	"internal/sandboxremote/openshellorg/",
	"internal/sandboxremote/vendors.go",
	"internal/orgclient/openshellorg.go",
	"cmd/observer/terminal_sandbox_orgshell*",
	"cmd/observer/sandbox_orgshell_*",
	"cmd/observer/sandbox_guest_orgshell*",
	"internal/config/sandbox_orgshell.go",
	// The sandbox setup tables (PT-89, plan sandbox-installation-lifecycle
	// section 3.2, which names "openshell-pkg" as a prerequisite id): the
	// prerequisite table and the per-driver verdict map are per-row data,
	// like the registry row's Setup list; the planner (plan.go) branches on
	// those rows, never on a name.
	"internal/sandboxsetup/prereqs.go",
	"internal/sandboxsetup/verdicts.go",
}

// openShellIDFiles are the production files besides the registry, the
// planner and the driver files that rule 3 lets name the id constant: the
// sandbox setup verdict map (PT-89), whose rows say which registry rows a
// driver's verdicts belong to.
var openShellIDFiles = []string{
	"internal/sandboxsetup/verdicts.go",
}

// openShellPlannerImporters are the files besides the driver files that
// rule 2 lets import the planner, read-only: the org-hosted gateway's
// authoritative org compile (lane G2), which reuses the planner's pure
// compiler rather than a second policy model (rule W2).
var openShellPlannerImporters = []string{
	"internal/openshellorg/compile.go",
	// The detective check (lane G3, design 7.6) reuses FU8's effective
	// policy comparison read-only.
	"internal/orgserver/openshellgw/detective.go",
	// Lane G4's tests of its compile internet row and the netrules.go
	// BlockedCIDRs hunk.
	"internal/openshellorg/compile_internet_test.go",
	// The sandbox setup verdict pin (PT-89): a test that holds each verdict
	// string of the setup verdict map equal to the driver's own constant,
	// reading those constants only.
	"internal/sandboxsetup/verdicts_test.go",
}

// openShellDriverFiles are the files rules 2 and 3 allow besides the
// planner (and, for rule 3, the registry).
const openShellDriverFiles = "cmd/observer/terminal_sandbox_openshell*"

// openShellPlanner is the planner's import path suffix.
const openShellPlanner = "internal/sandboxopenshell"

// openShellIDRE matches the id constant as an identifier.
var openShellIDRE = regexp.MustCompile(`\bBackendOpenShell\b`)

// openShellNameRE matches the name in any case (audit finding O1A-A11: a
// case-sensitive match let row.Label == "OpenShell" through).
var openShellNameRE = regexp.MustCompile(`(?i)openshell`)

// openShellNamed reports whether Go source names OpenShell in code: a
// string or rune literal, an identifier or a build constraint, matched in
// any case. Other comments are prose and are skipped.
func openShellNamed(src []byte) bool {
	if !openShellNameRE.Match(src) {
		return false
	}
	var s scanner.Scanner
	fset := token.NewFileSet()
	s.Init(fset.AddFile("", fset.Base(), len(src)), src, nil, scanner.ScanComments)
	for {
		_, tok, lit := s.Scan()
		switch tok {
		case token.EOF:
			return false
		case token.COMMENT:
			if !strings.HasPrefix(lit, "//go:build") && !strings.HasPrefix(lit, "// +build") {
				continue
			}
		case token.STRING, token.CHAR, token.IDENT:
		default:
			continue
		}
		if openShellNameRE.MatchString(lit) {
			return true
		}
	}
}

// openShellLiteralViolation is rule 1 for one file: a production file
// outside the allow-list that names OpenShell in code.
func openShellLiteralViolation(rel string, src []byte) bool {
	return !strings.HasSuffix(rel, "_test.go") && !allowedBy(rel, openShellLiteralFiles) && openShellNamed(src)
}

// allowedBy reports whether rel matches one of the patterns.
func allowedBy(rel string, patterns []string) bool {
	for _, p := range patterns {
		switch {
		case strings.HasSuffix(p, "/"):
			if strings.HasPrefix(rel, p) {
				return true
			}
		case strings.HasSuffix(p, "*"):
			if strings.HasPrefix(rel, strings.TrimSuffix(p, "*")) {
				return true
			}
		case rel == p:
			return true
		}
	}
	return false
}

// goSourceFiles lists the repository's Go files as slash paths, skipping
// throwaway spikes, test data, vendored and generated web trees.
func goSourceFiles(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "vendor", "testdata", "_spikes", "dist":
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(p, ".go") {
			rel, err := filepath.Rel(root, p)
			if err != nil {
				return err
			}
			out = append(out, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	sort.Strings(out)
	return out
}

func TestOpenShellBoundary(t *testing.T) {
	root := repoRoot(t)
	var plannerFound, idFound, driverFound bool
	for _, rel := range goSourceFiles(t, root) {
		b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatalf("%s: %v", rel, err)
		}
		src := string(b)
		test := strings.HasSuffix(rel, "_test.go")
		inPlanner := strings.HasPrefix(rel, openShellPlanner+"/")
		driver := allowedBy(rel, []string{openShellDriverFiles})
		plannerFound = plannerFound || inPlanner
		driverFound = driverFound || driver
		if rel == "internal/sandboxbackend/registry.go" {
			idFound = strings.Contains(src, `BackendOpenShell = "openshell"`)
		}
		// Rule 1.
		if openShellLiteralViolation(rel, b) {
			t.Errorf("%s: names openshell (in any case) outside the row, planner, driver, component and config files; read the row's capability fields instead", rel)
		}
		// Rule 2.
		f, err := parser.ParseFile(token.NewFileSet(), rel, b, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("%s: %v", rel, err)
		}
		for _, imp := range f.Imports {
			path, _ := strconv.Unquote(imp.Path.Value)
			if strings.HasSuffix(path, "/"+openShellPlanner) && !inPlanner && !driver && !allowedBy(rel, openShellPlannerImporters) {
				t.Errorf("%s: imports %s; only the driver files (%s) may", rel, openShellPlanner, openShellDriverFiles)
			}
		}
		// Rule 3.
		if !test && openShellIDRE.MatchString(src) && !inPlanner && !driver && rel != "internal/sandboxbackend/registry.go" && !allowedBy(rel, openShellIDFiles) {
			t.Errorf("%s: names sandboxbackend.BackendOpenShell; branch on the row's capability fields, never on its id", rel)
		}
	}
	// The anchors exist, so the rules are not vacuous.
	if !plannerFound || !idFound || !driverFound {
		t.Fatalf("anchors missing: planner %v, id constant %v, driver files %v", plannerFound, idFound, driverFound)
	}
}

// TestOpenShellBoundaryCatchesAViolation proves the rules fire: a
// production file outside the allow-list that names the literal, and one
// that imports the planner, are each refused by the predicates the walk
// uses. Rule 1's fixtures go through openShellLiteralViolation, the same
// predicate the walk calls, with source text, not only the allow-list.
func TestOpenShellBoundaryCatchesAViolation(t *testing.T) {
	const outside = "internal/sandboxselect/select.go"
	for _, tc := range []struct {
		name, rel, src string
		want           bool
	}{
		{"mixed-case label literal", outside, "package x\n\nfunc f(l string) bool { return l == \"OpenShell\" }\n", true},
		{"lowercase id literal", outside, "package x\n\nconst id = \"openshell\"\n", true},
		{"identifier", outside, "package x\n\nvar isOpenShellRow = true\n", true},
		{"omit tag in a build constraint", outside, "//go:build sbo_omit_terminals_sandbox_openshell\n\npackage x\n", true},
		{"import path", outside, "package x\n\nimport _ \"example.com/internal/sandboxopenshell\"\n", true},
		{"a comment citing the plan", outside, "package x\n\n// See the OpenShell build plan 05 section 3.1.\nvar y = 1\n", false},
		{"no mention", outside, "package x\n\nvar y = \"bwrap\"\n", false},
		{"an allowed file", "internal/sandboxopenshell/policy.go", "package x\n\nconst id = \"OpenShell\"\n", false},
		{"a test file", "internal/sandboxselect/select_test.go", "package x\n\nconst id = \"OpenShell\"\n", false},
	} {
		if got := openShellLiteralViolation(tc.rel, []byte(tc.src)); got != tc.want {
			t.Errorf("rule 1, %s: violation %v, want %v", tc.name, got, tc.want)
		}
	}
	for rel, want := range map[string]bool{
		"internal/sandboxselect/select.go":           false,
		"cmd/observer/terminal_sandbox.go":           false,
		"internal/sandboxopenshell/policy.go":        true,
		"cmd/observer/terminal_sandbox_openshell.go": true,
		"internal/config/sandbox_openshell.go":       true,
		"internal/sandboxbackend/registry.go":        true,
	} {
		if got := allowedBy(rel, openShellLiteralFiles); got != want {
			t.Errorf("rule 1 allows %s: %v, want %v", rel, got, want)
		}
	}
	if allowedBy("cmd/observer/terminal_sandbox_oci.go", []string{openShellDriverFiles}) {
		t.Error("rule 2 treats another driver as the OpenShell driver")
	}
	if !openShellIDRE.MatchString("row, _ := sandboxbackend.Get(sandboxbackend.BackendOpenShell)") || openShellIDRE.MatchString("BackendOpenShellX") {
		t.Error("rule 3's identifier match is wrong")
	}
}
