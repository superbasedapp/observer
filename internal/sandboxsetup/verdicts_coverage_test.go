package sandboxsetup

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// verdicts_coverage_test.go is the reverse of TestVerdictStringsArePinned
// (docs/sandbox-backend-checklist.md, section B, box B5): every verdict a
// driver package DECLARES either maps to a step of every registry row that
// driver probes (a verdictMap row) or is listed below as stepless for that
// row, with the reason it names no step. A new verdict in a driver package
// fails here until someone decides which, so a check can never again stop
// at a verdict the plan has no row for and leave a step reading "not
// checked" (the 2026-11-07 live finding F15).

// verdictPrefixes is, per driver package, the prefix of the exported
// constant names that are its probe verdicts ("Verdict" unless listed).
var verdictPrefixes = map[string]string{
	"sandboxremote": "Consent",
}

// steplessEverywhere are verdicts that never name a step on any row: they
// are not "something is missing on this machine" answers.
var steplessEverywhere = map[string]string{
	"available":            "the probe passed: every step reads done (rule probe_passes)",
	"unsupported_platform": "the row does not run on this host: the plan is Blocked as a whole (plan rule 2)",
	"disabled_by_config":   "the row is not enabled: the generic enable step owns it, judged from the config, not from the probe",
	"ok":                   "sandboxremote: the consent is recorded (a pass)",
}

// notVerdictTypes are, per driver package, the declared types of constants
// that carry the Verdict prefix but are not probe verdicts.
var notVerdictTypes = map[string]map[string]string{
	"openshellorg": {"FactVerdict": "the soundness report's per-fact verdicts (ok, unsound, attested), not probe answers"},
}

// steplessVerdict is a group of verdicts a driver declares that name no
// step on the listed rows (every row of the driver when Backends is empty).
type steplessVerdict struct {
	Driver   string
	Verdicts []string
	Backends []string
	Why      string
}

// steplessVerdicts is the explicit list. Each entry says why a person has
// no setup step for it: the plan then shows the check's own reason on the
// steps it could not judge (stateRules probe_unmapped). An entry marked
// "owed" is a candidate for a step that no lane has built yet; the
// playbook's owed list names it.
var steplessVerdicts = []steplessVerdict{
	{
		Driver: "sandboxoci", Verdicts: []string{"backend_version_untested"},
		Why: "the engine is there but below the tested minimum or its version is unreadable: an update the person chooses, not a missing install",
	},
	{
		Driver: "sandboxoci", Verdicts: []string{"built_below_plan"},
		Why: "a launch-time read-back of one container, never an answer about the host",
	},
	{
		Driver: "sandboxoci", Verdicts: []string{"artifact_unverified"},
		Why: "the configured image failed its trust check or is revoked: the person picks another [terminal.sandbox.oci].image (owed: an oci-image row naming the revoked reference)",
	},
	{Driver: "sandboxoci", Verdicts: []string{
		"install_source_unknown", "install_version_unknown", "install_runtime_missing", "install_scripts_required",
		"install_scripts_unpinned", "install_script_mismatch", "install_package_unpinned", "tool_unavailable_in_image",
	}, Why: "in-box tool delivery for one launch (a tool inside the image), not a host prerequisite"},
	{
		Driver: "sandboxoci", Backends: []string{"oci-runc"}, Verdicts: []string{"runtime_missing", "socket_bridge_unavailable"},
		Why: "gVisor runtime answers: the runc row runs no named runtime, so its probe never stops here",
	},
	{
		Driver: "sandboxoci", Backends: []string{"oci-runsc"}, Verdicts: []string{"engine_mode_unsupported"},
		Why: "a Docker user-namespace mode the uid table has no row for (userns-remap): an engine configuration Observer never changes (owed: a never step under docker-engine)",
	},
	{
		Driver: "sandboxvm", Verdicts: []string{"backend_version_untested"},
		Why: "Cloud Hypervisor is there but outside the tested range: Update of the pinned download owns it, not a missing install",
	},
	{
		Driver: "sandboxvm", Verdicts: []string{"built_below_plan", "source_unsupported", "tool_unavailable_in_image", "socket_path_too_long"},
		Why: "per-run answers (the read-back, the workspace share, the image's tools, the run's socket path), never a host prerequisite",
	},
	{
		Driver: "sandboxsbpl", Verdicts: []string{"backend_version_untested", "built_below_plan", "self_test_failed"},
		Why: "the OS's own sandbox-exec answered outside what was tested, or a run's read-back failed: a defect to report, nothing to install",
	},
	{
		Driver: "sandboxsbpl", Verdicts: []string{"fallback_driver_unavailable"},
		Why: "the config names the declared fallback driver, which is not built: a config choice, not a host prerequisite",
	},
	{
		Driver: "sandboxapple", Verdicts: []string{"backend_version_untested"},
		Why: "Apple's container CLI is there but outside the tested range: an update the person chooses (the guide names the download page)",
	},
	{
		Driver: "sandboxapple", Verdicts: []string{"built_below_plan"},
		Why: "a launch-time read-back of one container, never an answer about the host",
	},
	{
		Driver: "sandboxmxc", Verdicts: []string{"backend_version_untested", "probe_failed", "request_rejected", "deny_paths_unsupported"},
		Why: "the MXC library's version, a helper that crashed, or MXC refusing one request: nothing a person installs",
	},
	{Driver: "sandboxopenshell", Verdicts: []string{
		"openshell_version_unknown", "openshell_version_mismatch", "openshell_version_pin_mismatch", "openshell_untested",
		"gateway_binary_version_mismatch", "gateway_binary_untested", "driver_untested",
	}, Why: "OpenShell is installed but not at the tested version (owed: these could name openshell-pkg, whose guide installs v0.1.6)"},
	{Driver: "sandboxopenshell", Verdicts: []string{
		"gateway_mode_not_built", "gateway_unreachable", "gateway_unauthenticated", "gateway_not_local",
		"gateway_cert_custody_unavailable", "gateway_cert_custody_changed", "gateway_state_dir_foreign_fs",
		"gateway_runtime_dir_unsafe", "gateway_unit_state_unknown", "gateway_starting", "gateway_upgrade_pending",
		"gateway_unhealthy", "gateway_start_failed", "gateway_not_ready", "gateway_unit_foreign",
		"gateway_auto_approval", "gateway_policy_proposals", "gateway_global_policy", "gateway_settings_unknown",
	}, Why: "the state of the gateway the driver itself manages, or a vendor gateway's settings that widen policy: the driver or the person's gateway settings own them, no install step does"},
	{Driver: "sandboxopenshell", Verdicts: []string{
		"runtime_canary_not_run", "runtime_seccomp_blocks_landlock", "runtime_canary_failed", "runtime_canary_image_missing",
		"runtime_canary_not_started", "runtime_canary_timed_out", "bind_mounts_disabled", "bind_mounts_unknown",
		"runtime_image_unpinned", "runtime_image_unread", "runtime_image_missing", "runtime_image_digest_mismatch",
		"docker_engine_id_unread", "docker_engine_record_unreadable", "docker_engine_changed",
	}, Why: "Observer's own canary, the vendor's runtime images and the engine identity pin: answers about the vendor's runtime, not prerequisites the row's Setup lists (owed: a runtime image step if OpenShell gains one)"},
	{
		Driver: "openshellorg", Verdicts: []string{"org_gateway_not_offered", "custody_not_offered", "home_relay_unavailable", "laptop_relay_forbidden", "laptop_relay_not_opted_in"},
		Why: "the organization's offer, its relay policy and the person's opt-in: organization or Settings choices, not host prerequisites",
	},
	{
		Driver: "openshellorg", Verdicts: []string{"component_inactive", "not_in_backends"},
		Why: "the generic component and enable steps own these, judged from the config, not from the probe",
	},
}

// driverVerdictConstants parses the driver package's non-test Go files
// (every build tag: go/parser ignores constraints) and returns its exported
// verdict constants' string values. A constant whose value this test cannot
// resolve fails the test rather than being skipped.
func driverVerdictConstants(t *testing.T, driver string) map[string]string {
	t.Helper()
	dir := filepath.Join("..", driver)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("driver %s: %v", driver, err)
	}
	exprs := map[string]ast.Expr{}
	var order []string
	fset := token.NewFileSet()
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if err != nil {
			t.Fatalf("parse %s/%s: %v", driver, name, err)
		}
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, spec := range gd.Specs {
				vs := spec.(*ast.ValueSpec)
				if id, ok := vs.Type.(*ast.Ident); ok && notVerdictTypes[driver][id.Name] != "" {
					continue
				}
				for i, n := range vs.Names {
					if i < len(vs.Values) {
						if _, dup := exprs[n.Name]; !dup {
							order = append(order, n.Name)
						}
						exprs[n.Name] = vs.Values[i]
					}
				}
			}
		}
	}
	prefix := verdictPrefixes[driver]
	if prefix == "" {
		prefix = "Verdict"
	}
	var resolve func(e ast.Expr, depth int) (string, bool)
	resolve = func(e ast.Expr, depth int) (string, bool) {
		if depth > 8 {
			return "", false
		}
		switch v := e.(type) {
		case *ast.BasicLit:
			if v.Kind != token.STRING {
				return "", false
			}
			s, err := strconv.Unquote(v.Value)
			return s, err == nil
		case *ast.Ident:
			if x, ok := exprs[v.Name]; ok {
				return resolve(x, depth+1)
			}
		case *ast.CallExpr:
			// A conversion: string(ReasonX), Verdict("x").
			if len(v.Args) == 1 {
				return resolve(v.Args[0], depth+1)
			}
		case *ast.ParenExpr:
			return resolve(v.X, depth+1)
		}
		return "", false
	}
	out := map[string]string{}
	for _, name := range order {
		if !strings.HasPrefix(name, prefix) || !ast.IsExported(name) {
			continue
		}
		if lit, ok := exprs[name].(*ast.BasicLit); ok && lit.Kind != token.STRING {
			continue // a number (sandboxremote.ConsentVersion), never a verdict
		}
		val, ok := resolve(exprs[name], 0)
		if !ok {
			t.Errorf("driver %s: cannot resolve the value of %s; resolve it in this test", driver, name)
			continue
		}
		out[name] = val
	}
	if len(out) == 0 {
		t.Errorf("driver %s: no %s* constants found (the scan is broken)", driver, prefix)
	}
	return out
}

// TestEveryDriverVerdictIsMappedOrStepless: every declared verdict of every
// driver in the verdict map, on every row that driver probes, is a
// verdictMap row of that row or an explicit stepless entry; and no stepless
// entry is stale (names a verdict the driver no longer declares, or one the
// map now maps).
func TestEveryDriverVerdictIsMappedOrStepless(t *testing.T) {
	declared := map[string]map[string]bool{} // driver -> verdict values
	for _, d := range verdictMap {
		if declared[d.Driver] == nil {
			declared[d.Driver] = map[string]bool{}
			for _, v := range driverVerdictConstants(t, d.Driver) {
				declared[d.Driver][v] = true
			}
			for v := range cmdOnlyVerdicts[d.Driver] {
				declared[d.Driver][v] = true
			}
		}
	}
	stepless := func(driver, backend, verdict string) bool {
		if _, ok := steplessEverywhere[verdict]; ok {
			return true
		}
		for _, s := range steplessVerdicts {
			if s.Driver == driver && stringIn(s.Verdicts, verdict) && (len(s.Backends) == 0 || stringIn(s.Backends, backend)) {
				return true
			}
		}
		return false
	}
	for _, d := range verdictMap {
		mapped := map[string]bool{}
		for _, m := range d.Missing {
			mapped[m.Verdict] = true
		}
		// A prefix row maps its declared prefix constant (the probe
		// completes it with a field name; TestVerdictMapPrefixRows).
		for _, m := range d.MissingPrefix {
			mapped[m.Verdict] = true
		}
		var vals []string
		for v := range declared[d.Driver] {
			vals = append(vals, v)
		}
		sort.Strings(vals)
		for _, b := range d.Backends {
			for _, v := range vals {
				if mapped[v] || stepless(d.Driver, b, v) {
					continue
				}
				t.Errorf("%s (driver %s): verdict %q maps to no step and is not declared stepless; add a verdictMap row or a steplessVerdicts entry with its reason", b, d.Driver, v)
			}
		}
	}
	for _, s := range steplessVerdicts {
		if s.Why == "" || len(s.Verdicts) == 0 {
			t.Errorf("stepless %s %v has no reason or no verdict", s.Driver, s.Verdicts)
		}
		for _, v := range s.Verdicts {
			if !declared[s.Driver][v] {
				t.Errorf("stepless %s/%s: the driver no longer declares it", s.Driver, v)
			}
			for _, d := range verdictMap {
				if d.Driver != s.Driver {
					continue
				}
				for _, b := range d.Backends {
					if len(s.Backends) > 0 && !stringIn(s.Backends, b) {
						continue
					}
					for _, m := range d.Missing {
						if m.Verdict == v && m.ReasonHas == "" {
							t.Errorf("stepless %s/%s on %s: the map has a plain row for it", s.Driver, v, b)
						}
					}
				}
			}
		}
	}
}
