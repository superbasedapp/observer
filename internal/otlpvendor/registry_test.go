package otlpvendor

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// TestTableMatchesRegistry pins the two owners against each other: the
// mapping table here and the registry's OTLP column (internal/integration).
// Every mapping row is a registry tool declaring Mapped, and every Mapped
// registry tool has exactly one mapping row. A team-grain row must be a
// vendor-cloud export, and a user-grain one a local export.
func TestTableMatchesRegistry(t *testing.T) {
	seen := map[string]bool{}
	for _, v := range Vendors() {
		if seen[v.Tool] {
			t.Errorf("two mapping rows for %s", v.Tool)
		}
		seen[v.Tool] = true
		c, ok := integration.For(v.Tool)
		if !ok {
			t.Errorf("mapping row %s is not a registry tool", v.Tool)
			continue
		}
		if !c.OTLP.Mapped {
			t.Errorf("%s: mapped here but the registry OTLP column says not mapped", v.Tool)
		}
		wantOrigin := integration.OTLPLocal
		if v.Grain == GrainTeam {
			wantOrigin = integration.OTLPVendorCloud
		}
		if c.OTLP.Origin != wantOrigin {
			t.Errorf("%s: grain %s but registry origin %q", v.Tool, v.Grain, c.OTLP.Origin)
		}
		if v.SourceTag == "" || v.Evidence == "" || len(v.Rules) == 0 {
			t.Errorf("%s: incomplete row (source tag, evidence, rules)", v.Tool)
		}
	}
	for _, tool := range integration.OTLPExportTools() {
		c, _ := integration.For(tool)
		if c.OTLP.Mapped && !seen[tool] {
			t.Errorf("registry says %s is mapped but no mapping row exists", tool)
		}
	}
}

// TestActionTypesAreKnown keeps every raw-tool-name mapping inside the
// closed action vocabulary.
func TestActionTypesAreKnown(t *testing.T) {
	known := map[string]bool{
		models.ActionReadFile: true, models.ActionWriteFile: true, models.ActionEditFile: true,
		models.ActionRunCommand: true, models.ActionSearchText: true, models.ActionSearchFiles: true,
		models.ActionWebSearch: true, models.ActionWebFetch: true, models.ActionMCPCall: true,
	}
	for _, v := range Vendors() {
		for raw, a := range v.ActionTypes {
			if !known[a] {
				t.Errorf("%s: %q maps to unknown action type %q", v.Tool, raw, a)
			}
		}
	}
}

// TestServiceNamesAreUnique: one service.name claims one vendor.
func TestServiceNamesAreUnique(t *testing.T) {
	owner := map[string]string{}
	for _, v := range Vendors() {
		for _, n := range v.ServiceNames {
			if prev, dup := owner[n]; dup {
				t.Errorf("service.name %q claimed by %s and %s", n, prev, v.Tool)
			}
			owner[n] = v.Tool
		}
	}
	// A prefix claim must not also cover another row's exact name or
	// another row's prefix (the claim would then depend on table order).
	for _, v := range Vendors() {
		for _, p := range v.ServiceNamePrefixes {
			if p == "" {
				t.Errorf("%s: empty service.name prefix claims every resource", v.Tool)
			}
			for n, tool := range owner {
				if tool != v.Tool && strings.HasPrefix(n, p) {
					t.Errorf("%s prefix %q also covers %s's service.name %q", v.Tool, p, tool, n)
				}
			}
			for _, w := range Vendors() {
				for _, q := range w.ServiceNamePrefixes {
					if w.Tool != v.Tool && (strings.HasPrefix(q, p) || strings.HasPrefix(p, q)) {
						t.Errorf("prefixes %q (%s) and %q (%s) overlap", p, v.Tool, q, w.Tool)
					}
				}
			}
		}
	}
}

// TestPrefixClaim: a versioned service.name is claimed by its row's prefix,
// an exact name still claims exactly, and an unrelated name stays unclaimed.
func TestPrefixClaim(t *testing.T) {
	for _, tc := range []struct {
		svc, want string
	}{
		{"CodeBuddy-CLI-2.171.0", "codebuddy"},
		{"CodeBuddy-CLI-9.0.0-beta", "codebuddy"},
		{"bob-shell", "ibm-bob"},
		{"kimchi", "kimchi"},
		{"CodeBuddy", ""},
		{"langsmith", ""},
		{"dirac", ""},
	} {
		v, ok := claim(tc.svc)
		got := ""
		if ok {
			got = v.Tool
		}
		if got != tc.want {
			t.Errorf("claim(%q) = %q, want %q", tc.svc, got, tc.want)
		}
	}
}
