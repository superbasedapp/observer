package securityscanning

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/postureop"
	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

func TestNoForbiddenImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		ForbiddenTrees: []string{
			"database/sql",
			"net/http",
			"os/exec",
			"github.com/fsnotify/fsnotify",
			"github.com/marmutapp/superbased-observer/internal/config",
			"github.com/marmutapp/superbased-observer/internal/store",
			"github.com/marmutapp/superbased-observer/internal/orgserver",
			"github.com/marmutapp/superbased-observer/internal/componentstate",
		},
		Reason: "internal/policyfam/securityscanning must stay pure; the cmd layer supplies NodeFacts",
	})
}

// TestEnumsReviewed: every enum value the decoder accepts has a place on its
// axis (a value added without a direction review fails here).
func TestEnumsReviewed(t *testing.T) {
	if bad := postureop.ReviewEnums(EnumKeys, Axes); len(bad) > 0 {
		t.Fatalf("enum values without a direction: %v", bad)
	}
}

// TestKeyTableCoversEveryAxis: every axis has exactly one key-table row and
// every key-table row names a real axis.
func TestKeyTableCoversEveryAxis(t *testing.T) {
	seen := map[string]int{}
	for _, r := range keyRules {
		if _, ok := LookupAxis(r.Axis); !ok {
			t.Errorf("key rule %q names no axis", r.Axis)
		}
		seen[r.Axis]++
	}
	for _, a := range Axes {
		if seen[a.Name] != 1 {
			t.Errorf("axis %q has %d key rules, want 1", a.Name, seen[a.Name])
		}
	}
}

func TestDecodeBody(t *testing.T) {
	cases := []struct {
		name, body, wantErr string
	}{
		{"empty object", `{}`, ""},
		{"full sketch", `{"version":1,"require":{"components":["security.trust","security.secrets"],"prelaunch_trust":"ask","commit_gate":"quick_scan","quick_scan_budget_s":10,"max_scan_staleness_min":30,"max_advisory_db_age_h":72,"min_blocking_severity":"high","install_unknown":"ask","online_checks":"required","install_online_unknown":"ask","history_scan_on_enrol":true,"finding_retention_days":0},"allow":{"drivers":["scalibr","opengrep","actionlint"],"custom_manifests":["sha256:` + strings.Repeat("a", 64) + `"],"scanner_sources":["org_mirror"],"online_checks":"allowed"},"rule_pack":{"min_version":"2026.11.1"},"sections":{"deps":{"capability":"security.deps.v1"}}}`, ""},
		{"unknown top field", `{"bogus":1}`, "unknown field"},
		{"unknown nested field", `{"require":{"bogus":1}}`, "unknown field"},
		{"trailing data", `{} {}`, "trailing data"},
		{"wrong version", `{"version":2}`, "not supported"},
		{"bad enum", `{"require":{"prelaunch_trust":"maybe"}}`, "prelaunch_trust"},
		{"bad budget", `{"require":{"quick_scan_budget_s":7}}`, "quick_scan_budget_s"},
		{"zero staleness", `{"require":{"max_scan_staleness_min":0}}`, "max_scan_staleness_min"},
		{"bad retention", `{"require":{"finding_retention_days":30}}`, "finding_retention_days"},
		{"empty drivers", `{"allow":{"drivers":[]}}`, "allows nothing"},
		{"empty components", `{"require":{"components":[]}}`, "allows nothing"},
		{"unknown driver", `{"allow":{"drivers":["nmap"]}}`, "unknown value"},
		{"githooks not requirable", `{"require":{"components":["security.githooks"]}}`, "unknown value"},
		{"bad manifest", `{"allow":{"custom_manifests":["md5:00"]}}`, "unknown value"},
		{"bad source", `{"allow":{"scanner_sources":["internet"]}}`, "unknown value"},
		{"bad version", `{"rule_pack":{"min_version":"v1"}}`, "dotted numbers"},
		{"unknown section", `{"sections":{"nmap":{"capability":"security.nmap.v1"}}}`, "unknown child"},
		{"wrong capability", `{"sections":{"deps":{"capability":"security.deps.v2"}}}`, "capability"},
		{"empty sections", `{"sections":{}}`, "allows nothing"},
		{"contradiction", `{"require":{"online_checks":"required"},"allow":{"online_checks":"forbidden"}}`, "contradict"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := DecodeBody([]byte(c.body), 0)
			if c.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("err = %v, want containing %q", err, c.wantErr)
			}
		})
	}
}

func TestDecodeBodySizeCap(t *testing.T) {
	big := []byte(`{"require":{"prelaunch_trust":"ask"}}` + strings.Repeat(" ", 100))
	if _, err := DecodeBody(big, 50); err == nil || !strings.Contains(err.Error(), "max 50") {
		t.Fatalf("err = %v, want the size cap", err)
	}
}

// TestCanonicalBody: spellings of one body (key order, escapes, list order,
// duplicates) compile to the same bytes.
func TestCanonicalBody(t *testing.T) {
	a := `{"allow":{"drivers":["osv","scalibr","osv"]},"require":{"prelaunch_trust":"ask"}}`
	b := `{"require":{"prelaunch_trust":"ask"},"version":1,"allow":{"drivers":["scalibr","osv"]}}`
	_, ca, err := CompileBody([]byte(a), 0)
	if err != nil {
		t.Fatal(err)
	}
	_, cb, err := CompileBody([]byte(b), 0)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ca, cb) {
		t.Fatalf("canonical bodies differ:\n%s\n%s", ca, cb)
	}
	if _, cc, _ := CompileBody(ca, 0); !bytes.Equal(ca, cc) {
		t.Fatalf("canonical body is not a fixed point: %s -> %s", ca, cc)
	}
}

func TestRequiredCapabilities(t *testing.T) {
	s, _, err := CompileBody([]byte(`{"require":{"components":["security.deps","security.trust"]},"sections":{"deps":{"capability":"security.deps.v1"},"code":{"capability":"security.code.v1"}}}`), 0)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(RequiredCapabilities(s), ",")
	if want := "security.code.v1,security.deps.v1,security.trust.v1"; got != want {
		t.Fatalf("caps = %s, want %s", got, want)
	}
}

func TestSuperAdminReason(t *testing.T) {
	cases := []struct {
		name, body string
		need       bool
	}{
		{"plain floor", `{"require":{"prelaunch_trust":"refuse","finding_retention_days":730}}`, false},
		{"online required", `{"require":{"online_checks":"required"}}`, true},
		{"online leave", `{"require":{"online_checks":"leave"}}`, false},
		{"deny on unknown", `{"require":{"install_online_unknown":"deny"}}`, true},
		{"custom manifest", `{"allow":{"custom_manifests":["sha256:` + strings.Repeat("b", 64) + `"]}}`, true},
		{"process driver", `{"allow":{"drivers":["osv"]}}`, true},
		{"process child required", `{"require":{"components":["security.scan.osv"]}}`, true},
		{"egress child required", `{"require":{"components":["security.deps"]}}`, true},
		{"plain child required", `{"require":{"components":["security.trust"]}}`, false},
		{"egress section", `{"sections":{"deps":{"capability":"security.deps.v1"}}}`, true},
		{"plain section", `{"sections":{"trust":{"capability":"security.trust.v1"}}}`, false},
		{"forbid online", `{"allow":{"online_checks":"forbidden"}}`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, _, err := CompileBody([]byte(c.body), 0)
			if err != nil {
				t.Fatal(err)
			}
			reasons, need := SuperAdminReason(s)
			if need != c.need {
				t.Fatalf("need = %v (%v), want %v", need, reasons, c.need)
			}
		})
	}
}

func TestEnforcesEveryBody(t *testing.T) {
	if !Enforces(PolicySpec{}) {
		t.Fatal("a floor body must need the node's enforce consent")
	}
}

func TestEmptyListSentinel(t *testing.T) {
	_, err := DecodeBody([]byte(`{"allow":{"scanner_sources":[]}}`), 0)
	if !errors.Is(err, ErrEmptyList) {
		t.Fatalf("err = %v, want ErrEmptyList", err)
	}
}

// TestEveryAxisHasAFloorReader: the floor table covers every axis.
func TestEveryAxisHasAFloorReader(t *testing.T) {
	for _, a := range Axes {
		if _, ok := floorReaders[a.Name]; !ok {
			t.Errorf("axis %s has no floor reader", a.Name)
		}
	}
	if len(floorReaders) != len(Axes) {
		t.Errorf("%d floor readers for %d axes", len(floorReaders), len(Axes))
	}
}

// TestManagedPullVocabularyMatchesTheFamily pins the managed pull body's
// spelled-out vocabularies (internal/orgcontract/securitypolicy.go) to this
// family's tables.
func TestManagedPullVocabularyMatchesTheFamily(t *testing.T) {
	var comps, drivers []string
	for _, c := range Children {
		comps = append(comps, c.Component)
	}
	for _, d := range Drivers {
		drivers = append(drivers, d.ID)
	}
	if strings.Join(comps, ",") != strings.Join(orgcontract.SecurityManagedComponents, ",") {
		t.Errorf("components: family %v, managed pull %v", comps, orgcontract.SecurityManagedComponents)
	}
	if strings.Join(drivers, ",") != strings.Join(orgcontract.SecurityManagedDrivers, ",") {
		t.Errorf("drivers: family %v, managed pull %v", drivers, orgcontract.SecurityManagedDrivers)
	}
}
