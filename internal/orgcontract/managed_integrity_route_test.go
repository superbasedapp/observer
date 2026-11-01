package orgcontract

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// TestUnroutedSurfaceLabelVocabulary: only a closed tool and a closed
// surface kind make a label; a host, a path, a count or free text never
// does.
func TestUnroutedSurfaceLabelVocabulary(t *testing.T) {
	t.Parallel()
	cases := []struct {
		label string
		want  bool
	}{
		{"claude-code/cli", true},
		{"claude-code/desktop", true},
		{"codex/ide", true},
		{"codex/sdk", true},
		{"codex/web", true},
		{"claude-code/", false},
		{"claude-code", false},
		{"/cli", false},
		{"unknown-tool/cli", false},
		{"claude-code/terminal", false},
		{"claude-code/cli (vscode)", false},
		{"claude-code/cli/extra", false},
		{"claude-code/C:\\Users\\dev", false},
		{"codex/ide 3/5", false},
	}
	for _, tc := range cases {
		if got := validUnroutedSurfaceLabel(tc.label); got != tc.want {
			t.Errorf("validUnroutedSurfaceLabel(%q) = %v, want %v", tc.label, got, tc.want)
		}
	}
	if label, ok := UnroutedSurfaceLabel("codex", models.SurfaceDesktop); !ok || label != "codex/desktop" {
		t.Fatalf("UnroutedSurfaceLabel(codex, desktop) = %q, %v", label, ok)
	}
}

// TestUnroutedSurfaceKindsMatchModels: the kind half is exactly the closed
// models surface vocabulary.
func TestUnroutedSurfaceKindsMatchModels(t *testing.T) {
	t.Parallel()
	for _, kind := range UnroutedSurfaceKinds() {
		if !models.KnownSurface(kind) {
			t.Errorf("kind %q is not a models.Surface* kind", kind)
		}
	}
	for _, kind := range []string{models.SurfaceCLI, models.SurfaceIDE, models.SurfaceDesktop, models.SurfaceSDK, models.SurfaceWeb} {
		if !unroutedSurfaceKinds[kind] {
			t.Errorf("models kind %q has no unroutedSurfaceKinds row", kind)
		}
	}
	if models.KnownSurface("") || unroutedSurfaceKinds[""] {
		t.Error("an unstamped session must have no label")
	}
}

// TestNormalizeRouteObservation: the version gates the list, the list keeps
// closed labels only, and route_bypass_observed follows the list.
func TestNormalizeRouteObservation(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name         string
		in           ManagedIntegrityReport
		wantVersion  int
		wantSurfaces []string
		wantRisks    []string
	}{
		{
			name:        "older node sends no version",
			in:          ManagedIntegrityReport{CaptureCheckVersion: ManagedCaptureCheckVersion},
			wantVersion: 0,
		},
		{
			name: "no version drops surfaces and the label",
			in: ManagedIntegrityReport{
				CaptureCheckVersion: ManagedCaptureCheckVersion,
				UnroutedSurfaces:    []string{"claude-code/cli"},
				CaptureRisks:        []string{CaptureRiskRouteBypassObserved},
			},
			wantVersion: 0,
		},
		{
			name:        "future version is not reported",
			in:          ManagedIntegrityReport{RouteObservationVersion: ManagedRouteObservationVersion + 1, UnroutedSurfaces: []string{"codex/cli"}},
			wantVersion: 0,
		},
		{
			name:        "reported clean",
			in:          ManagedIntegrityReport{CaptureCheckVersion: ManagedCaptureCheckVersion, RouteObservationVersion: ManagedRouteObservationVersion},
			wantVersion: ManagedRouteObservationVersion,
		},
		{
			name: "closed labels kept, sorted, deduplicated, label derived",
			in: ManagedIntegrityReport{
				CaptureCheckVersion:     ManagedCaptureCheckVersion,
				RouteObservationVersion: ManagedRouteObservationVersion,
				UnroutedSurfaces:        []string{"codex/cli", "claude-code/desktop", "codex/cli", "/home/dev/x", "claude-code/cli (vscode)"},
				CaptureRisks:            []string{CaptureRiskHookRepaired},
			},
			wantVersion:  ManagedRouteObservationVersion,
			wantSurfaces: []string{"claude-code/desktop", "codex/cli"},
			wantRisks:    []string{CaptureRiskHookRepaired, CaptureRiskRouteBypassObserved},
		},
		{
			name: "label without a surface is dropped",
			in: ManagedIntegrityReport{
				CaptureCheckVersion:     ManagedCaptureCheckVersion,
				RouteObservationVersion: ManagedRouteObservationVersion,
				UnroutedSurfaces:        []string{"not-a-tool/cli"},
				CaptureRisks:            []string{CaptureRiskRouteBypassObserved},
			},
			wantVersion: ManagedRouteObservationVersion,
		},
		{
			name: "no capture checks keeps surfaces, carries no label",
			in: ManagedIntegrityReport{
				RouteObservationVersion: ManagedRouteObservationVersion,
				UnroutedSurfaces:        []string{"claude-code/cli"},
			},
			wantVersion:  ManagedRouteObservationVersion,
			wantSurfaces: []string{"claude-code/cli"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.in.NormalizeLabels()
			if got.RouteObservationVersion != tc.wantVersion {
				t.Fatalf("version = %d, want %d", got.RouteObservationVersion, tc.wantVersion)
			}
			if !reflect.DeepEqual(got.UnroutedSurfaces, tc.wantSurfaces) {
				t.Fatalf("surfaces = %#v, want %#v", got.UnroutedSurfaces, tc.wantSurfaces)
			}
			if !reflect.DeepEqual(got.CaptureRisks, tc.wantRisks) {
				t.Fatalf("capture risks = %#v, want %#v", got.CaptureRisks, tc.wantRisks)
			}
		})
	}
}

// TestRouteObservationVersionOnTheWire: a current node always states its
// version, and a body without the key (an older node, or a row an older
// server stored) decodes as not reported.
func TestRouteObservationVersionOnTheWire(t *testing.T) {
	t.Parallel()
	raw, err := json.Marshal(ManagedIntegrityReport{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"route_observation_version":0`) {
		t.Fatalf("report body %s lacks an explicit route_observation_version", raw)
	}
	raw, err = json.Marshal(ManagedIntegrityDetail{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"route_observation_version":0`) {
		t.Fatalf("stored detail %s lacks an explicit route_observation_version", raw)
	}
	var old ManagedIntegrityReport
	if err := json.Unmarshal([]byte(`{"machine_identity":"m","sibling_observers":0,"route_drift":0,"capture_check_version":1}`), &old); err != nil {
		t.Fatal(err)
	}
	if v := old.NormalizeLabels().OverallHealth(); v.Health != ManagedHealthNotReported || v.Reason != ManagedHealthReasonRouteNotReported {
		t.Fatalf("an older node's clean report = %+v, want not_reported / %s", v, ManagedHealthReasonRouteNotReported)
	}
}

// TestManagedIntegrityHealthRules: one row per rule of managedHealthRules,
// and every rule is reachable.
func TestManagedIntegrityHealthRules(t *testing.T) {
	t.Parallel()
	clean := ManagedIntegrityHealthFacts{State: ManagedIntegrityOK, CaptureChecksReported: true, RouteObservationReported: true, ConfigLayerReported: true}
	with := func(mut func(*ManagedIntegrityHealthFacts)) ManagedIntegrityHealthFacts {
		f := clean
		mut(&f)
		return f
	}
	cases := []struct {
		name   string
		facts  ManagedIntegrityHealthFacts
		health string
		reason string
	}{
		{"no report", ManagedIntegrityHealthFacts{}, ManagedHealthNotReported, ManagedHealthReasonNoReport},
		{"legacy route drift", with(func(f *ManagedIntegrityHealthFacts) { f.State = ManagedIntegrityRouteDrift }), ManagedHealthAtRisk, ManagedIntegrityRouteDrift},
		{"unrouted surface", with(func(f *ManagedIntegrityHealthFacts) { f.UnroutedSurfaces = 1 }), ManagedHealthAtRisk, ManagedHealthReasonRouteBypass},
		{"capture risk", with(func(f *ManagedIntegrityHealthFacts) { f.CaptureRisks = 2 }), ManagedHealthAtRisk, ManagedHealthReasonCaptureRisk},
		{"capture checks not reported", with(func(f *ManagedIntegrityHealthFacts) { f.CaptureChecksReported = false }), ManagedHealthNotReported, ManagedHealthReasonCaptureNotReported},
		{"route observation not reported", with(func(f *ManagedIntegrityHealthFacts) { f.RouteObservationReported = false }), ManagedHealthNotReported, ManagedHealthReasonRouteNotReported},
		{"config layers not reported", with(func(f *ManagedIntegrityHealthFacts) { f.ConfigLayerReported = false }), ManagedHealthNotReported, ManagedHealthReasonConfigNotReported},
		{"inconclusive capture check", with(func(f *ManagedIntegrityHealthFacts) { f.UnknownChecks = 1 }), ManagedHealthIncomplete, ManagedHealthReasonCaptureCheckUnknown},
		{"clear", clean, ManagedHealthOK, ManagedHealthReasonClear},
	}
	hit := map[int]bool{}
	for _, tc := range cases {
		got := DeriveManagedIntegrityHealth(tc.facts)
		if got.Health != tc.health || got.Reason != tc.reason {
			t.Errorf("%s: got %+v, want %s / %s", tc.name, got, tc.health, tc.reason)
		}
		for i, rule := range managedHealthRules {
			if rule.when(tc.facts) {
				hit[i] = true
				break
			}
		}
	}
	for i := range managedHealthRules {
		if !hit[i] {
			t.Errorf("managedHealthRules[%d] has no test row", i)
		}
	}
	// The legacy State() ok alone is not enough: a bypass outranks it.
	r := ManagedIntegrityReport{
		CaptureCheckVersion:     ManagedCaptureCheckVersion,
		RouteObservationVersion: ManagedRouteObservationVersion,
		UnroutedSurfaces:        []string{"claude-code/desktop"},
	}.NormalizeLabels()
	if r.State() != ManagedIntegrityOK {
		t.Fatalf("State() = %s, want the legacy ok", r.State())
	}
	if v := r.OverallHealth(); v.Health != ManagedHealthAtRisk || v.Reason != ManagedHealthReasonRouteBypass {
		t.Fatalf("OverallHealth = %+v, want at_risk / route_bypass_observed", v)
	}
}
