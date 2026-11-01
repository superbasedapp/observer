package orgcontract

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestEveryCaptureRiskLabelIsClassified pins the standing/act table: every
// CaptureRisk* constant in this package has a row, so a new label is a
// deliberate choice rather than a silent default.
func TestEveryCaptureRiskLabelIsClassified(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var names []string
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		for _, decl := range file.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, spec := range gd.Specs {
				for _, n := range spec.(*ast.ValueSpec).Names {
					if strings.HasPrefix(n.Name, "CaptureRisk") {
						names = append(names, n.Name)
					}
				}
			}
		}
	}
	if len(names) == 0 {
		t.Fatal("found no CaptureRisk* constants; the scan is broken")
	}
	values := map[string]string{
		"CaptureRiskHookRegistrationError":    CaptureRiskHookRegistrationError,
		"CaptureRiskHookBinaryMismatch":       CaptureRiskHookBinaryMismatch,
		"CaptureRiskHookConfigMissing":        CaptureRiskHookConfigMissing,
		"CaptureRiskCodexHookUntrusted":       CaptureRiskCodexHookUntrusted,
		"CaptureRiskHookConfigChanged":        CaptureRiskHookConfigChanged,
		"CaptureRiskAgentConfigDrift":         CaptureRiskAgentConfigDrift,
		"CaptureRiskHookRegistrationDrift":    CaptureRiskHookRegistrationDrift,
		"CaptureRiskHookRegistryMissing":      CaptureRiskHookRegistryMissing,
		"CaptureRiskHookRegistryEntryMissing": CaptureRiskHookRegistryEntryMissing,
		"CaptureRiskHookRepaired":             CaptureRiskHookRepaired,
		"CaptureRiskHookRegistrationFailed":   CaptureRiskHookRegistrationFailed,
		"CaptureRiskRouteRepaired":            CaptureRiskRouteRepaired,
		"CaptureRiskRouteBypassObserved":      CaptureRiskRouteBypassObserved,
		"CaptureRiskHookSilentSurface":        CaptureRiskHookSilentSurface,
		"CaptureRiskHookSwitchedOff":          CaptureRiskHookSwitchedOff,
		"CaptureRiskConfigLayerOverride":      CaptureRiskConfigLayerOverride,
		"CaptureRiskRouteInactiveProvider":    CaptureRiskRouteInactiveProvider,
		"CaptureRiskShellWrapMissing":         CaptureRiskShellWrapMissing,
		"CaptureRiskVendorPolicyBlocksMCP":    CaptureRiskVendorPolicyBlocksMCP,
		"CaptureRiskVendorPolicyPinsRoute":    CaptureRiskVendorPolicyPinsRoute,
	}
	for _, n := range names {
		v, ok := values[n]
		if !ok {
			t.Errorf("%s is a new capture-risk label: add it to captureRiskClasses (standing or act) and to this test", n)
			continue
		}
		if _, ok := captureRiskClasses[v]; !ok {
			t.Errorf("%s (%q) has no row in captureRiskClasses", n, v)
		}
		if !validCaptureRisk(v) {
			t.Errorf("%s (%q) is classified but not accepted by validCaptureRisk", n, v)
		}
	}
	if len(captureRiskClasses) != len(values) {
		t.Errorf("captureRiskClasses has %d rows, want %d", len(captureRiskClasses), len(values))
	}
	if isStandingCaptureRisk("some_future_label") {
		t.Error("an unknown label must default to an act (the loud side)")
	}
}

// TestKnownRisksSuppressStandingReappearance replays the gap 6 re-test: a
// deleted hash registry hides the long-standing binary mismatches for one
// report, and restoring it must not raise them as a new event, while the
// registry deletion itself is one.
func TestKnownRisksSuppressStandingReappearance(t *testing.T) {
	t0 := time.Date(2026, 10, 16, 9, 0, 0, 0, time.UTC)
	mismatch := func(tool string) CaptureRiskItem {
		return CaptureRiskItem{Risk: CaptureRiskHookBinaryMismatch, Tool: tool, File: "~/." + tool + "/hooks.json"}
	}
	mismatches := []CaptureRiskItem{mismatch("antigravity-cli"), mismatch("cline-cli"), mismatch("copilot-cli")}
	registryMissing := CaptureRiskItem{Risk: CaptureRiskHookRegistryMissing, File: "~/.observer/hook_checksums.json"}
	repaired := CaptureRiskItem{Risk: CaptureRiskHookRepaired, Tool: "claude-code", File: "~/.claude/settings.json"}

	type report struct {
		at       time.Duration
		labels   []string
		items    []CaptureRiskItem
		wantNew  []string // keys newly raised by this report
		firstOne bool     // the node's first report (no prior)
	}
	labelsOf := func(items ...CaptureRiskItem) []string {
		seen := map[string]bool{}
		var out []string
		for _, it := range items {
			if !seen[it.Risk] {
				seen[it.Risk] = true
				out = append(out, it.Risk)
			}
		}
		return out
	}
	withB := append(append([]CaptureRiskItem(nil), mismatches...), registryMissing)

	scenarios := []struct {
		name    string
		reports []report
	}{
		{"the re-test sequence", []report{
			{at: 0, labels: labelsOf(mismatches...), items: mismatches, firstOne: true},
			{
				at: time.Hour, labels: labelsOf(registryMissing), items: []CaptureRiskItem{registryMissing},
				wantNew: []string{registryMissing.Key()},
			},
			{at: 2 * time.Hour, labels: labelsOf(mismatches...), items: mismatches},
		}},
		{"standing items present in the prior report stay quiet", []report{
			{at: 0, labels: labelsOf(mismatches...), items: mismatches, firstOne: true},
			{at: time.Hour, labels: labelsOf(withB...), items: withB, wantNew: []string{registryMissing.Key()}},
		}},
		{"an act that reappears after being gone is a new event", []report{
			{at: 0, labels: labelsOf(repaired), items: []CaptureRiskItem{repaired}, firstOne: true},
			{at: time.Hour},
			{at: 2 * time.Hour, labels: labelsOf(repaired), items: []CaptureRiskItem{repaired}, wantNew: []string{repaired.Key()}},
		}},
		{"a standing item last seen 8 days ago is a new event", []report{
			{at: 0, labels: labelsOf(mismatch("cline-cli")), items: []CaptureRiskItem{mismatch("cline-cli")}, firstOne: true},
			{at: time.Hour},
			{
				at: 8*24*time.Hour + time.Hour, labels: labelsOf(mismatch("cline-cli")), items: []CaptureRiskItem{mismatch("cline-cli")},
				wantNew: []string{mismatch("cline-cli").Key()},
			},
		}},
		{"a label-only memory covers a located reappearance", []report{
			{at: 0, labels: []string{CaptureRiskHookBinaryMismatch}, firstOne: true},
			{at: time.Hour},
			{at: 2 * time.Hour, labels: labelsOf(mismatches...), items: mismatches},
		}},
		{"a brand-new standing item is still a new event", []report{
			{at: 0, labels: labelsOf(mismatch("cline-cli")), items: []CaptureRiskItem{mismatch("cline-cli")}, firstOne: true},
			{
				at: time.Hour, labels: labelsOf(mismatches...), items: mismatches,
				wantNew: []string{mismatch("antigravity-cli").Key(), mismatch("copilot-cli").Key()},
			},
		}},
	}

	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			var prior ManagedIntegrityDetail
			for i, r := range sc.reports {
				now := t0.Add(r.at)
				changes := DeriveCaptureRiskChanges(prior, !r.firstOne, r.labels, r.items, now)
				stamp := now.Format(time.RFC3339)
				var got []string
				for _, c := range changes {
					if c.FirstSeen == stamp {
						got = append(got, c.Key())
					}
				}
				if fmt.Sprint(sortedCopy(got)) != fmt.Sprint(sortedCopy(r.wantNew)) {
					t.Fatalf("report %d: new %v, want %v", i, got, r.wantNew)
				}
				prior = ManagedIntegrityDetail{
					CaptureCheckVersion: ManagedCaptureCheckVersion,
					CaptureRisks:        r.labels,
					CaptureRiskItems:    r.items,
					RecentChanges:       changes,
					KnownRisks:          MergeKnownCaptureRisks(prior.KnownRisks, r.labels, r.items, now),
				}
			}
		})
	}
}

// TestMergeKnownCaptureRisksWindowAndBound pins the memory itself: entries
// past the window drop, the current report refreshes LastSeen, bare labels
// become label-only entries, events are not kept, and the list is bounded to
// the newest.
func TestMergeKnownCaptureRisksWindowAndBound(t *testing.T) {
	now := time.Date(2026, 10, 16, 9, 0, 0, 0, time.UTC)
	stamp := func(d time.Duration) string { return now.Add(-d).Format(time.RFC3339) }
	prior := []KnownCaptureRisk{
		{CaptureRiskItem: CaptureRiskItem{Risk: CaptureRiskHookBinaryMismatch, Tool: "old"}, LastSeen: stamp(8 * 24 * time.Hour)},
		{CaptureRiskItem: CaptureRiskItem{Risk: CaptureRiskHookBinaryMismatch, Tool: "recent"}, LastSeen: stamp(24 * time.Hour)},
		{CaptureRiskItem: CaptureRiskItem{Risk: CaptureRiskHookConfigChanged, Tool: "refresh"}, LastSeen: stamp(48 * time.Hour)},
		{CaptureRiskItem: CaptureRiskItem{Risk: CaptureRiskHookConfigChanged, Tool: "garbled"}, LastSeen: "not a time"},
	}
	items := []CaptureRiskItem{{Risk: CaptureRiskHookConfigChanged, Tool: "refresh", Events: []string{"PreToolUse"}}}
	got := MergeKnownCaptureRisks(prior, []string{CaptureRiskHookConfigChanged, CaptureRiskAgentConfigDrift}, items, now)
	byTool := map[string]KnownCaptureRisk{}
	for _, k := range got {
		byTool[k.Risk+"/"+k.Tool] = k
		if len(k.Events) != 0 {
			t.Errorf("events kept in memory: %+v", k)
		}
	}
	tests := []struct {
		key      string
		present  bool
		lastSeen string
	}{
		{CaptureRiskHookBinaryMismatch + "/old", false, ""},
		{CaptureRiskHookConfigChanged + "/garbled", false, ""},
		{CaptureRiskHookBinaryMismatch + "/recent", true, stamp(24 * time.Hour)},
		{CaptureRiskHookConfigChanged + "/refresh", true, now.Format(time.RFC3339)},
		{CaptureRiskAgentConfigDrift + "/", true, now.Format(time.RFC3339)},
		// A label that is located in this report gets no extra label-only row.
		{CaptureRiskHookConfigChanged + "/", false, ""},
	}
	for _, tc := range tests {
		k, ok := byTool[tc.key]
		if ok != tc.present || (ok && k.LastSeen != tc.lastSeen) {
			t.Errorf("%s: present=%v lastSeen=%q, want present=%v lastSeen=%q", tc.key, ok, k.LastSeen, tc.present, tc.lastSeen)
		}
	}

	var many []KnownCaptureRisk
	for i := 0; i < 50; i++ {
		many = append(many, KnownCaptureRisk{
			CaptureRiskItem: CaptureRiskItem{Risk: CaptureRiskHookBinaryMismatch, Tool: fmt.Sprintf("t%02d", i)},
			LastSeen:        stamp(time.Duration(i) * time.Minute),
		})
	}
	bounded := MergeKnownCaptureRisks(many, nil, nil, now)
	if len(bounded) != maxKnownCaptureRisks {
		t.Fatalf("len = %d, want %d", len(bounded), maxKnownCaptureRisks)
	}
	if bounded[0].Tool != "t00" || bounded[len(bounded)-1].Tool != fmt.Sprintf("t%02d", maxKnownCaptureRisks-1) {
		t.Fatalf("bound kept the wrong entries: first %s last %s", bounded[0].Tool, bounded[len(bounded)-1].Tool)
	}
	if MergeKnownCaptureRisks(nil, nil, nil, now) != nil {
		t.Error("an empty memory must be nil so omitempty drops it")
	}
}

func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}
