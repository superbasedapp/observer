package postureop

import (
	"errors"
	"reflect"
	"testing"
)

// sandboxAxes is the sandbox module's axis table (b9 v2 section 8.5), as data.
var sandboxAxes = []Axis{
	{Name: "auto_class", Kind: AxisEnum, Order: []string{"none", "process", "container", "userspace_kernel", "hw_vm"}},
	{Name: "engine_privilege", Kind: AxisEnum, Order: []string{"rootful", "rootless"}},
	{Name: "egress_tier", Kind: AxisEnum, Order: []string{"host", "internet", "proxy_only", "none"}},
	{Name: "capture", Kind: AxisEnum, Order: []string{"none", "transcripts_only", "proxy_and_transcripts", "full"}},
	{Name: "key_custody", Kind: AxisEnum, Order: []string{"provider_injected", "home_relay"}},
	{Name: "location", Kind: AxisEnum, Order: []string{"remote", "local"}},
	{Name: "verification", Kind: AxisEnum, Order: []string{"beta", "live"}},
	{Name: "workspace_retention_days", Kind: AxisRetention},
	{Name: "enabled_backends", Kind: AxisSubsetStronger},
	{Name: "landlock_min_abi", Kind: AxisHigherStronger},
}

// securityAxes is the security module's axis table (security plan 4.9).
var securityAxes = []Axis{
	{Name: "prelaunch_trust", Kind: AxisEnum, Order: []string{"warn", "ask", "refuse"}},
	{Name: "commit_gate", Kind: AxisEnum, Order: []string{"ask", "quick_scan"}},
	{Name: "quick_scan_budget_s", Kind: AxisHigherStronger},
	{Name: "max_scan_staleness_min", Kind: AxisLowerStronger},
	{Name: "max_advisory_db_age_h", Kind: AxisLowerStronger},
	{Name: "min_blocking_severity", Kind: AxisEnum, Order: []string{"critical", "high", "medium", "low"}},
	{Name: "install_unknown", Kind: AxisEnum, Order: []string{"flag", "ask", "deny"}},
	{Name: "install_online_unknown", Kind: AxisEnum, Order: []string{"flag", "ask", "deny"}},
	{Name: "required_components", Kind: AxisSupersetStronger},
	{Name: "drivers", Kind: AxisSubsetStronger},
	{Name: "custom_manifests", Kind: AxisSubsetStronger},
	{Name: "scanner_sources", Kind: AxisSubsetStronger},
	{Name: "rule_pack_min_version", Kind: AxisVersion},
	{Name: "finding_retention_days", Kind: AxisRetention},
}

var classOf = map[string]string{"gvisor": "userspace_kernel", "docker-rootless": "container", "podman-rootless": "container", "bwrap": "process", "chv": "hw_vm"}

// sandboxPosture stands in for the sandbox module's evaluator: the class of
// the auto pick from a preference list and an availability set.
func sandboxPosture(pref []string, available map[string]bool, retention int64) Posture {
	class := "none"
	for _, b := range pref {
		if available[b] {
			class = classOf[b]
			break
		}
	}
	return Posture{
		"auto_class":               {S: class},
		"engine_privilege":         {S: "rootless"},
		"egress_tier":              {S: "proxy_only"},
		"capture":                  {S: "full"},
		"key_custody":              {S: "home_relay"},
		"location":                 {S: "local"},
		"verification":             {S: "live"},
		"workspace_retention_days": {N: retention},
		"enabled_backends":         {Set: append([]string(nil), pref...)},
		"landlock_min_abi":         {N: 3},
	}
}

// Sandbox 8.5 boundary rows for DirOrderedFilter: disjoint lists, removing
// the first entry, removing every entry.
func TestOrderedFilterBoundaries(t *testing.T) {
	avail := map[string]bool{"gvisor": true, "docker-rootless": true, "bwrap": true}
	local := []string{"gvisor", "docker-rootless", "bwrap"}
	before := sandboxPosture(local, avail, 0)
	cases := []struct {
		name       string
		org        []string
		wantAxis   string
		wantRefuse bool
	}{
		{"org keeps everything", []string{"bwrap", "docker-rootless", "gvisor", "chv"}, "", false},
		{"org removes a weaker tail entry", []string{"gvisor", "docker-rootless"}, "", false},
		{"org removes the strong first preference", []string{"docker-rootless", "bwrap"}, "auto_class", true},
		{"disjoint lists", []string{"chv"}, "auto_class", true},
		{"org removes every entry", []string{}, "auto_class", true},
	}
	for _, c := range cases {
		eff := OrderedFilter(local, c.org)
		after := sandboxPosture(eff, avail, 0)
		axis, _ := FirstLoosened(sandboxAxes, before, after)
		if (axis != "") != c.wantRefuse || axis != c.wantAxis {
			t.Errorf("%s: effective %v, first loosened %q, want %q", c.name, eff, axis, c.wantAxis)
		}
		for _, v := range eff {
			if indexOf(local, v) < 0 {
				t.Errorf("%s: OrderedFilter added %q", c.name, v)
			}
		}
		for i := 1; i < len(eff); i++ {
			if indexOf(local, eff[i]) < indexOf(local, eff[i-1]) {
				t.Errorf("%s: OrderedFilter reordered %v", c.name, eff)
			}
		}
	}
}

// A disjoint DirSetIntersection pin never widens; an empty result refuses.
func TestSetIntersectionDisjointNeverWidens(t *testing.T) {
	cases := []struct {
		name     string
		local    []string
		localAny bool
		org      []string
		want     []string
		wantErr  bool
	}{
		{"overlap", []string{"a", "b"}, false, []string{"b", "c"}, []string{"b"}, false},
		{"disjoint refuses, never any", []string{"a"}, false, []string{"c"}, nil, true},
		{"empty org refuses", []string{"a"}, false, nil, nil, true},
		{"local any takes the org list", nil, true, []string{"c", "c"}, []string{"c"}, false},
		{"local any and empty org refuses", nil, true, nil, nil, true},
	}
	for _, c := range cases {
		got, err := SetIntersection(c.local, c.localAny, c.org)
		if c.wantErr != errors.Is(err, ErrEmptyIntersection) || !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %v %v", c.name, got, err)
		}
		if err == nil && !c.localAny && !subset(got, c.local) {
			t.Errorf("%s: widened %v beyond local %v", c.name, got, c.local)
		}
	}
}

func TestAdditiveMaskOnlyHidesMore(t *testing.T) {
	got := AdditiveMask([]string{"/a"}, []string{"/b", "/a"})
	if !reflect.DeepEqual(got, []string{"/a", "/b"}) {
		t.Fatal(got)
	}
	if got := AdditiveMask(nil, nil); got != nil {
		t.Fatal(got)
	}
}

// TestRetention: 0 is forever, the maximum; raise-only; the axis agrees with
// the merge on every row (the JSP-1 R8 contradiction removed).
func TestRetention(t *testing.T) {
	rows := []struct{ local, org, want int64 }{
		{0, 30, 0},   // a local forever survives an org 30
		{30, 7, 30},  // never shortened
		{7, 30, 30},  // lengthened
		{30, 0, 0},   // the org may make it forever
		{0, 0, 0},    // both forever
		{14, 14, 14}, // equal
	}
	for _, r := range rows {
		got := RaiseRetention(r.local, r.org)
		if got != r.want {
			t.Errorf("RaiseRetention(%d,%d)=%d want %d", r.local, r.org, got, r.want)
		}
		before := Posture{"workspace_retention_days": {N: r.local}}
		after := Posture{"workspace_retention_days": {N: got}}
		if l := Compare(sandboxAxes, before, after); len(l) != 0 {
			t.Errorf("merge result loosens the axis: %v", l)
		}
	}
	if axis, _ := FirstLoosened(sandboxAxes, Posture{"workspace_retention_days": {N: 30}}, Posture{"workspace_retention_days": {N: 7}}); axis != "workspace_retention_days" {
		t.Fatal("a shortening must be named")
	}
	if axis, _ := FirstLoosened(sandboxAxes, Posture{"workspace_retention_days": {N: 0}}, Posture{"workspace_retention_days": {N: 3650}}); axis == "" {
		t.Fatal("forever to finite must be a loosening")
	}
	for _, c := range []struct {
		a, b int64
		want int
	}{{0, 30, 1}, {30, 0, -1}, {0, -1, 0}, {7, 30, -1}, {30, 30, 0}} {
		if got := RetentionCmp(c.a, c.b); got != c.want {
			t.Errorf("RetentionCmp(%d,%d)=%d", c.a, c.b, got)
		}
	}
}

// TestLowerIntKeepsTheShippedRule pins LowerInt to config.GovernanceLowerInt's
// shipped results (that function now delegates here).
func TestLowerIntKeepsTheShippedRule(t *testing.T) {
	for _, r := range []struct{ local, org, want int64 }{
		{0, 30, 30}, {60, 30, 30}, {10, 30, 10}, {30, 30, 30}, {10, 0, 10}, {10, -5, 10}, {-1, 30, 30},
	} {
		if got := LowerInt(r.local, r.org); got != r.want {
			t.Errorf("LowerInt(%d,%d)=%d want %d", r.local, r.org, got, r.want)
		}
	}
	if RaiseInt(3, 5) != 5 || RaiseInt(5, 3) != 5 {
		t.Fatal("RaiseInt")
	}
}

// The security plan's axis table (4.9) as data: a stricter update passes,
// each single-axis loosening is named, an unknown enum value fails closed.
func TestSecurityAxesAsData(t *testing.T) {
	before := Posture{
		"prelaunch_trust": {S: "ask"}, "commit_gate": {S: "quick_scan"}, "quick_scan_budget_s": {N: 5},
		"max_scan_staleness_min": {N: 60}, "max_advisory_db_age_h": {N: 168}, "min_blocking_severity": {S: "high"},
		"install_unknown": {S: "flag"}, "install_online_unknown": {S: "ask"}, "required_components": {Set: []string{"security.trust"}},
		"drivers": {Set: []string{"scalibr", "opengrep"}}, "custom_manifests": {Set: []string{"sha256:a"}},
		"scanner_sources": {Set: []string{"org_mirror", "vendor_release"}}, "rule_pack_min_version": {S: "2026.10.1"},
		"finding_retention_days": {N: 90},
	}
	stricter := Posture{
		"prelaunch_trust": {S: "refuse"}, "commit_gate": {S: "quick_scan"}, "quick_scan_budget_s": {N: 10},
		"max_scan_staleness_min": {N: 30}, "max_advisory_db_age_h": {N: 72}, "min_blocking_severity": {S: "medium"},
		"install_unknown": {S: "ask"}, "install_online_unknown": {S: "deny"}, "required_components": {Set: []string{"security.trust", "security.secrets"}},
		"drivers": {Set: []string{"scalibr"}}, "custom_manifests": {Set: nil},
		"scanner_sources": {Set: []string{"org_mirror"}}, "rule_pack_min_version": {S: "2026.11.1"},
		"finding_retention_days": {N: 0},
	}
	if got := Compare(securityAxes, before, stricter); len(got) != 0 {
		t.Fatalf("stricter update refused: %v", got)
	}
	loosen := map[string]Value{
		"prelaunch_trust": {S: "warn"}, "commit_gate": {S: "ask"}, "quick_scan_budget_s": {N: 1},
		"max_scan_staleness_min": {N: 120}, "max_advisory_db_age_h": {N: 400}, "min_blocking_severity": {S: "critical"},
		"install_unknown": {S: "flag"}, "install_online_unknown": {S: "flag"},
		"required_components": {Set: nil}, "drivers": {Set: []string{"scalibr", "opengrep", "gosec"}},
		"custom_manifests": {Set: []string{"sha256:a", "sha256:b"}}, "scanner_sources": {Set: []string{"org_mirror", "vendor_release", "user_installed"}},
		"rule_pack_min_version": {S: "2026.9.1"}, "finding_retention_days": {N: 30},
	}
	before["install_unknown"] = Value{S: "ask"}
	for axis, v := range loosen {
		after := Posture{}
		for k, val := range before {
			after[k] = val
		}
		after[axis] = v
		got := Compare(securityAxes, before, after)
		if len(got) != 1 || got[0].Axis != axis {
			t.Errorf("loosening %s: got %v", axis, got)
		}
	}
	after := Posture{}
	for k, val := range before {
		after[k] = val
	}
	after["prelaunch_trust"] = Value{S: "block"}
	if axis, _ := FirstLoosened(securityAxes, before, after); axis != "prelaunch_trust" {
		t.Errorf("unknown enum value accepted")
	}
	after["prelaunch_trust"] = before["prelaunch_trust"]
	after["rule_pack_min_version"] = Value{S: "v2026"}
	if axis, _ := FirstLoosened(securityAxes, before, after); axis != "rule_pack_min_version" {
		t.Errorf("malformed version accepted")
	}
	delete(after, "rule_pack_min_version")
	if axis, _ := FirstLoosened(securityAxes, before, after); axis != "rule_pack_min_version" {
		t.Errorf("a missing axis must fail closed")
	}
}

func TestEnumReview(t *testing.T) {
	keys := []EnumKey{
		{Key: "security.scanning.require.prelaunch_trust", Axis: "prelaunch_trust", Values: []string{"warn", "ask", "refuse"}},
		{Key: "terminal.sandbox.egress", Axis: "egress_tier", Values: []string{"host", "internet", "proxy_only", "none"}},
	}
	axes := append(append([]Axis(nil), sandboxAxes...), securityAxes...)
	if bad := ReviewEnums(keys, axes); len(bad) != 0 {
		t.Fatal(bad)
	}
	keys[1].Values = append(keys[1].Values, "allowlist")
	if bad := ReviewEnums(keys, axes); len(bad) != 1 {
		t.Fatalf("enum review missed a new value: %v", bad)
	}
	if bad := ReviewEnums([]EnumKey{{Key: "k", Axis: "nope"}}, axes); len(bad) != 1 {
		t.Fatal("unknown axis must fail")
	}
	if bad := ReviewEnums([]EnumKey{{Key: "k", Axis: "landlock_min_abi", Values: []string{"3"}}}, axes); len(bad) != 1 {
		t.Fatal("a non-enum axis must fail")
	}
}

func TestVersionCmp(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{{"2026.11.1", "2026.9.30", 1}, {"2026.11", "2026.11.0", 0}, {"1.2", "1.10", -1}} {
		got, err := VersionCmp(c.a, c.b)
		if err != nil || got != c.want {
			t.Errorf("VersionCmp(%s,%s)=%d %v", c.a, c.b, got, err)
		}
	}
	if _, err := VersionCmp("v1.2", "1"); err == nil {
		t.Error("a non-numeric version must not compare")
	}
}

// TestDirectionTable walks every direction: a row per (direction, kind,
// value) with the CheckPin verdict, and the merge for the directions that
// carry one.
func TestDirectionTable(t *testing.T) {
	type row struct {
		dir     Direction
		kind    string
		value   any
		safe    any
		wantErr bool
	}
	rows := []row{
		{DirFree, KindBool, true, nil, false},
		{DirFree, KindStringList, []string{}, nil, false},
		{DirRestrictiveOnly, KindBool, true, true, false},
		{DirRestrictiveOnly, KindBool, false, true, true},
		{DirRestrictiveOnly, KindInt, int64(1), int64(1), true},
		{DirRestrictiveOnly, KindStringList, []string{}, []string{}, false},
		{DirRestrictiveOnly, KindStringList, []string{"/srv"}, []string{}, true},
		{DirLoweringOnly, KindInt, int64(30), nil, false},
		{DirLoweringOnly, KindInt, int64(-1), nil, true},
		{DirLoweringOnly, KindBool, true, nil, true},
		{DirRaisingOnly, KindInt, int64(3), nil, false},
		{DirRaisingOnly, KindString, "3", nil, true},
		{DirRetention, KindInt, int64(0), nil, false},
		{DirRetention, KindInt, int64(-7), nil, true},
		{DirOrderedFilter, KindStringList, []string{"a"}, nil, false},
		{DirOrderedFilter, KindStringList, []string{}, nil, true},
		{DirSetIntersection, KindStringList, []string{}, nil, true},
		{DirSetIntersection, KindInt, int64(1), nil, true},
		{DirAdditiveMask, KindStringList, []string{}, nil, false},
		{Direction("narrowing_list"), KindStringList, []string{"a"}, nil, true},
	}
	for _, r := range rows {
		err := CheckPin(r.dir, r.kind, r.value, r.safe)
		if (err != nil) != r.wantErr {
			t.Errorf("CheckPin(%s,%s,%v)=%v want error=%v", r.dir, r.kind, r.value, err, r.wantErr)
		}
	}
	merges := []struct {
		dir        Direction
		local, org any
		want       any
		wantErr    bool
	}{
		{DirFree, true, false, false, false},
		{DirRestrictiveOnly, true, false, false, false},
		{DirLoweringOnly, int64(60), int64(30), int64(30), false},
		{DirLoweringOnly, int64(10), int64(30), int64(10), false},
		{DirRaisingOnly, int64(2), int64(3), int64(3), false},
		{DirRetention, int64(0), int64(30), int64(0), false},
		{DirRetention, int64(7), int64(30), int64(30), false},
		{DirOrderedFilter, []string{"a", "b", "c"}, []string{"c", "a"}, []string{"a", "c"}, false},
		{DirSetIntersection, []string{"a", "b"}, []string{"b"}, []string{"b"}, false},
		{DirSetIntersection, []string{"a"}, []string{"b"}, nil, true},
		{DirSetIntersection, nil, []string{"b"}, []string{"b"}, false},
		{DirAdditiveMask, []string{"/x"}, []string{"/y"}, []string{"/x", "/y"}, false},
		{DirLoweringOnly, "x", int64(3), nil, true},
		{Direction("bogus"), 1, 1, nil, true},
	}
	for _, m := range merges {
		got, err := Merge(m.dir, m.local, m.org)
		if (err != nil) != m.wantErr || (err == nil && !Equal(got, m.want)) {
			t.Errorf("Merge(%s,%v,%v)=%v,%v want %v", m.dir, m.local, m.org, got, err, m.want)
		}
	}
	seen := map[Direction]bool{}
	for _, r := range Rules {
		if seen[r.Dir] || r.merge == nil || r.Label == "" {
			t.Errorf("rule %s: duplicate, no merge or no label", r.Dir)
		}
		seen[r.Dir] = true
	}
	if len(seen) != 8 {
		t.Errorf("want eight directions, got %d", len(seen))
	}
}
