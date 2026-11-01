package orgcontract

import (
	"reflect"
	"testing"
)

// managed_integrity_p1_test.go: the lane P1 wire additions (managed route
// maintenance). route_repaired is an act label like hook_repaired, and the two
// route coverage lists are held to the closed drifted_tools vocabulary.

func TestRouteRepairedIsAnActLabel(t *testing.T) {
	if !validCaptureRisk(CaptureRiskRouteRepaired) {
		t.Fatal("route_repaired is not accepted on the wire")
	}
	if isStandingCaptureRisk(CaptureRiskRouteRepaired) {
		t.Fatal("route_repaired must be an act: a second repair is a new event")
	}
	if captureRiskRank[CaptureRiskRouteRepaired] == 0 {
		t.Fatal("route_repaired has no captureRiskPriority row")
	}
	items := NormalizeCaptureRiskItems([]CaptureRiskItem{{
		Risk: CaptureRiskRouteRepaired, Tool: "claude-code", File: "~/.claude/settings.json", At: "2026-10-18T12:00:00Z",
	}})
	if len(items) != 1 || items[0].At != "2026-10-18T12:00:00Z" || items[0].File != "~/.claude/settings.json" {
		t.Fatalf("normalized route_repaired item = %+v", items)
	}
}

func TestRouteCoverageListsAreClosedLabels(t *testing.T) {
	r := ManagedIntegrityReport{
		RoutesWritten:   []string{"codex", "claude-code", "/home/someone/.codex", "codex"},
		UnroutableTools: []string{"kimi-code", "not-a-tool"},
		UnselectedTools: []string{"qwen-code", "C:\\Users\\someone\\.codex", "crush", "qwen-code"},
	}.NormalizeLabels()
	r2 := ManagedIntegrityReport{RoutingOff: true, RoutingOffTools: []string{"codex", "/etc/passwd", "claude-code"}}.NormalizeLabels()
	if want := []string{"claude-code", "codex"}; !r2.RoutingOff || !reflect.DeepEqual(r2.RoutingOffTools, want) {
		t.Fatalf("RoutingOff = %v, RoutingOffTools = %v, want true, %v", r2.RoutingOff, r2.RoutingOffTools, want)
	}
	if want := []string{"crush", "qwen-code"}; !reflect.DeepEqual(r.UnselectedTools, want) {
		t.Fatalf("UnselectedTools = %v, want %v", r.UnselectedTools, want)
	}
	if want := []string{"claude-code", "codex"}; !reflect.DeepEqual(r.RoutesWritten, want) {
		t.Fatalf("RoutesWritten = %v, want %v", r.RoutesWritten, want)
	}
	if want := []string{"kimi-code"}; !reflect.DeepEqual(r.UnroutableTools, want) {
		t.Fatalf("UnroutableTools = %v, want %v", r.UnroutableTools, want)
	}
}
