package components

import (
	"strings"
	"testing"
)

func TestRenderMarkdownDeterministicAndClean(t *testing.T) {
	a, b := RenderMarkdown(), RenderMarkdown()
	if a != b {
		t.Fatal("RenderMarkdown is not deterministic")
	}
	if strings.ContainsAny(a, "–—") {
		t.Fatal("generated docs contain an em or en dash")
	}
	for _, c := range All() {
		if !strings.Contains(a, "`"+c.ID+"`") {
			t.Errorf("generated docs omit %s", c.ID)
		}
	}
	for _, a2 := range Artifacts() {
		if !strings.Contains(a, a2.ID) {
			t.Errorf("generated docs omit %s", a2.ID)
		}
	}
}

func TestCompiledRegistry(t *testing.T) {
	if got := Compiled(BinaryNode); len(got) != len(ForBinary(BinaryNode)) {
		t.Fatalf("with nothing omitted every node row is compiled, got %d", len(got))
	}
	if DistroOf(Compiled(BinaryNode)) != DistroFull {
		t.Fatal("a build with nothing omitted is the full distro")
	}
	// processobs, not obs: since the judge client split (phase PB, D-408)
	// full without obs IS the developer distro, which the next test pins.
	MarkOmitted("processobs")
	defer func() {
		omitMu.Lock()
		delete(omitted, "processobs")
		omitMu.Unlock()
	}()
	for _, id := range Compiled(BinaryNode) {
		if id == "processobs" {
			t.Fatal("an omitted component must not be reported as compiled")
		}
	}
	if DistroOf(Compiled(BinaryNode)) != DistroCustom {
		t.Fatal("full without processobs matches no prebuilt distro")
	}
}

// TestFullWithoutObsIsDeveloper pins the D-389 / D-408 shape: developer is
// the full product minus Plane A observability, so a no_obs build reports
// itself as the developer distro. D-749 Q34 adds the one later exception:
// a library-linked scanner driver (security.scan.scalibr, security plan
// section 4.2) is compiled only into managed and full, so the developer
// shape is full minus obs minus that driver; lane SEC-G5's linked
// actionlint (security.scan.actionlint) is the second.
func TestFullWithoutObsIsDeveloper(t *testing.T) {
	linkedDrivers := []string{"security.scan.scalibr", "security.scan.actionlint"}
	MarkOmitted("obs")
	for _, id := range linkedDrivers {
		MarkOmitted(id)
	}
	defer func() {
		omitMu.Lock()
		delete(omitted, "obs")
		for _, id := range linkedDrivers {
			delete(omitted, id)
		}
		omitMu.Unlock()
	}()
	if got := DistroOf(Compiled(BinaryNode)); got != DistroDeveloper {
		t.Fatalf("full without obs = %s, want developer", got)
	}
}
