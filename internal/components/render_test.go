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

// TestFullWithoutLinkedDriversIsDeveloper pins the developer shape: since
// D7 (plan of record 2026-11-19, superseding D-389) Plane A observability is
// compiled into developer, so developer is the full product minus only the
// library-linked scanner drivers compiled into managed and full (D-749 Q34:
// security.scan.scalibr; lane SEC-G5's linked actionlint; phase OS-2's image
// OS package extractors, security.scan.os; and the linked Go symbol check
// security.reach.go, plan 14.5 item 3b). A build without obs as well now
// matches no prebuilt distro.
func TestFullWithoutLinkedDriversIsDeveloper(t *testing.T) {
	linkedDrivers := []string{"security.scan.scalibr", "security.scan.actionlint", "security.scan.os", "security.reach.go"}
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
		t.Fatalf("full without the linked drivers = %s, want developer", got)
	}
	MarkOmitted("obs")
	if got := DistroOf(Compiled(BinaryNode)); got != DistroCustom {
		t.Fatalf("full without the linked drivers and obs = %s, want custom", got)
	}
}
