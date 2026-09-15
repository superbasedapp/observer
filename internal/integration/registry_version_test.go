package integration

import "testing"

// registryVersionToolCount is the golden pair partner of RegistryVersion:
// the number of tools in the registry the CURRENT RegistryVersion was
// stamped against. When the tool vocabulary changes (a row added or
// removed), update BOTH this constant and RegistryVersion in the same
// commit — that is the whole contract this test enforces.
//
// Background (adapter-parity audit, 2026-08-25): RegistryVersion sat at 1
// through ~24 tool additions because nothing pinned it, which left the G25
// aggregate consent rail's ConsentRegistryChanged gate
// (internal/aggregate/consent.go) silently inert — receipts always matched
// the live version because the live version never moved.
const registryVersionToolCount = 45

// TestRegistryVersionMovesWithVocabulary fails when the tool vocabulary
// changes without a RegistryVersion bump. It cannot verify the bump itself
// (a data constant can't prove intent), but it forces the author of a
// vocabulary change to touch this file — and the doc comment above tells
// them to bump RegistryVersion alongside it.
func TestRegistryVersionMovesWithVocabulary(t *testing.T) {
	got := len(Tools())
	if got != registryVersionToolCount {
		t.Fatalf("tool vocabulary changed: len(Tools()) = %d, golden pair says %d.\n"+
			"Update registryVersionToolCount AND bump RegistryVersion "+
			"(internal/integration/integration.go) in the same commit — the G25 "+
			"aggregate consent rail dispatches re-consent on RegistryVersion "+
			"changes, so a silent vocabulary change starves that gate.", got, registryVersionToolCount)
	}
	if RegistryVersion < 2 {
		t.Fatalf("RegistryVersion = %d; it was bumped to 2 on 2026-08-25 and must never regress", RegistryVersion)
	}
}
