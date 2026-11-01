package integration_test

import (
	"slices"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/platform/jetbrainshost"
)

// TestJetBrainsProductHostsMatch pins the registry's copy of the JetBrains
// product-host vocabulary to internal/platform/jetbrainshost, the package
// whose surface enricher stamps those hosts.
func TestJetBrainsProductHostsMatch(t *testing.T) {
	var want []string
	for _, p := range jetbrainshost.Products() {
		want = append(want, p.Host)
	}
	got := integration.JetBrainsProductHosts()
	slices.Sort(want)
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Errorf("integration JetBrains product hosts %v, jetbrainshost %v", got, want)
	}
}
