//go:build !sbo_omit_security && !sbo_omit_security_scan_custom

package main

import (
	"context"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/seccustom"
)

// TestCustomScanSelectedNeedsAComponentsBlock: an install with no
// [components] block resolves every compiled module active, and the
// off-by-default custom scanner must not switch itself on there (P-011).
func TestCustomScanSelectedNeedsAComponentsBlock(t *testing.T) {
	t.Parallel()
	if customScanSelected(componentstate.Legacy()) {
		t.Fatal("legacy install: custom scanners switched themselves on")
	}
	added := componentstate.Resolve(config.ComponentsConfig{Add: []string{customScanComponent}}, nil)
	if !customScanSelected(added) {
		t.Fatal("selected in [components]: still off")
	}
	if svc, err := customScannerService(context.Background(), componentstate.Legacy(), "", nil); svc != nil || err != nil {
		t.Fatalf("legacy service %v %v", svc, err)
	}
}

// TestCustomScanFlagsArePickers: numbers pick among the discovered
// candidates, and an out-of-range number is refused.
func TestCustomScanFlagsArePickers(t *testing.T) {
	t.Parallel()
	cand := seccustom.Candidates{Executable: []string{"/a/gosec", "/b/gosec"}, Companions: [][]string{{"/go/bin/go"}}}
	f := &customSourceFlags{executable: 2, companions: []int{1}, severity: []string{"LOW=info"}}
	f.limits[4] = 128 // child_processes
	c, err := f.choices(cand)
	if err != nil || c.Executable != "/b/gosec" || c.Companions[0] != "/go/bin/go" || c.Limits.ChildProcesses != 128 || c.Severity["LOW"] != "info" {
		t.Fatalf("choices %+v %v", c, err)
	}
	for _, bad := range []*customSourceFlags{{executable: 3}, {companions: []int{2}}, {severity: []string{"LOW"}}} {
		if _, err := bad.choices(cand); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	if len(securityCustomSubcommands()) != 1 {
		t.Fatal("observer security scanners is missing")
	}
}
