package diag

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/agentconfig"
	"github.com/marmutapp/superbased-observer/internal/hookdisable"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// TestConfigLayerToolsAreWireLabels pins the tool half of the managed
// integrity settings-layer vocabulary (DEC-7) to the node's two tables: every
// tool a hook-off row silences and every tool an effective-layer family
// belongs to must be a closed orgcontract label, or the managed-integrity
// step would have a finding it cannot report. Add the tool to
// orgcontract.configLayerTools (a one-line row).
func TestConfigLayerToolsAreWireLabels(t *testing.T) {
	t.Parallel()
	for _, s := range hookdisable.Switches {
		for _, tool := range s.Tools {
			if !orgcontract.ValidConfigLayerTool(tool) {
				t.Errorf("hookdisable row %s silences %q, which has no orgcontract.configLayerTools row", s.ID, tool)
			}
		}
	}
	for _, f := range agentconfig.Families() {
		if !orgcontract.ValidConfigLayerTool(f.Tool) {
			t.Errorf("effective-layer family %s belongs to %q, which has no orgcontract.configLayerTools row", f.ID, f.Tool)
		}
	}
}

// TestConfigLayerRiskCodesMatchTheDoctor holds the finding half of the
// vocabulary to the doctor's warn set: a code the config.layers row warns on
// crosses the wire, an informational code never does.
func TestConfigLayerRiskCodesMatchTheDoctor(t *testing.T) {
	t.Parallel()
	wire := map[string]bool{}
	for _, c := range orgcontract.ConfigLayerRiskCodes() {
		wire[c] = true
	}
	for code := range layerAdvice {
		_, onWire := orgcontract.ConfigLayerRiskLabel("claude-code", string(code))
		if LayerFindingWarns(code) != onWire {
			t.Errorf("finding %s: doctor warns %v, on the wire %v", code, LayerFindingWarns(code), onWire)
		}
		delete(wire, string(code))
	}
	for c := range wire {
		t.Errorf("orgcontract config-layer code %q is not an agentconfig finding code", c)
	}
}
