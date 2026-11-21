package otlpvendor

import (
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"

	"github.com/marmutapp/superbased-observer/internal/ownagent"
)

// resourceClaim is the per-resource read decision: which rows read the
// resource's records, and (for the own-agent row) the agent they belong to.
type resourceClaim struct {
	ownagent.OTLPClaim
	cands []*Vendor
}

// claimResource resolves one resource through the own-agent claim table
// (ownagent.ClaimOTLPResource): ownagent.ReadOTLPResource extracts the echo
// marker, the agent attribute and any hosted-app identity from the resource
// and its records, and this table adds the one fact only it knows, whether a
// coding-tool row claims the service.name.
func claimResource(res []*commonpb.KeyValue, records [][]*commonpb.KeyValue) resourceClaim {
	in := ownagent.ReadOTLPResource(res, records)
	coding, ok := claim(attrMap(res)[attrService].GetStringValue())
	if ok {
		in.CodingTool = coding.Tool
	}
	c := ownagent.ClaimOTLPResource(in)
	if c.Plane == ownagent.OTLPCodingTool {
		return resourceClaim{OTLPClaim: c, cands: []*Vendor{coding}}
	}
	// Every other plane keeps the pre-phase-2 reading of a resource no
	// service.name row claims: the event-name rows (Claude Code, whose
	// export must keep working under a renamed OTEL_SERVICE_NAME, even one
	// that inherited an sbo.agent from the process that started it) read
	// its LOGS. Those rows map logs only (TestEventNameRowsMapLogsOnly), so
	// they never read an own agent's spans. The own-agent row reads the
	// resource only when the claim table made it an own agent.
	var out []*Vendor
	if c.Plane == ownagent.OTLPOwnAgent {
		if v := agentRow(); v != nil {
			out = append(out, v)
		}
	}
	for i := range vendors {
		if vendors[i].ClaimByEventName {
			out = append(out, &vendors[i])
		}
	}
	return resourceClaim{OTLPClaim: c, cands: out}
}

// agentRow returns the own-agent row (Vendor.ClaimByAgent), or nil.
func agentRow() *Vendor {
	for i := range vendors {
		if vendors[i].ClaimByAgent {
			return &vendors[i]
		}
	}
	return nil
}

// spanRecords lists every span's attributes inside one resource.
func spanRecords(rs *tracepb.ResourceSpans) [][]*commonpb.KeyValue {
	var out [][]*commonpb.KeyValue
	for _, ss := range rs.GetScopeSpans() {
		for _, sp := range ss.GetSpans() {
			out = append(out, sp.GetAttributes())
		}
	}
	return out
}

// ClaimTraceResource decides one trace resource's plane: Plane B (a coding
// tool's service.name, or the developer's own agent), dropped (a malformed
// agent name) or unclaimed (the Plane A trace handler's, when one runs). The
// daemon partitions every trace export with it, so the same table decides
// which spans this package maps and which the Plane A handler may see; a
// resource with any plane but OTLPUnclaimed must never reach Plane A
// (ownagent.OTLPPlane.KeptFromPlaneA).
func ClaimTraceResource(rs *tracepb.ResourceSpans) ownagent.OTLPClaim {
	return claimResource(rs.GetResource().GetAttributes(), spanRecords(rs)).OTLPClaim
}
