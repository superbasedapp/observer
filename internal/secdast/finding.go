package secdast

import (
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
)

// Findings converts a run's hits into the shared finding shape, flag only:
// category code_vuln, scope manual, baseline unknown, status open. redact
// is the caller's scrubber (evidence passes through it before the cap);
// nil keeps the evidence as built (it holds no body text). The project hash
// is left "" here: the cmd seam stamps the project the run is recorded
// against (secsvc.RecordRun). The local key is keyed on the target's
// origin, so the same check on two servers of one project differs.
func Findings(t Target, hits []Hit, now time.Time, redact func(string) string) []secfinding.Finding {
	out := make([]secfinding.Finding, 0, len(hits))
	scope := "dast:" + t.Origin()
	for _, h := range hits {
		row, ok := CheckByID(h.Check)
		if !ok {
			continue
		}
		ev := h.Evidence
		if redact != nil {
			ev = redact(ev)
		}
		ev = secfinding.Clip(ev, secfinding.MaxEvidence)
		f := secfinding.Finding{
			LocalKey:         secfinding.LocalKey(scope, row.ID, secfinding.TextIdentity(h.Path+"\x00"+h.Key)),
			Rule:             secfinding.Rule{ID: row.ID, Version: Version, Pack: Driver, PackVersion: Version},
			Engine:           secfinding.Engine{Driver: Driver, DriverVersion: Version},
			Category:         policy.FindingCodeVuln,
			Severity:         row.Severity,
			Confidence:       row.Confidence,
			References:       secfinding.References{CWE: append([]string(nil), row.CWE...)},
			Scope:            policy.FindingScopeManual,
			EvidenceRedacted: ev,
			EvidenceHash:     secfinding.EvidenceHash(ev),
			Message:          row.Message,
			FixHint:          row.FixHint,
			Baseline:         policy.FindingBaselineUnknown,
			Status:           policy.FindingStatusOpen,
			FirstSeen:        now.UTC(),
			LastSeen:         now.UTC(),
		}
		out = append(out, f)
	}
	return out
}
