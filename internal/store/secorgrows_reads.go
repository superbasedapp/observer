//go:build !sbo_omit_security

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// secorgrows_reads.go holds the reads over the node-local sec_* tables the
// security wire seam binds (secorgrows.go). It is compiled out with the
// security module (sbo_omit_security), with the tables' one writer
// secfindings.go; secorgrows_omit.go keeps the API, reading nothing.

// SelectSecurityFindingRows reads the findings the wire carries: every open
// finding, and every other finding seen or closed inside the window, of the
// projects inside scope, newest first, at most max. The rows are unstripped
// (the composer strips them); org_key is the stored column as is.
func (s *Store) SelectSecurityFindingRows(ctx context.Context, max int, scope SecurityScope) ([]orgcontract.SecurityFindingRow, error) {
	if max <= 0 {
		max = orgcontract.MaxSecurityRowsPerPush
	}
	since := time.Now().UTC().Add(-secOrgFindingWindow).Format(secTime)
	scoped, scopeArgs := scope.where("project_root_hash")
	args := append([]any{since, since}, scopeArgs...)
	args = append(args, max)
	//nolint:gosec // G202: the scope fragment is built from constants; its values are bound.
	rows, err := s.db.QueryContext(ctx, `SELECT id, org_key, rel_path, start_line, end_line, path_aliases_json,
		rule_id, rule_version, rule_pack, rule_pack_version, driver, driver_version, engine_digest, database_epoch,
		category, severity, confidence, refs_json, scope, project_identity_hash, org_project_id,
		evidence_redacted, evidence_hash, baseline, baseline_ref_json,
		attribution, attribution_method, attribution_confidence, COALESCE(session_id, ''), action_id, prompt_action_id,
		tool, tool_version, model, surface, taint_at_write, taint_origin_class, commit_sha, patch_fp, landed,
		status, first_seen, last_seen, closed_at, fix_json, exception_id, verdict_ids_json
		FROM sec_findings
		WHERE (status = 'open' OR last_seen >= ? OR closed_at >= ?)`+scoped+`
		ORDER BY last_seen DESC, id LIMIT ?`, args...)
	if err != nil {
		return nil, fmt.Errorf("store.SelectSecurityFindingRows: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []orgcontract.SecurityFindingRow
	for rows.Next() {
		var r orgcontract.SecurityFindingRow
		var id, aliases, refs, baseRef, fix, verdicts string
		if err := rows.Scan(&id, &r.OrgKey, &r.RelPath, &r.StartLine, &r.EndLine, &aliases,
			&r.RuleID, &r.RuleVersion, &r.RulePack, &r.RulePackVersion, &r.Driver, &r.DriverVersion, &r.EngineDigest, &r.DatabaseEpoch,
			&r.Category, &r.Severity, &r.Confidence, &refs, &r.Scope, &r.ProjectIdentityHash, &r.OrgProjectID,
			&r.EvidenceRedacted, &r.EvidenceHash, &r.Baseline, &baseRef,
			&r.Attribution, &r.AttributionMethod, &r.AttributionConfidence, &r.SessionID, &r.ActionID, &r.PromptActionID,
			&r.Tool, &r.ToolVersion, &r.Model, &r.Surface, &r.Tainted, &r.TaintOriginClass, &r.CommitSHA, &r.PatchFP, &r.Landed,
			&r.Status, &r.FirstSeen, &r.LastSeen, &r.ClosedAt, &fix, &r.ExceptionID, &verdicts); err != nil {
			return nil, fmt.Errorf("store.SelectSecurityFindingRows: scan: %w", err)
		}
		r.FindingRef = SecurityFindingRef(id)
		secJSON(aliases, &r.PathAliases)
		secJSON(verdicts, &r.VerdictIDs)
		var rf struct{ CWE, OWASP, ATLAS []string }
		secJSON(refs, &rf)
		r.CWE, r.OWASP, r.ATLAS = rf.CWE, rf.OWASP, rf.ATLAS
		var br struct{ Kind, Ref, PackVersion, PolicyVersion string }
		secJSON(baseRef, &br)
		r.BaselineRefKind, r.BaselineRef, r.BaselinePackVersion, r.BaselinePolicyVersion = br.Kind, br.Ref, br.PackVersion, br.PolicyVersion
		var fo struct {
			RuleNoLongerFires, NoNewFindingInRegion, TestCommandObserved, TestFilesEdited bool
			TestExitCode                                                                  int
		}
		secJSON(fix, &fo)
		r.FixRuleNoLongerFires, r.FixNoNewFindingInRegion = fo.RuleNoLongerFires, fo.NoNewFindingInRegion
		r.FixTestCommandObserved, r.FixTestExitCode, r.FixTestFilesEdited = fo.TestCommandObserved, fo.TestExitCode, fo.TestFilesEdited
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.SelectSecurityFindingRows: %w", err)
	}
	return out, nil
}

// secJSON decodes a stored JSON column, leaving dst unchanged when the
// column is empty or does not decode (a tolerant read of node-local data).
func secJSON(raw string, dst any) {
	if raw == "" {
		return
	}
	_ = json.Unmarshal([]byte(raw), dst)
}

// SecurityPostureFacts are the store-side facts of the day's posture row
// over the projects inside scope: finding counts, projects, driver
// versions, scan freshness and outcomes, and commit-gate verdict counts (a
// scoped push counts only the verdicts of sessions in a scoped project). The
// cmd layer adds the detectors, the online-check state and the floor keys.
func (s *Store) SecurityPostureFacts(ctx context.Context, day string, now time.Time, scope SecurityScope) (orgcontract.SecurityPostureRow, error) {
	out := orgcontract.SecurityPostureRow{Day: day}
	fw, fargs := scope.where("project_root_hash")
	gw, gargs := scope.where("g.project_root_hash")
	//nolint:gosec // G202: the scope fragment is built from constants; its values are bound.
	rows, err := s.db.QueryContext(ctx, `SELECT category, severity, status, COUNT(*) FROM sec_findings
		WHERE 1 = 1`+fw+`
		GROUP BY category, severity, status ORDER BY category, severity, status`, fargs...)
	if err != nil {
		return out, fmt.Errorf("store.SecurityPostureFacts: counts: %w", err)
	}
	for rows.Next() {
		var c orgcontract.SecurityPostureCount
		if err := rows.Scan(&c.Category, &c.Severity, &c.Status, &c.Count); err != nil {
			_ = rows.Close()
			return out, fmt.Errorf("store.SecurityPostureFacts: counts: %w", err)
		}
		out.Findings = append(out.Findings, c)
	}
	if err := closeRows(rows); err != nil {
		return out, fmt.Errorf("store.SecurityPostureFacts: counts: %w", err)
	}
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(DISTINCT project_root_hash) FROM sec_findings WHERE 1 = 1`+fw, fargs...).Scan(&out.Projects); err != nil {
		return out, fmt.Errorf("store.SecurityPostureFacts: projects: %w", err)
	}
	drw, drargs := scope.where("f.project_root_hash")
	//nolint:gosec // G202: the scope fragment is built from constants; its values are bound.
	rows, err = s.db.QueryContext(ctx, `SELECT driver, driver_version FROM sec_findings f
		WHERE driver <> ''`+drw+` AND last_seen = (SELECT MAX(last_seen) FROM sec_findings g WHERE g.driver = f.driver`+gw+`)
		GROUP BY driver ORDER BY driver`, append(drargs, gargs...)...)
	if err != nil {
		return out, fmt.Errorf("store.SecurityPostureFacts: drivers: %w", err)
	}
	for rows.Next() {
		var d orgcontract.SecurityDriverVersion
		if err := rows.Scan(&d.Driver, &d.Version); err != nil {
			_ = rows.Close()
			return out, fmt.Errorf("store.SecurityPostureFacts: drivers: %w", err)
		}
		out.Drivers = append(out.Drivers, d)
	}
	if err := closeRows(rows); err != nil {
		return out, fmt.Errorf("store.SecurityPostureFacts: drivers: %w", err)
	}
	var newest string
	if err := s.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(started_at), '') FROM sec_scan_runs WHERE 1 = 1`+secScanRanSQL+fw, fargs...).Scan(&newest); err != nil {
		return out, fmt.Errorf("store.SecurityPostureFacts: freshness: %w", err)
	}
	out.ScanFreshness = secFreshness(newest, now)
	//nolint:gosec // G202: the scope fragment is built from constants; its values are bound.
	rows, err = s.db.QueryContext(ctx, `SELECT outcome, COUNT(*) FROM sec_scan_runs
		WHERE substr(started_at, 1, 10) = ?`+secScanRanSQL+fw+` GROUP BY outcome ORDER BY outcome`, append([]any{day}, fargs...)...)
	if err != nil {
		return out, fmt.Errorf("store.SecurityPostureFacts: outcomes: %w", err)
	}
	for rows.Next() {
		var o orgcontract.SecurityOutcomeCount
		if err := rows.Scan(&o.Outcome, &o.Runs); err != nil {
			_ = rows.Close()
			return out, fmt.Errorf("store.SecurityPostureFacts: outcomes: %w", err)
		}
		out.ScanOutcomes = append(out.ScanOutcomes, o)
	}
	if err := closeRows(rows); err != nil {
		return out, fmt.Errorf("store.SecurityPostureFacts: outcomes: %w", err)
	}
	gateScope, gateArgs := "", []any(nil)
	if scope.scoped() {
		pw, pargs := scope.where("p.root_path_hash")
		gateScope = ` AND session_id IN (SELECT ss.id FROM sessions ss JOIN projects p ON p.id = ss.project_id WHERE 1 = 1` + pw + `)`
		gateArgs = pargs
	}
	//nolint:gosec // G202: the scope fragment is built from constants; its values are bound.
	rows, err = s.db.QueryContext(ctx, `SELECT rule_id, COALESCE(decision, ''), COUNT(*) FROM guard_events
		WHERE rule_id IN ('S-791', 'S-792', 'S-793', 'S-794') AND substr(ts, 1, 10) = ?`+gateScope+`
		GROUP BY rule_id, decision ORDER BY rule_id, decision`, append([]any{day}, gateArgs...)...)
	if err != nil {
		return out, fmt.Errorf("store.SecurityPostureFacts: commit gate: %w", err)
	}
	for rows.Next() {
		var g orgcontract.SecurityGateCount
		if err := rows.Scan(&g.Rule, &g.Decision, &g.Events); err != nil {
			_ = rows.Close()
			return out, fmt.Errorf("store.SecurityPostureFacts: commit gate: %w", err)
		}
		out.CommitGate = append(out.CommitGate, g)
	}
	if err := closeRows(rows); err != nil {
		return out, fmt.Errorf("store.SecurityPostureFacts: commit gate: %w", err)
	}
	if err := s.securityGateAndTrustFacts(ctx, day, gateScope, gateArgs, &out); err != nil {
		return out, err
	}
	return out, nil
}

// securityGateOutcomeSQL is the commit-gate outcome table (lane SEC-H2,
// security plan 7.4's "asked, waited, denied, unknown"), one row per
// outcome over the day's S-791 to S-794 events. The outcomes overlap by
// design: an S-793 ask is both asked and waited. A dirty commit whose quick
// scan came back clean raises no event, so "waited" counts only the waits
// that did not end clean.
var securityGateOutcomeSQL = []struct{ outcome, where string }{
	{"asked", `decision = 'ask'`},
	{"denied", `decision = 'deny'`},
	{"waited", `rule_id = 'S-793'`},
	{"unknown", `rule_id = 'S-794'`},
}

// securityTrustVerdictRules maps the launch trust rules to the verdict they
// fire on (internal/secrules/trust.go): S-701 to S-704 on untrusted, S-705
// on flagged. A clean verdict raises no event and is not counted.
var securityTrustVerdictRules = []struct{ verdict, rules string }{
	{"flagged", `'S-705'`},
	{"untrusted", `'S-701', 'S-702', 'S-703', 'S-704'`},
}

// securityGateAndTrustFacts adds the day's commit-gate outcomes and launch
// trust verdict counts (lane SEC-H2) and names both as reported. A launch
// that fires two untrusted rules counts once (one event time per session).
func (s *Store) securityGateAndTrustFacts(ctx context.Context, day, gateScope string, gateArgs []any, out *orgcontract.SecurityPostureRow) error {
	for _, g := range securityGateOutcomeSQL {
		var n int64
		//nolint:gosec // G202: the WHERE fragments are this file's constants.
		q := `SELECT COUNT(*) FROM guard_events WHERE rule_id IN ('S-791', 'S-792', 'S-793', 'S-794') AND substr(ts, 1, 10) = ? AND ` + g.where + gateScope
		if err := s.db.QueryRowContext(ctx, q, append([]any{day}, gateArgs...)...).Scan(&n); err != nil {
			return fmt.Errorf("store.SecurityPostureFacts: gate outcomes: %w", err)
		}
		if n > 0 {
			out.GateOutcomes = append(out.GateOutcomes, orgcontract.SecurityGateOutcome{Outcome: g.outcome, Events: n})
		}
	}
	for _, v := range securityTrustVerdictRules {
		var n int64
		//nolint:gosec // G202: the rule lists are this file's constants.
		q := `SELECT COUNT(DISTINCT COALESCE(session_id, '') || '|' || ts) FROM guard_events WHERE rule_id IN (` + v.rules + `) AND substr(ts, 1, 10) = ?` + gateScope
		if err := s.db.QueryRowContext(ctx, q, append([]any{day}, gateArgs...)...).Scan(&n); err != nil {
			return fmt.Errorf("store.SecurityPostureFacts: trust verdicts: %w", err)
		}
		if n > 0 {
			out.TrustVerdicts = append(out.TrustVerdicts, orgcontract.SecurityVerdictCount{Verdict: v.verdict, Count: n})
		}
	}
	out.Reported = append(out.Reported, "trust_verdicts", "gate_outcomes")
	return nil
}

// probeSecFindings is the change probe of the finding and posture families:
// the finding count, the newest sighting and close, the newest lifecycle
// event and the newest scan run, salted with the share level, the
// raw-content flag, the org-key state and the scope of the compose (lane
// SEC-E2 audit finding 7), so a change to any of them re-sends the rows.
func (s *Store) probeSecFindings(ctx context.Context) (string, error) {
	base, err := s.snapProbeScalar(ctx, `SELECT
		(SELECT COUNT(*) FROM sec_findings) || ':' ||
		(SELECT COALESCE(MAX(last_seen), '') FROM sec_findings) || ':' ||
		(SELECT COALESCE(MAX(closed_at), '') FROM sec_findings) || ':' ||
		(SELECT COALESCE(MAX(id), 0) FROM sec_finding_events) || ':' ||
		(SELECT COALESCE(MAX(id), 0) FROM sec_scan_runs)`)
	if err != nil {
		return "", err
	}
	return base + "#" + s.secSalt.get(), nil
}

// probeSecPosture adds the commit-gate verdicts the posture counts.
func (s *Store) probeSecPosture(ctx context.Context) (string, error) {
	f, err := s.probeSecFindings(ctx)
	if err != nil {
		return "", err
	}
	g, err := s.snapProbeScalar(ctx, `SELECT COALESCE(MAX(id), 0) FROM guard_events WHERE rule_id IN ('S-791', 'S-792', 'S-793', 'S-794', 'S-701', 'S-702', 'S-703', 'S-704', 'S-705')`)
	if err != nil {
		return "", err
	}
	return f + ":" + g + ":" + time.Now().UTC().Format("2006-01-02"), nil
}

// SecOrgBaselineApproval reports whether the org approved the project's
// baseline reference (kind, ref) and when. The project is matched by the
// keys its own finding rows carry on the wire (org_project_id, else
// project_identity_hash), the keys the org approved them under.
func (s *Store) SecOrgBaselineApproval(ctx context.Context, rootHash, kind, ref string) (string, bool, error) {
	var at string
	err := s.db.QueryRowContext(ctx, `SELECT a.approved_at FROM sec_org_baseline_approvals a
		WHERE a.ref_kind = ? AND a.ref = ? AND a.project_key IN (
			SELECT CASE WHEN org_project_id <> '' THEN org_project_id ELSE project_identity_hash END
			FROM sec_findings WHERE project_root_hash = ?)
		ORDER BY a.approved_at DESC LIMIT 1`, kind, ref, rootHash).Scan(&at)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("store.SecOrgBaselineApproval: %w", err)
	}
	return at, true, nil
}
