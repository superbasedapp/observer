//go:build !sbo_omit_security

package dashboard

import (
	"fmt"
	"net/http"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// security_orgnotice.go serves GET /api/security/org-notice, the node's
// affected-worker notice (security plan 7.12, lane SEC-E3): while an org
// security floor is in force or code security sharing is on, the dashboard
// shows what is shared with the organization, the purpose the organization
// stated for it and, under operator ruling P-089, what the organization's
// views can see under its current settings, stated plainly: it is
// information, not a privacy promise. The "Not for evaluating" line appears
// only when the organization chose to show it. It reads only this node's own
// state (Options.SecurityOrgShare) and what the last push response carried
// (stored in schema_meta); it sends nothing.

// securityNoticeShared is the closed "what is shared" text, one row per
// condition, walked top-down (CLAUDE.md rule 5).
var securityNoticeShared = []struct {
	when func(level string, managed, floors bool) bool
	line string
}{
	{
		func(l string, _, _ bool) bool {
			return l == orgcontract.SecuritySharePosture || l == orgcontract.SecurityShareFindings
		},
		"Daily counts of code security findings by category, severity and status, and which security checks run here.",
	},
	{
		func(l string, _, _ bool) bool { return l == orgcontract.SecurityShareFindings },
		"Each finding's rule, category, severity and status, and the session and AI agent it is associated with.",
	},
	{
		func(l string, managed, _ bool) bool { return l == orgcontract.SecurityShareFindings && managed },
		"On this organization-managed machine, each finding's file path, lines and a masked excerpt (a secret's value is never sent).",
	},
	{
		func(_ string, _, floors bool) bool { return floors },
		"Your organization sets minimum security checks on this machine (a security floor).",
	},
}

// securityOrgNoticeJS is the notice's body.
type securityOrgNoticeJS struct {
	Active  bool     `json:"active"`
	Shared  []string `json:"shared"`
	Purpose string   `json:"purpose"`
	// PurposeStated is false while the organization has not chosen one (or
	// this node has not heard it yet).
	PurposeStated bool `json:"purpose_stated"`
	// OrgSees states what the organization's views can see under its
	// current settings (P-089), from this node's own sentence table.
	OrgSees []string `json:"org_sees"`
	// NotFor is the organization's optional purpose statement, "" unless
	// it chose to show it.
	NotFor string `json:"not_for"`
}

// orgSeesLines states what the organization's views can see under v (P-089)
// for a node at share level: one sentence per switched-on field (findings
// sharing only, where per-finding rows reach the org), the minimum group and
// a closing sentence that this is information, not a promise. ok is false
// while no push response carried the settings yet.
func orgSeesLines(v orgcontract.SecurityVisibility, ok bool, level string) []string {
	if !ok {
		return []string{"Your organization has not yet told this machine what its security views show."}
	}
	hidden := map[string]bool{}
	for _, f := range v.HiddenFields {
		hidden[f] = true
	}
	var out []string
	if level == orgcontract.SecurityShareFindings {
		for _, f := range orgcontract.SecurityVisibilityFields {
			if !hidden[f.ID] {
				out = append(out, "Your organization can see "+f.Shows+".")
			}
		}
	}
	if v.MinGroup <= 1 {
		out = append(out, "Your organization's views hide no group however small, so a finding on this machine can be singled out.")
	} else {
		out = append(out, fmt.Sprintf("Your organization's grouped views hide groups of fewer than %d members.", v.MinGroup))
	}
	return append(out, "This describes your organization's current settings, which it can change at any time; it is information, not a privacy promise.")
}

// handleSecurityOrgNotice serves GET /api/security/org-notice.
func (s *Server) handleSecurityOrgNotice(w http.ResponseWriter, r *http.Request) {
	out := securityOrgNoticeJS{Shared: []string{}, OrgSees: []string{}}
	read := s.opts.SecurityOrgShare
	if read == nil {
		writeJSON(w, out)
		return
	}
	share, ok := read(r.Context())
	if !ok {
		writeJSON(w, out)
		return
	}
	for _, row := range securityNoticeShared {
		if row.when(share.Level, share.Managed, share.FloorsInForce) {
			out.Shared = append(out.Shared, row.line)
		}
	}
	out.Active = len(out.Shared) > 0
	if out.Active {
		st := store.New(s.db())
		if id, err := st.SecurityOrgPurpose(r.Context()); err == nil {
			if label := orgcontract.SecurityPurposeLabel(id); label != "" {
				out.Purpose, out.PurposeStated = label, true
			}
		}
		v, ok, err := st.SecurityOrgVisibility(r.Context())
		ok = ok && err == nil
		out.OrgSees = orgSeesLines(v, ok, share.Level)
		if ok && v.PurposeStatement {
			out.NotFor = orgcontract.SecurityNotForEvaluationLine
		}
	}
	writeJSON(w, out)
}
