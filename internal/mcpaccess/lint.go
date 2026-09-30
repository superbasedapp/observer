package mcpaccess

import (
	"fmt"
	"strings"
)

// Severity of a lint problem.
type Severity string

// Severities. An error refuses compilation; a warning is reported and
// compilation proceeds.
const (
	SeverityError Severity = "error"
	SeverityWarn  Severity = "warn"
)

// Problem codes (the closed vocabulary the dashboard and the CLI render).
const (
	// CodeFeatureUnavailable: judge effect / taint / requires_mfa (R8.1).
	CodeFeatureUnavailable = "feature_unavailable"
	// CodeUnknownAction: action outside the enumerated set.
	CodeUnknownAction = "unknown_action"
	// CodeWildcardAction: a "*" (or empty) action - NO wildcard (R8.30.g).
	CodeWildcardAction = "wildcard_action"
	// CodeUnknownEffect: effect outside allow|deny|ask|judge.
	CodeUnknownEffect = "unknown_effect"
	// CodeUnsupportedSubjectKind: a selector no minted claim carries.
	CodeUnsupportedSubjectKind = "unsupported_subject_kind"
	// CodeSubjectValueRequired: a non-any selector without a value.
	CodeSubjectValueRequired = "subject_value_required"
	// CodeInvalidSubjectValue: a selector value malformed for its kind (a
	// project value that is not a project hash, an over-long team id).
	CodeInvalidSubjectValue = "invalid_subject_value"
	// CodeUnknownVServer: the grant names a vserver the registry lacks.
	CodeUnknownVServer = "unknown_vserver"
	// CodeUnknownServer: the grant names a server not in that vserver.
	CodeUnknownServer = "unknown_server"
	// CodeUnknownRank: an assurance / attestation floor outside the ranks.
	CodeUnknownRank = "unknown_rank"
	// CodeConditionOnDeny: a floor condition on a deny grant (a deny must be
	// a positive, unconditional predicate - R6).
	CodeConditionOnDeny = "condition_on_deny"
	// CodePassthroughOnNonBearer: credential_mode=passthrough on a vserver
	// whose sender_constraint is not bearer (R14.11) - ERROR.
	CodePassthroughOnNonBearer = "passthrough_on_non_bearer"
	// CodeInvalidRegistry: issuer / org / policy_gen / vserver shape errors.
	CodeInvalidRegistry = "invalid_registry"
	// CodeDuplicateGrant: two grants share an id.
	CodeDuplicateGrant = "duplicate_grant"
	// CodeUnknownAuditClass: audit_class outside normal|strict.
	CodeUnknownAuditClass = "unknown_audit_class"
	// CodeEmptyGrantSet: no enabled grant remains - the policy compiles to
	// deny-all (WARN).
	CodeEmptyGrantSet = "empty_grant_set"
	// CodeExpiredGrant: the grant's expires_at is in the past (WARN; dropped).
	CodeExpiredGrant = "expired_grant"
	// CodeDisabledGrant: enabled=false (WARN; dropped).
	CodeDisabledGrant = "disabled_grant"
	// CodeDenyOnlySet: only deny grants remain; the CEL sentinel keeps the
	// policy default-deny (WARN, informational).
	CodeDenyOnlySet = "deny_only_set"
	// CodeUnapprovedToolName: a snapshot-scoped grant names a tool that no
	// member it can reach approves (every candidate carries an approved
	// snapshot and none lists the name). The grant compiles but cannot match
	// until a snapshot listing the tool is adopted (WARN, R9.8).
	CodeUnapprovedToolName = "unapproved_tool_name"
)

// taskUnavailableMessage is the typed refusal of a task-action grant. It
// names the verified reason (no agentgateway-visible method discriminator)
// and what still governs tasks: the A2 front dispatches tasks/get, tasks/update
// and tasks/cancel natively (subject-bound task lookup + the PDP method
// table) and, with no task grant compilable, default-denies them in enforce
// mode.
const taskUnavailableMessage = "task-action grants are feature_unavailable in v1: the pinned agentgateway v1.5.0 evaluates " +
	"mcpAuthorization over mcp.task{target,name} only (McpAuthorizationSet::validate builds MCPInfo::from(&ResourceType) with " +
	"method_name None, and tasks/get, tasks/update and tasks/cancel share one authorize_task_request), so no CEL rule can " +
	"distinguish the three actions and a grant on one would silently widen to all three (R8.30.g); every compiler refuses " +
	"it identically (R8.1). The A2 front still dispatches tasks/get|update|cancel natively (subject-bound task binding + the " +
	"PDP method table) and default-denies them in enforce mode until agentgateway exposes the request method to CEL"

// Problem is one typed lint finding.
type Problem struct {
	Code     string   `json:"code"`
	Severity Severity `json:"severity"`
	GrantID  string   `json:"grant_id,omitempty"`
	Message  string   `json:"message"`
}

func (p Problem) String() string {
	if p.GrantID != "" {
		return fmt.Sprintf("%s [%s] grant %s: %s", p.Severity, p.Code, p.GrantID, p.Message)
	}
	return fmt.Sprintf("%s [%s]: %s", p.Severity, p.Code, p.Message)
}

// LintError is the typed error a compiler returns when Lint reports at least
// one error-severity problem; Problems carries every finding.
type LintError struct {
	Problems []Problem
}

func (e *LintError) Error() string {
	var errs []string
	for _, p := range e.Problems {
		if p.Severity == SeverityError {
			errs = append(errs, p.String())
		}
	}
	return "mcpaccess: policy does not compile: " + strings.Join(errs, "; ")
}

// HasErrors reports whether any problem is error-severity.
func HasErrors(ps []Problem) bool {
	for _, p := range ps {
		if p.Severity == SeverityError {
			return true
		}
	}
	return false
}

// Has reports whether a problem with code is present.
func Has(ps []Problem, code string) bool {
	for _, p := range ps {
		if p.Code == code {
			return true
		}
	}
	return false
}

// Lint statically checks a Spec and returns every finding (table-driven per
// grant, then the set-level checks). now is the evaluation instant for
// expiry (unix seconds; 0 skips the expiry check).
func Lint(spec Spec, now int64) []Problem {
	var ps []Problem
	ps = append(ps, lintRegistry(spec.Registry)...)
	seen := map[string]bool{}
	live := 0
	denyOnly := true
	for _, g := range spec.Grants {
		gp := lintGrant(g, spec.Registry, now)
		ps = append(ps, gp...)
		if g.ID != "" {
			if seen[g.ID] {
				ps = append(ps, Problem{Code: CodeDuplicateGrant, Severity: SeverityError, GrantID: g.ID, Message: "duplicate grant id"})
			}
			seen[g.ID] = true
		}
		if !HasErrors(gp) && !Has(gp, CodeExpiredGrant) && !Has(gp, CodeDisabledGrant) {
			live++
			if g.Effect != EffectDeny {
				denyOnly = false
			}
		}
	}
	switch {
	case live == 0:
		ps = append(ps, Problem{Code: CodeEmptyGrantSet, Severity: SeverityWarn, Message: "no enabled grant: the policy compiles to deny-all"})
	case denyOnly:
		ps = append(ps, Problem{Code: CodeDenyOnlySet, Severity: SeverityWarn, Message: "only deny grants: nothing is allowed; the deny-all sentinel keeps agentgateway default-deny"})
	}
	return ps
}

func lintRegistry(r Registry) []Problem {
	var ps []Problem
	reg := func(msg string) {
		ps = append(ps, Problem{Code: CodeInvalidRegistry, Severity: SeverityError, Message: msg})
	}
	if strings.TrimSpace(r.Issuer) == "" {
		reg("issuer is required")
	}
	if strings.TrimSpace(r.Org) == "" {
		reg("org is required")
	}
	if r.PolicyGen < 0 {
		reg("policy_gen must not be negative")
	}
	ids := map[string]bool{}
	for _, v := range r.VServers {
		if v.ID == "" {
			reg("vserver without id")
			continue
		}
		if ids[v.ID] {
			reg("duplicate vserver id " + v.ID)
		}
		ids[v.ID] = true
		if v.Slug == "" && v.Audience == "" {
			reg("vserver " + v.ID + ": slug or audience is required")
		}
		for _, s := range v.Servers {
			if s.Snapshot != nil && s.Snapshot.ID == "" {
				reg(fmt.Sprintf("vserver %s server %s: an approved snapshot needs an id", v.ID, s.ID))
			}
		}
		if r.AudienceOf(v) == "/mcp/"+v.Slug {
			reg("vserver " + v.ID + ": audience cannot be derived (no gateway_base_uri)")
		}
		for _, ph := range v.Projects {
			if !ValidSubjectValue(SubjectProject, ph) {
				reg(fmt.Sprintf("vserver %s: declared project %q is not a project hash", v.ID, ph))
			}
		}
		if !contains(SenderConstraints, v.SenderConstraint) {
			reg(fmt.Sprintf("vserver %s: unknown sender_constraint %q", v.ID, v.SenderConstraint))
		}
		for _, s := range v.Servers {
			if s.CredentialMode != "" && !contains(CredentialModes, s.CredentialMode) {
				reg(fmt.Sprintf("vserver %s server %s: unknown credential_mode %q", v.ID, s.ID, s.CredentialMode))
			}
			// R14.11: passthrough forwards the caller's ORIGINAL bearer via
			// x-sbo-orig-authz, which only the normalizing Bearer route
			// populates; a DPoP/mTLS-bound token is unusable upstream by
			// construction.
			if s.CredentialMode == "passthrough" && v.SenderConstraint != "bearer" {
				ps = append(ps, Problem{
					Code: CodePassthroughOnNonBearer, Severity: SeverityError,
					Message: fmt.Sprintf("vserver %s (sender_constraint=%s) member server %s uses credential_mode=passthrough, which is valid only on a bearer vserver (R14.11)", v.ID, v.SenderConstraint, s.ID),
				})
			}
		}
	}
	return ps
}

// grantCheck is one row of the per-grant lint table.
type grantCheck func(g Grant, r Registry, now int64) *Problem

var grantChecks = []grantCheck{
	func(g Grant, _ Registry, _ int64) *Problem {
		if g.ID == "" {
			return &Problem{Code: CodeDuplicateGrant, Severity: SeverityError, Message: "grant without id"}
		}
		return nil
	},
	func(g Grant, _ Registry, _ int64) *Problem {
		if g.Action == "" || g.Action == "*" {
			return &Problem{Code: CodeWildcardAction, Severity: SeverityError, GrantID: g.ID, Message: "action must be one enumerated method class; there is no wildcard (R8.30.g)"}
		}
		if _, ok := actionResource[g.Action]; !ok {
			return &Problem{Code: CodeUnknownAction, Severity: SeverityError, GrantID: g.ID, Message: fmt.Sprintf("unknown action %q", g.Action)}
		}
		return nil
	},
	func(g Grant, _ Registry, _ int64) *Problem {
		if CELUngrantable(g.Action) {
			return &Problem{Code: CodeFeatureUnavailable, Severity: SeverityError, GrantID: g.ID, Message: string(g.Action) + ": " + taskUnavailableMessage}
		}
		return nil
	},
	func(g Grant, _ Registry, _ int64) *Problem {
		switch g.Effect {
		case EffectAllow, EffectDeny, EffectAsk:
			return nil
		case EffectJudge:
			return &Problem{Code: CodeFeatureUnavailable, Severity: SeverityError, GrantID: g.ID, Message: "effect judge is v1.x (P6b); the v1 compilers reject it rather than drop it (R8.1)"}
		}
		return &Problem{Code: CodeUnknownEffect, Severity: SeverityError, GrantID: g.ID, Message: fmt.Sprintf("unknown effect %q", g.Effect)}
	},
	func(g Grant, _ Registry, _ int64) *Problem {
		if g.Conditions.Taint {
			return &Problem{Code: CodeFeatureUnavailable, Severity: SeverityError, GrantID: g.ID, Message: "taint conditions are v1.x (P6b); rejected, not dropped (R8.1)"}
		}
		if g.Conditions.RequiresMFA {
			return &Problem{Code: CodeFeatureUnavailable, Severity: SeverityError, GrantID: g.ID, Message: "requires_mfa needs a fresh user assertion no v1 token carries (R6); rejected, not dropped"}
		}
		return nil
	},
	func(g Grant, _ Registry, _ int64) *Problem {
		if g.Subject.Kind == SubjectAny || g.Subject.Kind == "" {
			return nil
		}
		if _, ok := subjectRule(g.Subject.Kind); !ok {
			return &Problem{Code: CodeUnsupportedSubjectKind, Severity: SeverityError, GrantID: g.ID, Message: fmt.Sprintf("subject kind %q has no minted claim in v1", g.Subject.Kind)}
		}
		if strings.TrimSpace(g.Subject.Value) == "" {
			return &Problem{Code: CodeSubjectValueRequired, Severity: SeverityError, GrantID: g.ID, Message: fmt.Sprintf("subject kind %s needs a value", g.Subject.Kind)}
		}
		if !ValidSubjectValue(g.Subject.Kind, g.Subject.Value) {
			return &Problem{
				Code: CodeInvalidSubjectValue, Severity: SeverityError, GrantID: g.ID,
				Message: fmt.Sprintf("subject %s value %q is malformed (a project value is a 16-64 lowercase-hex project hash; a team id is 1-128 bytes)", g.Subject.Kind, g.Subject.Value),
			}
		}
		return nil
	},
	func(g Grant, r Registry, _ int64) *Problem {
		v, ok := r.VServerByID(g.Resource.VServer)
		if !ok {
			return &Problem{Code: CodeUnknownVServer, Severity: SeverityError, GrantID: g.ID, Message: fmt.Sprintf("vserver %q is not in the registry", g.Resource.VServer)}
		}
		if g.Resource.Server != "" {
			for _, s := range v.Servers {
				if s.ID == g.Resource.Server || s.Target == g.Resource.Server {
					return nil
				}
			}
			return &Problem{Code: CodeUnknownServer, Severity: SeverityError, GrantID: g.ID, Message: fmt.Sprintf("server %q is not a member of vserver %s", g.Resource.Server, v.ID)}
		}
		return nil
	},
	func(g Grant, _ Registry, _ int64) *Problem {
		if f := g.Conditions.RequiresCredAssurance; f != "" && AcceptedAtLeast(CredAssuranceRanks, f) == nil {
			return &Problem{Code: CodeUnknownRank, Severity: SeverityError, GrantID: g.ID, Message: fmt.Sprintf("unknown requires_cred_assurance %q", f)}
		}
		if f := g.Conditions.RequiresClientAttestation; f != "" && AcceptedAtLeast(ClientAttestationRanks, f) == nil {
			return &Problem{Code: CodeUnknownRank, Severity: SeverityError, GrantID: g.ID, Message: fmt.Sprintf("unknown requires_client_attestation %q", f)}
		}
		return nil
	},
	func(g Grant, _ Registry, _ int64) *Problem {
		if g.Effect == EffectDeny && (g.Conditions.RequiresCredAssurance != "" || g.Conditions.RequiresClientAttestation != "") {
			return &Problem{Code: CodeConditionOnDeny, Severity: SeverityError, GrantID: g.ID, Message: "a deny grant must be an unconditional positive predicate (R6); put the assurance floor on the allow grant"}
		}
		return nil
	},
	func(g Grant, r Registry, _ int64) *Problem {
		// R9.8: a named snapshot-scoped grant whose every reachable member is
		// pinned and none approves the name can never match until adopted.
		if !SnapshotScoped(g.Action) || g.Resource.AnyName() {
			return nil
		}
		cands := candidateServers(r, g, EvalInput{})
		if len(cands) == 0 {
			return nil // unknown vserver/server: reported by the registry checks
		}
		for _, s := range cands {
			if !s.Pinned() || s.Snapshot.Approves(g.Resource.Name) {
				return nil
			}
		}
		return &Problem{
			Code: CodeUnapprovedToolName, Severity: SeverityWarn, GrantID: g.ID,
			Message: fmt.Sprintf("tool %q is not in the approved snapshot of any member it can reach; the grant cannot match until a snapshot listing it is adopted (R9.8)", g.Resource.Name),
		}
	},
	func(g Grant, _ Registry, _ int64) *Problem {
		if g.AuditClass != "" && !contains(AuditClasses, g.AuditClass) {
			return &Problem{Code: CodeUnknownAuditClass, Severity: SeverityError, GrantID: g.ID, Message: fmt.Sprintf("unknown audit_class %q", g.AuditClass)}
		}
		return nil
	},
	func(g Grant, _ Registry, _ int64) *Problem {
		if !g.Enabled {
			return &Problem{Code: CodeDisabledGrant, Severity: SeverityWarn, GrantID: g.ID, Message: "grant is disabled and is not compiled"}
		}
		return nil
	},
	func(g Grant, _ Registry, now int64) *Problem {
		if now > 0 && g.Conditions.ExpiresAt > 0 && g.Conditions.ExpiresAt <= now {
			return &Problem{Code: CodeExpiredGrant, Severity: SeverityWarn, GrantID: g.ID, Message: "grant has expired and is not compiled"}
		}
		return nil
	},
}

func lintGrant(g Grant, r Registry, now int64) []Problem {
	var ps []Problem
	for _, check := range grantChecks {
		if p := check(g, r, now); p != nil {
			ps = append(ps, *p)
		}
	}
	return ps
}
