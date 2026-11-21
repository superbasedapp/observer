package diag

import (
	"runtime"
	"slices"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/remedy"
)

// IBM Bob administrator policy, the two 2026-10-24 decisions (AP-135):
// EnforcedHooks carrying Observer's Bob hooks on an org-managed node (with
// the per-node registration standing down), and EnableTelemetry. The hook
// package owns the reading and the coverage rule (internal/hook/
// ibmbob_policy.go); these notes only report what it decides, so the doctor
// and `observer init` cannot disagree.

// checkIBMBobTeamsPolicy is ibm-bob-teams on Windows and macOS, where the
// policy lives in the registry (HKLM) or a managed-preferences plist. dom is
// what Bob's macOS preferences domains (FU-105), or its Windows HKLM and
// HKCU policy keys (FU-115), carry by key name: a key the user's own domain
// or the per-user HKCU key sets is reported as user-set, never as
// administrator policy, and never changes the stand-down reading above it.
func checkIBMBobTeamsPolicy(cfg config.Config, pol hook.IBMBobPolicy, dom hook.IBMBobPolicyDomains, home string) Check {
	const name = "ibm-bob-teams"
	var details []string
	worst := StatusOK
	note := func(s Status, msg string) {
		details = append(details, msg)
		if s > worst {
			worst = s
		}
	}
	if !pol.Found {
		where := "HKLM\\SOFTWARE\\Policies\\IBM\\Bob"
		if runtime.GOOS == "darwin" {
			where = "/Library/Managed Preferences/com.ibm.bob.plist"
		}
		msg := "ibm bob policy not deployed (" + where + ") - run `observer org emit-managed-settings --provider ibm-bob` to generate it"
		if !noteBobUserDomain(cfg, dom, note) {
			return Check{Name: name, Status: StatusOK, Message: msg}
		}
		msg = "ibm bob administrator policy not deployed (" + where + "), but Bob applies policy keys from " + bobUserSourcePhrase(dom) + " - see below"
		return Check{Name: name, Status: worst, Message: msg, Details: details}
	}
	if pol.OtelExport {
		note(StatusOK, "OtelConfiguration names an OTLP endpoint ("+pol.Source+"); the endpoint is not probed on this OS")
	} else {
		note(StatusOK, "policy present without a usable OtelConfiguration - Bob's OTLP export is not policy-managed")
	}
	noteBobPolicyTelemetry(pol, note)
	rems := noteBobPolicyHooks(pol, home, note)
	noteBobPolicyGateway(pol, note)
	noteBobUserDomain(cfg, dom, note)
	msg := "ibm bob policy deployed - all checks passed"
	if worst != StatusOK {
		msg = "ibm bob policy deployed - see warnings below"
	}
	return Check{Name: name, Status: worst, Message: msg, Details: details, Remediations: rems}
}

// bobNodeManaged reports whether this node is org-managed as the doctor
// sees it: the daemon's org lock says managed, or the node's config is
// admin-provisioned (native console).
func bobNodeManaged(cfg config.Config) bool {
	return cfg.Guard.Lock.Managed || cfg.OrgClient.Share.AdminManaged
}

// noteBobUserDomain reports the Bob policy keys the user's own com.ibm.bob
// preferences domain sets (FU-105), by name only, and whether it noted
// anything. Bob applies them as policy, but the user can write them, so they
// are named "user-set, not tamper-proof". It is a WARN on an org-managed
// node, where the user can extend (or try to shadow) the organization's
// policy and the managed-integrity report carries
// ibm-bob/user_policy_override; on an individual node it is informational,
// because there is no administrator policy to undermine and the user is the
// only authority.
func noteBobUserDomain(cfg config.Config, dom hook.IBMBobPolicyDomains, note func(Status, string)) bool {
	if dom.UserProblem == "" && len(dom.UserKeys) == 0 {
		return false
	}
	status, scope := StatusOK, "individual node: informational, the user is the only authority here"
	if bobNodeManaged(cfg) {
		status, scope = StatusWarn, "org-managed node: reported to the organization as ibm-bob/user_policy_override"
	}
	if dom.UserProblem != "" {
		what := "the user's own com.ibm.bob preferences domain"
		if dom.UserIsRegistry() {
			what = "the per-user policy key " + dom.UserSource
		}
		note(status, what+" exists but was not read ("+dom.UserProblem+"); whether it sets Bob policy keys is unknown ("+scope+")")
		return true
	}
	var added, shadow []string
	for _, k := range dom.UserKeys {
		if dom.AdminAlsoSets(k) {
			shadow = append(shadow, k)
		} else {
			added = append(added, k)
		}
	}
	if len(added) > 0 {
		note(status, "Bob applies "+strings.Join(added, ", ")+" from "+bobUserSourcePhrase(dom)+" ("+dom.UserSource+") as policy: user-set, not tamper-proof, never administrator policy ("+scope+")")
	}
	if len(shadow) > 0 {
		if dom.UserIsRegistry() {
			// FU-206: EnforcedHooks' precedence is live-grounded (HKLM
			// wins whenever it sets the key); every other key's is not.
			var other []string
			for _, k := range shadow {
				if k == hook.IBMBobPolicyEnforcedHooks {
					note(status, "the per-user policy key ("+dom.UserSource+") also sets EnforcedHooks, which the administrator's "+hook.IBMBobHKLMPolicySource+" key sets: "+hook.IBMBobEnforcedHooksPrecedence+", so the per-user hooks do not run while the administrator's key sets it ("+scope+")")
					continue
				}
				other = append(other, k)
			}
			if len(other) > 0 {
				note(status, "the per-user policy key ("+dom.UserSource+") also sets "+strings.Join(other, ", ")+", which the administrator's "+hook.IBMBobHKLMPolicySource+" key sets; which value Bob applies is not verified live, and the user-set copy is not tamper-proof ("+scope+")")
			}
		} else {
			note(status, "the user's own preferences domain ("+dom.UserSource+") also sets "+strings.Join(shadow, ", ")+", which the administrator's managed plist sets; the managed value is expected to win (CFPreferences forced precedence, not verified live on Bob), but the user-set copy is not tamper-proof ("+scope+")")
		}
	}
	if slices.Contains(dom.UserKeys, hook.IBMBobPolicyEnforcedHooks) && !(dom.UserIsRegistry() && slices.Contains(shadow, hook.IBMBobPolicyEnforcedHooks)) {
		note(status, "EnforcedHooks in "+dom.UserSource+" is user-level, not machine-enforced: Bob runs those hooks, but the user can change or remove them, and Observer never stands its per-node Bob hooks down for them (an Observer hook placed there fires twice)")
	}
	return true
}

// bobUserSourcePhrase names the user-writable Bob policy source in a
// sentence: the macOS preferences domain, or the Windows per-user (HKCU)
// policy key (FU-115).
func bobUserSourcePhrase(dom hook.IBMBobPolicyDomains) string {
	if dom.UserIsRegistry() {
		return "the per-user policy key"
	}
	return "the user's own preferences domain"
}

// noteBobPolicyTelemetry reports EnableTelemetry. Bob gates every telemetry
// client, the OTLP export to Observer included, on it (bobshell 2.0.6), so
// false together with an OtelConfiguration endpoint silences that export.
func noteBobPolicyTelemetry(pol hook.IBMBobPolicy, note func(Status, string)) {
	switch {
	case pol.EnableTelemetry == nil:
		return
	case *pol.EnableTelemetry:
		note(StatusOK, "EnableTelemetry is true - Bob's own telemetry to IBM stays on")
	case pol.OtelExport:
		note(StatusWarn, "EnableTelemetry is false AND OtelConfiguration is set - Bob gates every telemetry client on that one setting, so the OTLP export to Observer is silenced too; drop one of them")
	default:
		note(StatusOK, "EnableTelemetry is false - Bob's own telemetry to IBM is off (Bobalytics loses this node)")
	}
}

// noteBobPolicyGateway reports a GatewayUrl the policy locks (S-19). It
// overrides BOB_GATEWAY_URL, so it decides Bob's inference host; Observer
// emits none, because no Bob proxy route is grounded yet (the registry row
// is probe_required: the same base serves /admin/v1, which a route has to
// pass through). Informational: it is the administrator's choice.
func noteBobPolicyGateway(pol hook.IBMBobPolicy, note func(Status, string)) {
	if pol.GatewayURL == "" {
		return
	}
	note(StatusOK, "GatewayUrl locks Bob's inference host to "+pol.GatewayURL+" ("+pol.Source+"); it overrides BOB_GATEWAY_URL, "+
		"so any per-node route to Observer's proxy is ignored while it is set (Observer emits no GatewayUrl: no Bob route is grounded yet)")
}

// noteBobPolicyHooks reports whether EnforcedHooks carries Observer's Bob
// hooks and whether the per-node registration under home stood down. It
// returns the structured fixes for what it reported (the Remove panel when
// per-node entries are left beside the policy's).
func noteBobPolicyHooks(pol hook.IBMBobPolicy, home string, note func(Status, string)) []remedy.Remediation {
	if pol.EnforcedHooks == nil && !pol.EnforcedHooksWrongType {
		note(StatusOK, "no EnforcedHooks - Observer's Bob hooks are registered per node (`observer init` / `observer start`)")
		return nil
	}
	var rems []remedy.Remediation
	events := hook.IBMBobHookEvents()
	cov := pol.Coverage(events)
	var left []string
	if home != "" {
		left, _ = hook.IBMBobUserHookEvents(home)
	}
	switch {
	case cov.Problem != "":
		note(StatusWarn, "EnforcedHooks is present but not relied on: "+cov.Problem+" - Observer registers its Bob hooks per node, so if Bob runs the policy hooks every event fires twice")
	case len(cov.Covered) == 0:
		note(StatusOK, "EnforcedHooks carries no Observer hook - Observer's Bob hooks are registered per node")
	case !cov.Complete():
		note(StatusWarn, "EnforcedHooks carries Observer's hooks for "+strings.Join(cov.Covered, ", ")+" but not "+strings.Join(cov.Missing, ", ")+" - the per-node registration writes only the missing events")
	default:
		note(StatusOK, "EnforcedHooks carries Observer's Bob hooks ("+strings.Join(cov.Covered, ", ")+")")
		if missing := hook.IBMBobPolicyBinaryMissing(cov.Commands); len(missing) > 0 {
			note(StatusWarn, "the policy hook command "+strings.Join(missing, ", ")+" does not resolve to a runnable observer for this process - Bob runs it with its own PATH; if it is missing there too the policy hooks fail and nothing gates (put observer on PATH, or regenerate with --hook-binary)")
		}
		if len(left) > 0 {
			note(StatusWarn, "~/.bob/settings/settings.json still holds Observer's per-node entries for "+strings.Join(left, ", ")+" - Bob runs both, so those events fire twice; remove them (Remove Observer's wiring from ibm-bob in Settings > Connected tools) and the registration stays stood down")
			rems = append(rems, remedy.Of(remedy.UninstallTool, models.ToolIBMBob))
		} else {
			note(StatusOK, "per-node ibm-bob hook registration stood down (no Observer entry in ~/.bob/settings/settings.json)")
		}
	}
	return rems
}

// systemFileUntrusted mirrors the hook package's trust rule for a policy
// file: root-owned and not writable by group or others (unix only).
func systemFileUntrusted(path string) string {
	untrusted := ""
	noteSystemFile(path, func(_ Status, msg string) {
		if untrusted == "" {
			untrusted = msg
		}
	})
	return untrusted
}
