package compile

import (
	"encoding/json"
	"fmt"
)

// OpenCode dialect (spec §13.2): the permission.bash pattern map in
// ~/.config/opencode/opencode.json, values allow/ask/deny. OpenCode
// resolves overlapping patterns LAST-match-wins — inverted from every
// first-match dialect, and exactly the misconfiguration trap §13.2
// names: a hand-added specific rule placed before a generic one is
// silently dead. The compiler therefore appends managed entries AFTER
// all user entries (jsonObj.set appends new keys at the end), so a
// managed ask/deny wins over an earlier user allow — the policy-floor
// behavior (§4.6) expressed in emission order.
//
// Scope: bash command patterns only. permission.edit in this dialect
// is all-or-nothing (no per-path patterns), so the file-access rules
// (R-15x/R-160/R-304) are NOT compiled here — denying every edit to
// express "deny ~/.ssh writes" would be the over-blocking this
// package's discipline forbids; each None row says so.

// openCodeRows is the per-rule translation table — ONE row per
// built-in catalog rule ID, in catalog order (completeness pinned by
// TestTableCoversCatalog).
func openCodeRows() []Translation {
	noFileRules := "file-access permissioning in this dialect is all-or-nothing (permission.edit has no per-path patterns); compiling it would block every edit"
	return []Translation{
		{
			RuleID: "R-101", Fidelity: FidelityApprox,
			Note: "command patterns cannot see the target's scope, so the entries match EVERY recursive delete with arguments; broadened entries are demoted from deny to ask",
			Entries: []Entry{
				{Action: ActionAsk, Value: "rm -rf *"},
				{Action: ActionAsk, Value: "rm -fr *"},
			},
		},
		{
			RuleID: "R-102", Fidelity: FidelityApprox,
			Note: "same native surface as R-101; the shared entries dedup at compile time",
			Entries: []Entry{
				{Action: ActionAsk, Value: "rm -rf *"},
				{Action: ActionAsk, Value: "rm -fr *"},
			},
		},
		{
			RuleID: "R-103", Fidelity: FidelityNone,
			Note: "trigger tokens (find ... -delete, xargs rm) sit mid-command; an infix wildcard pattern would over-match unrelated pipelines",
		},
		{
			RuleID: "R-104", Fidelity: FidelityApprox,
			Note: "partial: the `git checkout --` arm is omitted (its pattern would also match every long flag); reset --hard and clean -f arms mirror the rule trigger",
			Entries: []Entry{
				{Action: ActionAsk, Value: "git reset --hard*"},
				{Action: ActionAsk, Value: "git clean -f*"},
			},
		},
		{
			RuleID: "R-110", Fidelity: FidelityApprox,
			Note: "the --force* pattern also matches --force-with-lease (which the rule allows) and no pattern checks protected-branch names, so the broadened entries are demoted from deny to ask",
			Entries: []Entry{
				{Action: ActionAsk, Value: "git push --force*"},
				{Action: ActionAsk, Value: "git push -f *"},
			},
		},
		{
			RuleID: "R-111", Fidelity: FidelityApprox,
			Note: "broadened: prompts on every branch/tag deletion, not just protected patterns",
			Entries: []Entry{
				{Action: ActionAsk, Value: "git branch -D *"},
				{Action: ActionAsk, Value: "git tag -d *"},
			},
		},
		{
			RuleID: "R-120", Fidelity: FidelityNone,
			Note: "destructive SQL verbs sit inside database-CLI arguments and heredocs, not in a command-prefix pattern",
		},
		{
			RuleID: "R-130", Fidelity: FidelityApprox,
			Note: "partial: kubectl delete --all, gcloud ... delete and aws s3 rm --recursive carry their destructive flags mid-command and are omitted; the emitted arms mirror the rule trigger",
			Entries: []Entry{
				{Action: ActionAsk, Value: "terraform destroy*"},
				{Action: ActionAsk, Value: "aws ec2 terminate-instances*"},
				{Action: ActionAsk, Value: "helm uninstall*"},
			},
		},
		{
			RuleID: "R-140", Fidelity: FidelityExact,
			Note: "publish commands are identified by their prefix exactly as the rule trigger is",
			Entries: []Entry{
				{Action: ActionAsk, Value: "npm publish*"},
				{Action: ActionAsk, Value: "cargo publish*"},
				{Action: ActionAsk, Value: "gem push*"},
				{Action: ActionAsk, Value: "twine upload*"},
			},
		},
		{
			RuleID: "R-141", Fidelity: FidelityApprox,
			Note: "partial: the chown -R outside-project arm needs path scope the dialect lacks; chmod -R 777 mirrors the rule trigger",
			Entries: []Entry{
				{Action: ActionAsk, Value: "chmod -R 777 *"},
			},
		},
		{
			RuleID: "R-142", Fidelity: FidelityApprox,
			Note: "partial: dd-to-device and bare `format` arms are omitted; mkfs/diskpart patterns are exact subsets of the rule, so they keep deny",
			Entries: []Entry{
				{Action: ActionDeny, Value: "mkfs*"},
				{Action: ActionDeny, Value: "diskpart*"},
			},
		},
		{RuleID: "R-150", Fidelity: FidelityNone, Note: noFileRules},
		{RuleID: "R-151", Fidelity: FidelityNone, Note: noFileRules},
		{RuleID: "R-152", Fidelity: FidelityNone, Note: noFileRules},
		{RuleID: "R-153", Fidelity: FidelityNone, Note: noFileRules},
		{
			RuleID: "R-154", Fidelity: FidelityNone,
			Note: "rc-file writes are redirections (echo >> ~/.bashrc), not command prefixes; " + noFileRules,
		},
		{
			RuleID: "R-155", Fidelity: FidelityApprox,
			Note: "crontab arm only, demoted to ask (crontab -l is a read); path arms: " + noFileRules,
			Entries: []Entry{
				{Action: ActionAsk, Value: "crontab *"},
			},
		},
		{RuleID: "R-156", Fidelity: FidelityNone, Note: noFileRules},
		{
			RuleID: "R-157", Fidelity: FidelityNone,
			Note: "R-157 is a PARSER-STATE rule (a wrapper whose inner command could not be analysed), not a command or path shape: there is nothing for a native prefix/glob to match, and the fail-closed decision depends on how far OUR parser got. Stays hook-enforced.",
		},
		{RuleID: "R-160", Fidelity: FidelityNone, Note: noFileRules},
		{
			RuleID: "R-161", Fidelity: FidelityNone,
			Note: "flag-only rule: the native dialect has no record-but-allow action",
		},
		{
			RuleID: "R-170", Fidelity: FidelityNone,
			Note: "the pipe-to-interpreter shape sits mid-command; a curl/wget prefix pattern would gate every download",
		},
		{
			RuleID: "R-171", Fidelity: FidelityNone,
			Note: "upload flags and remote destinations sit mid-command",
		},
		{
			RuleID: "R-172", Fidelity: FidelityNone,
			Note: "content detection (typed secret detectors), not command-shape",
		},
		{
			RuleID: "R-190", Fidelity: FidelityNone,
			Note: "content detection (typed PII detectors over the developer's own prompt text), not command-shape; the reconsider-once mode vocabulary lives in [guard.prompt], not the native dialect",
		},
		{
			RuleID: "R-173", Fidelity: FidelityNone,
			Note: "flag-only rule; encoded-subdomain grading is content analysis",
		},
		{
			RuleID: "R-180", Fidelity: FidelityNone,
			Note: "flag-only rule over inbound content; native dialects act on tool calls",
		},
		{
			RuleID: "R-204", Fidelity: FidelityNone,
			Note: "meta-rule about the compiled artifacts themselves; flag-only",
		},
		{
			RuleID: "R-205", Fidelity: FidelityNone,
			Note: "org bundle integrity check at the fetch seam; not a tool-call shape",
		},
		{RuleID: "R-301", Fidelity: FidelityNone, Note: "config-scan finding (pin diff), not a tool-call shape"},
		{RuleID: "R-302", Fidelity: FidelityNone, Note: "config-scan finding (pin diff), not a tool-call shape"},
		{RuleID: "R-303", Fidelity: FidelityNone, Note: "tool-description content heuristic, not a tool-call shape"},
		{
			RuleID: "R-304", Fidelity: FidelityNone,
			Note: "MCP registry writes are file accesses; " + noFileRules,
		},
		{RuleID: "R-305", Fidelity: FidelityNone, Note: "config-scan finding (pin diff), not a tool-call shape"},
		{RuleID: "T-501", Fidelity: FidelityNone, Note: "session taint is runtime state; no static native expression"},
		{RuleID: "T-502", Fidelity: FidelityNone, Note: "session taint is runtime state; no static native expression"},
		{RuleID: "T-503", Fidelity: FidelityNone, Note: "session taint is runtime state; no static native expression"},
		{RuleID: "T-504", Fidelity: FidelityNone, Note: "session taint is runtime state; no static native expression"},
		{RuleID: "T-505", Fidelity: FidelityNone, Note: "session taint is runtime state; no static native expression"},
		{RuleID: "B-601", Fidelity: FidelityNone, Note: "session spend is runtime state; budget enforcement is the proxy's (§12.1 hard mode)"},
		{RuleID: "B-602", Fidelity: FidelityNone, Note: "daily spend is runtime state; budget enforcement is the proxy's (§12.1 hard mode)"},
		{RuleID: "B-603", Fidelity: FidelityNone, Note: "monthly spend is runtime state; budget enforcement is the proxy's (§12.1 hard mode)"},
		{RuleID: "B-604", Fidelity: FidelityNone, Note: "weekly spend is runtime state; budget enforcement is the proxy's (§12.1 hard mode)"},
		{RuleID: "B-621", Fidelity: FidelityNone, Note: "session token usage is runtime state; budget enforcement is the proxy's (§12.1 hard mode)"},
		{RuleID: "B-622", Fidelity: FidelityNone, Note: "daily token usage is runtime state; budget enforcement is the proxy's (§12.1 hard mode)"},
		{RuleID: "B-623", Fidelity: FidelityNone, Note: "monthly token usage is runtime state; budget enforcement is the proxy's (§12.1 hard mode)"},
		{RuleID: "B-624", Fidelity: FidelityNone, Note: "weekly token usage is runtime state; budget enforcement is the proxy's (§12.1 hard mode)"},
		{RuleID: "B-625", Fidelity: FidelityNone, Note: "whether the organization's budget ever verified is daemon state; the refusal is the proxy's (org-budget ruling R2)"},
		{RuleID: "B-626", Fidelity: FidelityNone, Note: "per-tool budget caps are ORGANIZATION policy evaluated against runtime spend; no native dialect can express them and the enforcement is the proxy's and the process controller's (bundle BUD-N)"},
		{RuleID: "B-627", Fidelity: FidelityNone, Note: "per-tool budget caps are ORGANIZATION policy evaluated against runtime spend; no native dialect can express them and the enforcement is the proxy's and the process controller's (bundle BUD-N)"},
		{RuleID: "B-628", Fidelity: FidelityNone, Note: "per-model budget caps are ORGANIZATION policy evaluated against runtime spend; no native dialect can express them and the enforcement is the proxy's and the process controller's (bundle BUD-N)"},
		{RuleID: "B-629", Fidelity: FidelityNone, Note: "per-model budget caps are ORGANIZATION policy evaluated against runtime spend; no native dialect can express them and the enforcement is the proxy's and the process controller's (bundle BUD-N)"},
		{RuleID: "B-610", Fidelity: FidelityNone, Note: "5h usage-window utilization is runtime state; limit enforcement is the proxy's (§12.1)"},
		{RuleID: "B-611", Fidelity: FidelityNone, Note: "5h usage-window utilization is runtime state; limit enforcement is the proxy's (§12.1)"},
		{RuleID: "B-612", Fidelity: FidelityNone, Note: "weekly usage-window utilization is runtime state; limit enforcement is the proxy's (§12.1)"},
		{RuleID: "B-613", Fidelity: FidelityNone, Note: "weekly usage-window utilization is runtime state; limit enforcement is the proxy's (§12.1)"},
		{RuleID: "A-610", Fidelity: FidelityNone, Note: "repeat tracking is runtime state; anomaly rules never block (§12.2)"},
	}
}

// openCodeUniverse is every bash pattern the table can emit — the
// managed-entry recognition set for permission.bash keys.
func openCodeUniverse() map[string]bool {
	u := map[string]bool{}
	for _, row := range openCodeRows() {
		for _, e := range row.Entries {
			u[e.Value] = true
		}
	}
	return u
}

// applyOpenCode merges want into the opencode.json permission.bash
// map. User keys keep their values AND their order; managed keys the
// policy no longer wants are removed; new managed keys append AFTER
// every existing key (last-match-wins: appended entries take
// precedence — the §13.2 ordering inversion this dialect demands). A
// string-valued permission.bash (a global default such as "ask")
// converts to {"*": <default>, <managed>...}, preserving its meaning
// for non-matching commands. A managed key the user re-pointed at a
// different action is set back (policy floor; recorded in Added).
func applyOpenCode(existing []byte, want []Entry) (ApplyResult, error) {
	root, err := parseJSONObj(existing)
	if err != nil {
		return ApplyResult{}, fmt.Errorf("compile.applyOpenCode: %w", err)
	}
	perm := &jsonObj{}
	if raw, ok := root.get("permission"); ok {
		if perm, err = parseJSONObj(raw); err != nil {
			return ApplyResult{}, fmt.Errorf("compile.applyOpenCode: permission: %w", err)
		}
	}

	bash := &jsonObj{}
	converted := false
	if raw, ok := perm.get("bash"); ok {
		var global string
		if err := json.Unmarshal(raw, &global); err == nil {
			// String form: only convert when we actually have entries
			// to install; an empty want leaves the file untouched.
			if len(want) > 0 {
				gb, _ := json.Marshal(global)
				bash.set("*", gb)
				converted = true
			}
		} else if bash, err = parseJSONObj(raw); err != nil {
			return ApplyResult{}, fmt.Errorf("compile.applyOpenCode: permission.bash: %w", err)
		}
	}

	universe := openCodeUniverse()
	wantAction := map[string]string{}
	order := make([]string, 0, len(want))
	for _, e := range want {
		if _, ok := wantAction[e.Value]; !ok {
			order = append(order, e.Value)
		}
		wantAction[e.Value] = e.Action
	}

	var res ApplyResult
	changed := converted
	for _, key := range bash.keys() {
		if !universe[key] {
			continue
		}
		if _, wanted := wantAction[key]; !wanted {
			var prev string
			if raw, ok := bash.get(key); ok {
				_ = json.Unmarshal(raw, &prev)
			}
			bash.remove(key)
			res.Removed = append(res.Removed, Entry{Action: prev, Value: key})
			changed = true
		}
	}
	for _, key := range order {
		action := wantAction[key]
		if raw, ok := bash.get(key); ok {
			var current string
			if err := json.Unmarshal(raw, &current); err == nil && current == action {
				continue
			}
		}
		ab, _ := json.Marshal(action)
		bash.set(key, ab)
		res.Added = append(res.Added, Entry{Action: action, Value: key})
		changed = true
	}
	if !changed {
		return res, nil
	}
	perm.set("bash", bash.encode(""))
	root.set("permission", perm.encode(""))
	res.Updated = append(root.encode(""), '\n')
	return res, nil
}
