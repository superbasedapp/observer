package compile

import (
	"encoding/json"
	"fmt"
)

// Claude Code dialect (spec §13.2): permissions.deny / permissions.ask
// string arrays in ~/.claude/settings.json. Entry values are Claude
// Code permission rules — Bash(prefix:*) string-prefix matchers for
// commands; Read(...)/Edit(...)/Write(...) gitignore-style path
// matchers for file access (~/ anchors home, **/ matches any depth).
// Deny-first semantics align natively with the policy model, and deny
// rules hold even in the client's bypass-permissions mode — exactly
// the daemon-down backstop §13.2 wants.
//
// applyClaudeCode rewrites the file with register.go's never-clobber
// hygiene: unknown top-level keys, unknown permissions sub-keys
// (allow, additionalDirectories, ...) and user-authored deny/ask
// entries all survive byte-for-byte (modulo re-indentation).

// claudeCodeRows is the per-rule translation table — ONE row per
// built-in catalog rule ID, in catalog order (completeness pinned by
// TestTableCoversCatalog). Read the Notes: every approximation is
// documented in its row, never in prose elsewhere.
func claudeCodeRows() []Translation {
	return []Translation{
		{
			RuleID: "R-101", Fidelity: FidelityApprox,
			Note: "Bash() rules are string-prefix matchers and cannot see the target's scope, so the entries match EVERY recursive delete, not just outside-project/root/home ones; broadened entries are demoted from the rule's deny to ask",
			Entries: []Entry{
				{Action: ActionAsk, Value: "Bash(rm -rf:*)"},
				{Action: ActionAsk, Value: "Bash(rm -fr:*)"},
			},
		},
		{
			RuleID: "R-102", Fidelity: FidelityApprox,
			Note: "same native surface as R-101 — the dialect cannot distinguish in-project VCS-dir deletes from any other recursive delete; the shared entries dedup at compile time",
			Entries: []Entry{
				{Action: ActionAsk, Value: "Bash(rm -rf:*)"},
				{Action: ActionAsk, Value: "Bash(rm -fr:*)"},
			},
		},
		{
			RuleID: "R-103", Fidelity: FidelityNone,
			Note: "trigger tokens (find ... -delete, xargs rm) sit mid-command; Bash() rules only match the command prefix",
		},
		{
			RuleID: "R-104", Fidelity: FidelityApprox,
			Note: "partial: the `git checkout --` arm is omitted (its prefix would also match --track/--detach and every other long flag); reset --hard and clean -f arms are exact prefixes of the rule trigger",
			Entries: []Entry{
				{Action: ActionAsk, Value: "Bash(git reset --hard:*)"},
				{Action: ActionAsk, Value: "Bash(git clean -f:*)"},
			},
		},
		{
			RuleID: "R-110", Fidelity: FidelityApprox,
			Note: "prefix matching can neither exclude --force-with-lease (which the rule allows; its prefix contains --force) nor check protected-branch names, so the broadened entries are demoted from deny to ask",
			Entries: []Entry{
				{Action: ActionAsk, Value: "Bash(git push --force:*)"},
				{Action: ActionAsk, Value: "Bash(git push -f:*)"},
			},
		},
		{
			RuleID: "R-111", Fidelity: FidelityApprox,
			Note: "broadened: prompts on every branch/tag deletion, not just protected patterns (no branch-name matching in the dialect)",
			Entries: []Entry{
				{Action: ActionAsk, Value: "Bash(git branch -D:*)"},
				{Action: ActionAsk, Value: "Bash(git tag -d:*)"},
			},
		},
		{
			RuleID: "R-120", Fidelity: FidelityNone,
			Note: "destructive SQL verbs sit inside database-CLI arguments and heredocs, not at the command prefix",
		},
		{
			RuleID: "R-130", Fidelity: FidelityApprox,
			Note: "partial: kubectl delete --all, gcloud ... delete and aws s3 rm --recursive carry their destructive flags mid-command and are omitted (denying every kubectl delete would over-block); the emitted arms are exact prefixes",
			Entries: []Entry{
				{Action: ActionAsk, Value: "Bash(terraform destroy:*)"},
				{Action: ActionAsk, Value: "Bash(aws ec2 terminate-instances:*)"},
				{Action: ActionAsk, Value: "Bash(helm uninstall:*)"},
			},
		},
		{
			RuleID: "R-140", Fidelity: FidelityExact,
			Note: "publish commands are identified by their prefix exactly as the rule trigger is",
			Entries: []Entry{
				{Action: ActionAsk, Value: "Bash(npm publish:*)"},
				{Action: ActionAsk, Value: "Bash(cargo publish:*)"},
				{Action: ActionAsk, Value: "Bash(gem push:*)"},
				{Action: ActionAsk, Value: "Bash(twine upload:*)"},
			},
		},
		{
			RuleID: "R-141", Fidelity: FidelityApprox,
			Note: "partial: the chown -R outside-project arm needs path scope the dialect lacks; chmod -R 777 is an exact prefix",
			Entries: []Entry{
				{Action: ActionAsk, Value: "Bash(chmod -R 777:*)"},
			},
		},
		{
			RuleID: "R-142", Fidelity: FidelityApprox,
			Note: "partial: dd-to-device (of=/dev/... mid-command) and bare `format` (too generic a prefix) are omitted; mkfs/diskpart prefixes are exact subsets of the rule, so they keep deny",
			Entries: []Entry{
				{Action: ActionDeny, Value: "Bash(mkfs:*)"},
				{Action: ActionDeny, Value: "Bash(diskpart:*)"},
			},
		},
		{
			RuleID: "R-150", Fidelity: FidelityNone,
			Note: "outside-project scoping needs the resolved project root; user-level settings have none",
		},
		{
			RuleID: "R-151", Fidelity: FidelityNone,
			Note: "cross-project bleed detection needs the observed-projects root set — daemon knowledge no static config carries",
		},
		{
			RuleID: "R-152", Fidelity: FidelityApprox,
			Note: "core credential locations only: ~/.npmrc is omitted (the ecosystem legitimately writes it), browser-profile/keychain/wallet dirs are omitted (platform-variable paths); shell-command arms (cat ~/.ssh/id_rsa) stay hook-enforced; both Edit() and Write() rules are emitted to cover every file-modification tool family",
			Entries: []Entry{
				{Action: ActionDeny, Value: "Edit(~/.ssh/**)"},
				{Action: ActionDeny, Value: "Write(~/.ssh/**)"},
				{Action: ActionDeny, Value: "Edit(~/.aws/**)"},
				{Action: ActionDeny, Value: "Write(~/.aws/**)"},
				{Action: ActionDeny, Value: "Edit(~/.gnupg/**)"},
				{Action: ActionDeny, Value: "Write(~/.gnupg/**)"},
				{Action: ActionDeny, Value: "Edit(~/.kube/config)"},
				{Action: ActionDeny, Value: "Write(~/.kube/config)"},
				{Action: ActionDeny, Value: "Edit(~/.netrc)"},
				{Action: ActionDeny, Value: "Write(~/.netrc)"},
				{Action: ActionAsk, Value: "Read(~/.ssh/**)"},
				{Action: ActionAsk, Value: "Read(~/.aws/**)"},
				{Action: ActionAsk, Value: "Read(~/.gnupg/**)"},
				{Action: ActionAsk, Value: "Read(~/.kube/config)"},
				{Action: ActionAsk, Value: "Read(~/.netrc)"},
			},
		},
		{
			RuleID: "R-153", Fidelity: FidelityApprox,
			Note: "Read-tool arm only — interpreter/shell reads (python -c open('.env')) stay hook-enforced (the documented F1 caveat applies on both planes)",
			Entries: []Entry{
				{Action: ActionAsk, Value: "Read(**/.env*)"},
				{Action: ActionAsk, Value: "Read(**/*.pem)"},
				{Action: ActionAsk, Value: "Read(**/*.key)"},
				{Action: ActionAsk, Value: "Read(**/id_rsa*)"},
				{Action: ActionAsk, Value: "Read(**/credentials*.json)"},
			},
		},
		{
			RuleID: "R-154", Fidelity: FidelityApprox,
			Note: "common rc/profile set (bash, zsh, profile, PowerShell profile dirs); shell-command writes (echo >> ~/.bashrc) stay hook-enforced",
			Entries: []Entry{
				{Action: ActionDeny, Value: "Edit(~/.bashrc)"},
				{Action: ActionDeny, Value: "Write(~/.bashrc)"},
				{Action: ActionDeny, Value: "Edit(~/.zshrc)"},
				{Action: ActionDeny, Value: "Write(~/.zshrc)"},
				{Action: ActionDeny, Value: "Edit(~/.profile)"},
				{Action: ActionDeny, Value: "Write(~/.profile)"},
				{Action: ActionDeny, Value: "Edit(~/.bash_profile)"},
				{Action: ActionDeny, Value: "Write(~/.bash_profile)"},
				{Action: ActionDeny, Value: "Edit(~/Documents/WindowsPowerShell/**)"},
				{Action: ActionDeny, Value: "Write(~/Documents/WindowsPowerShell/**)"},
				{Action: ActionDeny, Value: "Edit(~/Documents/PowerShell/**)"},
				{Action: ActionDeny, Value: "Write(~/Documents/PowerShell/**)"},
			},
		},
		{
			RuleID: "R-155", Fidelity: FidelityApprox,
			Note: "systemd-user/LaunchAgents path arms are exact; the crontab command entry is demoted to ask (crontab -l is a read); Run-registry and schtasks arms carry their payload mid-command and are omitted",
			Entries: []Entry{
				{Action: ActionDeny, Value: "Edit(~/.config/systemd/user/**)"},
				{Action: ActionDeny, Value: "Write(~/.config/systemd/user/**)"},
				{Action: ActionDeny, Value: "Edit(~/Library/LaunchAgents/**)"},
				{Action: ActionDeny, Value: "Write(~/Library/LaunchAgents/**)"},
				{Action: ActionAsk, Value: "Bash(crontab:*)"},
			},
		},
		{
			RuleID: "R-156", Fidelity: FidelityApprox,
			Note: "Edit/Write-tool arm only; shell-command writes into .git/hooks stay hook-enforced",
			Entries: []Entry{
				{Action: ActionAsk, Value: "Edit(**/.git/hooks/**)"},
				{Action: ActionAsk, Value: "Write(**/.git/hooks/**)"},
			},
		},
		{
			RuleID: "R-157", Fidelity: FidelityNone,
			Note: "R-157 is a PARSER-STATE rule (a wrapper whose inner command could not be analysed), not a command or path shape: there is nothing for a native prefix/glob to match, and the fail-closed decision depends on how far OUR parser got. Stays hook-enforced.",
		},
		{
			RuleID: "R-160", Fidelity: FidelityApprox,
			Note: "observer config dir plus Claude Code's own settings files (user + project — the **/ form covers both); other clients' hook configs are their own dialects' concern; shell-command arms stay hook-enforced",
			Entries: []Entry{
				{Action: ActionDeny, Value: "Edit(~/.observer/**)"},
				{Action: ActionDeny, Value: "Write(~/.observer/**)"},
				{Action: ActionDeny, Value: "Edit(**/.claude/settings.json)"},
				{Action: ActionDeny, Value: "Write(**/.claude/settings.json)"},
			},
		},
		{
			RuleID: "R-161", Fidelity: FidelityNone,
			Note: "flag-only rule: the native dialect has no record-but-allow action",
		},
		{
			RuleID: "R-170", Fidelity: FidelityNone,
			Note: "the pipe-to-interpreter shape sits mid-command (the pipe); a curl/wget prefix entry would block every download",
		},
		{
			RuleID: "R-171", Fidelity: FidelityNone,
			Note: "upload flags (-d @file, --upload-file) and remote destinations sit mid-command",
		},
		{
			RuleID: "R-172", Fidelity: FidelityNone,
			Note: "content detection (typed secret detectors over arguments/bodies), not command-shape",
		},
		{
			RuleID: "R-190", Fidelity: FidelityNone,
			Note: "content detection (typed PII detectors over the developer's own prompt text), not command-shape; the reconsider-once mode vocabulary lives in [guard.prompt], not the native dialect",
		},
		{
			RuleID: "R-173", Fidelity: FidelityNone,
			Note: "flag-only rule; encoded-subdomain grading is content analysis, not command-shape",
		},
		{
			RuleID: "R-180", Fidelity: FidelityNone,
			Note: "flag-only rule over inbound content; native dialects act on tool calls, not content",
		},
		{
			RuleID: "R-204", Fidelity: FidelityNone,
			Note: "meta-rule about the compiled artifacts themselves; flag-only",
		},
		{
			RuleID: "R-205", Fidelity: FidelityNone,
			Note: "org bundle integrity check at the fetch seam; not a tool-call shape",
		},
		{
			RuleID: "R-301", Fidelity: FidelityNone,
			Note: "config-scan finding (pin diff), not a tool-call shape",
		},
		{
			RuleID: "R-302", Fidelity: FidelityNone,
			Note: "config-scan finding (pin diff), not a tool-call shape",
		},
		{
			RuleID: "R-303", Fidelity: FidelityNone,
			Note: "tool-description content heuristic, not a tool-call shape",
		},
		{
			RuleID: "R-304", Fidelity: FidelityApprox,
			Note: "Edit/Write-tool arm over the MCP registry files (user-level + project-level via **/); shell-command arms stay hook-enforced",
			Entries: []Entry{
				{Action: ActionDeny, Value: "Edit(~/.claude.json)"},
				{Action: ActionDeny, Value: "Write(~/.claude.json)"},
				{Action: ActionDeny, Value: "Edit(**/.mcp.json)"},
				{Action: ActionDeny, Value: "Write(**/.mcp.json)"},
				{Action: ActionDeny, Value: "Edit(**/.cursor/mcp.json)"},
				{Action: ActionDeny, Value: "Write(**/.cursor/mcp.json)"},
				{Action: ActionDeny, Value: "Edit(~/.codex/config.toml)"},
				{Action: ActionDeny, Value: "Write(~/.codex/config.toml)"},
			},
		},
		{
			RuleID: "R-305", Fidelity: FidelityNone,
			Note: "config-scan finding (pin diff), not a tool-call shape",
		},
		{
			RuleID: "T-501", Fidelity: FidelityNone,
			Note: "session taint is runtime state; no static native expression",
		},
		{
			RuleID: "T-502", Fidelity: FidelityNone,
			Note: "session taint is runtime state; no static native expression",
		},
		{
			RuleID: "T-503", Fidelity: FidelityNone,
			Note: "session taint is runtime state; no static native expression",
		},
		{
			RuleID: "T-504", Fidelity: FidelityNone,
			Note: "session taint is runtime state; no static native expression",
		},
		{
			RuleID: "T-505", Fidelity: FidelityNone,
			Note: "session taint is runtime state; no static native expression",
		},
		{
			RuleID: "B-601", Fidelity: FidelityNone,
			Note: "session spend is runtime state; budget enforcement is the proxy's (§12.1 hard mode)",
		},
		{
			RuleID: "B-602", Fidelity: FidelityNone,
			Note: "daily spend is runtime state; budget enforcement is the proxy's (§12.1 hard mode)",
		},
		{
			RuleID: "B-603", Fidelity: FidelityNone,
			Note: "monthly spend is runtime state; budget enforcement is the proxy's (§12.1 hard mode)",
		},
		{
			RuleID: "B-604", Fidelity: FidelityNone,
			Note: "weekly spend is runtime state; budget enforcement is the proxy's (§12.1 hard mode)",
		},
		{
			RuleID: "B-621", Fidelity: FidelityNone,
			Note: "session token usage is runtime state; budget enforcement is the proxy's (§12.1 hard mode)",
		},
		{
			RuleID: "B-622", Fidelity: FidelityNone,
			Note: "daily token usage is runtime state; budget enforcement is the proxy's (§12.1 hard mode)",
		},
		{
			RuleID: "B-623", Fidelity: FidelityNone,
			Note: "monthly token usage is runtime state; budget enforcement is the proxy's (§12.1 hard mode)",
		},
		{
			RuleID: "B-624", Fidelity: FidelityNone,
			Note: "weekly token usage is runtime state; budget enforcement is the proxy's (§12.1 hard mode)",
		},
		{
			RuleID: "B-625", Fidelity: FidelityNone,
			Note: "whether the organization's budget ever verified is daemon state; the refusal is the proxy's (org-budget ruling R2)",
		},
		{
			RuleID: "B-610", Fidelity: FidelityNone,
			Note: "5h usage-window utilization is runtime state; limit enforcement is the proxy's (§12.1)",
		},
		{
			RuleID: "B-611", Fidelity: FidelityNone,
			Note: "5h usage-window utilization is runtime state; limit enforcement is the proxy's (§12.1)",
		},
		{
			RuleID: "B-612", Fidelity: FidelityNone,
			Note: "weekly usage-window utilization is runtime state; limit enforcement is the proxy's (§12.1)",
		},
		{
			RuleID: "B-613", Fidelity: FidelityNone,
			Note: "weekly usage-window utilization is runtime state; limit enforcement is the proxy's (§12.1)",
		},
		{
			RuleID: "A-610", Fidelity: FidelityNone,
			Note: "repeat tracking is runtime state; anomaly rules never block (§12.2)",
		},
	}
}

// claudeCodeUniverse is every entry value the table can emit — the
// managed-entry recognition set (register.go's content-heuristic
// precedent): values in it are treated as observer-managed in both
// the deny and ask arrays.
func claudeCodeUniverse() map[string]bool {
	u := map[string]bool{}
	for _, row := range claudeCodeRows() {
		for _, e := range row.Entries {
			u[e.Value] = true
		}
	}
	return u
}

// applyClaudeCode merges want into the settings JSON: wanted entries
// are appended to permissions.deny / permissions.ask, managed entries
// the policy no longer wants are removed, and EVERYTHING else —
// unknown top-level keys, unknown permissions sub-keys, user-authored
// entries, key order — survives. Errors (malformed JSON, non-array
// deny/ask) mean "do not write".
func applyClaudeCode(existing []byte, want []Entry) (ApplyResult, error) {
	root, err := parseJSONObj(existing)
	if err != nil {
		return ApplyResult{}, fmt.Errorf("compile.applyClaudeCode: %w", err)
	}
	perms := &jsonObj{}
	if raw, ok := root.get("permissions"); ok {
		if perms, err = parseJSONObj(raw); err != nil {
			return ApplyResult{}, fmt.Errorf("compile.applyClaudeCode: permissions: %w", err)
		}
	}

	universe := claudeCodeUniverse()
	wantByAction := map[string][]string{}
	wantSet := map[string]map[string]bool{ActionDeny: {}, ActionAsk: {}}
	for _, e := range want {
		wantByAction[e.Action] = append(wantByAction[e.Action], e.Value)
		wantSet[e.Action][e.Value] = true
	}

	var res ApplyResult
	changed := false
	for _, action := range []string{ActionDeny, ActionAsk} {
		key := map[string]string{ActionDeny: "deny", ActionAsk: "ask"}[action]
		var arr []string
		hadKey := false
		if raw, ok := perms.get(key); ok {
			hadKey = true
			if err := json.Unmarshal(raw, &arr); err != nil {
				return ApplyResult{}, fmt.Errorf("compile.applyClaudeCode: permissions.%s is not a string array: %w", key, err)
			}
		}
		next := make([]string, 0, len(arr)+len(wantByAction[action]))
		present := map[string]bool{}
		for _, v := range arr {
			if universe[v] && !wantSet[action][v] {
				res.Removed = append(res.Removed, Entry{Action: action, Value: v})
				changed = true
				continue
			}
			next = append(next, v)
			present[v] = true
		}
		for _, v := range wantByAction[action] {
			if present[v] {
				continue
			}
			next = append(next, v)
			res.Added = append(res.Added, Entry{Action: action, Value: v})
			changed = true
		}
		if len(next) == 0 && !hadKey {
			continue
		}
		encoded, err := json.Marshal(next)
		if err != nil {
			return ApplyResult{}, fmt.Errorf("compile.applyClaudeCode: marshal %s: %w", key, err)
		}
		perms.set(key, encoded)
	}
	if !changed {
		return res, nil
	}
	root.set("permissions", perms.encode(""))
	res.Updated = append(root.encode(""), '\n')
	return res, nil
}
