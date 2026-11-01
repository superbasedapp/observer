# Guard rule catalog

GENERATED - do not edit by hand. Regenerate with:

    observer guard rules --markdown > docs/guard-rules.md

Rule IDs are stable and never reused (guard spec §5). The
Observe/Enforce columns are the mode-decision pair; observe is
the fresh-install default (operator decision D2). Multi-row IDs
split one catalog rule by sub-shape (e.g. read vs write) and
appear once per row.

| ID | Category | Severity | Observe | Enforce | Trigger |
|---|---|---|---|---|---|
| R-101 | destructive | critical | flag | deny | recursive delete targeting a filesystem root, the home directory, a root-depth wildcard, or a path outside the project |
| R-101 | destructive | critical | flag | deny | interpreter one-liner or inline script recursively deleting a filesystem root, the home directory, a root-depth wildcard, or a path outside the project |
| R-101 | destructive | critical | flag | ask | recursive delete of the pipeline item ($_) inside a PowerShell script block, whose target the guard cannot check |
| R-102 | destructive | high | flag | ask | recursive delete inside the project targeting the VCS directory or the project root itself |
| R-102 | destructive | high | flag | ask | recursive delete after a directory change in the same command that the guard cannot resolve, or that is outside the project only if an earlier directory change fails |
| R-103 | destructive | high | flag | ask | mass-deletion chain (find -delete / xargs rm) |
| R-104 | destructive | high | flag | ask | git command that discards uncommitted work (reset --hard / checkout -- / clean -f) |
| R-110 | destructive | critical | flag | deny | force push to a protected branch |
| R-111 | destructive | warn | flag | ask | deletion of a protected branch or tag |
| R-120 | destructive | critical | flag | deny | destructive SQL through a database CLI (DROP/TRUNCATE/DELETE without WHERE) |
| R-130 | destructive | critical | flag | ask | cloud-infrastructure destruction command |
| R-140 | destructive | high | flag | ask | package registry publish/yank |
| R-141 | destructive | high | flag | ask | bulk permission/ownership change (chmod -R 777 / chown -R outside project) |
| R-142 | destructive | critical | flag | deny | disk/device-level operation (mkfs / dd to a device / diskpart / format) |
| R-150 | boundary | warn | flag | flag | file read outside the project root |
| R-150 | boundary | warn | flag | ask | file write outside the project root |
| R-151 | boundary | high | flag | ask | write into a DIFFERENT observed project's root (cross-project bleed) |
| R-152 | boundary | critical | flag | deny | write to a sensitive credential/profile location |
| R-152 | boundary | critical | flag | ask | read of a sensitive credential/profile location |
| R-152 | boundary | critical | flag | deny | shell command writing to a sensitive credential/profile location |
| R-152 | boundary | critical | flag | deny | interpreter one-liner or inline script deleting a sensitive credential/profile location |
| R-152 | boundary | critical | flag | ask | shell command reading a sensitive credential/profile location |
| R-152 | boundary | critical | flag | ask | interpreter one-liner or inline script naming a sensitive credential/profile location |
| R-153 | boundary | high | flag | ask | read of a secret-bearing file (.env / key material / credentials) |
| R-153 | boundary | high | flag | ask | shell command reading a secret-bearing file (.env / key material / credentials) |
| R-153 | boundary | high | flag | ask | interpreter one-liner or inline script naming a secret-bearing file (.env / key material / credentials) |
| R-154 | boundary | critical | flag | deny | write to a shell rc/profile file (persistence vector) |
| R-154 | boundary | critical | flag | deny | shell command writing to a shell rc/profile file (persistence vector) |
| R-154 | boundary | critical | flag | deny | interpreter one-liner or inline script deleting a shell rc/profile file |
| R-155 | boundary | critical | flag | deny | write to an autostart/persistence location (cron, systemd, LaunchAgents, Startup) |
| R-155 | boundary | critical | flag | deny | shell command writing to an autostart/persistence location |
| R-155 | boundary | critical | flag | deny | interpreter one-liner or inline script deleting an autostart/persistence location |
| R-155 | boundary | critical | flag | deny | persistence-installing command (crontab / schtasks /create / Run registry key / systemctl enable) |
| R-156 | boundary | high | flag | ask | write to .git/hooks (in-repo persistence vector) |
| R-156 | boundary | high | flag | ask | shell command writing to .git/hooks (in-repo persistence vector) |
| R-156 | boundary | high | flag | ask | interpreter one-liner or inline script deleting a .git/hooks entry |
| R-157 | boundary | high | flag | deny | wrapper whose inner command could not be analysed (fail-closed) |
| R-160 | boundary | critical | flag | deny | agent modifying observer/guard/hook configuration |
| R-160 | boundary | critical | flag | deny | shell command modifying observer/guard/hook configuration |
| R-160 | boundary | critical | flag | deny | interpreter one-liner or inline script deleting observer/guard/hook configuration |
| R-161 | boundary | high | flag | flag | agent modifying the project guard policy file |
| R-161 | boundary | high | flag | flag | shell command modifying the project guard policy file |
| R-162 | boundary | critical | flag | deny | agent write or edit that turns a coding agent's hooks off (disableAllHooks and its siblings) in a hook-bearing settings file |
| R-162 | boundary | critical | flag | deny | shell command or inline script that turns a coding agent's hooks off in a hook-bearing settings file |
| R-163 | boundary | high | flag | flag | shell command writing a hook-bearing settings file with content the guard cannot see (recorded; the hook-disable watch reports a switch that turns on) |
| R-112 | boundary | critical | flag | deny | git command that skips the repository's hooks (--no-verify, -n, core.hooksPath for one command, injected git config, or an alias that does so) |
| R-113 | boundary | high | flag | deny | git command run with a hook manager's skip switch in its environment (HUSKY=0, SKIP=, LEFTHOOK=0 and their siblings) |
| R-113 | boundary | high | flag | ask | export of a hook manager's skip switch for later commands (HUSKY=0, SKIP=, LEFTHOOK=0 and their siblings) |
| R-114 | boundary | high | flag | deny | git config change to where or whether hooks run (core.hooksPath, core.fsmonitor) |
| R-114 | boundary | high | flag | deny | agent write to git's own config, attributes, refs or objects, or the global git config |
| R-114 | boundary | high | flag | deny | shell command writing git's own config, attributes, refs or objects, or the global git config |
| R-114 | boundary | high | flag | ask | agent edit of a git hook manager's config (.husky/, .pre-commit-config.yaml, lefthook.yml and their siblings) |
| R-114 | boundary | high | flag | ask | shell command writing a git hook manager's config |
| R-114 | boundary | high | flag | ask | agent edit of .gitattributes adding a custom filter, diff or merge driver (a program the git config runs) |
| R-114 | boundary | high | flag | ask | shell command writing .gitattributes with a custom filter, diff or merge driver |
| R-165 | boundary | high | flag | deny | agent approving its own guard exception or loosening the guard (observer guard approve, guard disable and their siblings) |
| R-165 | boundary | high | flag | deny | agent calling the local dashboard's guard approval or policy routes |
| R-165 | boundary | high | flag | deny | agent writing a grant into the guard's approvals table |
| R-165 | boundary | high | flag | flag | agent requesting a guard exception (recorded; a human decides it) |
| R-165 | boundary | high | flag | deny | agent writing the developer's consent record (the scanner database accept or the online checks' disclosure) |
| R-165 | boundary | high | flag | deny | shell command writing the developer's consent record (redirect, tee, cp, mv and their kin) |
| R-165 | boundary | high | flag | deny | interpreter one-liner or inline script naming the developer's consent record |
| R-166 | boundary | high | flag | deny | agent write to a protected test, CI or coverage path (opt-in path classes) |
| R-166 | boundary | high | flag | deny | shell command writing a protected test, CI or coverage path (opt-in path classes) |
| R-170 | exfil | critical | flag | deny | remote content piped into an interpreter (curl\|sh-class remote-code execution) |
| R-171 | exfil | high | flag | ask | shell command uploading file contents to a remote destination |
| R-172 | exfil | critical | flag | deny | secret-shaped value in the arguments of a network-touching command |
| R-172 | exfil | critical | flag | deny | secret-shaped content in an outbound LLM API request |
| R-172 | exfil | critical | flag | deny | secret-shaped content typed directly into a prompt to your coding-agent tool, before it reaches the model |
| R-173 | exfil | warn | flag | flag | DNS lookup of an encoded-looking subdomain (DNS-tunnel exfil shape) |
| R-190 | pii | warn | flag | deny | deterministic PII (credit card, SSN, IBAN, ...) in the developer's own prompt text |
| R-180 | injection | high | flag | flag | inbound tool-result/web content carries injection-shaped instruction patterns |
| R-204 | posture | high | flag | flag | compiled native guard rules drifted from the effective policy |
| R-205 | posture | high | flag | flag | org policy bundle failed integrity verification and was rejected |
| R-301 | mcp | warn | flag | flag | new MCP server appeared without an approved pin |
| R-302 | mcp | critical | flag | flag | pinned MCP server's declared tools or descriptions changed (rug-pull shape) |
| R-303 | mcp | high | flag | flag | MCP tool description carries a poisoning-shaped pattern |
| R-304 | mcp | critical | flag | deny | agent modifying an MCP server registry file |
| R-304 | mcp | critical | flag | deny | shell command modifying an MCP server registry file |
| R-305 | mcp | critical | flag | flag | pinned MCP server's command/binary or URL changed under the same name |
| R-306 | mcp | high | flag | deny | MCP tool call to a server not approved by the node's compiled tools.mcp_access table |
| R-307 | mcp | critical | flag | deny | MCP tool call denied by the organization's tools.mcp_access grant |
| T-501 | taint | high | flag | ask | shell command while the session carries untrusted content with instruction-like patterns |
| T-502 | taint | high | flag | ask | out-of-project write while the session carries untrusted content |
| T-503 | taint | warn | flag | flag | git push while the session carries untrusted content |
| T-504 | taint | critical | flag | deny | network-touching command after the session read a secrets-bearing file |
| T-505 | taint | warn | flag | flag | MCP call to a different server after consuming an unpinned server's result (cross-server toxic-flow shape) |
| B-601 | budget | high | flag | flag | session cost exceeded [guard.budget].session_usd |
| B-602 | budget | high | flag | flag | daily cost (all sessions) exceeded [guard.budget].daily_usd |
| B-603 | budget | high | flag | flag | calendar-month cost (all sessions) exceeded [guard.budget].monthly_usd |
| B-604 | budget | high | flag | flag | rolling-7-day cost (all sessions) exceeded [guard.budget].weekly_usd |
| B-621 | budget | high | flag | flag | session token usage exceeded [guard.budget].session_tokens |
| B-622 | budget | high | flag | flag | daily token usage (all sessions) exceeded [guard.budget].daily_tokens |
| B-623 | budget | high | flag | flag | calendar-month token usage (all sessions) exceeded [guard.budget].monthly_tokens |
| B-624 | budget | high | flag | flag | rolling-7-day token usage (all sessions) exceeded [guard.budget].weekly_tokens |
| B-626 | budget | high | flag | deny | per-tool spend exceeded the organization's tool budget cap |
| B-626 | budget | high | flag | flag | per-tool spend exceeded the organization's tool budget cap |
| B-627 | budget | high | flag | deny | per-tool token usage exceeded the organization's tool budget cap |
| B-627 | budget | high | flag | flag | per-tool token usage exceeded the organization's tool budget cap |
| B-628 | budget | high | flag | deny | per-model spend exceeded the organization's model budget cap |
| B-628 | budget | high | flag | flag | per-model spend exceeded the organization's model budget cap |
| B-629 | budget | high | flag | deny | per-model token usage exceeded the organization's model budget cap |
| B-629 | budget | high | flag | flag | per-model token usage exceeded the organization's model budget cap |
| B-625 | budget | high | flag | deny | the organization requires a budget on this managed node and none has been verified |
| B-610 | limit | warn | flag | flag | 5h usage window utilization reached [guard.budget.window].util_5h_warn |
| B-611 | limit | high | flag | deny | 5h usage window utilization reached [guard.budget.window].util_5h_deny |
| B-612 | limit | warn | flag | flag | weekly usage window utilization reached [guard.budget.window].util_weekly_warn |
| B-613 | limit | high | flag | deny | weekly usage window utilization reached [guard.budget.window].util_weekly_deny |
| A-610 | anomaly | warn | flag | flag | identical tool call repeated consecutively past the stuck-loop threshold |
| A-613 | anomaly | high | flag | flag | repeated attempts at a denied action in different shapes (policy evasion, opt-in) |

## Code security: package checks (pack `security.deps`)

These rows fire only while the security module and its `security.deps`
child are active (see `docs/package-checks.md`). S-741 is the only
row that denies by default; S-744 and S-748 deny only in the variant a
node's `[security.deps]` unknown_action or online_unknown_action chooses.
S-746 is reserved (the `--ignore-scripts` rewrite).

| ID | Category | Severity | Observe | Enforce | Trigger |
|---|---|---|---|---|---|
| S-741 | code_security | critical | ask | deny | agent install of a package an authenticated source lists as malicious |
| S-742 | code_security | high | ask | ask | agent install of a package one edit from a popular name (a possible typosquat) |
| S-743 | code_security | warn | flag | flag | agent install of a package published more recently than the minimum package age |
| S-744 | code_security | warn | flag | flag | agent install of a package the registry does not know, or that no usable index could check; also the once-per-session note that package checks are not set up |
| S-744 | code_security | warn | ask | ask | agent install of a package the registry does not know, or that no usable index could check ([security.deps] unknown_action = ask) |
| S-744 | code_security | warn | ask | deny | agent install of a package the registry does not know, or that no usable index could check ([security.deps] unknown_action = deny) |
| S-745 | code_security | warn | flag | flag | agent install that names a custom registry or package index (dependency confusion) |
| S-747 | code_security | warn | flag | flag | agent manifest edit that adds a dependency the install gate flags (a commit that adds one is recorded as finding deps.s-747) |
| S-748 | code_security | warn | flag | ask | agent install the online package check could not answer in time |
| S-748 | code_security | warn | ask | ask | agent install the online package check could not answer in time ([security.deps] online_unknown_action = ask) |
| S-748 | code_security | warn | ask | deny | agent install the online package check could not answer in time ([security.deps] online_unknown_action = deny) |
| S-749 | code_security | high | flag | flag | agent install of a package some of whose versions are listed as malicious, without a pin outside them |

## Code security: commit gate

These rows fire only while the security module is active (see
`docs/code-security.md`). S-792 holds a push while a commit the push's
remote does not have yet adds a secret, also after the secret is removed
from the files. Amending, rebasing or resetting does not release that
hold until the reflog no longer reaches the old commit (30 days by
default). The hold is released by a push the developer approves (which
sends the commit, so rotate the secret afterwards), or, after dropping
the secret from the commit, by `git reflog expire --expire-unreachable=now --all`, then `git gc --prune=now`.

| ID | Category | Severity | Observe | Enforce | Trigger |
|---|---|---|---|---|---|
| S-791 | code_security | high | ask | deny | agent commit while a new high-confidence finding is open in this project |
| S-792 | code_security | high | ask | deny | agent push while a new high-confidence finding is open in this project, or held by a commit the push's remote does not have yet |
| S-792 | code_security | high | ask | ask | agent push of a commit held only past a reflog cap (no longer held for a deny; asked, never allowed) |
| S-793 | code_security | warn | ask | ask | agent commit with agent changes that the quick scan did not find clean |
| S-794 | code_security | warn | ask | ask | agent commit while this project's security state is unknown |
| S-791 | code_security | high | deny | deny | agent commit while a new high-confidence finding is open in this project (the org's commit gate floor) |
| S-792 | code_security | high | deny | deny | agent push while a new high-confidence finding is open in this project, or held by a commit the push's remote does not have yet (the org's commit gate floor) |
| S-792 | code_security | high | deny | deny | agent push of a commit held only past a reflog cap (no longer held for a deny; asked, never allowed) (the org's commit gate floor) |
| S-793 | code_security | warn | deny | deny | agent commit with agent changes that the quick scan did not find clean (the org's commit gate floor) |
| S-794 | code_security | warn | deny | deny | agent commit while this project's security state is unknown (the org's commit gate floor) |
| S-792 | code_security | high | ask | deny | agent write to the remote-tracking refs or the remote configuration while a new high-confidence finding is open in this project |

Tune rules without redefining them via `[[override]]` entries in
`~/.observer/guard-policy.toml` (guard spec §4.4); disable IDs via
`[guard.rules] disable`. Project policy files may only escalate
(§4.6 one-way layering).

## Shell dialects

Shell rules read a command the way the shell that runs it reads it.
A shell tool named PowerShell or pwsh (Claude Code's PowerShell tool on
Windows, for one) is read as PowerShell. A shell tool with a generic
name (Bash, shell) whose working directory is a Windows one (a drive
letter or UNC path) is read both ways, POSIX and PowerShell, and a hit
in either reading counts: Codex and Copilot CLI ran every command
through Windows PowerShell 5.1 on Windows. The PowerShell reading knows
single, double and here-string (`@'...'@`, `@"..."@`) quoting,
backtick escapes and line continuations, comments (`#`, `<# #>`), `;`
and pipelines, the `&` call operator, environment changes (`$env:NAME =`,
`Set-Item env:`, `New-Item -Path Env:`,
`[Environment]::SetEnvironmentVariable`) and `NUL` as the null device.
Nested `cmd /c`, `powershell -Command` / `-EncodedCommand`, `pwsh -c`,
`Invoke-Expression`, script blocks and `Start-Process -ArgumentList`
payloads are read too, to a bounded depth. A line past the parser's
bounds is marked unanalyzed and held by R-157, as on the POSIX path;
it is never silently allowed. R-112, R-113, R-114 and R-165 carry
PowerShell rows, including the commands captured live on Windows, in
their test corpus.

When a command is read both ways, a rule's reason quotes the PowerShell
reading, which keeps a Windows path's backslashes (the POSIX reading of
`C:\Users\dev` is `C:Usersdev`); a hit in either reading still counts.
`observer guard test` reads a command the same way: on a Windows
directory both ways, and `--shell posix|powershell|cmd` names one shell.
A UNC path (`\\server\share\x`) is a Windows path of its own: it is
outside every drive or POSIX project, a bare share is a filesystem root,
and it compares case-sensitively with another UNC path.
