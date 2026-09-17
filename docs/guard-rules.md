# Guard rule catalog

GENERATED — do not edit by hand. Regenerate with:

    observer guard rules --markdown > docs/guard-rules.md

Rule IDs are stable and never reused (guard spec §5). The
Observe/Enforce columns are the mode-decision pair; observe is
the fresh-install default (operator decision D2). Multi-row IDs
split one catalog rule by sub-shape (e.g. read vs write) and
appear once per row.

| ID | Category | Severity | Observe | Enforce | Trigger |
|---|---|---|---|---|---|
| R-101 | destructive | critical | flag | deny | recursive delete targeting a filesystem root, the home directory, a root-depth wildcard, or a path outside the project |
| R-102 | destructive | high | flag | ask | recursive delete inside the project targeting the VCS directory or the project root itself |
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
| R-152 | boundary | critical | flag | ask | shell command reading a sensitive credential/profile location |
| R-153 | boundary | high | flag | ask | read of a secret-bearing file (.env / key material / credentials) |
| R-153 | boundary | high | flag | ask | shell command reading a secret-bearing file (.env / key material / credentials) |
| R-154 | boundary | critical | flag | deny | write to a shell rc/profile file (persistence vector) |
| R-154 | boundary | critical | flag | deny | shell command writing to a shell rc/profile file (persistence vector) |
| R-155 | boundary | critical | flag | deny | write to an autostart/persistence location (cron, systemd, LaunchAgents, Startup) |
| R-155 | boundary | critical | flag | deny | shell command writing to an autostart/persistence location |
| R-155 | boundary | critical | flag | deny | persistence-installing command (crontab / schtasks /create / Run registry key / systemctl enable) |
| R-156 | boundary | high | flag | ask | write to .git/hooks (in-repo persistence vector) |
| R-156 | boundary | high | flag | ask | shell command writing to .git/hooks (in-repo persistence vector) |
| R-157 | boundary | high | flag | deny | wrapper whose inner command could not be analysed (fail-closed) |
| R-160 | boundary | critical | flag | deny | agent modifying observer/guard/hook configuration |
| R-160 | boundary | critical | flag | deny | shell command modifying observer/guard/hook configuration |
| R-161 | boundary | high | flag | flag | agent modifying the project guard policy file |
| R-161 | boundary | high | flag | flag | shell command modifying the project guard policy file |
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

Tune rules without redefining them via `[[override]]` entries in
`~/.observer/guard-policy.toml` (guard spec §4.4); disable IDs via
`[guard.rules] disable`. Project policy files may only escalate
(§4.6 one-way layering).
