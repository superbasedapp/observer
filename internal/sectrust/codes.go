package sectrust

// CodeRow is one row of the reason-code table.
type CodeRow struct {
	Code string
	// Level is the level the reason carries. A row with RepositoryRun set
	// carries LevelUntrusted until its digest is accepted, then
	// LevelFlagged.
	Level Level
	// RepositoryRun marks a command the repository makes the agent run
	// without the user asking: its reasons carry a digest the developer can
	// accept (plan section 5.1, revision 2.4 change (a)).
	RepositoryRun bool
	// Acceptable marks a code whose reasons always carry a digest the
	// developer can accept, though it is not a repository-run command (a git
	// program, hidden characters, a symlink out of the tree): an accept
	// lowers the reason one level. RepositoryRun implies it.
	Acceptable bool
	// Fixed marks a code no accept can lower: there is nothing exact to
	// accept (a cut-short listing, a file too large to hash, the launch
	// environment). Its reasons never carry a digest, not even in
	// one of the developer's own files (ownFile).
	Fixed bool
	// Input says, in one line, what fires the row.
	Input string
}

// codeTable is the closed reason-code vocabulary, in the order the JSP-7
// write-up lists it (security plan section 5.1: "the reason-code table of
// the JSP-7 write-up is the starting table for Phase B"). Changed from the
// spike: the _suspicious variants are gone (indicators word a reason, never
// decide it), repository-run commands are digest-accepted, vscode_terminal_env
// is dropped, a remote https MCP server is information, and plugin_code
// covers plugins, custom tools and crushrc.
var codeTable = []CodeRow{
	{Code: "symlink_escape", Level: LevelUntrusted, Acceptable: true, Input: "a table path or a direct child of a config directory resolves outside the repository"},
	{Code: "file_over_cap", Level: LevelUntrusted, RepositoryRun: true, Input: "a table file over the 256 KiB read cap: nothing in it was judged, so it is untrusted until its whole-file digest is accepted"},
	{Code: "file_over_hash_cap", Level: LevelUntrusted, Fixed: true, Input: "a table file over the 64 MiB hash cap, or a file a command names that is: no digest can cover it, so it cannot be accepted"},
	{Code: "parse_error", Level: LevelUntrusted, RepositoryRun: true, Input: "a settings, MCP, hooks or tasks file that does not parse: the agent may still read it, so it is untrusted until its whole-file digest is accepted"},
	{Code: "truncated", Level: LevelFlagged, Fixed: true, Input: "a bound (the roots between the repository root and the launch directory, the entries of a directory, the files of a glob) cut the read short: some table files were not read"},
	{Code: "truncated_code", Level: LevelUntrusted, Fixed: true, Input: "the listing of a plugin or custom tool directory was cut short, or a command names more than 16 repository files: code the agent may load or run was not covered"},
	{Code: "file_unreadable", Level: LevelUntrusted, Acceptable: true, Input: "a table file that exists but could not be read or hashed: nothing in it was judged, so it is untrusted until the digest of the reason (its code, path and why) is accepted; once the file reads again it is judged like any other"},
	{Code: "hooks_off_switch", Level: LevelUntrusted, Input: "a project row of internal/hookdisable.Switches set to its off value"},
	{Code: "base_url_override", Level: LevelUntrusted, Input: "a provider base-URL variable or config key whose value is not loopback (Observer is the local base URL)"},
	{Code: "plugin_host_override", Level: LevelUntrusted, Fixed: true, Input: "on a managed node, the launch environment sets OBSERVER_BIN or OBSERVER_CONFIG to something other than the plugin host's pinned path"},
	{Code: "config_dir_redirect", Level: LevelUntrusted, Input: "a variable that moves an agent's or Observer's config, home or binary (CODEX_HOME, CLAUDE_CONFIG_DIR, OBSERVER_BIN, OBSERVER_CONFIG and siblings)"},
	{Code: "process_injection_env", Level: LevelUntrusted, Input: "a variable that injects code into a process or into git (NODE_OPTIONS, LD_PRELOAD, GIT_CONFIG_PARAMETERS and siblings), including terminal.integrated.env.*"},
	{Code: "hook_command", Level: LevelUntrusted, RepositoryRun: true, Input: "a command under a hooks subtree or in a hook file"},
	{Code: "statusline_command", Level: LevelUntrusted, RepositoryRun: true, Input: "a status line command"},
	{Code: "credential_helper_command", Level: LevelUntrusted, RepositoryRun: true, Input: "apiKeyHelper, awsCredentialExport, awsAuthRefresh, otelHeadersHelper"},
	{Code: "mcp_server_command", Level: LevelUntrusted, RepositoryRun: true, Input: "an MCP stdio server entry (mcpServers, servers, mcp, mcp_servers, context_servers)"},
	{Code: "mcp_server_url", Level: LevelInfo, Input: "an MCP server reached by https to a host name, or by loopback"},
	{Code: "mcp_server_url_insecure", Level: LevelFlagged, Input: "an MCP server reached by plain http to a remote host, by a raw IP address, or by an unknown scheme"},
	{Code: "auto_approve", Level: LevelUntrusted, Input: "an auto-approve or permission-bypass switch (chat.tools.autoApprove, defaultMode bypassPermissions, enableAllProjectMcpServers, approval_policy never, yolo, an allow list holding * or Bash(*))"},
	{Code: "trust_disabled", Level: LevelUntrusted, Input: "Gemini security.folderTrust.enabled = false"},
	{Code: "trust_self_grant", Level: LevelUntrusted, Input: "a trust_level = \"trusted\" in project config"},
	{Code: "git_fsmonitor", Level: LevelUntrusted, Acceptable: true, Input: ".git/config core.fsmonitor set to a command"},
	{Code: "git_command_key", Level: LevelUntrusted, Acceptable: true, Input: ".git/config core.sshCommand, core.pager, core.editor, sequence.editor, core.askpass, diff.external, core.gitProxy, uploadpack.packObjectsHook"},
	{Code: "git_filter_driver", Level: LevelUntrusted, Acceptable: true, Input: ".git/config filter driver command (git-lfs exempt)"},
	{Code: "git_diff_driver", Level: LevelUntrusted, Acceptable: true, Input: ".git/config diff driver command"},
	{Code: "git_merge_driver", Level: LevelUntrusted, Acceptable: true, Input: ".git/config merge driver command"},
	{Code: "gitattributes_driver_defined", Level: LevelUntrusted, Acceptable: true, Input: "a .gitattributes driver that .git/config defines"},
	{Code: "git_hookspath", Level: LevelFlagged, Acceptable: true, Input: ".git/config core.hooksPath"},
	{Code: "git_alias_shell", Level: LevelFlagged, Acceptable: true, Input: ".git/config alias that runs a shell command (!...)"},
	{Code: "git_alias_bypass", Level: LevelFlagged, Acceptable: true, Input: ".git/config alias holding --no-verify or hooksPath"},
	{Code: "git_credential_helper", Level: LevelFlagged, Acceptable: true, Input: ".git/config credential.helper"},
	{Code: "git_include", Level: LevelFlagged, Acceptable: true, Input: ".git/config include or includeIf"},
	{Code: "folder_open_task", Level: LevelUntrusted, RepositoryRun: true, Input: "a .vscode/tasks.json task with runOptions.runOn = folderOpen"},
	{Code: "devcontainer_ignored_field", Level: LevelFlagged, Acceptable: true, Input: "a conditional row (N2): initializeCommand wherever the trust check runs, because it runs on the host whenever a devcontainer tool opens the folder (ruling P-108), and where the container sandbox is active every .devcontainer/devcontainer.json field Observer's container sandbox ignores because it would run on the host or raise the container's privilege (initializeCommand, runArgs, privileged, capAdd, securityOpt, mounts, build and the rest), which another devcontainer tool would honour; also the file itself when it does not parse"},
	{Code: "plugin_code", Level: LevelUntrusted, RepositoryRun: true, Input: "a plugin, custom tool or crushrc the agent loads and runs (a code row of the path table)"},
	{Code: "hidden_unicode_tag", Level: LevelUntrusted, Acceptable: true, Input: "Unicode tag characters in an instruction, rule, skill, agent or command file"},
	{Code: "hidden_unicode_bidi", Level: LevelUntrusted, Acceptable: true, Input: "bidirectional control characters in the same files"},
	{Code: "hidden_unicode_zero_width", Level: LevelFlagged, Acceptable: true, Input: "zero-width characters in the same files (a zero-width joiner inside an emoji sequence is ignored)"},
}

// codeIndex finds a row by code.
var codeIndex = func() map[string]CodeRow {
	m := make(map[string]CodeRow, len(codeTable))
	for _, r := range codeTable {
		m[r.Code] = r
	}
	return m
}()

// Codes returns the reason-code table (a copy), in order.
func Codes() []CodeRow { return append([]CodeRow(nil), codeTable...) }
