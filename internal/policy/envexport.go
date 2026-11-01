package policy

// ExportedEnv lists the NAME=value pairs a command unit sets for the
// commands after it in the same line, or for every later process of the
// user: `export`, `declare -x`, cmd's `set`, `setx`, PowerShell's
// `$env:NAME = value`, the env: drive cmdlets (`Set-Item env:NAME v`) and
// `[Environment]::SetEnvironmentVariable`. It is the one reader of those
// shapes (exportAssignments, psEnvAssignment) for packages outside policy
// (the install gate, internal/secfeed), so they are never copied.
func ExportedEnv(cmd *Command) []string {
	if cmd == nil {
		return nil
	}
	as := exportAssignments(cmd)
	out := make([]string, 0, len(as))
	for _, a := range as {
		out = append(out, a.name+"="+a.value)
	}
	return out
}
