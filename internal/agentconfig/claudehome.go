package agentconfig

import "strings"

// claudeLegacyConfigDirEnv is the second name a reader of Claude Code's
// user config directory honours after CLAUDE_CONFIG_DIR. The launcher has
// read it since R2-5 (both names appear in the claude 2.1.x binary's
// strings table). The writers' relocation rule (relocClaudeConfigDir) names
// only CLAUDE_CONFIG_DIR; whether a writer should follow this name too is
// open (it needs a live check), so it stays a reader-side name here.
const claudeLegacyConfigDirEnv = "ANTHROPIC_CONFIG_DIR"

// ClaudeConfigDirEnvs are the variables ClaudeConfigDir reads, in the order
// it reads them.
func ClaudeConfigDirEnvs() []string {
	return []string{relocClaudeConfigDir.Env, claudeLegacyConfigDirEnv}
}

// ClaudeConfigDir is the one resolver of Claude Code's user config directory
// for a reader (the launcher's settings.json and sign-in file, the node
// dashboard's sign-in probe, the local plan-limits reader; FU-131, FU-138):
// CLAUDE_CONFIG_DIR, then ANTHROPIC_CONFIG_DIR, then ~/.claude under e.Home.
//
// The first variable that is set (after trimming) decides. A value that is
// not an absolute path by e's OS path syntax (FU-143) is refused, the way
// the relocation rules refuse it (R-188 F6): Claude Code reads it against
// its own working directory, so Observer cannot tell which directory it
// names, and the ~/.claude default is not what Claude Code reads then. dir
// is "" and refusedEnv names the variable (never its value). dir is "" with
// no refusal when no variable is set and e.Home is empty.
//
// e.Getenv is used as given: a caller that pins a home passes the pinned-home
// lookup (crossmount.HomeEnvAt), a launcher passes the environment of the
// claude it starts.
func ClaudeConfigDir(e PathEnv) (dir, refusedEnv string) {
	for _, name := range ClaudeConfigDirEnvs() {
		v := strings.TrimSpace(e.env(name))
		if v == "" {
			continue
		}
		if !e.isAbs(v) {
			return "", name
		}
		return e.Join(v), ""
	}
	if e.Home == "" {
		return "", ""
	}
	d, ok := e.expand(relocClaudeConfigDir.Anchor)
	if !ok {
		return "", ""
	}
	return d, ""
}
