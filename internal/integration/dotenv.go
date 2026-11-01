package integration

import "strings"

// DotenvOverride is the capability of a tool that loads .env files itself
// and lets them override the environment it was launched with
// (ProxyRoute.DotenvOverride, surface-gap CLI-7). Every field names files or
// variables; a launcher and the doctor read such a file by KEY PRESENCE
// only (agentconfig.DotenvKeysPresent), never a value: a .env file holds
// credentials.
type DotenvOverride struct {
	// Files are the .env files the tool loads, in load order. "~/" is the
	// home directory and "<project>/" the directory the tool runs in (the
	// git root and the working directory both resolve there for a launch
	// from the project root).
	Files []string
	// Keys are the variables whose presence in one of the files overrides
	// the launcher's route.
	Keys []string
	// FileArguments are the product's argv keys that name one more .env
	// file (compared on the token before any '='; a value must follow).
	FileArguments []string
	// Grounding names where the loading order is documented.
	Grounding string
}

// EnvFileArguments returns the .env files named by FileArguments in args
// (`--env-file x` or `--env-file=x`), stopping at a bare "--".
func (d DotenvOverride) EnvFileArguments(args []string) []string {
	var out []string
	for i, tok := range args {
		if tok == "--" {
			break
		}
		for _, key := range d.FileArguments {
			if tok == key && i+1 < len(args) && strings.TrimSpace(args[i+1]) != "" {
				out = append(out, args[i+1])
			}
			if v, ok := strings.CutPrefix(tok, key+"="); ok && strings.TrimSpace(v) != "" {
				out = append(out, v)
			}
		}
	}
	return out
}

// AuthSettingKey is one settings key whose presence means the tool has a
// saved sign-in choice (RouteGate.AuthSettingKeys). File is an
// internal/agentconfig FileRow id (the one owner of the path; pinned by
// agentconfig's registry tests), Key the dotted key inside it.
type AuthSettingKey struct {
	File string
	Key  string
}
