package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ErrHomeUnresolved is the named reason Load refuses a path that starts
// with "~" when no home directory can be resolved (R-183): HOME is unset
// (USERPROFILE on Windows). Before it, the unexpanded path was used as a
// relative one, so a daemon started with no home created a folder named
// "~" (holding an observer.db) under its working directory.
var ErrHomeUnresolved = errors.New("home_unresolved: no home directory could be resolved (HOME, or USERPROFILE on Windows, is not set)")

// homeRelative splits a home-relative spelling: "~" alone, "~/rest", and on
// Windows also `~\rest`. ok is false for any other path ("~user/x" and
// "~foo" are ordinary names, never expanded).
func homeRelative(p string, sep byte) (rest string, ok bool) {
	if p == "~" {
		return "", true
	}
	if len(p) >= 2 && p[0] == '~' && (p[1] == '/' || (sep == '\\' && p[1] == '\\')) {
		return p[2:], true
	}
	return "", false
}

// expandHomeWith expands a home-relative p against the home userHome
// returns, or fails with ErrHomeUnresolved; any other p is returned as is.
func expandHomeWith(p string, sep byte, userHome func() (string, error)) (string, error) {
	rest, ok := homeRelative(p, sep)
	if !ok {
		return p, nil
	}
	home, err := userHome()
	if err != nil || home == "" {
		return "", ErrHomeUnresolved
	}
	if rest == "" {
		return home, nil
	}
	return filepath.Join(home, rest), nil
}

// expandHome expands a home-relative path, leaving it unchanged when no
// home resolves (callers that must not use such a path go through
// expandHomePaths, which refuses it instead).
func expandHome(p string) string {
	out, err := expandHomeWith(p, filepath.Separator, os.UserHomeDir)
	if err != nil {
		return p
	}
	return out
}

// expandHomePaths expands every path Load resolves against the home, in
// one table, and refuses the load with ErrHomeUnresolved, naming the key,
// when one starts with "~" and no home resolves.
func expandHomePaths(cfg *Config) error {
	for _, f := range []struct {
		key string
		p   *string
	}{
		{"observer.db_path", &cfg.Observer.DBPath},
		{"archive.path", &cfg.Archive.Path},
		{"mcp_relay.ipc_path", &cfg.MCPRelay.IPCPath},
		{"compression.conversation.stash.dir", &cfg.Compression.Conversation.Stash.Dir},
		{"loc.editor_token_file", &cfg.Loc.EditorTokenFile},
		{"proxy.client_token_file", &cfg.Proxy.ClientTokenFile},
		{"update.state_dir", &cfg.Update.StateDir},
	} {
		v, err := expandHomeWith(*f.p, filepath.Separator, os.UserHomeDir)
		if err != nil {
			return fmt.Errorf("config: %s = %q: %w; set HOME (USERPROFILE on Windows) or use an absolute path", f.key, *f.p, err)
		}
		*f.p = v
	}
	return nil
}
