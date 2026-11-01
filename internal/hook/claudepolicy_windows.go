//go:build windows

package hook

import (
	"errors"

	"golang.org/x/sys/windows/registry"
)

// claudePolicyKey is Claude Code's Windows policy key, read under HKLM (an
// administrator source) and HKCU (the user-writable fallback); the policy
// document is the JSON in its `Settings` value (REG_SZ or REG_EXPAND_SZ;
// managed-settings page "Where each mechanism stores the policy").
const (
	claudePolicyKey   = `SOFTWARE\Policies\ClaudeCode`
	claudePolicyValue = "Settings"
)

// claudeOSPolicy returns the HKLM source, the HKCU source and "windows".
// Observer only READS the keys.
func claudeOSPolicy() (mdm, hkcu ClaudePolicySource, goos string) {
	return readClaudePolicyRegistry(registry.LOCAL_MACHINE, `HKLM\`, ClaudeSourceMDM),
		readClaudePolicyRegistry(registry.CURRENT_USER, `HKCU\`, ClaudeSourceHKCU), "windows"
}

func readClaudePolicyRegistry(root registry.Key, prefix string, kind ClaudePolicySourceKind) ClaudePolicySource {
	s := ClaudePolicySource{Kind: kind, Location: prefix + claudePolicyKey + `\` + claudePolicyValue}
	k, err := registry.OpenKey(root, claudePolicyKey, registry.QUERY_VALUE)
	if err != nil {
		if !errors.Is(err, registry.ErrNotExist) {
			s.Found, s.Problem = true, "could not be opened"
		}
		return s
	}
	defer func() { _ = k.Close() }()
	v, _, err := k.GetStringValue(claudePolicyValue)
	switch {
	case errors.Is(err, registry.ErrNotExist):
		return s
	case errors.Is(err, registry.ErrUnexpectedType):
		s.Found, s.Problem = true, "is not a string value"
		return s
	case err != nil:
		s.Found, s.Problem = true, "could not be read"
		return s
	}
	s.Found = true
	if len(v) > claudePolicyMaxBytes {
		s.Problem = "is too large"
		return s
	}
	d, err := ParseClaudePolicyDocument([]byte(v))
	if err != nil {
		s.Problem = "does not hold a JSON object"
		return s
	}
	s.Doc = d
	return s
}
