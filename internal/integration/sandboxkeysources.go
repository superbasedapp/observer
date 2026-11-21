package integration

import "sort"

// sandboxkeysources.go is the grounded side of decision SBXD-4
// (docs/decisions/sandbox-terminal-decisions-2026-11.md): where a tool keeps
// provider keys it saved itself (SavedKeys) and its subscription login
// (LoginSeed). Data only: the hosted host helper reads a row, never a tool
// name, and only for a tool the person opted in, under in-box custody, when
// the run starts. A tool without a row is never read. Each row names its
// source and the date it was read.

// SandboxSavedKey is one provider's key in a tool's own key file: an RFC
// 6901 JSON pointer to the key, and optionally a pointer whose string value
// must equal TypeValue for the entry to be an API key.
type SandboxSavedKey struct {
	Provider    string
	Pointer     string
	TypePointer string
	TypeValue   string
}

// SandboxSavedKeys is a tool's own key file.
type SandboxSavedKeys struct {
	// Files maps a GOOS value to the HOME-relative file; the "" entry is
	// every OS without its own.
	Files map[string]string
	// Keys are the providers' keys in the file.
	Keys []SandboxSavedKey
	// Grounding names the source (and what it says) and the date it was
	// read.
	Grounding string
}

// FileFor is the HOME-relative file on goos ("" when none).
func (s SandboxSavedKeys) FileFor(goos string) string {
	if f, ok := s.Files[goos]; ok {
		return f
	}
	return s.Files[""]
}

// Providers are the providers the file can hold keys of, in row order,
// each once.
func (s SandboxSavedKeys) Providers() []string {
	var out []string
	seen := map[string]bool{}
	for _, k := range s.Keys {
		if !seen[k.Provider] {
			seen[k.Provider] = true
			out = append(out, k.Provider)
		}
	}
	return out
}

// SandboxLoginSeed is a tool's login file and its access token's fields.
type SandboxLoginSeed struct {
	// File is the HOME-relative login file, the place the tool in the box
	// reads; Artifact is its internal/agentconfig FileRow id, through which
	// the cmd seam resolves the vendor's own relocation variable on this
	// machine ("" for none).
	File     string
	Artifact string
	// KeychainOn lists the GOOS values on which the vendor keeps the login
	// in the system keychain instead (no file to read: never seeded there).
	KeychainOn []string
	// Object is the member that holds the login; Access and Expiry its
	// access token and expiry fields (ExpiryMillis: the expiry is epoch
	// milliseconds, else seconds).
	Object       string
	Access       string
	Expiry       string
	ExpiryMillis bool
	// Keep are the other fields of Object that carry no secret and are kept
	// in the seeded file. Every other field, the refresh token above all,
	// and every other top-level member, is dropped.
	Keep []string
	// Grounding names the source and the date it was read.
	Grounding string
}

// SandboxSavedKeysFor returns tool's saved-keys row; ok false when none is
// grounded.
func SandboxSavedKeysFor(tool string) (SandboxSavedKeys, bool) {
	c, ok := For(tool)
	if !ok || c.Sandbox.SavedKeys == nil || len(c.Sandbox.SavedKeys.Keys) == 0 {
		return SandboxSavedKeys{}, false
	}
	return *c.Sandbox.SavedKeys, true
}

// SandboxLoginSeedFor returns tool's login-seed row; ok false when none is
// grounded.
func SandboxLoginSeedFor(tool string) (SandboxLoginSeed, bool) {
	c, ok := For(tool)
	if !ok || c.Sandbox.LoginSeed == nil || c.Sandbox.LoginSeed.File == "" {
		return SandboxLoginSeed{}, false
	}
	return *c.Sandbox.LoginSeed, true
}

// SandboxKeySourceTools returns the tools with a grounded saved-keys row
// and those with a grounded login-seed row, each sorted.
func SandboxKeySourceTools() (savedKeys, loginSeed []string) {
	for _, c := range Capabilities() {
		if _, ok := SandboxSavedKeysFor(c.Tool); ok {
			savedKeys = append(savedKeys, c.Tool)
		}
		if _, ok := SandboxLoginSeedFor(c.Tool); ok {
			loginSeed = append(loginSeed, c.Tool)
		}
	}
	sort.Strings(savedKeys)
	sort.Strings(loginSeed)
	return savedKeys, loginSeed
}
