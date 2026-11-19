package sandboxkey

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

// toolkeys.go is the pure half of decision SBXD-4: the keys a tool saved in
// its own key file (b) and the narrowed login seed (c), both opt-in per
// tool and used only under in-box custody. The caller reads the file (only
// when a run starts, never logged) and passes its bytes; nothing here opens
// a file. Each field set comes from the tool's grounded registry row
// (internal/integration SandboxSavedKeys / SandboxLoginSeed), converted by
// the caller into the plain types below.

// SavedKeyField is one provider's key in a tool's own key file: the JSON
// pointer (RFC 6901) of the key, and optionally a pointer whose string
// value must equal TypeValue for the entry to be an API key (OpenCode keeps
// an OAuth login beside API keys in the same file; only "api" entries are
// keys).
type SavedKeyField struct {
	Provider    string
	Pointer     string
	TypePointer string
	TypeValue   string
}

// SavedKeys reads the keys of fields whose provider is in want from doc (a
// tool's own key file), provider id -> key. A file that does not parse, a
// field that is absent, not a string, empty, or of another type is skipped;
// nothing about the file's content is ever returned but the keys.
func SavedKeys(doc []byte, fields []SavedKeyField, want []string) map[string]string {
	var root any
	if err := json.Unmarshal(doc, &root); err != nil {
		return nil
	}
	out := map[string]string{}
	for _, f := range fields {
		if !containsString(want, f.Provider) {
			continue
		}
		if _, done := out[f.Provider]; done {
			continue
		}
		if f.TypePointer != "" {
			if t, ok := pointerString(root, f.TypePointer); !ok || t != f.TypeValue {
				continue
			}
		}
		if k, ok := pointerString(root, f.Pointer); ok && strings.TrimSpace(k) != "" {
			out[f.Provider] = strings.TrimSpace(k)
		}
	}
	return out
}

// pointerString resolves an RFC 6901 pointer to a string value.
func pointerString(root any, ptr string) (string, bool) {
	v, ok := pointer(root, ptr)
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

// pointer resolves an RFC 6901 pointer ("" is the root).
func pointer(root any, ptr string) (any, bool) {
	if ptr == "" {
		return root, true
	}
	if !strings.HasPrefix(ptr, "/") {
		return nil, false
	}
	cur := root
	for _, tok := range strings.Split(ptr[1:], "/") {
		tok = strings.ReplaceAll(strings.ReplaceAll(tok, "~1", "/"), "~0", "~")
		switch c := cur.(type) {
		case map[string]any:
			next, ok := c[tok]
			if !ok {
				return nil, false
			}
			cur = next
		case []any:
			i, err := strconv.Atoi(tok)
			if err != nil || i < 0 || i >= len(c) {
				return nil, false
			}
			cur = c[i]
		default:
			return nil, false
		}
	}
	return cur, true
}

func containsString(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// LoginSeedSpec is how a tool's login file holds its access token: the
// object the login lives in, its access token and expiry fields (the
// expiry in epoch milliseconds when ExpiryMillis, else seconds), and the
// other fields of that object that carry no secret and may be kept. Every
// field not named here (the refresh token above all, and every other
// top-level member) is dropped.
type LoginSeedSpec struct {
	Object       string
	Access       string
	Expiry       string
	ExpiryMillis bool
	Keep         []string
}

// The LoginSeed outcome codes.
const (
	LoginSeedOK         = "seeded"
	LoginSeedUnreadable = "login_unreadable"
	LoginSeedNoLogin    = "no_login"
	LoginSeedNoExpiry   = "no_expiry"
	LoginSeedExpired    = "expired"
)

// LoginSeedResult is the narrowed login file (Doc, only when Code is
// LoginSeedOK) and when its access token expires.
type LoginSeedResult struct {
	Code      string
	Doc       []byte
	ExpiresAt time.Time
}

// loginSeedFacts are what the rules read.
type loginSeedFacts struct {
	parsed  bool
	access  string
	expires time.Time
	now     time.Time
	margin  time.Duration
}

// loginSeedRules are walked top-down; the first that refuses decides.
var loginSeedRules = []struct {
	code   string
	refuse func(loginSeedFacts) bool
}{
	{LoginSeedUnreadable, func(f loginSeedFacts) bool { return !f.parsed }},
	{LoginSeedNoLogin, func(f loginSeedFacts) bool { return f.access == "" }},
	// A token whose expiry the file does not say is not seeded: nothing
	// could tell the person when it stops working, and it might outlive
	// the run.
	{LoginSeedNoExpiry, func(f loginSeedFacts) bool { return f.expires.IsZero() }},
	{LoginSeedExpired, func(f loginSeedFacts) bool { return !f.now.Add(f.margin).Before(f.expires) }},
}

// SeedLogin narrows a tool's login file to its access token (decision
// SBXD-4 (c)): the same file shape with only Object's access token, expiry
// and Keep fields, so nothing in the box can renew the login after the run.
// A token that expires within margin of now is not seeded.
func SeedLogin(doc []byte, spec LoginSeedSpec, now time.Time, margin time.Duration) LoginSeedResult {
	f := loginSeedFacts{now: now, margin: margin}
	var root map[string]any
	obj := map[string]any{}
	if err := json.Unmarshal(doc, &root); err == nil {
		f.parsed = true
		if o, ok := root[spec.Object].(map[string]any); ok {
			obj = o
			f.access, _ = o[spec.Access].(string)
			if n, ok := o[spec.Expiry].(float64); ok && n > 0 {
				if spec.ExpiryMillis {
					f.expires = time.UnixMilli(int64(n)).UTC()
				} else {
					f.expires = time.Unix(int64(n), 0).UTC()
				}
			}
		}
	}
	for _, r := range loginSeedRules {
		if r.refuse(f) {
			return LoginSeedResult{Code: r.code, ExpiresAt: f.expires}
		}
	}
	narrowed := map[string]any{spec.Access: f.access, spec.Expiry: obj[spec.Expiry]}
	for _, k := range spec.Keep {
		// A refresh token is never kept, whatever a row's Keep says.
		if v, ok := obj[k]; ok && k != spec.Access && k != spec.Expiry && !strings.Contains(strings.ToLower(k), "refresh") {
			narrowed[k] = v
		}
	}
	b, err := json.Marshal(map[string]any{spec.Object: narrowed})
	if err != nil {
		return LoginSeedResult{Code: LoginSeedUnreadable}
	}
	return LoginSeedResult{Code: LoginSeedOK, Doc: b, ExpiresAt: f.expires}
}
