package connectflow

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// MaxCreateBodyBytes bounds the create request body.
const MaxCreateBodyBytes = 4 << 10

// MaxMachineNameRunes bounds a machine name after cleaning.
const MaxMachineNameRunes = 64

// CreateRequest is the create body as the machine sent it (the JSON tags are
// the wire contract with `observer connect`).
type CreateRequest struct {
	DevicePublicKey string `json:"device_public_key"`
	MachineName     string `json:"machine_name"`
	OS              string `json:"os"`
	Arch            string `json:"arch"`
	ObserverVersion string `json:"observer_version"`
	TargetHint      string `json:"target_hint"`
}

// Create is a validated, cleaned create request.
type Create struct {
	PublicKey       ed25519.PublicKey
	MachineName     string
	OS              string
	Arch            string
	ObserverVersion string
	TargetHint      string
}

// FieldError names the create field that broke its rule. Code is the wire
// error code (invalid_<field>).
type FieldError struct {
	Field string
	Code  string
}

// Error implements error.
func (e *FieldError) Error() string {
	return fmt.Sprintf("connectflow: %s breaks its rule", e.Field)
}

// fieldRule is one row of the create validation table.
type fieldRule struct {
	field string
	// check validates the raw request and writes the cleaned value into out.
	check func(in CreateRequest, out *Create) bool
}

// createRules validate a create request, top down; the first broken rule is
// the one reported.
var createRules = []fieldRule{
	{field: "device_public_key", check: func(in CreateRequest, out *Create) bool {
		raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(in.DevicePublicKey))
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return false
		}
		out.PublicKey = ed25519.PublicKey(raw)
		return true
	}},
	{field: "machine_name", check: func(in CreateRequest, out *Create) bool {
		name := CleanMachineName(in.MachineName)
		if name == "" || utf8.RuneCountInString(name) > MaxMachineNameRunes {
			return false
		}
		out.MachineName = name
		return true
	}},
	{field: "os", check: func(in CreateRequest, out *Create) bool {
		out.OS = in.OS
		return tokenShape(in.OS, 16)
	}},
	{field: "arch", check: func(in CreateRequest, out *Create) bool {
		out.Arch = in.Arch
		return tokenShape(in.Arch, 16)
	}},
	{field: "observer_version", check: func(in CreateRequest, out *Create) bool {
		out.ObserverVersion = in.ObserverVersion
		return versionShape(in.ObserverVersion)
	}},
	{field: "target_hint", check: func(in CreateRequest, out *Create) bool {
		hint := strings.ToLower(strings.TrimSpace(in.TargetHint))
		out.TargetHint = hint
		return hint == "" || TeamSlugShape(hint)
	}},
}

// ValidateCreate checks every field of a create request and returns the
// cleaned request, or a *FieldError naming the first field that breaks its
// rule.
func ValidateCreate(in CreateRequest) (Create, error) {
	var out Create
	for _, r := range createRules {
		if !r.check(in, &out) {
			return Create{}, &FieldError{Field: r.field, Code: "invalid_" + r.field}
		}
	}
	return out, nil
}

// tokenShape is 1 to max of [a-z0-9_] (runtime.GOOS and runtime.GOARCH).
func tokenShape(s string, max int) bool {
	if s == "" || len(s) > max {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
			return false
		}
	}
	return true
}

// versionShape is 1 to 32 of [0-9A-Za-z.+_-].
func versionShape(s string) bool {
	if s == "" || len(s) > 32 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		case c == '.' || c == '+' || c == '_' || c == '-':
		default:
			return false
		}
	}
	return true
}

// TeamSlugShape reports whether s has the shape of a team slug: 3 to 40 of
// [a-z0-9-], no leading or trailing hyphen, not a personal (u-) slug. It is
// the hint's shape only; whether a team holds the slug is the store's.
func TeamSlugShape(s string) bool {
	if len(s) < 3 || len(s) > 40 || strings.HasPrefix(s, "u-") {
		return false
	}
	if s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}

// CleanMachineName removes control, format (bidi, zero-width) and other
// invisible characters, folds every run of white space to one space and
// trims. The result is what the approval page shows.
func CleanMachineName(raw string) string {
	var b strings.Builder
	space := false
	for _, r := range raw {
		switch {
		case r == utf8.RuneError:
			continue
		case unicode.IsSpace(r):
			space = true
			continue
		case unicode.IsControl(r), unicode.Is(unicode.Cf, r), unicode.Is(unicode.Co, r), unicode.Is(unicode.Cs, r):
			continue
		}
		if space && b.Len() > 0 {
			b.WriteByte(' ')
		}
		space = false
		b.WriteRune(r)
	}
	return b.String()
}
