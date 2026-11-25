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

// CreateRequest is the create body as the client sent it (the JSON tags are
// the wire contract with `observer connect` and, for purpose sdk_key, with
// the SDKs' `setup`). One body carries both purposes' fields; the purpose's
// rule table (purposeRows) says which it must and must not carry.
type CreateRequest struct {
	// Purpose is "" or PurposeMachine for `observer connect`, PurposeSDKKey
	// for the SDK setup's device sign-in.
	Purpose         string `json:"purpose"`
	DevicePublicKey string `json:"device_public_key"`
	MachineName     string `json:"machine_name"`
	OS              string `json:"os"`
	Arch            string `json:"arch"`
	ObserverVersion string `json:"observer_version"`
	TargetHint      string `json:"target_hint"`
	// Client names the SDK package whose setup asks (sdk_key only; a closed
	// set, sdkClients).
	Client string `json:"client"`
	// ClientVersion is that package's version (sdk_key only).
	ClientVersion string `json:"client_version"`
	// ProjectName is the service name setup detected, shown on the approval
	// page (sdk_key only).
	ProjectName string `json:"project_name"`
	// RedeemHash is base64url-nopad(SHA-256(redeem secret)) (sdk_key only;
	// internal/sdkkeygrant.RedeemHash): signed into the key grant, so the
	// tenant host redeems the grant only for the process that holds the
	// secret.
	RedeemHash string `json:"redeem_hash"`
}

// Create is a validated, cleaned create request.
type Create struct {
	// Purpose is the request's purpose; it decides its AuthKind (AuthFor).
	Purpose         Purpose
	PublicKey       ed25519.PublicKey
	MachineName     string
	OS              string
	Arch            string
	ObserverVersion string
	TargetHint      string
	Client          string
	ClientVersion   string
	ProjectName     string
	RedeemHash      string
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
	// code is the wire error code when check fails; "" is invalid_<field>.
	code string
}

// machineCreateRules validate a machine create request (`observer connect`),
// top down; the first broken rule is the one reported. The SDK's fields must
// be absent.
var machineCreateRules = []fieldRule{
	{field: "device_public_key", check: func(in CreateRequest, out *Create) bool {
		raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(in.DevicePublicKey))
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return false
		}
		out.PublicKey = ed25519.PublicKey(raw)
		return true
	}},
	machineNameRule,
	osRule,
	{field: "arch", check: func(in CreateRequest, out *Create) bool {
		out.Arch = in.Arch
		return tokenShape(in.Arch, 16)
	}},
	{field: "observer_version", check: func(in CreateRequest, out *Create) bool {
		out.ObserverVersion = in.ObserverVersion
		return versionShape(in.ObserverVersion)
	}},
	targetHintRule,
	absentRule("client", func(in CreateRequest) string { return in.Client }),
	absentRule("client_version", func(in CreateRequest) string { return in.ClientVersion }),
	absentRule("project_name", func(in CreateRequest) string { return in.ProjectName }),
	absentRule("redeem_hash", func(in CreateRequest) string { return in.RedeemHash }),
}

// sdkKeyCreateRules validate an SDK setup's create request (purpose
// sdk_key), top down (sdk/contract/fixtures/setup/connect-create.json
// request_rules). It carries no device key and no Observer version (the SDK
// polls with the device code the create returns), and names its client and
// version, its project and the hash of its redeem secret.
var sdkKeyCreateRules = []fieldRule{
	absentRule("device_public_key", func(in CreateRequest) string { return in.DevicePublicKey }),
	absentRule("observer_version", func(in CreateRequest) string { return in.ObserverVersion }),
	{field: "client", check: func(in CreateRequest, out *Create) bool {
		out.Client = in.Client
		return sdkClient(in.Client)
	}},
	{field: "client_version", check: func(in CreateRequest, out *Create) bool {
		out.ClientVersion = in.ClientVersion
		return versionShape(in.ClientVersion)
	}},
	{field: "project_name", check: func(in CreateRequest, out *Create) bool {
		out.ProjectName = in.ProjectName
		return projectNameShape(in.ProjectName)
	}},
	machineNameRule,
	osRule,
	archRule,
	targetHintRule,
	{field: "redeem_hash", check: func(in CreateRequest, out *Create) bool {
		out.RedeemHash = in.RedeemHash
		return b64SHA256Shape(in.RedeemHash)
	}},
}

// machineNameRule, osRule, archRule and targetHintRule are shared by both
// purposes.
var (
	machineNameRule = fieldRule{field: "machine_name", check: func(in CreateRequest, out *Create) bool {
		name := CleanMachineName(in.MachineName)
		if name == "" || utf8.RuneCountInString(name) > MaxMachineNameRunes {
			return false
		}
		out.MachineName = name
		return true
	}}
	osRule = fieldRule{field: "os", check: func(in CreateRequest, out *Create) bool {
		out.OS = in.OS
		return tokenShape(in.OS, 16)
	}}
	archRule = fieldRule{field: "arch", check: func(in CreateRequest, out *Create) bool {
		out.Arch = in.Arch
		return tokenShape(in.Arch, 16)
	}}
	targetHintRule = fieldRule{field: "target_hint", check: func(in CreateRequest, out *Create) bool {
		hint := strings.ToLower(strings.TrimSpace(in.TargetHint))
		out.TargetHint = hint
		return hint == "" || TeamSlugShape(hint)
	}}
)

// absentRule is a field the purpose does not take: it must be empty, and a
// body that carries it is not a request of this purpose at all (400
// bad_request, the contract's rule for a body that mixes the two purposes).
func absentRule(field string, get func(CreateRequest) string) fieldRule {
	return fieldRule{field: field, code: "bad_request", check: func(in CreateRequest, _ *Create) bool { return get(in) == "" }}
}

// ValidateCreate checks every field of a create request against its
// purpose's rule table and returns the cleaned request, or a *FieldError
// naming the first field that breaks its rule (the purpose first).
func ValidateCreate(in CreateRequest) (Create, error) {
	row, ok := purposeRowFor(Purpose(in.Purpose))
	if !ok {
		return Create{}, &FieldError{Field: "purpose", Code: "invalid_purpose"}
	}
	out := Create{Purpose: row.purpose}
	for _, r := range row.create {
		if !r.check(in, &out) {
			code := r.code
			if code == "" {
				code = "invalid_" + r.field
			}
			return Create{}, &FieldError{Field: r.field, Code: code}
		}
	}
	return out, nil
}

// sdkClients are the packages whose setup may ask for an SDK key (a closed
// set: the two SDKs that ship setup).
var sdkClients = []string{"superbased-sdk-python", "superbased-sdk-typescript"}

// sdkClient reports whether s is one of sdkClients.
func sdkClient(s string) bool {
	for _, c := range sdkClients {
		if s == c {
			return true
		}
	}
	return false
}

// projectNameShape is 1 to 64 of [a-z0-9._-]: the normalised service name
// setup detected.
func projectNameShape(s string) bool {
	if s == "" || len(s) > MaxMachineNameRunes {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '.' && c != '_' && c != '-' {
			return false
		}
	}
	return true
}

// b64SHA256Shape is exactly 43 characters of the unpadded base64url
// alphabet that decode strictly (the unused low bits of the last character
// zero, so one digest has one spelling) to 32 bytes: a SHA-256 digest
// (internal/sdkkeygrant.RedeemHash).
func b64SHA256Shape(s string) bool {
	if len(s) != 43 {
		return false
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	return err == nil && len(b) == 32
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
