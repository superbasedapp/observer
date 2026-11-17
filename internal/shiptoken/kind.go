package shiptoken

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"time"
)

// kind.go is the token KIND table (OTel-direct ingest phase 1,
// docs/plans/otel-direct-ingest-design-2026-11-16.md section 5; ledger
// OTELDIRECT-1). One token store, two kinds: the cloud-session ship token a
// vendor sandbox flushes with (every rule above this file, unchanged), and
// the telemetry token a developer's own AI tool exports OpenTelemetry with,
// straight to the org, with no node on the machine. Every rule that differs
// between the two is a column of one row here, so the decision logic stays a
// table and a third kind is one more row.

// Kind is a token kind, stored in org_cloud_session_tokens.kind.
type Kind string

// The kinds.
const (
	// KindCloudSession is the cloud-session ship token (sbocs_).
	KindCloudSession Kind = "cloud_session"
	// KindTelemetry is the OTel-direct telemetry token (sbotel_).
	KindTelemetry Kind = "telemetry"
)

// TelemetryPrefix starts every telemetry token. It differs from Prefix so a
// leaked token says which rail it opens, and so neither parser ever accepts
// the other kind.
const TelemetryPrefix = "sbotel_"

// TelemetryIDPrefix starts every telemetry token's public id.
const TelemetryIDPrefix = "otk_"

// Telemetry lifetime bounds (provisional default 1, awaiting the operator:
// 90 days by default, 365 at most). A telemetry token lives in a shell
// profile or a settings file, so it is long-lived next to a ship token; it
// can be rotated or revoked at any time and the org switch stops all of
// them at once.
const (
	TelemetryDefaultLifetime = 90 * 24 * time.Hour
	TelemetryMinLifetime     = 24 * time.Hour
	TelemetryMaxLifetime     = 365 * 24 * time.Hour
)

// MaxActiveTelemetryPerMember bounds a member's live telemetry tokens.
const MaxActiveTelemetryPerMember = 10

// KindRule is one row of the kind table.
type KindRule struct {
	// Kind is the row's kind.
	Kind Kind
	// Prefix and IDPrefix start the secret and the public id.
	Prefix, IDPrefix string
	// DefaultLifetime, MinLifetime and MaxLifetime bound the lifetime.
	DefaultLifetime, MinLifetime, MaxLifetime time.Duration
	// LifetimeRowCap reports that the kind carries a lifetime row cap
	// (row_cap / rows_used). A telemetry token is bounded by its rate quota
	// instead, so a long-lived token never runs dry.
	LifetimeRowCap bool
	// RequiresNode reports that a member needs an enrolled node to mint or
	// land with the kind. A telemetry member by definition may have none.
	RequiresNode bool
	// MaxActive bounds a member's live tokens of the kind.
	MaxActive int
	// EnvironmentLabelRequired reports that the label is required (it names
	// the cloud environment or the device).
	EnvironmentLabelRequired bool
}

// kindRules is THE kind table, one row per kind. TestKindTable pins every
// cell; a new kind is one more row.
var kindRules = []KindRule{
	{
		Kind: KindCloudSession, Prefix: Prefix, IDPrefix: IDPrefix,
		DefaultLifetime: DefaultLifetime, MinLifetime: MinLifetime, MaxLifetime: MaxLifetime,
		LifetimeRowCap: true, RequiresNode: true, MaxActive: 20, EnvironmentLabelRequired: true,
	},
	{
		Kind: KindTelemetry, Prefix: TelemetryPrefix, IDPrefix: TelemetryIDPrefix,
		DefaultLifetime: TelemetryDefaultLifetime, MinLifetime: TelemetryMinLifetime, MaxLifetime: TelemetryMaxLifetime,
		LifetimeRowCap: false, RequiresNode: false, MaxActive: MaxActiveTelemetryPerMember, EnvironmentLabelRequired: true,
	},
}

// KindRules returns a copy of the kind table.
func KindRules() []KindRule {
	out := make([]KindRule, len(kindRules))
	copy(out, kindRules)
	return out
}

// RuleFor returns k's row.
func RuleFor(k Kind) (KindRule, bool) {
	for _, r := range kindRules {
		if r.Kind == k {
			return r, true
		}
	}
	return KindRule{}, false
}

// ValidKind reports whether k is a known kind.
func ValidKind(k Kind) bool {
	_, ok := RuleFor(k)
	return ok
}

// GenerateKind mints a token of kind k from rand.
func GenerateKind(rand io.Reader, k Kind) (Minted, error) {
	r, ok := RuleFor(k)
	if !ok {
		return Minted{}, fmt.Errorf("shiptoken.GenerateKind: unknown kind %q", k)
	}
	secret := make([]byte, secretBytes)
	if _, err := io.ReadFull(rand, secret); err != nil {
		return Minted{}, fmt.Errorf("shiptoken.GenerateKind: secret: %w", err)
	}
	id := make([]byte, idBytes)
	if _, err := io.ReadFull(rand, id); err != nil {
		return Minted{}, fmt.Errorf("shiptoken.GenerateKind: id: %w", err)
	}
	tok := r.Prefix + base64.RawURLEncoding.EncodeToString(secret)
	return Minted{Token: tok, ID: r.IDPrefix + hex.EncodeToString(id), Hash: Hash(tok)}, nil
}

// ParseKind checks that raw is a well-formed token of kind k and returns it
// trimmed. A token of another kind is ErrMalformed.
func ParseKind(raw string, k Kind) (string, error) {
	r, ok := RuleFor(k)
	if !ok {
		return "", ErrMalformed
	}
	tok := strings.TrimSpace(raw)
	if !strings.HasPrefix(tok, r.Prefix) {
		return "", ErrMalformed
	}
	body := tok[len(r.Prefix):]
	if len(body) != encodedSecretLen {
		return "", ErrMalformed
	}
	if _, err := base64.RawURLEncoding.DecodeString(body); err != nil {
		return "", ErrMalformed
	}
	return tok, nil
}

// FromAuthorizationKind extracts a token of kind k from an Authorization
// header value ("Bearer <token>").
func FromAuthorizationKind(header string, k Kind) (string, error) {
	scheme, rest, ok := strings.Cut(strings.TrimSpace(header), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", ErrMalformed
	}
	return ParseKind(rest, k)
}

// ValidIDKind reports whether id has kind k's public id shape.
func ValidIDKind(id string, k Kind) bool {
	r, ok := RuleFor(k)
	if !ok || !strings.HasPrefix(id, r.IDPrefix) || len(id) != len(r.IDPrefix)+2*idBytes {
		return false
	}
	_, err := hex.DecodeString(id[len(r.IDPrefix):])
	return err == nil && strings.ToLower(id) == id
}

// ClampLifetimeKind resolves a requested lifetime for kind k through the
// lifetime table with k's bounds (an unknown kind takes the cloud-session
// bounds, the shortest).
func ClampLifetimeKind(k Kind, requested time.Duration) time.Duration {
	r, ok := RuleFor(k)
	if !ok {
		return ClampLifetime(requested)
	}
	switch {
	case requested <= 0:
		return r.DefaultLifetime
	case requested < r.MinLifetime:
		return r.MinLifetime
	case requested > r.MaxLifetime:
		return r.MaxLifetime
	default:
		return requested
	}
}

// TelemetryUnenrolledPosture is the content posture of a telemetry member
// with no enrolment to read one from (provisional default 3, awaiting the
// operator): the org's tenancy, and a managed SaaS org keeps raw content
// (CLAUDE.md "enterprise / org-managed nodes ship full content"). One value,
// so the operator's ruling is one edit.
const TelemetryUnenrolledPosture = PostureFullContent

// telemetryPostureRule is one row of the telemetry posture table.
type telemetryPostureRule struct {
	name    string
	match   func(enrolled, managed bool) bool
	posture string
}

// telemetryPostureRules decide a telemetry member's content posture at
// every batch, top-down, from the server's own enrolment records (never
// from the export): a managed enrolment (or the member's enterprise switch)
// keeps raw content; an individual enrolment ships hashes only, exactly as
// that member's node would; no enrolment follows the org's tenancy.
var telemetryPostureRules = []telemetryPostureRule{
	{"a managed member keeps raw content", func(_, managed bool) bool { return managed }, PostureFullContent},
	{"an individually enrolled member ships hashes", func(enrolled, _ bool) bool { return enrolled }, PostureMetadataOnly},
	{"a member with no enrolment follows the org", func(bool, bool) bool { return true }, TelemetryUnenrolledPosture},
}

// TelemetryPosture resolves a telemetry member's content posture.
func TelemetryPosture(enrolled, managed bool) string {
	for _, r := range telemetryPostureRules {
		if r.match(enrolled, managed) {
			return r.posture
		}
	}
	return PostureMetadataOnly
}

// Telemetry refusal codes (the OTel-direct route and the telemetry mint
// routes). None says anything about a token the caller does not hold.
const (
	// CodeTelemetryDisabled: the org has not turned OTel-direct telemetry
	// on (off by default, provisional default 2), or an admin turned it off.
	CodeTelemetryDisabled = "otel_direct_disabled"
	// CodeTelemetryRateLimited: the token's rate quota is spent; the
	// response carries Retry-After and OTLP exporters retry.
	CodeTelemetryRateLimited = "otel_token_rate_limited"
	// CodeTelemetryMissing / CodeTelemetryInvalid: no telemetry token, or
	// not one (a ship token, an Ed25519 node bearer, garbage).
	CodeTelemetryMissing = "otel_token_missing"
	CodeTelemetryInvalid = "otel_token_invalid"
	// CodeTelemetryExpired / CodeTelemetryRevoked: the token's status.
	CodeTelemetryExpired = "otel_token_expired"
	CodeTelemetryRevoked = "otel_token_revoked"
	// CodeTelemetryMemberInactive: the token's member is not active.
	CodeTelemetryMemberInactive = "otel_token_member_inactive"
)

// TelemetryRefusalCode maps a token status to its refusal code ("" for
// active).
func TelemetryRefusalCode(status string) string {
	switch status {
	case StatusActive:
		return ""
	case StatusExpired:
		return CodeTelemetryExpired
	case StatusRevoked:
		return CodeTelemetryRevoked
	default:
		return CodeTelemetryInvalid
	}
}
