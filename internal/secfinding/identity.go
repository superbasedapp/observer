package secfinding

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"unicode"
)

// Identity domains keep every key family apart (section 4.5.1).
const (
	domainLocal     = "sbo-secfinding-local-v1"
	domainOrg       = "sbo-secfinding-org-v1"
	domainOrgSecret = "sbo-secfinding-org-secret-v1" //nolint:gosec // G101: an HMAC domain label, not a credential
	domainNode      = "sbo-secfinding-node-secret-v1"
)

// MatchKind says how a match identity was built.
type MatchKind string

// The MatchKind values (section 4.5.1).
const (
	// MatchText is the normalized matched text.
	MatchText MatchKind = "text"
	// MatchSymbol is the enclosing symbol and the AST node shape, where
	// code intelligence is active.
	MatchSymbol MatchKind = "symbol"
	// MatchSecret is a secret: HMAC(node key, type || normalized value).
	MatchSecret MatchKind = "secret"
	// MatchDependency is ecosystem || package || version || advisory id.
	MatchDependency MatchKind = "dependency"
	// MatchEngine is an engine's own location-free fingerprint (Opengrep's
	// matchBasedId/v1).
	MatchEngine MatchKind = "engine"
)

// MatchIdentity is the location-free part of a finding's identity. It
// never holds a secret value: a secret identity holds only its node-keyed
// HMAC.
type MatchIdentity struct {
	Kind  MatchKind
	Value string
}

// NormalizeMatch is the whitespace and identifier-stable normalization of
// matched text: every run of white space becomes one space and the ends
// are trimmed, so reindenting or rewrapping a line keeps its identity.
func NormalizeMatch(text string) string {
	var b strings.Builder
	space := false
	for _, r := range text {
		if unicode.IsSpace(r) {
			space = true
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

// TextIdentity is the identity of a match by its normalized text.
func TextIdentity(text string) MatchIdentity {
	return MatchIdentity{Kind: MatchText, Value: NormalizeMatch(text)}
}

// SymbolIdentity is the identity of a match by its enclosing symbol and AST
// node shape.
func SymbolIdentity(symbol, nodeShape string) MatchIdentity {
	return MatchIdentity{Kind: MatchSymbol, Value: symbol + "\x00" + nodeShape}
}

// EngineIdentity is the identity an engine's own location-free fingerprint
// gives.
func EngineIdentity(fingerprint string) MatchIdentity {
	return MatchIdentity{Kind: MatchEngine, Value: fingerprint}
}

// DependencyIdentity is the identity of a dependency finding.
func DependencyIdentity(ecosystem, pkg, version, advisory string) MatchIdentity {
	return MatchIdentity{Kind: MatchDependency, Value: join(ecosystem, pkg, version, advisory)}
}

// normalizeSecret trims the surrounding white space a secret may carry
// when it is copied, so the same credential keys the same way.
func normalizeSecret(v string) string { return strings.TrimSpace(v) }

// ErrNoNodeKey is SecretIdentity's refusal without a node key: an HMAC
// under an empty key is a plain hash, which a reader of the findings table
// could test guesses against.
var ErrNoNodeKey = errors.New("secfinding.SecretIdentity: no node key")

// SecretIdentity is a secret's local identity: HMAC(node key, type ||
// normalized value). The value is consumed here and never kept. An empty
// node key is refused with ErrNoNodeKey.
func SecretIdentity(nodeKey []byte, secretType, value string) (MatchIdentity, error) {
	if len(nodeKey) == 0 {
		return MatchIdentity{}, ErrNoNodeKey
	}
	return MatchIdentity{Kind: MatchSecret, Value: keyed(nodeKey, domainNode, secretType, normalizeSecret(value))}, nil
}

// LocalKey is the location-free lifecycle key (section 4.5.1): the rule
// and the match identity, under the project, so the same match in two
// projects keys differently and a move, a nearby edit or a rename keeps
// the key.
func LocalKey(projectRootHash, ruleID string, id MatchIdentity) string {
	return digest(domainLocal, projectRootHash, ruleID, string(id.Kind), id.Value)
}

// OrgKey is the org dedupe key for a non-secret finding: HMAC(org dedupe
// key, rule id || match identity). It is "" without the org key: a node
// that does not hold it never computes one. A secret identity gives "":
// the org key of a secret is OrgSecretKey, never built from the node-keyed
// HMAC.
func OrgKey(orgDedupeKey []byte, ruleID string, id MatchIdentity) string {
	if len(orgDedupeKey) == 0 || id.Kind == MatchSecret {
		return ""
	}
	return keyed(orgDedupeKey, domainOrg, ruleID, string(id.Kind), id.Value)
}

// OrgSecretKey is the org dedupe key of a secret: HMAC(org dedupe key,
// secret type || normalized value), so the same leaked key on two nodes
// deduplicates. "" without the org key.
func OrgSecretKey(orgDedupeKey []byte, secretType, value string) string {
	if len(orgDedupeKey) == 0 {
		return ""
	}
	return keyed(orgDedupeKey, domainOrgSecret, secretType, normalizeSecret(value))
}

func join(parts ...string) string { return strings.Join(parts, "\x00") }

func digest(domain string, parts ...string) string {
	sum := sha256.Sum256([]byte(domain + "\x00" + join(parts...)))
	return hex.EncodeToString(sum[:])
}

func keyed(key []byte, domain string, parts ...string) string {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(domain + "\x00" + join(parts...)))
	return hex.EncodeToString(h.Sum(nil))
}

// EvidenceHash is the hash of redacted evidence (section 4.5).
func EvidenceHash(evidenceRedacted string) string {
	if evidenceRedacted == "" {
		return ""
	}
	return digest("sbo-secfinding-evidence-v1", evidenceRedacted)
}
