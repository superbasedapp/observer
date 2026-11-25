package update

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/updatespec"
)

// releaseindex.go is the VENDOR-signed release index (modular packaging
// plan 5.6): per release, one document binding each artifact's archive
// digest to its distro and components digest, signed with the vendor key
// compiled into this tree.
//
// WHY IT EXISTS. A v2 manifest is signed by the ORG. Without the index the
// org alone could claim that the archive with hash H is the minimal build
// while it is in fact the full one (both are genuinely vendor-signed
// archives, so the per-archive .sig cannot tell them apart). The node
// therefore checks the chosen artifact's distro and components digest
// against this vendor document, so neither can be asserted by the org.
//
// The index never travels alone: the v2 route's response envelope carries
// the manifest AND the index bytes with the index signature (plan 5.6.1,
// third-pass M2), and the manifest binds the index by its hash
// (release_index_sha256), so one response holds all trust material and
// nothing is cached outside the update state.
//
// It is PURE like the rest of this package: bytes in, a decision out.

// ReleaseIndexSchemaV1 is the only release index schema.
const ReleaseIndexSchemaV1 = "sbo.release-index.v1"

// ReleaseIndexSigningDomain is the index's domain tag. The vendor key also
// signs archive bytes (raw, no domain) and the release manifest (its own
// domain); the tag keeps an index signature from verifying as either.
const ReleaseIndexSigningDomain = "sbo-release-index-v1"

// ReleaseIndexFileName / ReleaseIndexSigFileName are the two files a
// release (and an air-gap bundle) carries.
const (
	ReleaseIndexFileName    = "release-index.json"
	ReleaseIndexSigFileName = "release-index.json.sig"
)

// MaxReleaseIndexBytes caps one index document (4 distros x 5 platforms
// is about 20 entries; the cap leaves room for kinds yet to come).
const MaxReleaseIndexBytes = 256 * 1024

var (
	// ErrReleaseIndexInvalid wraps every structural or signature failure.
	ErrReleaseIndexInvalid = errors.New("update: release index is invalid")
	// ErrReleaseIndexMismatch means the index is authentic but disagrees
	// with the manifest about an artifact.
	ErrReleaseIndexMismatch = errors.New("update: release index disagrees with the manifest")
)

// ReleaseIndexEntry is one artifact the vendor built.
type ReleaseIndexEntry struct {
	Filename         string   `json:"filename"`
	Kind             string   `json:"kind"`
	Distro           string   `json:"distro"`
	OS               string   `json:"os"`
	Arch             string   `json:"arch"`
	ArchiveType      string   `json:"archive_type"`
	SizeBytes        int64    `json:"size_bytes"`
	SHA256           string   `json:"sha256"`
	Member           string   `json:"member"`
	MemberSHA256     string   `json:"member_sha256"`
	AliasMembers     []string `json:"alias_members,omitempty"`
	ComponentsDigest string   `json:"components_digest"`
}

// ReleaseIndex is the signed per-release document.
type ReleaseIndex struct {
	Schema string `json:"schema"`
	// Version is the release ("v1.36.0").
	Version string `json:"version"`
	// CatalogVersion is the component catalog version the components
	// digests were computed under (components.CatalogVersion).
	CatalogVersion int                 `json:"catalog_version"`
	Artifacts      []ReleaseIndexEntry `json:"artifacts"`
}

// Artifact renders an entry as the manifest artifact it describes. The
// vendor signature over the archive bytes is not part of the index (it
// travels as the archive's own .sig), so it is left empty.
func (e ReleaseIndexEntry) Artifact() Artifact {
	return Artifact{
		Kind: e.Kind, OS: e.OS, Arch: e.Arch, ArchiveType: e.ArchiveType,
		Filename: e.Filename, SizeBytes: e.SizeBytes, SHA256: e.SHA256,
		Member: e.Member, MemberSHA256: e.MemberSHA256, AliasMembers: e.AliasMembers,
		Distro: NormalizeDistro(e.Distro), ComponentsDigest: e.ComponentsDigest,
	}
}

// CanonicalReleaseIndex encodes an index deterministically (sorted keys,
// no insignificant whitespace, no HTML escaping), the CanonicalJSON
// discipline. The producer signs these bytes' hash.
func CanonicalReleaseIndex(ix ReleaseIndex) ([]byte, error) {
	raw, err := json.Marshal(ix)
	if err != nil {
		return nil, fmt.Errorf("update.CanonicalReleaseIndex: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var generic any
	if err := dec.Decode(&generic); err != nil {
		return nil, fmt.Errorf("update.CanonicalReleaseIndex: %w", err)
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(generic); err != nil {
		return nil, fmt.Errorf("update.CanonicalReleaseIndex: %w", err)
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// ReleaseIndexSigningMessage is sha256(domain || 0 || version || 0 ||
// index_sha256). The version comes from the SIGNED bytes, never from an
// envelope field (the ROUTING-SIG-1 lesson).
func ReleaseIndexSigningMessage(version, indexHash string) []byte {
	h := sha256.New()
	h.Write([]byte(ReleaseIndexSigningDomain))
	h.Write([]byte{0})
	h.Write([]byte(version))
	h.Write([]byte{0})
	h.Write([]byte(indexHash))
	return h.Sum(nil)
}

// SignReleaseIndex returns the base64 signature over a canonical index.
// The release pipeline (scripts/vendorsign index) is its one production
// caller; tests call it with throwaway keys.
func SignReleaseIndex(priv ed25519.PrivateKey, body []byte) (string, error) {
	ix, err := DecodeReleaseIndex(body)
	if err != nil {
		return "", err
	}
	if len(priv) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("update.SignReleaseIndex: %w: bad private key", ErrReleaseIndexInvalid)
	}
	sig := ed25519.Sign(priv, ReleaseIndexSigningMessage(ix.Version, HashBytes(body)))
	return base64.StdEncoding.EncodeToString(sig), nil
}

// DecodeReleaseIndex parses and validates index bytes within the cap.
func DecodeReleaseIndex(body []byte) (ReleaseIndex, error) {
	var ix ReleaseIndex
	if len(body) == 0 || len(body) > MaxReleaseIndexBytes {
		return ix, fmt.Errorf("update.DecodeReleaseIndex: %w: %d bytes (max %d)", ErrReleaseIndexInvalid, len(body), MaxReleaseIndexBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	if err := dec.Decode(&ix); err != nil {
		return ReleaseIndex{}, fmt.Errorf("update.DecodeReleaseIndex: %w: %w", ErrReleaseIndexInvalid, err)
	}
	if dec.More() {
		return ReleaseIndex{}, fmt.Errorf("update.DecodeReleaseIndex: %w: trailing JSON value", ErrReleaseIndexInvalid)
	}
	if err := ValidateReleaseIndex(ix); err != nil {
		return ReleaseIndex{}, err
	}
	return ix, nil
}

// ValidateReleaseIndex checks an index's structure: known schema, semver
// version, at least one entry, and every entry well formed with a known
// distro and a hex components digest. Filenames and keys are unique.
func ValidateReleaseIndex(ix ReleaseIndex) error {
	if ix.Schema != ReleaseIndexSchemaV1 {
		return fmt.Errorf("update.ValidateReleaseIndex: %w: unknown schema %q", ErrReleaseIndexInvalid, ix.Schema)
	}
	if _, ok := ParseSemver(ix.Version); !ok || !strings.HasPrefix(ix.Version, "v") {
		return fmt.Errorf("update.ValidateReleaseIndex: %w: version %q", ErrReleaseIndexInvalid, ix.Version)
	}
	if len(ix.Artifacts) == 0 {
		return fmt.Errorf("update.ValidateReleaseIndex: %w: no artifacts", ErrReleaseIndexInvalid)
	}
	names := map[string]bool{}
	keys := map[ArtifactKey]bool{}
	for _, e := range ix.Artifacts {
		a := e.Artifact()
		if err := validateArtifact(a); err != nil {
			return fmt.Errorf("update.ValidateReleaseIndex: %w: %s: %w", ErrReleaseIndexInvalid, e.Filename, err)
		}
		if strings.TrimSpace(e.Distro) == "" || !ArtifactDistro(e.Distro) {
			return fmt.Errorf("update.ValidateReleaseIndex: %w: %s: distro %q", ErrReleaseIndexInvalid, e.Filename, e.Distro)
		}
		if !updatespec.IsHexSHA256(e.ComponentsDigest) {
			return fmt.Errorf("update.ValidateReleaseIndex: %w: %s: components_digest", ErrReleaseIndexInvalid, e.Filename)
		}
		if names[e.Filename] || keys[KeyOf(a)] {
			return fmt.Errorf("update.ValidateReleaseIndex: %w: duplicate %s", ErrReleaseIndexInvalid, e.Filename)
		}
		names[e.Filename], keys[KeyOf(a)] = true, true
	}
	return nil
}

// VerifyReleaseIndex checks the index signature against the accepted
// vendor keys (any of them: a rotation ships an overlap release) and
// returns the decoded index. An empty key set is a REFUSAL, never a skip:
// "I have no key" must not read as "no key needed".
func VerifyReleaseIndex(body []byte, sigB64 string, keys []ed25519.PublicKey) (ReleaseIndex, error) {
	ix, err := DecodeReleaseIndex(body)
	if err != nil {
		return ReleaseIndex{}, err
	}
	if len(keys) == 0 {
		return ReleaseIndex{}, fmt.Errorf("update.VerifyReleaseIndex: %w: %w", ErrReleaseIndexInvalid, ErrNoVendorKey)
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sigB64))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return ReleaseIndex{}, fmt.Errorf("update.VerifyReleaseIndex: %w: bad signature encoding", ErrReleaseIndexInvalid)
	}
	msg := ReleaseIndexSigningMessage(ix.Version, HashBytes(body))
	for _, k := range keys {
		if len(k) == ed25519.PublicKeySize && ed25519.Verify(k, msg, sig) {
			return ix, nil
		}
	}
	return ReleaseIndex{}, fmt.Errorf("update.VerifyReleaseIndex: %w: it does not verify against any accepted vendor key", ErrReleaseIndexInvalid)
}

// EntryByFilename returns the entry for one archive file name (exact).
func (ix ReleaseIndex) EntryByFilename(name string) (ReleaseIndexEntry, bool) {
	for _, e := range ix.Artifacts {
		if e.Filename == name {
			return e, true
		}
	}
	return ReleaseIndexEntry{}, false
}

// CheckArtifactAgainstIndex requires the index to name the artifact by
// file name and to agree on every fact the org could otherwise assert:
// the archive hash and size, the platform, the distro and the components
// digest.
func CheckArtifactAgainstIndex(ix ReleaseIndex, a Artifact) error {
	e, ok := ix.EntryByFilename(a.Filename)
	if !ok {
		return fmt.Errorf("%w: the release index for %s does not name %s", ErrReleaseIndexMismatch, ix.Version, a.Filename)
	}
	want := e.Artifact()
	switch {
	case !strings.EqualFold(want.SHA256, a.SHA256) || want.SizeBytes != a.SizeBytes:
		return fmt.Errorf("%w: %s archive hash or size", ErrReleaseIndexMismatch, a.Filename)
	case KeyOf(want) != KeyOf(a):
		return fmt.Errorf("%w: %s is %s in the index, %s in the manifest", ErrReleaseIndexMismatch, a.Filename, KeyOf(want), KeyOf(a))
	case !strings.EqualFold(want.ComponentsDigest, a.ComponentsDigest):
		return fmt.Errorf("%w: %s components digest", ErrReleaseIndexMismatch, a.Filename)
	case !strings.EqualFold(want.MemberSHA256, a.MemberSHA256):
		return fmt.Errorf("%w: %s member hash", ErrReleaseIndexMismatch, a.Filename)
	}
	return nil
}
