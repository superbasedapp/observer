package update

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/marmutapp/superbased-observer/internal/updatespec"
)

// SchemaV1 is the only manifest schema this agent understands. The
// field is the compat key: an unknown value is IGNORED rather than
// rejected (verify rule 5), so a future server can publish a v2
// manifest without bricking older nodes.
const SchemaV1 = "sbo.update-manifest.v1"

// SchemaV2 is the distro-aware manifest (modular packaging plan 5.6.1):
// v1's fields plus, per artifact, distro and components_digest, and at
// manifest level release_index_sha256 and distro_epoch. It is served only
// on the parallel /api/agent/update/manifest/v2 route and signed under its
// own domain tag (SigningDomainV2), so a v1 node never sees one and a v2
// document can never be re-presented on the v1 rail.
const SchemaV2 = "sbo.update-manifest.v2"

// MaxNotesChars caps Manifest.Notes in runes.
//
// It deliberately equals announce.MaxBodyChars (280): the update notice
// renders through the announcement banner component (plan §1), so a
// longer note would be a banner the operator cannot read. It is
// duplicated as a literal rather than imported so this package stays
// stdlib-only (see doc.go); manifest_test.go asserts the two agree, so
// a change on either side fails loudly.
const MaxNotesChars = 280

// MaxManifestBytes is the decode cap for one manifest document. The
// fast-forward / endless-data mitigation of §2.3: a stream longer than
// this is refused rather than buffered.
const MaxManifestBytes = 256 * 1024

// MaxEnvelopeBytes is the decode cap for the signed envelope that
// carries a manifest (the base64 manifest plus its signature fields).
const MaxEnvelopeBytes = 512 * 1024

// KindAgent is the artifact kind for the node agent binary. It is the
// only kind v1 delivers; the field exists so the org server can mirror
// other artifacts (an edge collector, an org-server image bundle)
// without a wire change.
const KindAgent = "agent"

// Artifact is one downloadable archive for one platform.
//
// Member + MemberSHA256 pin the binary INSIDE the archive, so an
// archive carrying an extra file cannot smuggle anything past the
// extractor (§3.1).
type Artifact struct {
	// Kind is the artifact family (KindAgent).
	Kind string `json:"kind"`
	// OS is the GOOS-shaped target ("linux", "darwin", "windows").
	OS string `json:"os"`
	// Arch is the GOARCH-shaped target ("amd64", "arm64").
	Arch string `json:"arch"`
	// ArchiveType is "tar.gz" or "zip" — both shapes the release
	// pipeline really emits (npm-release.yml:1181-1189).
	ArchiveType string `json:"archive_type"`
	// Filename is the archive's base name at the mirror. It is a base
	// name only: a separator or a ".." element is a validation failure.
	Filename string `json:"filename"`
	// SizeBytes is the exact archive size and doubles as the download
	// ceiling (a stream that exceeds it is aborted, §2.3).
	SizeBytes int64 `json:"size_bytes"`
	// SHA256 is the hex sha256 of the archive bytes, taken from the
	// SIGNED manifest and never from a mirror response header.
	SHA256 string `json:"sha256"`
	// Member is the archive entry holding the real binary ("observer",
	// "observer.exe").
	Member string `json:"member"`
	// MemberSHA256 is the hex sha256 of the extracted member.
	MemberSHA256 string `json:"member_sha256"`
	// AliasMembers names the alias entries the archive carries beside
	// Member — a relative symlink in the POSIX tarballs, a byte copy in
	// the win32 zip. Naming them explicitly is what lets the extractor
	// SKIP them and still treat any other member as a failure.
	AliasMembers []string `json:"alias_members,omitempty"`
	// UpstreamSigType names the vendor signature scheme. There is
	// exactly one (SigTypeEd25519), and that is the point: the
	// vocabulary is the set of schemes something in this tree actually
	// verifies.
	UpstreamSigType string `json:"upstream_sig_type,omitempty"`
	// UpstreamSig is the base64 vendor signature over the ARCHIVE
	// bytes, verified against a key compiled into the agent
	// (vendorkey.go). An artifact with an empty UpstreamSig is
	// blocked{unsigned_artifact} and never applied — the fail-closed
	// interim until the W6 release pipeline produces these (review H0).
	UpstreamSig string `json:"upstream_sig,omitempty"`
	// Distro names the prebuilt node distro, or the custom distro id
	// (custom-<manifest digest>, distro.go), the archive holds (v2 only).
	// A v1 artifact leaves it empty, which means full: every v1 document
	// delivers the full build and an old node never reads this field.
	Distro string `json:"distro,omitempty"`
	// ComponentsDigest is components.Digest of the binary's compiled set
	// (v2 only). The vendor release index binds it to the archive hash,
	// and the node's pre-swap probe compares it with what the staged
	// binary reports about itself.
	ComponentsDigest string `json:"components_digest,omitempty"`
}

// Manifest is one signed publication: everything needed to move a node
// to one version on one channel.
//
// Mix-and-match (§2.3) is foreclosed by shape: a manifest lists EVERY
// artifact for ONE version with its hash, and artifacts are never
// selected across manifests. That is TUF's snapshot role collapsed into
// the manifest, which is honest for a single-publisher product.
type Manifest struct {
	// Schema is the compat key (SchemaV1).
	Schema string `json:"schema"`
	// Channel is the channel this document was published on.
	Channel Channel `json:"channel"`
	// ManifestVersion is the org's monotonic publish counter and the
	// rollout engine's ordinal (§3.6). Replay protection compares it
	// (verify rule 6) and the signature binds it (§3.2).
	ManifestVersion int64 `json:"manifest_version"`
	// Version is the agent version this manifest delivers, semver with
	// a leading "v".
	Version string `json:"version"`
	// ReleasedAt is RFC3339.
	ReleasedAt string `json:"released_at"`
	// ExpiresAt is RFC3339 and REQUIRED, for the same reason it is
	// required on an announcement: a stale manifest is worse than none,
	// and expiry is the anti-freeze control of §2.3.
	ExpiresAt string `json:"expires_at"`
	// MinFromVersion is the oldest installed version that may jump
	// straight to Version. A node below it reports
	// blocked{required_stop} and the surfaces name the intermediate
	// version to install first (GitLab's "required stops", made
	// explicit rather than discovered at runtime). Empty = no stop.
	MinFromVersion string `json:"min_from_version,omitempty"`
	// MinServerVersion is the org-server version this agent version
	// needs. Rendered on the Updates page; not enforced on the node.
	MinServerVersion string `json:"min_server_version,omitempty"`
	// EOSAt is RFC3339 end-of-support for Version. Surfaced, never
	// enforced (§1).
	EOSAt string `json:"eos_at,omitempty"`
	// Notes is plain text, <= MaxNotesChars runes. Never HTML, never
	// markdown.
	Notes string `json:"notes,omitempty"`
	// NotesURL is an optional https link to the release notes.
	NotesURL string `json:"notes_url,omitempty"`
	// AllowDowngradeTo names the exact version an admin-minted
	// downgrade manifest targets. It is the ONLY way Version may be
	// lower than installed, and it still needs node consent
	// ([update].allow_downgrade, default false) — verify rule 7.
	AllowDowngradeTo string `json:"allow_downgrade_to,omitempty"`
	// SchemaVersion is the AGENT DATABASE schema high-water mark the
	// target binary carries (internal/db's migration count). It is the
	// producer's answer to the one question BuildApplyPlan cannot
	// answer on its own: does this apply advance the schema, and does
	// it therefore need a full VACUUM INTO snapshot of a database that
	// may be tens of gigabytes?
	//
	// ZERO MEANS UNKNOWN, and unknown is treated as "may advance" — the
	// conservative direction, because an unnecessary snapshot costs
	// disk and a missing one costs a brick (§3.7 step 5). A manifest
	// minted before this field existed therefore behaves exactly as
	// before; one that carries it snapshots only across a real
	// migration.
	SchemaVersion int `json:"schema_version,omitempty"`
	// ReleaseIndexSHA256 is the hex sha256 of the vendor-signed release
	// index served beside a v2 manifest (v2 only). The node checks the
	// index bytes it received against it, so the org cannot swap in a
	// different (even genuinely vendor-signed) index for another release.
	ReleaseIndexSHA256 string `json:"release_index_sha256,omitempty"`
	// DistroEpoch is the org-authored distro epoch for this channel (v2
	// only). A node accepts a distro CHANGE only when it is ahead of the
	// epoch it last applied on the channel (plan 5.6.1).
	DistroEpoch int64 `json:"distro_epoch,omitempty"`
	// Artifacts lists every artifact for this version.
	Artifacts []Artifact `json:"artifacts"`
}

// Envelope is the signed wrapper the agent rail serves. It mirrors
// OrgAnnouncementDoc: bytes, a hash of those bytes, the key that signed
// them, and the signature.
type Envelope struct {
	// ManifestB64 is the canonical manifest JSON, base64 (std
	// encoding). Carrying BYTES rather than a nested object is what
	// makes the hash and the signature verifiable byte-for-byte
	// regardless of how any JSON library re-orders a map.
	ManifestB64 string `json:"manifest"`
	// ManifestHash is the hex sha256 of the decoded manifest bytes.
	ManifestHash string `json:"manifest_hash"`
	// KeyID identifies the org distribution key that signed this
	// document. It must agree with any key another rail already pinned
	// (verify rule 3).
	KeyID string `json:"key_id"`
	// Signature is base64 Ed25519 over ManifestSigningMessage — domain
	// tagged AND version bound, so neither a cross-rail document nor a
	// version-bumped capture verifies here.
	Signature string `json:"signature"`
}

// CanonicalJSON encodes a manifest deterministically: object keys
// sorted, no insignificant whitespace, no HTML escaping, no trailing
// newline. Signing and verification MUST both go through it — the
// signature covers a hash of these bytes, so any encoding difference is
// a verification failure.
//
// Numbers survive the round trip exactly (json.Number), so a large
// manifest_version cannot be mangled into a float.
func CanonicalJSON(m Manifest) ([]byte, error) {
	raw, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("update.CanonicalJSON: marshal: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var generic any
	if err := dec.Decode(&generic); err != nil {
		return nil, fmt.Errorf("update.CanonicalJSON: decode: %w", err)
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	// Go's encoder emits map keys in sorted order, which is the whole
	// reason the value is round-tripped through a map first.
	if err := enc.Encode(generic); err != nil {
		return nil, fmt.Errorf("update.CanonicalJSON: encode: %w", err)
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// HashBytes returns the lowercase hex sha256 of b. It is the one hash
// spelling this package uses, for manifests and for artifacts alike; the
// owner is updatespec.HashBytes, which the content channel shares.
func HashBytes(b []byte) string {
	return updatespec.HashBytes(b)
}

// DecodeManifest parses manifest bytes within MaxManifestBytes and
// refuses anything but exactly one JSON value — a trailing second
// document is a smuggling shape, not a parse detail.
func DecodeManifest(b []byte) (Manifest, error) {
	var m Manifest
	if len(b) > MaxManifestBytes {
		return m, fmt.Errorf("update.DecodeManifest: %w (%d bytes)", ErrEnvelopeDecode, len(b))
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	// Unknown fields are TOLERATED on purpose: `schema` is the compat
	// key (verify rule 5), so a later v1-compatible field must not turn
	// into a decode failure on an older agent.
	if err := dec.Decode(&m); err != nil {
		return Manifest{}, fmt.Errorf("update.DecodeManifest: %w: %w", ErrEnvelopeDecode, err)
	}
	if dec.More() {
		return Manifest{}, fmt.Errorf("update.DecodeManifest: %w: trailing JSON value", ErrEnvelopeDecode)
	}
	return m, nil
}

// ProbeSchema reads ONLY the schema field out of manifest bytes.
//
// It exists because verify rule 5 (unknown schema -> ignore the
// document, fail-open) must be answerable for a document this binary
// cannot otherwise parse: a future v2 manifest may legitimately change
// the shape of any other field, and a decode error there must not be
// reported as a corrupt document.
func ProbeSchema(b []byte) (string, error) {
	if len(b) > MaxManifestBytes {
		return "", fmt.Errorf("update.ProbeSchema: %w (%d bytes)", ErrEnvelopeDecode, len(b))
	}
	var probe struct {
		Schema string `json:"schema"`
	}
	if err := json.Unmarshal(b, &probe); err != nil {
		return "", fmt.Errorf("update.ProbeSchema: %w: %w", ErrEnvelopeDecode, err)
	}
	return probe.Schema, nil
}

// ErrInvalidManifest is the sentinel every Validate failure wraps.
var ErrInvalidManifest = errors.New("invalid manifest")

// Validate checks a manifest's STRUCTURE — shape, caps, encodings,
// duplicate artifacts. It answers "is this a well-formed document",
// never "should this node apply it": trust (signature), freshness
// (expiry), ordering (replay) and eligibility (downgrade, required
// stop, platform) are verify.go's ordered rules, so a caller cannot
// accidentally treat a structurally valid manifest as an authorised one.
func Validate(m Manifest) error {
	if m.Schema != SchemaV1 && m.Schema != SchemaV2 {
		return fmt.Errorf("update.Validate: %w: unknown schema %q", ErrInvalidManifest, m.Schema)
	}
	if err := validateDistroFields(m); err != nil {
		return fmt.Errorf("update.Validate: %w", err)
	}
	if !KnownChannel(m.Channel) {
		return fmt.Errorf("update.Validate: %w: unknown channel %q", ErrInvalidManifest, m.Channel)
	}
	if m.ManifestVersion <= 0 {
		return fmt.Errorf("update.Validate: %w: manifest_version must be positive", ErrInvalidManifest)
	}
	if _, ok := ParseSemver(m.Version); !ok || !strings.HasPrefix(m.Version, "v") {
		return fmt.Errorf("update.Validate: %w: version %q must be semver with a leading v", ErrInvalidManifest, m.Version)
	}
	released, err := parseRFC3339(m.ReleasedAt)
	if err != nil {
		return fmt.Errorf("update.Validate: %w: released_at: %w", ErrInvalidManifest, err)
	}
	expires, err := parseRFC3339(m.ExpiresAt)
	if err != nil {
		return fmt.Errorf("update.Validate: %w: expires_at is required: %w", ErrInvalidManifest, err)
	}
	if !expires.After(released) {
		return fmt.Errorf("update.Validate: %w: expires_at must be after released_at", ErrInvalidManifest)
	}
	if m.EOSAt != "" {
		if _, err := parseRFC3339(m.EOSAt); err != nil {
			return fmt.Errorf("update.Validate: %w: eos_at: %w", ErrInvalidManifest, err)
		}
	}
	for _, f := range []struct {
		name, val string
	}{
		{"min_from_version", m.MinFromVersion},
		{"min_server_version", m.MinServerVersion},
		{"allow_downgrade_to", m.AllowDowngradeTo},
	} {
		if f.val == "" {
			continue
		}
		if _, ok := ParseSemver(f.val); !ok {
			return fmt.Errorf("update.Validate: %w: %s %q is not semver", ErrInvalidManifest, f.name, f.val)
		}
	}
	if n := utf8.RuneCountInString(m.Notes); n > MaxNotesChars {
		return fmt.Errorf("update.Validate: %w: notes is %d runes (max %d)", ErrInvalidManifest, n, MaxNotesChars)
	}
	if m.NotesURL != "" && !strings.HasPrefix(m.NotesURL, "https://") {
		return fmt.Errorf("update.Validate: %w: notes_url must be https", ErrInvalidManifest)
	}
	if len(m.Artifacts) == 0 {
		return fmt.Errorf("update.Validate: %w: no artifacts", ErrInvalidManifest)
	}
	seen := map[ArtifactKey]bool{}
	for i, a := range m.Artifacts {
		if err := validateArtifact(a); err != nil {
			return fmt.Errorf("update.Validate: artifact %d (%s/%s): %w", i, a.OS, a.Arch, err)
		}
		k := KeyOf(a)
		if seen[k] {
			return fmt.Errorf("update.Validate: %w: duplicate artifact %s", ErrInvalidManifest, k)
		}
		seen[k] = true
	}
	return nil
}

// validateArtifact checks one artifact row.
func validateArtifact(a Artifact) error {
	if a.Kind == "" {
		return fmt.Errorf("%w: kind is required", ErrInvalidManifest)
	}
	if a.OS == "" || a.Arch == "" {
		return fmt.Errorf("%w: os and arch are required", ErrInvalidManifest)
	}
	if !KnownArchiveType(a.ArchiveType) {
		return fmt.Errorf("%w: unknown archive_type %q", ErrInvalidManifest, a.ArchiveType)
	}
	if err := updatespec.ValidBaseName(a.Filename); err != nil {
		return fmt.Errorf("%w: filename: %w", ErrInvalidManifest, err)
	}
	if a.SizeBytes <= 0 {
		return fmt.Errorf("%w: size_bytes must be positive", ErrInvalidManifest)
	}
	if !updatespec.IsHexSHA256(a.SHA256) {
		return fmt.Errorf("%w: sha256 must be 64 hex characters", ErrInvalidManifest)
	}
	if !updatespec.IsHexSHA256(a.MemberSHA256) {
		return fmt.Errorf("%w: member_sha256 must be 64 hex characters", ErrInvalidManifest)
	}
	if err := validMemberName(a.Member); err != nil {
		return fmt.Errorf("%w: member: %w", ErrInvalidManifest, err)
	}
	names := map[string]bool{a.Member: true}
	for _, alias := range a.AliasMembers {
		if err := validMemberName(alias); err != nil {
			return fmt.Errorf("%w: alias_members: %w", ErrInvalidManifest, err)
		}
		if names[alias] {
			return fmt.Errorf("%w: alias_members repeats %q", ErrInvalidManifest, alias)
		}
		names[alias] = true
	}
	if a.UpstreamSig != "" && a.UpstreamSigType == "" {
		return fmt.Errorf("%w: upstream_sig_type is required with a signature", ErrInvalidManifest)
	}
	if a.UpstreamSigType != "" && !KnownSigType(a.UpstreamSigType) {
		return fmt.Errorf("%w: unknown upstream_sig_type %q", ErrInvalidManifest, a.UpstreamSigType)
	}
	return nil
}

// validateDistroFields checks the fields that differ between the two
// schemas. A v1 document must carry none of v2's fields (it always means
// the full build, plan 5.6), so a v1 artifact naming another distro is a
// malformed document, not a hint. A v2 document must carry all of them:
// a distro artifact without a components digest is one the release index
// cannot bind and the node's probe cannot check.
func validateDistroFields(m Manifest) error {
	if m.Schema == SchemaV1 {
		if m.ReleaseIndexSHA256 != "" || m.DistroEpoch != 0 {
			return fmt.Errorf("%w: a v1 manifest carries no release_index_sha256 or distro_epoch", ErrInvalidManifest)
		}
		for _, a := range m.Artifacts {
			if NormalizeDistro(a.Distro) != DistroFull || a.ComponentsDigest != "" {
				return fmt.Errorf("%w: a v1 manifest delivers only the full build (%s names distro %q)",
					ErrInvalidManifest, a.Filename, a.Distro)
			}
		}
		return nil
	}
	if !updatespec.IsHexSHA256(m.ReleaseIndexSHA256) {
		return fmt.Errorf("%w: release_index_sha256 must be 64 hex characters", ErrInvalidManifest)
	}
	if m.DistroEpoch < 0 {
		return fmt.Errorf("%w: distro_epoch must not be negative", ErrInvalidManifest)
	}
	for _, a := range m.Artifacts {
		if strings.TrimSpace(a.Distro) == "" || !ArtifactDistro(a.Distro) {
			return fmt.Errorf("%w: %s: distro %q is neither a prebuilt node distro nor a custom distro id", ErrInvalidManifest, a.Filename, a.Distro)
		}
		if !updatespec.IsHexSHA256(a.ComponentsDigest) {
			return fmt.Errorf("%w: %s: components_digest must be 64 hex characters", ErrInvalidManifest, a.Filename)
		}
	}
	return nil
}

// SigTypeEd25519 is the ONLY vendor signature scheme: the RAW 64
// Ed25519 signature bytes over the whole archive, carried base64 in
// UpstreamSig, verified against a key compiled into the agent
// (vendorkey.go).
//
// It is a bare signature rather than a container because that is
// exactly what the verifier implements — cmd/observer's
// verifyVendorSignature base64-decodes UpstreamSig and calls
// ed25519.Verify over the archive bytes.
//
// This vocabulary was briefly wider. `cosign-bundle` and `minisign`
// were declared here as future-proofing and never implemented: nothing
// emitted them and nothing unwrapped them, so a manifest could carry a
// label that read as a stronger guarantee than the check anyone
// performed. A scheme this tree cannot verify must not be spellable in
// a manifest, so both are gone. Adding one back is a vocabulary entry
// AND a verifier, in the same change.
const SigTypeEd25519 = "ed25519"

// KnownSigType reports whether t is a vendor signature scheme this
// agent can verify. Vocabulary and capability are the SAME set here,
// deliberately — see SigTypeEd25519.
func KnownSigType(t string) bool {
	return t == SigTypeEd25519
}

// validMemberName rejects an archive member name that is absolute,
// escapes the extraction root, or is otherwise not a plain relative
// path. Nested members are permitted ("bin/observer"); traversal is not.
func validMemberName(name string) error {
	if name == "" {
		return errors.New("empty")
	}
	if IsAbsArchivePath(name) {
		return fmt.Errorf("%q is absolute", name)
	}
	if hasTraversal(name) {
		return fmt.Errorf("%q escapes the extraction root", name)
	}
	if strings.HasSuffix(name, "/") {
		return fmt.Errorf("%q is a directory", name)
	}
	return nil
}

// parseRFC3339 parses a required RFC3339 timestamp.
func parseRFC3339(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, errors.New("empty")
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, err
	}
	return t.UTC(), nil
}

// SortArtifacts orders artifacts by kind, os, arch. Publishing sorts
// before canonicalising so two servers building the same release
// produce byte-identical manifests.
func SortArtifacts(as []Artifact) {
	sort.SliceStable(as, func(i, j int) bool {
		if as[i].Kind != as[j].Kind {
			return as[i].Kind < as[j].Kind
		}
		// Distro sorts between kind and platform. A v1 list is all full,
		// so its order (and its canonical bytes) are unchanged.
		if di, dj := NormalizeDistro(as[i].Distro), NormalizeDistro(as[j].Distro); di != dj {
			return di < dj
		}
		if as[i].OS != as[j].OS {
			return as[i].OS < as[j].OS
		}
		return as[i].Arch < as[j].Arch
	})
}
