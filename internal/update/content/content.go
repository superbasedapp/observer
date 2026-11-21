package content

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// SchemaV1 is the only content manifest schema.
const SchemaV1 = "sbo.content-manifest.v1"

// Domain tags. The vendor key also signs archives (raw), release manifests
// and release indexes (their own tags); these keep a content signature from
// verifying as any of them, and an org countersignature from verifying as a
// vendor signature.
const (
	SigningDomain = "sbo-content-manifest-v1"
	MirrorDomain  = "sbo-content-mirror-v1"
	// FeedSigningDomain is the content-feed key's domain (static feed
	// mirroring plan section 6.4): a feed-key signature never verifies as a
	// release-key one, nor the reverse, even if the two keys were the same.
	FeedSigningDomain = "sbo-content-feed-v1"
)

// SignerFeed is the Envelope.Signer value of a manifest signed with the
// content-feed key (SignFeed). An empty Signer is the release vendor key.
const SignerFeed = "feed"

// MaxDeltaDrop caps the names one delta entry removes from its base.
const MaxDeltaDrop = 100000

// Caps.
const (
	// MaxManifestBytes caps one decoded manifest.
	MaxManifestBytes = 1 << 20
	// MaxEnvelopeBytes caps one envelope (base64 manifest plus
	// signatures).
	MaxEnvelopeBytes = 2 << 20
	// MaxEntries caps the artifacts one manifest lists.
	MaxEntries = 512
)

// Kind is one typed content kind of the channel.
type Kind string

// The content kinds. A new kind is one row in kindTable.
const (
	MaliciousPackages Kind = "security.malicious_packages"
	PopularNames      Kind = "security.popular_names"
	OSVExport         Kind = "security.osv_export"
	OSVOSExport       Kind = "security.osv_os_export"
	// OSVShards is the remote-matching shard manifest (OS and CI scanning
	// plan sections 13.3 and 13.11, lane RM-1): one entry per shard set, its
	// descriptor (<Set>.set.json, internal/secscan/osvshardkey is the format
	// owner), which pins the set's content-addressed index files and shards
	// by digest. The shard objects themselves are served from the public
	// shard bucket, never as entries of this kind.
	OSVShards Kind = "security.osv_shards"
	// KEV and EPSS are the exploit-likelihood kinds (OS and CI scanning plan
	// section 14.7): the CISA Known Exploited Vulnerabilities catalog and
	// the FIRST EPSS daily scores, compacted by the publisher
	// (internal/secexploit is the format owner).
	KEV           Kind = "security.kev"
	EPSS          Kind = "security.epss"
	AgentCVETable Kind = "security.agent_cve_table"
	RulePack      Kind = "security.rule_pack"
	Engine        Kind = "security.engine"
	SandboxRootfs Kind = "sandbox.rootfs"
	SandboxImage  Kind = "sandbox.image"
	SandboxGuest  Kind = "sandbox.guest_binary"
	SandboxNative Kind = "sandbox.native_files"
)

// Class groups kinds by what they carry.
type Class string

// The content classes.
const (
	// ClassFeed is data that changes daily (advisories, lists).
	ClassFeed Class = "feed"
	// ClassEngine is a third-party engine binary's pin.
	ClassEngine Class = "engine"
	// ClassArtifact is an Observer-built artifact set (sandbox).
	ClassArtifact Class = "artifact"
)

// KindSpec is one row of the kind table.
type KindSpec struct {
	Kind  Kind
	Class Class
	// MaxValidity bounds expires_at - issued_at: a manifest claiming a
	// longer life is refused, so a captured manifest cannot be kept valid
	// for a year.
	MaxValidity time.Duration
	// AgeFloor is how long after issue the data may still be used as stale;
	// past it the data is unknown. A consumer may pass a stricter floor
	// (the security floor's max_advisory_db_age_h).
	AgeFloor time.Duration
	// Owner names the plan section that consumes the kind.
	Owner string
	// TargetOS is the OS the kind's artifacts run on whatever the node's
	// own OS is ("linux" for the microVM guest kinds, whose rootfs, kernel
	// and guest observer run inside a Linux guest); "" means the node's own
	// platform. PlatformFor reads it, so a Windows or macOS node verifies a
	// guest set's linux entries instead of skipping them (Windows 11 Pro
	// rerun 2026-10-25: a tampered guest set was accepted on Windows).
	TargetOS string
	// CompleteSet marks a kind whose entries are one set that is used
	// whole (the microVM guest image set, the container image's descriptor
	// and SBOM): every entry name the manifest lists must have an entry the
	// node's platform walk selects, or the set is refused as partial_set
	// (CheckCompleteSet, WINFIX2 audit finding 8). A kind whose entries are
	// alternatives per platform under different names (the native files)
	// leaves it false.
	CompleteSet bool
	// ManifestIsContent marks a kind whose manifest is itself the content
	// the node acts on (the engine pins and the digests it revokes), with
	// the artifact bytes optional. A manifest none of whose entries names
	// the node's platform installs only when it carries a revocation, so
	// a revocation reaches every node, and then removes only the revoked
	// bytes; one that does not is refused as not_covered_here and the
	// node keeps its last good manifest and engine bytes (WINFIX4 audit
	// finding 6: before, it installed empty and pruned the node's engine).
	// Every other kind refuses such a manifest as not_covered
	// (contentchan, Windows 11 Pro rerun 2026-10-25), never installing it
	// empty.
	ManifestIsContent bool
}

const day = 24 * time.Hour

// kindTable is THE kind table, one test case per row.
var kindTable = []KindSpec{
	{Kind: MaliciousPackages, Class: ClassFeed, MaxValidity: 14 * day, AgeFloor: 30 * day, Owner: "security 8.5, D1"},
	{Kind: PopularNames, Class: ClassFeed, MaxValidity: 60 * day, AgeFloor: 180 * day, Owner: "security 8.5, D1"},
	{Kind: OSVExport, Class: ClassFeed, MaxValidity: 7 * day, AgeFloor: 14 * day, Owner: "security 8.2, D2"},
	{Kind: OSVOSExport, Class: ClassFeed, MaxValidity: 7 * day, AgeFloor: 14 * day, Owner: "OS and CI scanning 6.4 and 6.6.1, OS-2"},
	{Kind: OSVShards, Class: ClassFeed, MaxValidity: 7 * day, AgeFloor: 14 * day, Owner: "OS and CI scanning 13.3 and 13.11, RM-1"},
	{Kind: KEV, Class: ClassFeed, MaxValidity: 7 * day, AgeFloor: 14 * day, Owner: "OS and CI scanning 14.7, M3L-1"},
	{Kind: EPSS, Class: ClassFeed, MaxValidity: 7 * day, AgeFloor: 14 * day, Owner: "OS and CI scanning 14.7, M3L-1"},
	{Kind: AgentCVETable, Class: ClassFeed, MaxValidity: 30 * day, AgeFloor: 90 * day, Owner: "security 8.5"},
	{Kind: RulePack, Class: ClassFeed, MaxValidity: 90 * day, AgeFloor: 365 * day, Owner: "security 8.5, G"},
	{Kind: Engine, Class: ClassEngine, MaxValidity: 180 * day, AgeFloor: 365 * day, Owner: "security 8.1, D2 and G", ManifestIsContent: true},
	{Kind: SandboxRootfs, Class: ClassArtifact, MaxValidity: 180 * day, AgeFloor: 365 * day, Owner: "sandbox 12.3, P3", TargetOS: "linux", CompleteSet: true},
	{Kind: SandboxImage, Class: ClassArtifact, MaxValidity: 180 * day, AgeFloor: 365 * day, Owner: "sandbox 12.3, P3", CompleteSet: true},
	{Kind: SandboxGuest, Class: ClassArtifact, MaxValidity: 180 * day, AgeFloor: 365 * day, Owner: "sandbox 12.3, P3", TargetOS: "linux", CompleteSet: true},
	{Kind: SandboxNative, Class: ClassArtifact, MaxValidity: 180 * day, AgeFloor: 365 * day, Owner: "sandbox 12.3, P3"},
}

// Kinds returns a copy of the kind table.
func Kinds() []KindSpec {
	out := make([]KindSpec, len(kindTable))
	copy(out, kindTable)
	return out
}

// KindOf returns the row for kind.
func KindOf(kind Kind) (KindSpec, bool) {
	for _, s := range kindTable {
		if s.Kind == kind {
			return s, true
		}
	}
	return KindSpec{}, false
}

// UpstreamMethod is how an entry's upstream origin was checked where the
// manifest was built (JSP-8: an entry carries what can be verified there).
type UpstreamMethod string

// The upstream methods.
const (
	// UpstreamNone: the artifact is Observer's own (the vendor signature
	// is the origin), or the upstream publishes nothing to check.
	UpstreamNone UpstreamMethod = "none"
	// UpstreamCosignKeylessOnline: a keyless cosign signature verified ONCE,
	// online, against Rekor where the manifest was built (Opengrep: its
	// certificate lives 10 minutes, so a node cannot re-verify offline and
	// checks only the digest). Identity and issuer are recorded.
	UpstreamCosignKeylessOnline UpstreamMethod = "cosign_keyless_online"
	// UpstreamSHA256Sums: the upstream's checksum file, carried whole so a
	// node can see the entry's digest in it.
	UpstreamSHA256Sums UpstreamMethod = "sha256sums"
	// UpstreamSLSABundle: the upstream's SHA256SUMS plus its SLSA
	// provenance as a Sigstore bundle (osv-scanner), carried so a node with
	// a pinned trusted root may re-verify it offline.
	UpstreamSLSABundle UpstreamMethod = "slsa_provenance_bundle"
	// UpstreamAuthenticode: a Windows Authenticode signature checked at
	// build (sandbox native files).
	UpstreamAuthenticode UpstreamMethod = "authenticode"
	// UpstreamGCSObjectHash: the upstream object's generation, CRC32C and
	// MD5 as served by the OSV bucket, checked where the manifest was built
	// (the OSV exports; Object, Generation, CRC32C and MD5 are recorded).
	// For a delta entry they name the object the delta was cut from.
	UpstreamGCSObjectHash UpstreamMethod = "gcs_object_hash"
)

// knownUpstreamMethods is the closed method set.
var knownUpstreamMethods = map[UpstreamMethod]bool{
	UpstreamNone: true, UpstreamCosignKeylessOnline: true, UpstreamSHA256Sums: true,
	UpstreamSLSABundle: true, UpstreamAuthenticode: true, UpstreamGCSObjectHash: true,
}

// UpstreamCheck records an entry's upstream check.
type UpstreamCheck struct {
	Method UpstreamMethod `json:"method"`
	// Identity and Issuer are the signing identity pinned at build (for
	// Opengrep the branch form .../rolling-release.yml@refs/heads/release-v<version>).
	Identity string `json:"identity,omitempty"`
	Issuer   string `json:"issuer,omitempty"`
	// VerifiedAt is RFC3339; VerifiedWhere is release_pipeline or
	// org_mirror_import.
	VerifiedAt    string `json:"verified_at,omitempty"`
	VerifiedWhere string `json:"verified_where,omitempty"`
	// SHA256SumsB64 is the upstream checksum file (base64).
	SHA256SumsB64 string `json:"sha256sums,omitempty"`
	// BundleB64 is the provenance bundle (base64).
	BundleB64 string `json:"bundle,omitempty"`
	// Object is the upstream object's https URL, and Generation, CRC32C
	// (base64 big-endian Castagnoli, the x-goog-hash spelling) and MD5
	// (base64) what the bucket served for it (gcs_object_hash).
	Object     string `json:"object,omitempty"`
	Generation string `json:"generation,omitempty"`
	CRC32C     string `json:"crc32c,omitempty"`
	MD5        string `json:"md5,omitempty"`
}

// DeltaOf marks an entry as a cumulative delta over another entry of the
// same manifest (the OSV exports, static feed mirroring plan section 6.2):
// a node holding the base applies the delta's records over it and removes
// Drop, never a chain of deltas.
type DeltaOf struct {
	// Base is the base entry's Name.
	Base string `json:"base"`
	// BaseSHA256 is the base entry's digest; it must equal that entry's.
	BaseSHA256 string `json:"base_sha256"`
	// Records is the entry count of the export after applying the delta
	// (the node checks it).
	Records int `json:"records"`
	// Drop names the entries removed from the base, sorted, each a valid
	// base name.
	Drop []string `json:"drop,omitempty"`
}

// Entry is one artifact a manifest covers.
type Entry struct {
	// Name is the artifact's base name in the kind's directory.
	Name string `json:"name"`
	// Version is the upstream or feed version label of the bytes.
	Version string `json:"version,omitempty"`
	// OS and Arch scope a platform artifact; empty means every platform.
	OS   string `json:"os,omitempty"`
	Arch string `json:"arch,omitempty"`
	// SizeBytes is exact and doubles as the download ceiling.
	SizeBytes int64 `json:"size_bytes"`
	// SHA256 is the hex digest of the bytes.
	SHA256 string `json:"sha256"`
	// Source names where the bytes came from ("osv:MAL", a repository).
	Source string `json:"source,omitempty"`
	// License is the SPDX expression of the data or binary.
	License  string        `json:"license,omitempty"`
	Upstream UpstreamCheck `json:"upstream"`
	// Delta, when set, makes the entry a cumulative delta over another
	// entry of the manifest (DeltaOf).
	Delta *DeltaOf `json:"delta,omitempty"`
}

// Revocation withdraws an artifact by digest.
type Revocation struct {
	SHA256 string `json:"sha256"`
	Name   string `json:"name,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// Manifest is one signed publication of a kind.
type Manifest struct {
	Schema string `json:"schema"`
	Kind   Kind   `json:"kind"`
	// ManifestVersion is the monotonic publish counter of the kind.
	ManifestVersion int64 `json:"manifest_version"`
	// Epoch is the data epoch of the kind; it may not go backwards.
	Epoch int64 `json:"epoch"`
	// IssuedAt and ExpiresAt are RFC3339; ExpiresAt is required.
	IssuedAt  string       `json:"issued_at"`
	ExpiresAt string       `json:"expires_at"`
	Entries   []Entry      `json:"entries"`
	Revoked   []Revocation `json:"revoked,omitempty"`
}

// Envelope carries a manifest's exact bytes and its signatures.
type Envelope struct {
	ManifestB64  string `json:"manifest"`
	ManifestHash string `json:"manifest_hash"`
	VendorKeyID  string `json:"vendor_key_id"`
	VendorSig    string `json:"vendor_sig"`
	// Signer names which vendor key signed: empty is the release vendor key
	// (SigningMessage), SignerFeed the content-feed key (FeedSigningMessage,
	// ClassFeed kinds only). VendorKeyID and VendorSig carry either key's.
	Signer string `json:"signer,omitempty"`
	// OrgKeyID and OrgSig are added by the org mirror (Countersign).
	OrgKeyID string `json:"org_key_id,omitempty"`
	OrgSig   string `json:"org_sig,omitempty"`
}

// KeyID is the key id spelling the vendor key uses: the first 16
// bytes of sha256(public key), hex.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:16])
}

// SigningMessage is what the vendor signs: the domain, the kind, the
// manifest version and the manifest hash, each NUL-separated, so neither a
// document of another kind nor a version-bumped capture verifies.
func SigningMessage(kind Kind, version int64, manifestHash string) []byte {
	return message(SigningDomain, kind, version, manifestHash, "")
}

// FeedSigningMessage is what the content-feed key signs: SigningMessage's
// fields under FeedSigningDomain.
func FeedSigningMessage(kind Kind, version int64, manifestHash string) []byte {
	return message(FeedSigningDomain, kind, version, manifestHash, "")
}

// MirrorMessage is what the org countersigns: the vendor message's
// fields plus the vendor signature itself, under the mirror domain.
func MirrorMessage(kind Kind, version int64, manifestHash, vendorSig string) []byte {
	return message(MirrorDomain, kind, version, manifestHash, vendorSig)
}

func message(domain string, kind Kind, version int64, hash, extra string) []byte {
	var b bytes.Buffer
	b.WriteString(domain)
	b.WriteByte(0)
	b.WriteString(string(kind))
	b.WriteByte(0)
	b.WriteString(strconv.FormatInt(version, 10))
	b.WriteByte(0)
	b.WriteString(hash)
	if extra != "" {
		b.WriteByte(0)
		b.WriteString(extra)
	}
	return b.Bytes()
}

// CanonicalJSON encodes a manifest deterministically (the
// CanonicalJSON rules: sorted keys, no HTML escaping, no trailing newline).
func CanonicalJSON(m Manifest) ([]byte, error) {
	raw, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("update.CanonicalJSON: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var generic any
	if err := dec.Decode(&generic); err != nil {
		return nil, fmt.Errorf("update.CanonicalJSON: %w", err)
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(generic); err != nil {
		return nil, fmt.Errorf("update.CanonicalJSON: %w", err)
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// Sign validates m and signs it with the vendor private key. It is
// the builder's half (the release pipeline, the index builder); a node
// never holds the private key.
func Sign(m Manifest, priv ed25519.PrivateKey) (Envelope, error) {
	return sign("update.Sign", m, priv, "", SigningMessage)
}

// SignFeed validates m and signs it with the content-feed private key
// (static feed mirroring plan section 6.4): FeedSigningMessage, Signer
// SignerFeed. Only ClassFeed kinds may be signed this way, because only
// those verify (ruleVendor); the daily publisher holds this key and never
// the release key.
func SignFeed(m Manifest, priv ed25519.PrivateKey) (Envelope, error) {
	if spec, ok := KindOf(m.Kind); ok && spec.Class != ClassFeed {
		return Envelope{}, fmt.Errorf("update.SignFeed: kind %q is not a feed kind; the content-feed key signs feed kinds only", m.Kind)
	}
	return sign("update.SignFeed", m, priv, SignerFeed, FeedSigningMessage)
}

// sign is Sign and SignFeed's shared body.
func sign(op string, m Manifest, priv ed25519.PrivateKey, signer string, msg func(Kind, int64, string) []byte) (Envelope, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return Envelope{}, fmt.Errorf("%s: not an Ed25519 private key", op)
	}
	if err := Validate(m); err != nil {
		return Envelope{}, fmt.Errorf("%s: %w", op, err)
	}
	body, err := CanonicalJSON(m)
	if err != nil {
		return Envelope{}, err
	}
	hash := HashBytes(body)
	pub, _ := priv.Public().(ed25519.PublicKey)
	sig := ed25519.Sign(priv, msg(m.Kind, m.ManifestVersion, hash))
	return Envelope{
		ManifestB64: base64.StdEncoding.EncodeToString(body), ManifestHash: hash,
		VendorKeyID: KeyID(pub), VendorSig: base64.StdEncoding.EncodeToString(sig),
		Signer: signer,
	}, nil
}

// Countersign adds the org mirror's signature to a vendor-signed
// envelope. It does not verify the vendor signature: the mirror import
// verifies with Verify first, and a node verifies both.
func Countersign(env Envelope, priv ed25519.PrivateKey) (Envelope, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return Envelope{}, errors.New("update.Countersign: not an Ed25519 private key")
	}
	body, err := base64.StdEncoding.DecodeString(env.ManifestB64)
	if err != nil {
		return Envelope{}, fmt.Errorf("update.Countersign: %w", err)
	}
	var probe struct {
		Kind            Kind  `json:"kind"`
		ManifestVersion int64 `json:"manifest_version"`
	}
	if err := json.Unmarshal(body, &probe); err != nil {
		return Envelope{}, fmt.Errorf("update.Countersign: %w", err)
	}
	pub, _ := priv.Public().(ed25519.PublicKey)
	sig := ed25519.Sign(priv, MirrorMessage(probe.Kind, probe.ManifestVersion, HashBytes(body), env.VendorSig))
	env.OrgKeyID = KeyID(pub)
	env.OrgSig = base64.StdEncoding.EncodeToString(sig)
	return env, nil
}

// EncodeEnvelope is the envelope's file and wire form.
func EncodeEnvelope(env Envelope) ([]byte, error) {
	b, err := json.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("update.EncodeEnvelope: %w", err)
	}
	return b, nil
}

// ErrInvalid wraps every structural refusal.
var ErrInvalid = errors.New("update: content manifest is invalid")

// Validate checks a manifest's structure: schema, kind, versions,
// times and their bound, entries and revocations. Trust and ordering are
// Verify's rules.
func Validate(m Manifest) error {
	bad := func(format string, a ...any) error {
		return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
	}
	if m.Schema != SchemaV1 {
		return bad("unknown schema %q", m.Schema)
	}
	spec, ok := KindOf(m.Kind)
	if !ok {
		return bad("unknown kind %q", m.Kind)
	}
	if m.ManifestVersion <= 0 {
		return bad("manifest_version must be positive")
	}
	if m.Epoch < 0 {
		return bad("epoch must not be negative")
	}
	issued, err := parseRFC3339(m.IssuedAt)
	if err != nil {
		return bad("issued_at: %v", err)
	}
	expires, err := parseRFC3339(m.ExpiresAt)
	if err != nil {
		return bad("expires_at is required: %v", err)
	}
	if !expires.After(issued) {
		return bad("expires_at must be after issued_at")
	}
	if expires.Sub(issued) > spec.MaxValidity {
		return bad("validity %s exceeds the kind's bound %s", expires.Sub(issued), spec.MaxValidity)
	}
	if len(m.Entries) == 0 || len(m.Entries) > MaxEntries {
		return bad("%d entries (want 1 to %d)", len(m.Entries), MaxEntries)
	}
	revoked := map[string]bool{}
	for _, r := range m.Revoked {
		if !isHexSHA256(r.SHA256) {
			return bad("revocation sha256 must be 64 hex characters")
		}
		revoked[r.SHA256] = true
	}
	seen := map[string]bool{}
	for i, e := range m.Entries {
		if err := validBaseName(e.Name); err != nil {
			return bad("entry %d name: %v", i, err)
		}
		key := e.Name + "\x00" + e.OS + "\x00" + e.Arch
		if seen[key] {
			return bad("entry %d repeats %q", i, e.Name)
		}
		seen[key] = true
		if e.SizeBytes <= 0 {
			return bad("entry %q size_bytes must be positive", e.Name)
		}
		if !isHexSHA256(e.SHA256) {
			return bad("entry %q sha256 must be 64 hex characters", e.Name)
		}
		if revoked[e.SHA256] {
			return bad("entry %q is listed and revoked in the same manifest", e.Name)
		}
		if err := validateUpstream(e); err != nil {
			return bad("entry %q upstream: %v", e.Name, err)
		}
	}
	for _, e := range m.Entries {
		if err := validateDelta(m, e); err != nil {
			return bad("entry %q delta: %v", e.Name, err)
		}
	}
	return nil
}

// validateDelta checks a delta entry against its base: the base is another
// entry of the same manifest with the stated digest and is not itself a
// delta (a node applies one delta over one base, never a chain), the
// record count is positive, and the dropped names are valid, sorted,
// distinct and capped.
func validateDelta(m Manifest, e Entry) error {
	d := e.Delta
	if d == nil {
		return nil
	}
	if d.Base == "" || d.Base == e.Name {
		return errors.New("base must name another entry")
	}
	if !isHexSHA256(d.BaseSHA256) {
		return errors.New("base_sha256 must be 64 hex characters")
	}
	found := false
	for _, b := range m.Entries {
		if b.Name != d.Base || !strings.EqualFold(b.SHA256, d.BaseSHA256) {
			continue
		}
		if b.Delta != nil {
			return fmt.Errorf("base %q is itself a delta", d.Base)
		}
		found = true
	}
	if !found {
		return fmt.Errorf("no entry %q with sha256 %s in the manifest", d.Base, d.BaseSHA256)
	}
	if d.Records <= 0 {
		return errors.New("records must be positive")
	}
	if len(d.Drop) > MaxDeltaDrop {
		return fmt.Errorf("%d dropped names (at most %d)", len(d.Drop), MaxDeltaDrop)
	}
	for i, name := range d.Drop {
		if err := validBaseName(name); err != nil {
			return fmt.Errorf("drop %d: %w", i, err)
		}
		if i > 0 && d.Drop[i-1] >= name {
			return fmt.Errorf("drop is not sorted and distinct at %q", name)
		}
	}
	return nil
}

// validateUpstream checks the upstream record against its method.
func validateUpstream(e Entry) error {
	u := e.Upstream
	if !knownUpstreamMethods[u.Method] {
		return fmt.Errorf("unknown method %q", u.Method)
	}
	switch u.Method {
	case UpstreamCosignKeylessOnline:
		if u.Identity == "" || u.Issuer == "" {
			return errors.New("cosign_keyless_online needs identity and issuer")
		}
		if _, err := parseRFC3339(u.VerifiedAt); err != nil {
			return fmt.Errorf("verified_at: %w", err)
		}
	case UpstreamSHA256Sums, UpstreamSLSABundle:
		if !SumsListDigest(u.SHA256SumsB64, e.SHA256) {
			return errors.New("the upstream SHA256SUMS does not list the entry's digest")
		}
		if u.Method == UpstreamSLSABundle && u.BundleB64 == "" {
			return errors.New("slsa_provenance_bundle needs the bundle")
		}
	case UpstreamGCSObjectHash:
		obj, err := url.Parse(u.Object)
		if err != nil || obj.Scheme != "https" || obj.Host == "" {
			return errors.New("gcs_object_hash needs the object's https URL")
		}
		if u.CRC32C == "" && u.MD5 == "" {
			return errors.New("gcs_object_hash needs the object's crc32c or md5")
		}
		if u.CRC32C != "" && !isB64Len(u.CRC32C, 4) {
			return errors.New("crc32c must be base64 of 4 bytes")
		}
		if u.MD5 != "" && !isB64Len(u.MD5, 16) {
			return errors.New("md5 must be base64 of 16 bytes")
		}
	}
	return nil
}

// isB64Len reports whether s is standard base64 of exactly n bytes.
func isB64Len(s string, n int) bool {
	raw, err := base64.StdEncoding.DecodeString(s)
	return err == nil && len(raw) == n
}

// SumsListDigest reports whether a base64 SHA256SUMS file lists digest.
func SumsListDigest(sumsB64, digest string) bool {
	raw, err := base64.StdEncoding.DecodeString(sumsB64)
	if err != nil || len(raw) == 0 {
		return false
	}
	for _, line := range strings.Split(string(raw), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && strings.EqualFold(f[0], digest) {
			return true
		}
	}
	return false
}

// Accepted is the last manifest a node accepted for a kind: the
// replay and epoch high-water marks.
type Accepted struct {
	ManifestVersion int64  `json:"manifest_version"`
	Epoch           int64  `json:"epoch"`
	ManifestHash    string `json:"manifest_hash"`
}

// VerifyInput is one verification.
type VerifyInput struct {
	// Envelope is the envelope bytes as received.
	Envelope []byte
	// Kind is the kind the caller asked for; a manifest of another kind is
	// refused.
	Kind Kind
	// VendorKeys are the accepted vendor keys: the caller passes the set
	// compiled into the agent (internal/update.VendorPublicKeys); none
	// verifies nothing (fail closed).
	VendorKeys []ed25519.PublicKey
	// FeedKeys are the content-feed keys compiled into the agent
	// (internal/update.ContentFeedPublicKeys). They verify only an envelope
	// whose Signer is SignerFeed, and only for ClassFeed kinds; an engine or
	// artifact kind always needs a VendorKeys signature.
	FeedKeys []ed25519.PublicKey
	// RequireOrg demands the org mirror's countersignature under OrgKey
	// (a managed node: content comes only from its org mirror).
	RequireOrg bool
	OrgKey     ed25519.PublicKey
	// Accepted is the node's high-water mark; nil on first install.
	Accepted *Accepted
	// Now is the verification time.
	Now time.Time
	// AllowExpired re-verifies data already accepted (a reload of the
	// last-known-good): the signature, structure and ordering rules still
	// run, the expiry does not, and FreshnessAt then says stale or unknown.
	// Never set for a new manifest.
	AllowExpired bool
}

// Reason is a refusal's closed reason code, one per rule.
type Reason string

// The refusal reasons, in rule order.
const (
	ContentReasonEnvelope   Reason = "envelope"
	ContentReasonHash       Reason = "manifest_hash"
	ContentReasonNoKey      Reason = "no_vendor_key"
	ContentReasonVendorSig  Reason = "vendor_signature"
	ContentReasonOrgSig     Reason = "org_signature"
	ContentReasonStructure  Reason = "structure"
	ContentReasonKind       Reason = "kind"
	ContentReasonRollback   Reason = "rollback"
	ContentReasonFork       Reason = "fork"
	ContentReasonEpoch      Reason = "epoch"
	ContentReasonNotYet     Reason = "not_yet_valid"
	ContentReasonExpired    Reason = "expired"
	ContentReasonArtifact   Reason = "artifact_digest"
	ContentReasonRevoked    Reason = "revoked"
	ContentReasonNotCovered Reason = "not_covered"
	// ContentReasonPartialSet: a complete-set kind names an entry that no
	// entry of the manifest supplies for the node's platform.
	ContentReasonPartialSet Reason = "partial_set"
	// ContentReasonNotCoveredHere: a kind whose manifest is the content
	// (ManifestIsContent, the engine pins) published a manifest with no
	// entry for the node's platform and no revocation; the node keeps its
	// last good one (WINFIX4 audit finding 6).
	ContentReasonNotCoveredHere Reason = "not_covered_here"
	// ContentReasonFeedKeyNotAllowed: a manifest signed with the
	// content-feed key (Signer SignerFeed) is of a kind that is not
	// ClassFeed; only the release vendor key may sign an engine or artifact
	// kind (static feed mirroring plan section 6.4).
	ContentReasonFeedKeyNotAllowed Reason = "feed_key_not_allowed"
)

// Refusal is a verification refusal.
type Refusal struct {
	Reason Reason
	Detail string
}

func (e *Refusal) Error() string {
	if e.Detail == "" {
		return "update: content refused: " + string(e.Reason)
	}
	return "update: content refused: " + string(e.Reason) + ": " + e.Detail
}

// ReasonOf returns err's reason, or "" when err is not a refusal.
func ReasonOf(err error) Reason {
	var ce *Refusal
	if errors.As(err, &ce) {
		return ce.Reason
	}
	return ""
}

// Result is a verified manifest.
type Result struct {
	Manifest Manifest
	Hash     string
	// Countersigned reports a verified org countersignature.
	Countersigned bool
}

// pass is one verification's working state.
type pass struct {
	in     VerifyInput
	env    Envelope
	body   []byte
	m      Manifest
	signed bool
}

// rule is one row of the verification table.
type rule struct {
	reason Reason
	check  func(p *pass) error
}

// rules is THE verification table, walked top-down; the first
// failure refuses. Trust (hash, signatures) comes before the body is
// interpreted, and ordering (rollback, epoch) before freshness.
var rules = []rule{
	{ContentReasonEnvelope, ruleEnvelope},
	{ContentReasonHash, ruleHash},
	{ContentReasonVendorSig, ruleVendor},
	{ContentReasonOrgSig, ruleOrg},
	{ContentReasonStructure, ruleStructure},
	{ContentReasonKind, ruleKind},
	{ContentReasonRollback, ruleRollback},
	{ContentReasonEpoch, ruleEpoch},
	{ContentReasonExpired, ruleTime},
}

// Verify runs the verification table. A refusal is a *Refusal.
func Verify(in VerifyInput) (Result, error) {
	p := &pass{in: in}
	for _, r := range rules {
		if err := r.check(p); err != nil {
			var ce *Refusal
			if errors.As(err, &ce) {
				return Result{}, ce
			}
			return Result{}, &Refusal{Reason: r.reason, Detail: err.Error()}
		}
	}
	return Result{Manifest: p.m, Hash: p.env.ManifestHash, Countersigned: p.signed}, nil
}

func ruleEnvelope(p *pass) error {
	if len(p.in.Envelope) == 0 || len(p.in.Envelope) > MaxEnvelopeBytes {
		return fmt.Errorf("envelope is %d bytes", len(p.in.Envelope))
	}
	dec := json.NewDecoder(bytes.NewReader(p.in.Envelope))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p.env); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing JSON value")
	}
	body, err := base64.StdEncoding.DecodeString(p.env.ManifestB64)
	if err != nil {
		return err
	}
	if len(body) == 0 || len(body) > MaxManifestBytes {
		return fmt.Errorf("manifest is %d bytes", len(body))
	}
	p.body = body
	return nil
}

func ruleHash(p *pass) error {
	if !isHexSHA256(p.env.ManifestHash) || HashBytes(p.body) != p.env.ManifestHash {
		return errors.New("manifest hash does not match its bytes")
	}
	return nil
}

// probeKindVersion reads the two signed fields before full decoding, so the
// signature is checked before the body is interpreted.
func (p *pass) probeKindVersion() (Kind, int64, error) {
	var probe struct {
		Kind            Kind  `json:"kind"`
		ManifestVersion int64 `json:"manifest_version"`
	}
	if err := json.Unmarshal(p.body, &probe); err != nil {
		return "", 0, err
	}
	return probe.Kind, probe.ManifestVersion, nil
}

// ruleVendor checks the vendor signature. The envelope's Signer picks the
// key set and the domain: empty is the release vendor key over
// SigningMessage (every kind); SignerFeed is the content-feed key over
// FeedSigningMessage, accepted only for a ClassFeed kind, so a feed-key
// compromise can never swap an engine or a sandbox artifact; any other
// value is refused. Signer is not itself signed, and needs not be: each
// key set verifies only its own domain, so relabelling an envelope makes
// its signature verify nothing.
func ruleVendor(p *pass) error {
	var (
		keys  []ed25519.PublicKey
		msgOf func(Kind, int64, string) []byte
		what  string
	)
	switch p.env.Signer {
	case "":
		keys, msgOf, what = p.in.VendorKeys, SigningMessage, "vendor"
	case SignerFeed:
		keys, msgOf, what = p.in.FeedKeys, FeedSigningMessage, "content-feed"
	default:
		return fmt.Errorf("unknown signer %q", p.env.Signer)
	}
	noKey := &Refusal{Reason: ContentReasonNoKey, Detail: "this build carries no " + what + " key"}
	if p.env.Signer == "" && len(keys) == 0 {
		return noKey
	}
	kind, version, err := p.probeKindVersion()
	if err != nil {
		return err
	}
	if p.env.Signer == SignerFeed {
		// The kind's class decides before the key set does: a feed
		// signature on an engine or artifact kind is refused as such even
		// on a build that carries no feed key.
		if spec, ok := KindOf(kind); !ok || spec.Class != ClassFeed {
			return &Refusal{Reason: ContentReasonFeedKeyNotAllowed, Detail: fmt.Sprintf("kind %q is not a feed kind", kind)}
		}
		if len(keys) == 0 {
			return noKey
		}
	}
	sig, err := base64.StdEncoding.DecodeString(p.env.VendorSig)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return errors.New("vendor signature is not a base64 Ed25519 signature")
	}
	msg := msgOf(kind, version, p.env.ManifestHash)
	for _, k := range keys {
		if len(k) == ed25519.PublicKeySize && ed25519.Verify(k, msg, sig) {
			return nil
		}
	}
	return fmt.Errorf("no accepted %s key verifies the signature", what)
}

func ruleOrg(p *pass) error {
	if p.env.OrgSig == "" {
		if p.in.RequireOrg {
			return errors.New("the org mirror's countersignature is required and missing")
		}
		return nil
	}
	if len(p.in.OrgKey) != ed25519.PublicKeySize {
		if p.in.RequireOrg {
			return errors.New("no pinned org key to verify the countersignature")
		}
		// An individual node has no org key; an unverifiable extra
		// signature adds nothing and is ignored.
		return nil
	}
	if p.env.OrgKeyID != KeyID(p.in.OrgKey) {
		return errors.New("countersignature names another org key")
	}
	kind, version, err := p.probeKindVersion()
	if err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(p.env.OrgSig)
	if err != nil || len(sig) != ed25519.SignatureSize ||
		!ed25519.Verify(p.in.OrgKey, MirrorMessage(kind, version, p.env.ManifestHash, p.env.VendorSig), sig) {
		return errors.New("the org countersignature does not verify")
	}
	p.signed = true
	return nil
}

func ruleStructure(p *pass) error {
	dec := json.NewDecoder(bytes.NewReader(p.body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p.m); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing JSON value")
	}
	return Validate(p.m)
}

func ruleKind(p *pass) error {
	if p.m.Kind != p.in.Kind {
		return fmt.Errorf("manifest is kind %q, asked for %q", p.m.Kind, p.in.Kind)
	}
	return nil
}

func ruleRollback(p *pass) error {
	a := p.in.Accepted
	if a == nil {
		return nil
	}
	switch {
	case p.m.ManifestVersion < a.ManifestVersion:
		return &Refusal{Reason: ContentReasonRollback, Detail: fmt.Sprintf("version %d is below the accepted %d", p.m.ManifestVersion, a.ManifestVersion)}
	case p.m.ManifestVersion == a.ManifestVersion && p.env.ManifestHash != a.ManifestHash:
		return &Refusal{Reason: ContentReasonFork, Detail: fmt.Sprintf("version %d with other bytes than the accepted one", p.m.ManifestVersion)}
	}
	return nil
}

func ruleEpoch(p *pass) error {
	if a := p.in.Accepted; a != nil && p.m.Epoch < a.Epoch {
		return fmt.Errorf("epoch %d is below the accepted %d", p.m.Epoch, a.Epoch)
	}
	return nil
}

func ruleTime(p *pass) error {
	issued, _ := parseRFC3339(p.m.IssuedAt)
	expires, _ := parseRFC3339(p.m.ExpiresAt)
	// A small allowance for clock skew on the issuing side.
	if issued.After(p.in.Now.Add(10 * time.Minute)) {
		return &Refusal{Reason: ContentReasonNotYet, Detail: "issued in the future"}
	}
	if !p.in.AllowExpired && !p.in.Now.Before(expires) {
		return errors.New("the manifest has expired")
	}
	return nil
}

// Freshness is how usable accepted data is now.
type Freshness string

// The freshness values.
const (
	// Fresh: inside the manifest's validity.
	Fresh Freshness = "fresh"
	// Stale: expired, within the age floor; usable, shown as stale.
	Stale Freshness = "stale"
	// Unknown: past the age floor, or nothing accepted; never
	// treated as current (PR14).
	Unknown Freshness = "unknown"
)

// FreshnessAt classifies accepted data at now. floor 0 means the kind's
// AgeFloor; a stricter consumer floor is honoured, a looser one is not.
func FreshnessAt(m Manifest, now time.Time, floor time.Duration) Freshness {
	spec, ok := KindOf(m.Kind)
	if !ok {
		return Unknown
	}
	issued, err1 := parseRFC3339(m.IssuedAt)
	expires, err2 := parseRFC3339(m.ExpiresAt)
	if err1 != nil || err2 != nil {
		return Unknown
	}
	if floor <= 0 || floor > spec.AgeFloor {
		floor = spec.AgeFloor
	}
	switch {
	case now.Sub(issued) > floor:
		return Unknown
	case now.Before(expires):
		return Fresh
	}
	return Stale
}

// PlatformFor is the platform a kind's entries are selected for on a node
// whose own platform is goos/goarch: the kind's TargetOS when it has one,
// else the node's.
func PlatformFor(kind Kind, goos, goarch string) (string, string) {
	if spec, ok := KindOf(kind); ok && spec.TargetOS != "" {
		return spec.TargetOS, goarch
	}
	return goos, goarch
}

// EntryApplies is THE platform comparison of an entry (an entry with no OS
// and Arch matches every platform): every reader and installer of a
// manifest selects entries through it, never through its own copy.
func EntryApplies(e Entry, goos, goarch string) bool {
	return (e.OS == "" || e.OS == goos) && (e.Arch == "" || e.Arch == goarch)
}

// CheckCompleteSet refuses a manifest of a CompleteSet kind in which an
// entry name has no entry that applies to goos/goarch (EntryApplies, the one
// platform comparison): the set is partial for this node's platform, so it
// is refused at import with partial_set naming what is missing, never
// installed to fail at launch (WINFIX2 audit finding 8: a set where only
// the SBOM applied to the node's architecture imported). A kind that is not
// a complete set is never refused here.
func CheckCompleteSet(m Manifest, goos, goarch string) error {
	spec, ok := KindOf(m.Kind)
	if !ok || !spec.CompleteSet {
		return nil
	}
	applies := map[string]bool{}
	for _, e := range m.Entries {
		applies[e.Name] = applies[e.Name] || EntryApplies(e, goos, goarch)
	}
	var missing []string
	for name, ok := range applies {
		if !ok {
			missing = append(missing, name)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	sort.Strings(missing)
	return &Refusal{Reason: ContentReasonPartialSet, Detail: fmt.Sprintf("the set is partial for %s/%s: no entry of %s applies", goos, goarch, strings.Join(missing, ", "))}
}

// EntryFor returns the entry named name for the platform (an entry with no
// OS and Arch matches every platform), unless it is revoked.
func EntryFor(m Manifest, name, goos, goarch string) (Entry, error) {
	for _, e := range m.Entries {
		if e.Name != name {
			continue
		}
		if !EntryApplies(e, goos, goarch) {
			continue
		}
		if IsRevoked(m, e.SHA256) {
			return Entry{}, &Refusal{Reason: ContentReasonRevoked, Detail: name}
		}
		return e, nil
	}
	return Entry{}, &Refusal{Reason: ContentReasonNotCovered, Detail: name}
}

// IsRevoked reports whether m revokes the digest.
func IsRevoked(m Manifest, sha string) bool {
	for _, r := range m.Revoked {
		if strings.EqualFold(r.SHA256, sha) {
			return true
		}
	}
	return false
}

// CheckArtifact verifies artifact bytes against an entry: exact size
// and digest. A mismatch is a refusal, never a warning.
func CheckArtifact(e Entry, data []byte) error {
	if int64(len(data)) != e.SizeBytes {
		return &Refusal{Reason: ContentReasonArtifact, Detail: fmt.Sprintf("%s is %d bytes, the manifest says %d", e.Name, len(data), e.SizeBytes)}
	}
	if HashBytes(data) != strings.ToLower(e.SHA256) {
		return &Refusal{Reason: ContentReasonArtifact, Detail: e.Name + " does not match its digest"}
	}
	return nil
}

// State is a kind's durable state: the last-known-good accepted
// manifest and the last failure. It is what posture and doctor read.
type State struct {
	Kind Kind `json:"kind"`
	// Accepted is the high-water mark; nil before the first install.
	Accepted   *Accepted `json:"accepted,omitempty"`
	IssuedAt   string    `json:"issued_at,omitempty"`
	ExpiresAt  string    `json:"expires_at,omitempty"`
	AcceptedAt string    `json:"accepted_at,omitempty"`
	// LastFailure is the reason code of the most recent failed update and
	// LastFailureAt its time; cleared by the next success.
	LastFailure   Reason `json:"last_failure,omitempty"`
	LastFailureAt string `json:"last_failure_at,omitempty"`
}

// Apply is the last-known-good transition: a success replaces
// the accepted state; a failure keeps it and records the reason.
func Apply(prev State, res Result, err error, now time.Time) State {
	at := now.UTC().Format(time.RFC3339)
	if err != nil {
		next := prev
		next.LastFailure = ReasonOf(err)
		if next.LastFailure == "" {
			next.LastFailure = ContentReasonEnvelope
		}
		next.LastFailureAt = at
		return next
	}
	return State{
		Kind:       res.Manifest.Kind,
		Accepted:   &Accepted{ManifestVersion: res.Manifest.ManifestVersion, Epoch: res.Manifest.Epoch, ManifestHash: res.Hash},
		IssuedAt:   res.Manifest.IssuedAt,
		ExpiresAt:  res.Manifest.ExpiresAt,
		AcceptedAt: at,
	}
}

// SortEntries orders entries by name, OS and arch (the builder's
// deterministic output).
func SortEntries(es []Entry) {
	sort.Slice(es, func(i, j int) bool {
		if es[i].Name != es[j].Name {
			return es[i].Name < es[j].Name
		}
		if es[i].OS != es[j].OS {
			return es[i].OS < es[j].OS
		}
		return es[i].Arch < es[j].Arch
	})
}
