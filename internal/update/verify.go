package update

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"
)

// SigningDomain is the manifest rail's domain tag.
//
// One org key signs the announcement rail, the routing-policy rail and
// this one, so the SIGNED MESSAGE — not the key — is what keeps them
// apart: a captured announcement re-presented as a manifest fails here,
// and a genuine manifest cannot be replayed at a bumped
// manifest_version, because the version is inside the signed message
// (the ROUTING-SIG-1 lesson, applied at birth rather than retrofitted).
const SigningDomain = "sbo-update-manifest-v1"

// ManifestSigningMessage returns the bytes an Ed25519 signature must
// cover: sha256(domain || 0x00 || manifest_version || 0x00 ||
// manifest_hash).
//
// It is the SHARED owner of the message layout — the org server's
// publish path (W2) calls exactly this function to sign, so the two
// sides cannot drift. It mirrors orgcontract.AnnouncementSigningMessage
// down to the separator byte.
func ManifestSigningMessage(manifestVersion int64, manifestHash string) []byte {
	h := sha256.New()
	h.Write([]byte(SigningDomain))
	h.Write([]byte{0})
	h.Write([]byte(strconv.FormatInt(manifestVersion, 10)))
	h.Write([]byte{0})
	h.Write([]byte(manifestHash))
	return h.Sum(nil)
}

// Verification failures, one sentinel per rule. Typed because §3.2
// requires "every failure typed": the state machine maps them onto a
// State + Reason, and the tests assert one rule at a time.
var (
	// ErrEnvelopeDecode — rule 1: not exactly one JSON value within the cap.
	ErrEnvelopeDecode = errors.New("update: envelope did not decode")
	// ErrManifestHashMismatch — rule 2.
	ErrManifestHashMismatch = errors.New("update: manifest hash mismatch")
	// ErrKeyDisagreement — rule 3: the offered key contradicts a key
	// another rail already pinned. TOFU applies only to a genuinely
	// first pin; a CHANGED key is refused loudly, never TOFU-accepted.
	ErrKeyDisagreement = errors.New("update: manifest signing key disagrees with the pinned org key")
	// ErrSignatureInvalid — rule 4.
	ErrSignatureInvalid = errors.New("update: manifest signature invalid (it must cover this rail's domain tag AND this manifest_version)")
	// ErrUnknownSchema — rule 5. It is a FAIL-OPEN sentinel: the caller
	// IGNORES the document (no banner, no state change), because a
	// future v2 manifest reaching a v1 node is forward compatibility
	// working, not an error an operator must clear (§2.4).
	ErrUnknownSchema = errors.New("update: unknown manifest schema (ignored)")
	// ErrManifestReplay — rule 6: manifest_version is not ahead of the
	// last one this node accepted.
	ErrManifestReplay = errors.New("update: manifest_version is not ahead of the last accepted version")
	// ErrDowngradeRefused — rule 7.
	ErrDowngradeRefused = errors.New("update: manifest targets a lower version without an admin downgrade and node consent")
	// ErrManifestExpired — rule 8a.
	ErrManifestExpired = errors.New("update: manifest has expired")
	// ErrRequiredStop — rule 8b: installed version is below
	// min_from_version, so an intermediate version must be installed
	// first (GitLab's "required stops", made explicit).
	ErrRequiredStop = errors.New("update: an intermediate version must be installed first")
	// ErrNoArtifact — rule 9a: nothing built for this os/arch/kind.
	ErrNoArtifact = errors.New("update: manifest has no artifact for this platform")
	// ErrUnsignedArtifact — rule 9b: empty upstream_sig. Fail-closed
	// per review H0 until W6 produces vendor signatures.
	ErrUnsignedArtifact = errors.New("update: artifact carries no vendor signature")
)

// VerifyInput is everything the nine rules need. Every value is
// supplied by the caller — this package reads no file, opens no socket
// and calls no clock.
type VerifyInput struct {
	// EnvelopeBytes is the raw document as received. When set, rule 1
	// decodes it (cap + exactly-one-value); when empty, Envelope is
	// used as already-decoded input.
	EnvelopeBytes []byte
	// Envelope is the decoded envelope, for callers that decoded it
	// themselves (orgcontract.DecodeCapped on the fetch path).
	Envelope Envelope
	// PinnedKeyID is the key id another rail already pinned for this
	// org, or "" on a genuinely first pin (rule 3).
	PinnedKeyID string
	// PinnedPublicKey is the base64 Ed25519 public key to verify
	// against. REQUIRED: verification against "whatever key the
	// document offered" is not verification.
	PinnedPublicKey string
	// InstalledVersion is this binary's version (main.version).
	InstalledVersion string
	// LastAcceptedManifestVersion is the highest manifest_version this
	// node has accepted on this channel (rule 6).
	LastAcceptedManifestVersion int64
	// AllowDowngrade is the node's [update].allow_downgrade consent
	// (rule 7). Default false.
	AllowDowngrade bool
	// Now is the comparison clock for expiry (rule 8).
	Now time.Time
	// GOOS, GOARCH and Kind select the artifact (rule 9). Empty GOOS /
	// GOARCH fall back to this binary's own platform; empty Kind means
	// KindAgent.
	GOOS, GOARCH, Kind string
}

// VerifyResult is what a caller acts on. It carries the decision, not
// just the document: State/Reason are exactly what the node reports and
// what the org board renders, so no caller has to re-derive them from
// an error.
type VerifyResult struct {
	// Manifest is the decoded manifest (zero until rule 5 passes).
	Manifest Manifest
	// Artifact is the row selected for this platform (zero unless rule
	// 9 passed).
	Artifact Artifact
	// State is the state this outcome puts the node in.
	State State
	// Reason qualifies State when it is blocked.
	Reason Reason
	// Rule names the rule that decided the outcome ("4-signature",
	// "9-artifact"), for logs and for `observer update status`.
	Rule string
	// UpdateAvailable is true only when every rule passed AND the
	// manifest's version is ahead of the installed one.
	UpdateAvailable bool
}

// verifyRule is one row of the §3.2 table.
type verifyRule struct {
	name  string
	check func(*verifyPass) error
}

// verifyPass is the state threaded through the rule table.
type verifyPass struct {
	in           VerifyInput
	env          Envelope
	manifestJSON []byte
	res          VerifyResult
}

// verifyRules is §3.2 as DATA, walked top-down, one row per numbered
// rule and one test case per row (CLAUDE.md #5). The ORDER is part of
// the specification: a document is never inspected for content before
// its signature is checked, and eligibility (6-9) is never judged on a
// manifest whose authorship (1-4) is unproven.
var verifyRules = []verifyRule{
	{"1-envelope", ruleEnvelope},
	{"2-manifest-hash", ruleManifestHash},
	{"3-key-agreement", ruleKeyAgreement},
	{"4-signature", ruleSignature},
	{"5-schema", ruleSchema},
	{"6-replay", ruleReplay},
	{"7-downgrade", ruleDowngrade},
	{"8-freshness", ruleFreshness},
	{"9-artifact", ruleArtifact},
}

// Verify walks the nine ordered rules of §3.2 and returns the decision.
//
// It is PURE: no HTTP, no SQL, no clock, no filesystem. Artifact BYTE
// verification (archive sha256, the vendor signature, the member hash,
// the --version probe) happens at apply time (§3.7 steps 2-4) because
// it needs bytes; what happens here is everything that can be decided
// from the document alone.
//
// Failure direction follows §2.4: notify is FAIL-OPEN, so rules 1-5
// return a result in StateIdle — no banner, no state change, nothing
// for an operator to clear — while the eligibility rules 6-9 return the
// state the node should actually report (blocked / stale_manifest),
// because those are facts an admin needs to see on the board.
func Verify(in VerifyInput) (VerifyResult, error) {
	p := &verifyPass{in: in, env: in.Envelope, res: VerifyResult{State: StateIdle}}
	for _, r := range verifyRules {
		if err := r.check(p); err != nil {
			p.res.Rule = r.name
			return p.res, err
		}
	}
	p.res.Rule = "verified"
	p.res.State = StateAvailable
	p.res.UpdateAvailable = true
	return p.res, nil
}

// ruleEnvelope is rule 1: the envelope decodes within the size cap and
// is exactly ONE JSON value. A trailing second document is a smuggling
// shape (the DecodeCapped discipline), not a parse detail.
func ruleEnvelope(p *verifyPass) error {
	if len(p.in.EnvelopeBytes) == 0 {
		if p.env.ManifestB64 == "" {
			return fmt.Errorf("update.Verify: %w: empty envelope", ErrEnvelopeDecode)
		}
		return nil
	}
	if len(p.in.EnvelopeBytes) > MaxEnvelopeBytes {
		return fmt.Errorf("update.Verify: %w: %d bytes exceeds the %d cap",
			ErrEnvelopeDecode, len(p.in.EnvelopeBytes), MaxEnvelopeBytes)
	}
	var env Envelope
	dec := json.NewDecoder(bytes.NewReader(p.in.EnvelopeBytes))
	if err := dec.Decode(&env); err != nil {
		return fmt.Errorf("update.Verify: %w: %w", ErrEnvelopeDecode, err)
	}
	if dec.More() {
		return fmt.Errorf("update.Verify: %w: trailing JSON value", ErrEnvelopeDecode)
	}
	p.env = env
	return nil
}

// ruleManifestHash is rule 2: manifest_hash matches the manifest bytes.
// The hash authorizes nothing on its own — it is checked BEFORE the
// signature only because it gives the clearer error.
func ruleManifestHash(p *verifyPass) error {
	raw, err := base64.StdEncoding.DecodeString(p.env.ManifestB64)
	if err != nil {
		return fmt.Errorf("update.Verify: %w: manifest is not valid base64", ErrEnvelopeDecode)
	}
	if len(raw) > MaxManifestBytes {
		return fmt.Errorf("update.Verify: %w: manifest is %d bytes (max %d)", ErrEnvelopeDecode, len(raw), MaxManifestBytes)
	}
	if got := HashBytes(raw); got != p.env.ManifestHash {
		return fmt.Errorf("update.Verify: %w (declared %s, computed %s)", ErrManifestHashMismatch, p.env.ManifestHash, got)
	}
	p.manifestJSON = raw
	return nil
}

// ruleKeyAgreement is rule 3: the offered key_id must agree with any
// key another rail has already pinned for this org. ONE org, ONE
// distribution identity — TOFU applies only to a genuinely first pin,
// so a long-enrolled node cannot have a second key introduced by the
// first manifest it ever fetches.
func ruleKeyAgreement(p *verifyPass) error {
	if p.in.PinnedKeyID == "" {
		return nil // genuinely first pin
	}
	if p.env.KeyID != p.in.PinnedKeyID {
		return fmt.Errorf("update.Verify: %w (pinned %q, offered %q) — re-enrol to rotate trust",
			ErrKeyDisagreement, p.in.PinnedKeyID, p.env.KeyID)
	}
	return nil
}

// ruleSignature is rule 4: Ed25519 over the domain-tagged,
// version-bound message, against the PINNED key.
func ruleSignature(p *verifyPass) error {
	pub, err := base64.StdEncoding.DecodeString(p.in.PinnedPublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("update.Verify: %w: bad pinned public key", ErrSignatureInvalid)
	}
	sig, err := base64.StdEncoding.DecodeString(p.env.Signature)
	if err != nil {
		return fmt.Errorf("update.Verify: %w: bad signature encoding", ErrSignatureInvalid)
	}
	// The signed message binds manifest_version, so it must come from
	// the SIGNED bytes and not from any envelope field an attacker
	// could edit independently.
	mv, err := manifestVersionOf(p.manifestJSON)
	if err != nil {
		return fmt.Errorf("update.Verify: %w: %w", ErrEnvelopeDecode, err)
	}
	msg := ManifestSigningMessage(mv, p.env.ManifestHash)
	if !ed25519.Verify(ed25519.PublicKey(pub), msg, sig) {
		return fmt.Errorf("update.Verify: %w", ErrSignatureInvalid)
	}
	return nil
}

// ruleSchema is rule 5: a known schema, else IGNORE the document.
// Fail-open: the result stays StateIdle so no banner appears and no
// state changes.
func ruleSchema(p *verifyPass) error {
	schema, err := ProbeSchema(p.manifestJSON)
	if err != nil {
		return fmt.Errorf("update.Verify: %w", err)
	}
	if schema != SchemaV1 {
		return fmt.Errorf("update.Verify: %w: %q", ErrUnknownSchema, schema)
	}
	m, err := DecodeManifest(p.manifestJSON)
	if err != nil {
		return fmt.Errorf("update.Verify: %w", err)
	}
	if err := Validate(m); err != nil {
		return fmt.Errorf("update.Verify: %w", err)
	}
	p.res.Manifest = m
	return nil
}

// ruleReplay is rule 6: manifest_version must be strictly ahead of the
// last accepted one. This is the freeze/rollback control of §2.3 and it
// works only because the signature binds the version (rule 4).
func ruleReplay(p *verifyPass) error {
	if p.res.Manifest.ManifestVersion <= p.in.LastAcceptedManifestVersion {
		return fmt.Errorf("update.Verify: %w (offered %d, last accepted %d)",
			ErrManifestReplay, p.res.Manifest.ManifestVersion, p.in.LastAcceptedManifestVersion)
	}
	return nil
}

// ruleDowngrade is rule 7: version must be ahead of installed, unless
// allow_downgrade_to names EXACTLY this target AND the node consented.
// Both halves are required — an admin-minted downgrade without node
// consent is a server-forced change, which this product does not have.
func ruleDowngrade(p *verifyPass) error {
	m := p.res.Manifest
	installed := p.in.InstalledVersion
	if IsUpdateAvailable(installed, m.Version) {
		return nil
	}
	// Not ahead. A dev or pre-release build is never told it is behind
	// (semver.go), and it is never downgraded either.
	if IsDevBuild(installed) || HasPreRelease(installed) {
		p.res.State = StateIdle
		return fmt.Errorf("update.Verify: %w: installed %q is a dev/pre-release build", ErrDowngradeRefused, installed)
	}
	if m.AllowDowngradeTo == "" || m.AllowDowngradeTo != m.Version || !p.in.AllowDowngrade {
		p.res.State = StateBlocked
		p.res.Reason = ReasonDowngrade
		return fmt.Errorf("update.Verify: %w (installed %s, offered %s, allow_downgrade_to %q, node consent %t)",
			ErrDowngradeRefused, installed, m.Version, m.AllowDowngradeTo, p.in.AllowDowngrade)
	}
	if cmp, ok := CompareSemver(m.Version, installed); !ok || cmp > 0 {
		p.res.State = StateBlocked
		p.res.Reason = ReasonDowngrade
		return fmt.Errorf("update.Verify: %w: allow_downgrade_to must name an installed-or-lower target", ErrDowngradeRefused)
	}
	return nil
}

// ruleFreshness is rule 8: expires_at must be in the future, and
// min_from_version must be at or below the installed version.
func ruleFreshness(p *verifyPass) error {
	m := p.res.Manifest
	exp, err := parseRFC3339(m.ExpiresAt)
	if err != nil {
		return fmt.Errorf("update.Verify: %w: expires_at: %w", ErrInvalidManifest, err)
	}
	now := p.in.Now
	if now.IsZero() {
		return fmt.Errorf("update.Verify: %w: Now is required to judge freshness", ErrInvalidManifest)
	}
	if !exp.After(now.UTC()) {
		p.res.State = StateStaleManifest
		return fmt.Errorf("update.Verify: %w (expired %s)", ErrManifestExpired, m.ExpiresAt)
	}
	if m.MinFromVersion != "" {
		cmp, ok := CompareSemver(p.in.InstalledVersion, m.MinFromVersion)
		if !ok {
			// An unparseable installed version cannot be shown to
			// satisfy a required stop, so it does not.
			p.res.State = StateBlocked
			p.res.Reason = ReasonRequiredStop
			return fmt.Errorf("update.Verify: %w: installed version %q is not comparable against min_from_version %s",
				ErrRequiredStop, p.in.InstalledVersion, m.MinFromVersion)
		}
		if cmp < 0 {
			p.res.State = StateBlocked
			p.res.Reason = ReasonRequiredStop
			return fmt.Errorf("update.Verify: %w: install %s first (installed %s, target %s)",
				ErrRequiredStop, m.MinFromVersion, p.in.InstalledVersion, m.Version)
		}
	}
	return nil
}

// ruleArtifact is rule 9: an artifact exists for this platform, its
// archive_type is a known shape, and it carries a NON-EMPTY vendor
// signature. The last clause is the H0 fail-closed interim: an artifact
// with no vendor signature is blocked{unsigned_artifact}, never applied,
// so the two-signature claim is never quietly one signature.
func ruleArtifact(p *verifyPass) error {
	kind := p.in.Kind
	if kind == "" {
		kind = KindAgent
	}
	goos, goarch := p.in.GOOS, p.in.GOARCH
	if goos == "" || goarch == "" {
		cos, carch := CurrentPlatform()
		if goos == "" {
			goos = cos
		}
		if goarch == "" {
			goarch = carch
		}
	}
	a, ok := SelectArtifact(p.res.Manifest, kind, goos, goarch)
	if !ok {
		p.res.State = StateBlocked
		p.res.Reason = ReasonNoArtifact
		return fmt.Errorf("update.Verify: %w (%s/%s/%s)", ErrNoArtifact, kind, goos, goarch)
	}
	if !KnownArchiveType(a.ArchiveType) {
		p.res.State = StateBlocked
		p.res.Reason = ReasonNoArtifact
		return fmt.Errorf("update.Verify: %w: unknown archive_type %q", ErrNoArtifact, a.ArchiveType)
	}
	if a.UpstreamSig == "" || !KnownSigType(a.UpstreamSigType) {
		p.res.State = StateBlocked
		p.res.Reason = ReasonUnsignedArtifact
		return fmt.Errorf("update.Verify: %w (%s)", ErrUnsignedArtifact, a.Filename)
	}
	p.res.Artifact = a
	return nil
}

// manifestVersionOf reads manifest_version out of raw manifest bytes.
// It is read from the SIGNED bytes on purpose (see ruleSignature).
func manifestVersionOf(b []byte) (int64, error) {
	var probe struct {
		ManifestVersion int64 `json:"manifest_version"`
	}
	if err := json.Unmarshal(b, &probe); err != nil {
		return 0, err
	}
	return probe.ManifestVersion, nil
}
