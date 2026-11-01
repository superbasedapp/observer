package orgcontract

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
)

// Signed-rail binding, version 3: the project audience on the guard bundle
// rail (security plan section 7.11, spike JSP-10, lane sec-p).
//
// A node that advertises PolicyBindingV3Capability, of an org that has
// published at least one project-scoped guard bundle, receives:
//
//   - the composed bundle (org-wide, team and member layers, exactly as v2)
//     signed over the v3 message: the v2 fields plus the assignment epoch and
//     the digest of the signed project mapping;
//   - the project mapping (ProjectMapping): for the projects whose sections
//     reach this member, org_project_id to the identity signal hashes the
//     resolver accepts for it (remote, upstream remote and root commit hashes
//     only), its own signature, capped at MaxProjectMappingProjects;
//   - one envelope per mapped project, signed over the v3 message with the
//     org project id set and the mapping digest empty, carrying only that
//     project's sections composed strictest-wins.
//
// The node never asserts a project: it matches its own identity hashes
// against the mapping the org signed and loads only the matched envelopes.
// Once it has held a v3 delivery it refuses a v2 or v1 one (downgrade), an
// epoch lower than one it accepted, and a mapping whose digest or epoch
// differs from the signed composed bundle.

// PolicyBindingV3Capability is the ?policy_caps token a node sends on
// GET /api/v1/policy-bundle to ask for the project audience (v3). A server
// that predates it ignores it; a server whose org has no project-scoped
// bundle answers exactly as for v2.
const PolicyBindingV3Capability = "binding-v3"

// policyBundleSigningV3Domain opens every v3 guard-bundle message.
const policyBundleSigningV3Domain = "sbo-policy-bundle-v3"

// projectMappingSigningDomain opens the project mapping's signed message.
const projectMappingSigningDomain = "sbo-project-mapping-v1"

// MaxProjectMappingProjects caps one member's mapping (JSP-10: 0.5 ms to read
// at 200 projects). Above the cap the mapping is Truncated; the resolve call
// that covers the rest is a later lane.
const MaxProjectMappingProjects = 200

// DefaultProjectMappingMaxAge is how long after the node accepted (or was
// last told, by a 304, that it still holds) a mapping the node keeps using
// it offline. Past it the project layer is unknown.
const DefaultProjectMappingMaxAge = 7 * 24 * 60 * 60

// ProjectBinding is what a v3 signature binds besides the TOML.
type ProjectBinding struct {
	OrgID   string `json:"org_id"`
	Subject string `json:"subject"`
	// OrgProjectID is set on a per-project envelope and empty on the
	// composed bundle.
	OrgProjectID string `json:"org_project_id,omitempty"`
	// Epoch is the org's monotonic assignment epoch.
	Epoch int64 `json:"epoch"`
	// MappingDigest is ProjectMappingDigest of the mapping delivered with
	// the composed bundle; empty on a per-project envelope.
	MappingDigest string `json:"mapping_digest,omitempty"`
	// FamiliesDigest is ProjectFamiliesDigest of the envelope's family
	// members (lane sec-p3); empty when it carries none, and always empty
	// on the composed bundle. Set, it selects the families signing domain.
	FamiliesDigest string `json:"families_digest,omitempty"`
}

// PolicyBundleV3SigningMessage is the v3 message: the v3 domain, then the
// version, the hex SHA-256 of the TOML, the org, the subject, an empty
// projection target (shape parity with v2), the org project id, the epoch and
// the mapping digest, each length-prefixed. An envelope that carries family
// members (FamiliesDigest set, lane sec-p3) is signed under its own domain,
// policyBundleSigningV3FamiliesDomain, with the families digest appended, so
// stripping or adding the members never verifies against the other form.
func PolicyBundleV3SigningMessage(version int64, bundleTOML []byte, b ProjectBinding) []byte {
	sum := sha256.Sum256(bundleTOML)
	var buf bytes.Buffer
	domain := policyBundleSigningV3Domain
	if b.FamiliesDigest != "" {
		domain = policyBundleSigningV3FamiliesDomain
	}
	buf.WriteString(domain)
	writeLPField(&buf, strconv.FormatInt(version, 10))
	writeLPField(&buf, hex.EncodeToString(sum[:]))
	writeLPField(&buf, b.OrgID)
	writeLPField(&buf, b.Subject)
	writeLPField(&buf, "")
	writeLPField(&buf, b.OrgProjectID)
	writeLPField(&buf, strconv.FormatInt(b.Epoch, 10))
	writeLPField(&buf, b.MappingDigest)
	if b.FamiliesDigest != "" {
		writeLPField(&buf, b.FamiliesDigest)
	}
	return buf.Bytes()
}

// ProjectDelivery is the project half of a v3 delivery.
type ProjectDelivery struct {
	Mapping ProjectMapping `json:"mapping"`
	// Envelopes are the per-project envelopes, sorted by org project id.
	Envelopes []PolicyBundle `json:"envelopes,omitempty"`
}

// ProjectRepoHashes is one repository's identity signal hashes, the same
// unsalted SHA-256 values nodes already ship (agent migration 102). Owner
// hashes and the content fingerprint are never carried (JSP-10).
type ProjectRepoHashes struct {
	RemoteHash         string `json:"remote_hash,omitempty"`
	UpstreamRemoteHash string `json:"upstream_remote_hash,omitempty"`
	RootCommitHash     string `json:"root_commit_hash,omitempty"`
}

// ProjectMappingEntry is one org project and its repositories.
type ProjectMappingEntry struct {
	OrgProjectID string              `json:"org_project_id"`
	Repos        []ProjectRepoHashes `json:"repos"`
}

// ProjectMapping is the signed org_project_id to identity hash table for one
// member.
type ProjectMapping struct {
	OrgID   string `json:"org_id"`
	Subject string `json:"subject"`
	Epoch   int64  `json:"epoch"`
	// MaxAgeSeconds bounds offline use (DefaultProjectMappingMaxAge).
	MaxAgeSeconds int64 `json:"max_age_seconds"`
	// Truncated reports that more projects reached the member than
	// MaxProjectMappingProjects; the rest are not matched.
	Truncated bool                  `json:"truncated,omitempty"`
	Projects  []ProjectMappingEntry `json:"projects"`
	Signature string                `json:"signature,omitempty"`
	PublicKey string                `json:"public_key,omitempty"`
}

// canonicalProjectMapping is m with its signature fields cleared and its
// lists sorted, the one form the digest covers.
func canonicalProjectMapping(m ProjectMapping) ProjectMapping {
	out := m
	out.Signature, out.PublicKey = "", ""
	out.Projects = make([]ProjectMappingEntry, 0, len(m.Projects))
	for _, e := range m.Projects {
		repos := append([]ProjectRepoHashes(nil), e.Repos...)
		sort.Slice(repos, func(i, j int) bool {
			a, b := repos[i], repos[j]
			if a.RemoteHash != b.RemoteHash {
				return a.RemoteHash < b.RemoteHash
			}
			if a.UpstreamRemoteHash != b.UpstreamRemoteHash {
				return a.UpstreamRemoteHash < b.UpstreamRemoteHash
			}
			return a.RootCommitHash < b.RootCommitHash
		})
		if repos == nil {
			repos = []ProjectRepoHashes{}
		}
		out.Projects = append(out.Projects, ProjectMappingEntry{OrgProjectID: e.OrgProjectID, Repos: repos})
	}
	sort.Slice(out.Projects, func(i, j int) bool { return out.Projects[i].OrgProjectID < out.Projects[j].OrgProjectID })
	return out
}

// ProjectMappingDigest is hex(SHA-256) of the mapping's canonical JSON (every
// field but the signature and key). It is what the composed bundle's v3
// binding carries.
func ProjectMappingDigest(m ProjectMapping) string {
	raw, err := json.Marshal(canonicalProjectMapping(m))
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// projectMappingMessage is the mapping's signed message: the domain and its
// digest, length-prefixed.
func projectMappingMessage(digest string) []byte {
	var buf bytes.Buffer
	buf.WriteString(projectMappingSigningDomain)
	writeLPField(&buf, digest)
	return buf.Bytes()
}

// SignProjectMapping signs m with priv and returns it with its signature and
// public key set.
func SignProjectMapping(priv ed25519.PrivateKey, m ProjectMapping) ProjectMapping {
	out := canonicalProjectMapping(m)
	out.PublicKey = base64.RawURLEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
	out.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, projectMappingMessage(ProjectMappingDigest(out))))
	return out
}

// VerifyProjectMapping checks m's signature against its embedded key and
// returns the key (the caller compares it to the pin and to the bundle's).
func VerifyProjectMapping(m ProjectMapping) (ed25519.PublicKey, error) {
	pub, err := base64.RawURLEncoding.DecodeString(m.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("orgcontract.VerifyProjectMapping: bad public key")
	}
	sig, err := base64.RawURLEncoding.DecodeString(m.Signature)
	if err != nil {
		return nil, fmt.Errorf("orgcontract.VerifyProjectMapping: decode signature: %w", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), projectMappingMessage(ProjectMappingDigest(m)), sig) {
		return nil, errors.New("orgcontract.VerifyProjectMapping: signature verification failed")
	}
	return ed25519.PublicKey(pub), nil
}

// The pre-launch resolve call (security plan section 7.11 "Delivery" item 3,
// lane sec-p2a): POST /api/agent/project/resolve. A node holding a v3
// delivery asks, at launch and at session start (never on the hook path),
// which org projects a repository its cached mapping does not match belongs
// to. The server answers with a signed ProjectResolveAnswer bound to the org,
// the verified member, the assignment epoch, the composed bundle version, the
// exact request (by digest) and the node's nonce, with a short expiry; it
// covers every project whose sections reach the member, so it also answers a
// member above MaxProjectMappingProjects. The answer carries the v3 envelope
// of each matched project, signed exactly like a delivery's envelopes.

// projectResolveSigningDomain opens the resolve answer's signed message. It
// is its own domain: a mapping or bundle signature never verifies here.
const projectResolveSigningDomain = "sbo-project-resolve-v1"

// DefaultProjectResolveTTL is how long a resolve answer stays usable after
// it was issued (seconds). Past it the node asks again.
const DefaultProjectResolveTTL = 60 * 60

// MaxProjectResolveHashes caps the remote-kind hashes one request may carry
// (a remote and an upstream remote, each in every match form, with room).
const MaxProjectResolveHashes = 16

// ProjectResolveRequest is what the node sends: its own identity hashes (the
// same unsalted SHA-256 values it ships since agent migration 102) in every
// match form (ProjectRemoteForms), and a fresh random nonce the answer must
// echo. The node never names a project.
type ProjectResolveRequest struct {
	RemoteHashes   []string `json:"remote_hashes,omitempty"`
	RootCommitHash string   `json:"root_commit_hash,omitempty"`
	Nonce          string   `json:"nonce"`
}

// ProjectResolveRequestDigest is hex(SHA-256) over the request's canonical
// form (the hashes sorted and deduplicated, then the root commit hash and the
// nonce), each length-prefixed. The answer binds it, so an answer for another
// repository or another request never verifies as this one's.
func ProjectResolveRequestDigest(r ProjectResolveRequest) string {
	hashes := sortedUnique(r.RemoteHashes)
	var buf bytes.Buffer
	buf.WriteString(projectResolveSigningDomain + "/request")
	writeLPField(&buf, strconv.Itoa(len(hashes)))
	for _, h := range hashes {
		writeLPField(&buf, h)
	}
	writeLPField(&buf, r.RootCommitHash)
	writeLPField(&buf, r.Nonce)
	sum := sha256.Sum256(buf.Bytes())
	return hex.EncodeToString(sum[:])
}

// ProjectResolveAnswer is the server's signed answer.
type ProjectResolveAnswer struct {
	OrgID   string `json:"org_id"`
	Subject string `json:"subject"`
	// Epoch is the org's assignment epoch the answer was computed under.
	Epoch int64 `json:"epoch"`
	// BundleVersion is the composed bundle version served to this member at
	// the same time; the envelopes carry it.
	BundleVersion int64 `json:"bundle_version"`
	// RequestDigest is ProjectResolveRequestDigest of the request answered.
	RequestDigest string `json:"request_digest"`
	Nonce         string `json:"nonce"`
	// OrgProjectIDs are the matched projects, sorted; empty means the org
	// knows no project with sections for this member that the repository
	// belongs to (not matched).
	OrgProjectIDs []string `json:"org_project_ids"`
	// IssuedAt and ExpiresAt are Unix seconds.
	IssuedAt  int64 `json:"issued_at"`
	ExpiresAt int64 `json:"expires_at"`
	// Envelopes are the matched projects' v3 envelopes (bound to the org,
	// the member, the project, Epoch and BundleVersion). Each is signed on
	// its own and is not part of the answer's signed message. A matched
	// project the server could not compose has no envelope.
	Envelopes []PolicyBundle `json:"envelopes,omitempty"`
	Signature string         `json:"signature,omitempty"`
	PublicKey string         `json:"public_key,omitempty"`
}

// projectResolveMessage is the answer's signed message: the domain, then
// every field but the envelopes, the signature and the key, length-prefixed.
func projectResolveMessage(a ProjectResolveAnswer) []byte {
	ids := sortedUnique(a.OrgProjectIDs)
	var buf bytes.Buffer
	buf.WriteString(projectResolveSigningDomain)
	writeLPField(&buf, a.OrgID)
	writeLPField(&buf, a.Subject)
	writeLPField(&buf, strconv.FormatInt(a.Epoch, 10))
	writeLPField(&buf, strconv.FormatInt(a.BundleVersion, 10))
	writeLPField(&buf, a.RequestDigest)
	writeLPField(&buf, a.Nonce)
	writeLPField(&buf, strconv.FormatInt(a.IssuedAt, 10))
	writeLPField(&buf, strconv.FormatInt(a.ExpiresAt, 10))
	writeLPField(&buf, strconv.Itoa(len(ids)))
	for _, id := range ids {
		writeLPField(&buf, id)
	}
	return buf.Bytes()
}

// SignProjectResolveAnswer signs a with priv and returns it with its project
// list sorted and its signature and public key set.
func SignProjectResolveAnswer(priv ed25519.PrivateKey, a ProjectResolveAnswer) ProjectResolveAnswer {
	out := a
	out.OrgProjectIDs = sortedUnique(a.OrgProjectIDs)
	out.PublicKey = base64.RawURLEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
	out.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, projectResolveMessage(out)))
	return out
}

// VerifyProjectResolveAnswer checks a's signature against its embedded key
// and returns the key (the caller compares it to the pin).
func VerifyProjectResolveAnswer(a ProjectResolveAnswer) (ed25519.PublicKey, error) {
	pub, err := base64.RawURLEncoding.DecodeString(a.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("orgcontract.VerifyProjectResolveAnswer: bad public key")
	}
	sig, err := base64.RawURLEncoding.DecodeString(a.Signature)
	if err != nil {
		return nil, fmt.Errorf("orgcontract.VerifyProjectResolveAnswer: decode signature: %w", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), projectResolveMessage(a), sig) {
		return nil, errors.New("orgcontract.VerifyProjectResolveAnswer: signature verification failed")
	}
	return ed25519.PublicKey(pub), nil
}

// sortedUnique returns the non-empty values of in, sorted and deduplicated
// (never nil).
func sortedUnique(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
