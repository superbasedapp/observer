package secverify

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/secchange"
)

// orgmode.go is verify's org mode (security plan 7.9 F2 and 7.10, lane
// SEC-F2B): the org's signed CI policy and its signed change record
// lookup answer, both fetched by a separate CI job that holds the CI
// credential and never checks out the pull request, are checked here
// against the org key the protected workflow pins. The policy brings the
// verify policy text, the provenance floor and the org's keys file (its
// root, the key certificates it issued and its revocation list); the
// lookup brings, per commit, the records the org received and its signed
// receipt of each (the countersign). Nothing here waits or fetches: the
// bounded wait belongs to the fetch job, and a lookup that never came
// leaves the commits to their notes (unknown_provenance where none).

// ErrOrgDocument wraps every refusal of an org document.
var ErrOrgDocument = errors.New("secverify: org document refused")

// The org document clock bounds.
const (
	// orgClockSkew is how far an org document's times may run ahead of the
	// runner's clock.
	orgClockSkew = 5 * time.Minute
	// MaxOrgLookupAge bounds a lookup answer's age.
	MaxOrgLookupAge = 24 * time.Hour
)

// OrgPolicy is a checked CI policy.
type OrgPolicy struct {
	OrgID       string
	Version     int64
	WaitSeconds int
	// Policy is the verify policy the org set (the built-in defaults when
	// it set no text), with Source org and its provenance floor.
	Policy Policy
	// Trust is the org's keys file.
	Trust secchange.TrustSet
}

// decodeSigned reads a signed CI document strictly.
func decodeSigned(doc []byte) (orgcontract.CISignedDocument, error) {
	var d orgcontract.CISignedDocument
	if len(doc) > orgcontract.MaxCIDocumentBytes {
		return d, fmt.Errorf("%w: over %d bytes", ErrOrgDocument, orgcontract.MaxCIDocumentBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil || dec.More() {
		return d, fmt.Errorf("%w: not a signed CI document", ErrOrgDocument)
	}
	return d, nil
}

// decodeBody reads a document body strictly into v.
func decodeBody(body []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil || dec.More() {
		return fmt.Errorf("%w: body is not well formed", ErrOrgDocument)
	}
	return nil
}

// ParseOrgPolicy checks the org's signed CI policy: the signature under
// the policy domain by orgKey over this org and the body's own version, the
// org id, a version of at least minVersion (a rollback floor the protected
// workflow may pin), a lifetime that covers now, a floor and a wait in
// their vocabulary, the verify policy text (refused like a --policy file)
// and the keys file.
func ParseOrgPolicy(doc []byte, orgID string, orgKey ed25519.PublicKey, minVersion int64, now time.Time) (OrgPolicy, error) {
	if orgID == "" || len(orgKey) != ed25519.PublicKeySize {
		return OrgPolicy{}, fmt.Errorf("%w: the org id and the org key are required", ErrOrgDocument)
	}
	d, err := decodeSigned(doc)
	if err != nil {
		return OrgPolicy{}, err
	}
	var body orgcontract.CIPolicy
	if err := decodeBody(d.Body, &body); err != nil {
		return OrgPolicy{}, err
	}
	if err := orgcontract.VerifyCIDocument(orgcontract.CIPolicyDomain, orgID, body.Version, d, orgKey); err != nil {
		return OrgPolicy{}, fmt.Errorf("%w: %w", ErrOrgDocument, err)
	}
	if body.OrgID != orgID {
		return OrgPolicy{}, fmt.Errorf("%w: the policy is another org's", ErrOrgDocument)
	}
	if body.Version < 1 || body.Version < minVersion {
		return OrgPolicy{}, fmt.Errorf("%w: policy version %d is below the pinned floor %d", ErrOrgDocument, body.Version, minVersion)
	}
	issued, err1 := time.Parse(time.RFC3339, body.IssuedAt)
	expires, err2 := time.Parse(time.RFC3339, body.ExpiresAt)
	if err1 != nil || err2 != nil || !expires.After(issued) {
		return OrgPolicy{}, fmt.Errorf("%w: policy times are not well formed", ErrOrgDocument)
	}
	if now.Add(orgClockSkew).Before(issued) || now.After(expires) {
		return OrgPolicy{}, fmt.Errorf("%w: the policy is not valid now (issued %s, expires %s); fetch it again", ErrOrgDocument, body.IssuedAt, body.ExpiresAt)
	}
	floor := secchange.FloorAction(body.ProvenanceFloor)
	if floor == "" || !validFloor(floor) {
		return OrgPolicy{}, fmt.Errorf("%w: provenance floor %q", ErrOrgDocument, clipSafe(body.ProvenanceFloor, 16))
	}
	if body.WaitSeconds < 0 || body.WaitSeconds > 1800 {
		return OrgPolicy{}, fmt.Errorf("%w: wait %d seconds", ErrOrgDocument, body.WaitSeconds)
	}
	pol := DefaultPolicy()
	if body.VerifyPolicy != "" {
		if pol, err = ParsePolicy([]byte(body.VerifyPolicy), SourceOrg); err != nil {
			return OrgPolicy{}, err
		}
	}
	pol.Source, pol.Provenance, pol.OrgVersion = SourceOrg, floor, body.Version
	trust, err := secchange.ParseTrustFile(body.Keys)
	if err != nil {
		return OrgPolicy{}, fmt.Errorf("%w: keys: %w", ErrOrgDocument, err)
	}
	return OrgPolicy{OrgID: orgID, Version: body.Version, WaitSeconds: body.WaitSeconds, Policy: pol, Trust: trust}, nil
}

// OrgLookup is a checked lookup answer.
type OrgLookup struct {
	AnsweredAt string
	records    map[string][]orgcontract.CILookupRecord
}

// Records returns the records the org answered for a commit.
func (l *OrgLookup) Records(sha string) []orgcontract.CILookupRecord {
	if l == nil {
		return nil
	}
	return l.records[sha]
}

// ParseOrgLookup checks the org's signed lookup answer: the signature under
// the lookup domain by orgKey over this org, the org id, and an answer
// time within MaxOrgLookupAge of now.
func ParseOrgLookup(doc []byte, orgID string, orgKey ed25519.PublicKey, now time.Time) (*OrgLookup, error) {
	if orgID == "" || len(orgKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: the org id and the org key are required", ErrOrgDocument)
	}
	d, err := decodeSigned(doc)
	if err != nil {
		return nil, err
	}
	if err := orgcontract.VerifyCIDocument(orgcontract.CILookupDomain, orgID, 0, d, orgKey); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrOrgDocument, err)
	}
	var ans orgcontract.CILookupAnswer
	if err := decodeBody(d.Body, &ans); err != nil {
		return nil, err
	}
	if ans.OrgID != orgID {
		return nil, fmt.Errorf("%w: the lookup answer is another org's", ErrOrgDocument)
	}
	at, err := time.Parse(time.RFC3339, ans.AnsweredAt)
	if err != nil || now.Add(orgClockSkew).Before(at) || now.Sub(at) > MaxOrgLookupAge {
		return nil, fmt.Errorf("%w: the lookup answer is not from the last %s", ErrOrgDocument, MaxOrgLookupAge)
	}
	l := &OrgLookup{AnsweredAt: ans.AnsweredAt, records: map[string][]orgcontract.CILookupRecord{}}
	for _, c := range ans.Commits {
		recs := c.Records
		if len(recs) > orgcontract.MaxCIRecordsPerCommit {
			recs = recs[:orgcontract.MaxCIRecordsPerCommit]
		}
		l.records[c.SHA] = append(l.records[c.SHA], recs...)
	}
	return l, nil
}

// OrgProvenance is the org half of the provenance step's input.
type OrgProvenance struct {
	OrgID         string
	OrgKey        ed25519.PublicKey
	PolicyVersion int64
	// Lookup is the checked answer; nil when the fetch job brought none
	// (the org did not answer within the wait), and the commits then read
	// only their notes.
	Lookup *OrgLookup
}

// OrgReport is the org half of the provenance report.
type OrgReport struct {
	OrgID         string `json:"org_id"`
	PolicyVersion int64  `json:"policy_version"`
	// Lookup is "answered" or "unavailable".
	Lookup     string `json:"lookup"`
	AnsweredAt string `json:"answered_at,omitempty"`
	// Countersigned counts the commits whose deciding record carries the
	// org's checked receipt; Pending those decided by a record the org has
	// not countersigned (yet, or ever: a key that is not enrolled).
	Countersigned int `json:"countersigned"`
	Pending       int `json:"pending"`
	// EnvelopeMissing counts the org records that came without the signed
	// envelope (a node that shipped only the digest), which cannot verify.
	EnvelopeMissing int `json:"envelope_missing"`
	// Refused counts the org records the org itself refused at ingest
	// (replayed, revoked key, bad signature, binding mismatch) for the
	// commit asked about.
	Refused int `json:"refused"`
}

// The org lookup states.
const (
	OrgLookupAnswered    = "answered"
	OrgLookupUnavailable = "unavailable"
)

// ReasonEnvelopeMissing is a commit's reason when the org holds a record
// for it but not the signed envelope, and nothing else spoke for it.
const ReasonEnvelopeMissing = "envelope_missing"

// orgRefusal is an org record's failure, with its closed code.
type orgRefusal struct{ code string }

func (e orgRefusal) Error() string { return "secverify: org record refused: " + e.code }

// orgRefusedStates maps the org's refusal states to their codes.
var orgRefusedStates = map[string]string{
	orgcontract.ChangeIngestReplay:    "org_refused_replay",
	orgcontract.ChangeIngestBinding:   "org_refused_binding",
	orgcontract.ChangeIngestSignature: "org_refused_signature",
	orgcontract.ChangeIngestRevoked:   "org_refused_revoked_key",
}

// orgCommit gathers one commit's org records into the candidate list:
// a record the org refused for this very commit (matched by its sha) is a
// failed candidate, except a record refused as a replay whose own envelope
// verifies here and binds this commit, which is verified like any other
// (lane SEC-F2B audit finding 2: an earlier record from another key, an
// insider's naming someone else's sha for example, never fails the commit's
// own verified record; two verified records from two keys still decide
// records_from_two_keys); a record that came with its envelope is verified
// like a note (once per digest: a note and the org's copy of the same
// record are one candidate); a countersign that does not check fails its
// record. A present record that itself fails verification fails in every
// mode (P-059). It returns the digests the org countersigned.
func orgCommit(org *OrgProvenance, trust secchange.TrustSet, c ProvenanceCommit, cr *ProvenanceCommitReport, cands []secchange.Candidate, seen map[string]bool, rep *OrgReport) ([]secchange.Candidate, map[string]bool, bool) {
	countersigned := map[string]bool{}
	envelopeMissing := false
	for _, r := range org.Lookup.Records(c.Facts.SHA) {
		if code, refused := orgRefusedStates[r.State]; refused && !replayButOwnRecordBinds(r, trust, c.Facts) {
			if r.MatchedBy == orgcontract.CIMatchCommitSHA {
				rep.Refused++
				cands = append(cands, secchange.Candidate{Err: orgRefusal{code}})
				cr.Errors = append(cr.Errors, code)
			}
			continue
		}
		if r.Envelope == "" {
			envelopeMissing = true
			rep.EnvelopeMissing++
			cr.Errors = append(cr.Errors, ReasonEnvelopeMissing)
			continue
		}
		env, err := secchange.ParseEnvelope([]byte(r.Envelope))
		var v secchange.Verified
		if err == nil {
			v, err = secchange.Verify(env, trust)
		}
		if err == nil && v.Digest != r.RecordDigest {
			err = orgRefusal{"org_record_digest_mismatch"}
		}
		if err == nil && r.Countersign != nil {
			cs := *r.Countersign
			if cerr := orgcontract.VerifyChangeCountersign(cs, org.OrgKey); cerr != nil || cs.OrgID != org.OrgID || cs.RecordDigest != v.Digest || cs.KeyID != v.KeyID {
				err = orgRefusal{"countersign_invalid"}
			} else {
				countersigned[v.Digest] = true
			}
		}
		if err != nil {
			cands = append(cands, secchange.Candidate{Err: err})
			cr.Errors = append(cr.Errors, refusalCode(err))
			continue
		}
		if seen[v.Digest] {
			continue
		}
		seen[v.Digest] = true
		cands = append(cands, secchange.Candidate{Verified: v})
		if code := secchange.BindingRefusal(v.Record.Binding, c.Facts); code != "" {
			cr.Errors = append(cr.Errors, code)
		}
	}
	return cands, countersigned, envelopeMissing
}

// ReasonClaimByAnotherMember is the code a commit's report carries when two
// verified records from two keys spoke for it and the org's lookup named
// the commit's committer or author as the member of exactly one of the
// keys: that record decides, and the other is reported as another member's
// claim (lane SEC-P4 decision 8, SECP-31: an insider's certified key could
// claim a colleague's sha first).
const ReasonClaimByAnotherMember = "claim_by_another_member"

// orgResolveClaim picks between two verified records from two keys for one
// commit by the member the org certified each key to (the lookup's
// org-signed member hash) against the commit's committer and author email
// hashes: when exactly one key's member matches, the candidates are that
// key's verified records alone (ok true). When two match because one key's
// member is the author and the other's the committer, the committer's key
// decides (lane LEFT-SHARED: the committer made the commit object). Zero
// matches (an unmatched commit never passes), two with no committer read,
// or one member that is both stay records_from_two_keys (ok false). A key
// the lookup named no member for never matches; with no member on record
// (the org's identity map is the member email) today's result stands.
func orgResolveClaim(org *OrgProvenance, c ProvenanceCommit, cands []secchange.Candidate) ([]secchange.Candidate, bool) {
	if org == nil || org.Lookup == nil || len(c.IdentityHashes) == 0 {
		return nil, false
	}
	memberOf := map[string]string{}
	for _, r := range org.Lookup.Records(c.Facts.SHA) {
		if r.MemberHash != "" && r.KeyID != "" {
			memberOf[r.KeyID] = r.MemberHash
		}
	}
	identity := map[string]bool{}
	for _, h := range c.IdentityHashes {
		if h != "" {
			identity[h] = true
		}
	}
	matched := map[string]bool{}
	keys := map[string]bool{}
	for _, cd := range cands {
		if cd.Err != nil {
			continue
		}
		keys[cd.Verified.KeyID] = true
		if h := memberOf[cd.Verified.KeyID]; h != "" && identity[h] {
			matched[cd.Verified.KeyID] = true
		}
	}
	if len(matched) > 1 && c.CommitterHash != "" {
		byCommitter := map[string]bool{}
		for k := range matched {
			if memberOf[k] == c.CommitterHash {
				byCommitter[k] = true
			}
		}
		if len(byCommitter) == 1 {
			matched = byCommitter
		}
	}
	if len(matched) != 1 || len(keys) < 2 {
		return nil, false
	}
	var out []secchange.Candidate
	for _, cd := range cands {
		if cd.Err == nil && matched[cd.Verified.KeyID] {
			out = append(out, cd)
		}
	}
	return out, true
}

// replayButOwnRecordBinds reports whether an org record refused only as a
// replay carries an envelope that verifies against the policy's keys (a
// certified, unrevoked key), whose digest is the record's, and whose
// binding matches the commit (exactly or through its patch fingerprint).
// Only the replay refusal yields to this: a revoked key, a bad signature or
// a binding mismatch the org saw stays a failed candidate.
func replayButOwnRecordBinds(r orgcontract.CILookupRecord, trust secchange.TrustSet, facts secchange.CommitFacts) bool {
	if r.State != orgcontract.ChangeIngestReplay || r.Envelope == "" {
		return false
	}
	env, err := secchange.ParseEnvelope([]byte(r.Envelope))
	if err != nil {
		return false
	}
	v, err := secchange.Verify(env, trust)
	if err != nil || v.Digest != r.RecordDigest {
		return false
	}
	m, _ := secchange.CheckBinding(v.Record.Binding, facts)
	return m == secchange.MatchExact || m == secchange.MatchPatch
}
