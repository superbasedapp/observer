package secchange

import (
	"sort"
	"time"
)

// rules.go holds the protocol's decision tables (security plan 7.10
// "Binding", "Replay", "Amend, rebase, squash", "Key id, algorithm,
// rotation, revocation" and "Missing record"). Each is an ordered table
// walked top-down; the first row that matches decides (CLAUDE.md rule 5).

// CommitFacts are what a verifier knows about a presented commit. An empty
// org, machine or project field is "not known here" and is not compared.
type CommitFacts struct {
	SHA             string
	Tree            string
	PatchFP         string
	OrgID           string
	MachineIdentity string
	ProjectHash     string
}

// Match says how a record speaks for a presented commit.
type Match string

// The Match values.
const (
	// MatchExact: the record names this commit and its tree.
	MatchExact Match = "exact"
	// MatchPatch: the record names another commit with the same patch (a
	// rebase, a cherry-pick): it verifies through patch_fp.
	MatchPatch Match = "patch"
	// MatchNone: the record does not speak for this commit (an amend that
	// changed the patch, another commit, another org or machine).
	MatchNone Match = "none"
)

// bindingRule is one row of the binding table.
type bindingRule struct {
	name string
	// code is the closed refusal code a MatchNone row names (decision log
	// P-059: a record that does not speak for the commit it is attached to
	// is a verification failure, named); "" on a matching row.
	code  string
	when  func(b Binding, c CommitFacts) bool
	match Match
}

func differs(want, got string) bool { return got != "" && want != got }

// bindingRules is the ordered binding table.
var bindingRules = []bindingRule{
	{"org differs", "record_for_another_org", func(b Binding, c CommitFacts) bool { return differs(b.OrgID, c.OrgID) }, MatchNone},
	{"machine differs", "record_for_another_machine", func(b Binding, c CommitFacts) bool { return differs(b.MachineIdentity, c.MachineIdentity) }, MatchNone},
	{"project differs", "record_for_another_project", func(b Binding, c CommitFacts) bool { return differs(b.ProjectHash, c.ProjectHash) }, MatchNone},
	{"same commit and tree", "", func(b Binding, c CommitFacts) bool { return b.CommitSHA == c.SHA && b.TreeSHA == c.Tree }, MatchExact},
	{"same commit, other tree", "payload_does_not_match_commit", func(b Binding, c CommitFacts) bool { return b.CommitSHA == c.SHA }, MatchNone},
	{"same patch", "", func(b Binding, c CommitFacts) bool {
		return b.PatchFPState == "ok" && b.PatchFP != "" && b.PatchFP == c.PatchFP
	}, MatchPatch},
	{"otherwise", "record_for_another_commit", func(Binding, CommitFacts) bool { return true }, MatchNone},
}

// CheckBinding says how a record's binding speaks for a presented commit,
// with the name of the table row that decided.
func CheckBinding(b Binding, c CommitFacts) (Match, string) {
	for _, r := range bindingRules {
		if r.when(b, c) {
			return r.match, r.name
		}
	}
	return MatchNone, "otherwise"
}

// BindingRefusal is the closed code naming why a record that verified does
// not speak for the commit it was presented with ("" when it does): its
// payload does not match the commit, or it was replayed onto another
// commit, org, machine or project. Decision log P-059 makes each of these a
// verification failure, never an unknown.
func BindingRefusal(b Binding, c CommitFacts) string {
	for _, r := range bindingRules {
		if r.when(b, c) {
			return r.code
		}
	}
	return "record_for_another_commit"
}

// Stored is what a replay store keeps per accepted record.
type Stored struct {
	KeyID     string
	CommitSHA string
	PatchFP   string
	Digest    string
}

// Ingest is a replay-store decision.
type Ingest string

// The Ingest values.
const (
	IngestAccept    Ingest = "accept"
	IngestDuplicate Ingest = "duplicate"
	// IngestReplay refuses a second record for the same commit from a
	// different key.
	IngestReplay Ingest = "refuse_replay"
	// IngestUpdate replaces the same key's earlier record for the same
	// commit (a rebuilt record after a finding closed, for example).
	IngestUpdate Ingest = "update"
)

type ingestRule struct {
	name string
	when func(s, n Stored) bool
	out  Ingest
}

// ingestRules is the ordered replay table, applied to each stored record
// against the new one; the strongest outcome wins (see DecideIngest).
var ingestRules = []ingestRule{
	{"same record", func(s, n Stored) bool { return s.Digest == n.Digest }, IngestDuplicate},
	{"same commit, other key", func(s, n Stored) bool { return s.CommitSHA == n.CommitSHA && s.KeyID != n.KeyID }, IngestReplay},
	{"same commit, same key", func(s, n Stored) bool { return s.CommitSHA == n.CommitSHA }, IngestUpdate},
}

// ingestRank orders outcomes: a refusal beats a duplicate beats an update
// beats an accept.
var ingestRank = map[Ingest]int{IngestReplay: 3, IngestDuplicate: 2, IngestUpdate: 1, IngestAccept: 0}

// DecideIngest is the replay store's decision for a new record given the
// records already stored for the same commit or patch.
func DecideIngest(existing []Stored, n Stored) Ingest {
	out := IngestAccept
	for _, s := range existing {
		for _, r := range ingestRules {
			if r.when(s, n) {
				if ingestRank[r.out] > ingestRank[out] {
					out = r.out
				}
				break
			}
		}
	}
	return out
}

// Provenance is a verifier's outcome for one commit.
type Provenance string

// The Provenance values.
const (
	ProvenanceVerified Provenance = "verified"
	// ProvenanceRebased verified through patch_fp.
	ProvenanceRebased Provenance = "verified_rebased"
	// ProvenanceDerived is a squash commit whose inputs verified.
	ProvenanceDerived Provenance = "derived"
	// ProvenanceUnknown: the commit carries no record (missing, or an amend
	// or rebase whose rewrite left no note behind).
	ProvenanceUnknown Provenance = "unknown_provenance"
	// ProvenanceFailed: a record is present and fails verification (a bad
	// signature, an unknown or revoked key, outside the key's validity, a
	// payload that does not match the commit, a record replayed onto another
	// commit, or two keys claiming one commit). Decision log P-059: a
	// verification failure, reported by name, never an unknown and never
	// lowered to a review label by the provenance floor.
	ProvenanceFailed Provenance = "verification_failed"
)

// Candidate is one record a verifier found for a commit (from a note or a
// trailer), checked or not.
type Candidate struct {
	Verified Verified
	// Err is why the record did not verify; nil when it did.
	Err error
}

// CommitOutcome is one commit's decision.
type CommitOutcome struct {
	SHA        string
	Provenance Provenance
	// Digest is the record that decided ("" when none did).
	Digest string
	KeyID  string
	// Reason is a closed reason code.
	Reason string
}

// The CommitOutcome reasons.
const (
	ReasonExact      = "record_verified"
	ReasonPatch      = "record_verified_through_patch"
	ReasonMissing    = "no_record"
	ReasonInvalid    = "record_invalid"
	ReasonUnbound    = "record_does_not_bind"
	ReasonReplay     = "records_from_two_keys"
	ReasonSquash     = "squash_inputs_verified"
	ReasonSquashNone = "squash_without_verified_inputs"
)

// DecideCommit picks one commit's outcome from its candidates: an exact
// binding beats a patch binding; two verified records for the commit from
// different keys are a replay; with no verified record, a record that is
// present but invalid or bound to something else is a verification failure
// (decision log P-059), and only a commit with no record at all is unknown.
func DecideCommit(c CommitFacts, cands []Candidate) CommitOutcome {
	out := CommitOutcome{SHA: c.SHA, Provenance: ProvenanceUnknown, Reason: ReasonMissing}
	var exact, patch []Verified
	invalid, unbound := false, false
	for _, cd := range cands {
		if cd.Err != nil {
			invalid = true
			continue
		}
		switch m, _ := CheckBinding(cd.Verified.Record.Binding, c); m {
		case MatchExact:
			exact = append(exact, cd.Verified)
		case MatchPatch:
			patch = append(patch, cd.Verified)
		default:
			unbound = true
		}
	}
	pick := func(vs []Verified, p Provenance, reason string) bool {
		if len(vs) == 0 {
			return false
		}
		keys := map[string]bool{}
		for _, v := range vs {
			keys[v.KeyID] = true
		}
		if len(keys) > 1 {
			out.Provenance, out.Reason = ProvenanceFailed, ReasonReplay
			return true
		}
		sort.Slice(vs, func(i, j int) bool { return vs[i].Digest < vs[j].Digest })
		out.Provenance, out.Reason, out.Digest, out.KeyID = p, reason, vs[0].Digest, vs[0].KeyID
		return true
	}
	if pick(exact, ProvenanceVerified, ReasonExact) || pick(patch, ProvenanceRebased, ReasonPatch) {
		return out
	}
	switch {
	case invalid:
		out.Provenance, out.Reason = ProvenanceFailed, ReasonInvalid
	case unbound:
		out.Provenance, out.Reason = ProvenanceFailed, ReasonUnbound
	}
	return out
}

// SquashStatement is the derived statement for a squash merge commit: the
// verified records of the pull request's commits it stands on. It is
// computed by the CI step, never signed by a node.
type SquashStatement struct {
	Kind      string   `json:"kind"`
	CommitSHA string   `json:"commit_sha"`
	Inputs    []string `json:"inputs"`
	// Unverified counts the pull request's commits whose provenance is
	// unknown.
	Unverified int `json:"unverified"`
}

// DeriveSquash builds the squash statement from the outcomes of the pull
// request's commits. A squash with no verifiable input is unknown.
func DeriveSquash(mergeSHA string, outcomes []CommitOutcome) (SquashStatement, CommitOutcome) {
	st := SquashStatement{Kind: "squash", CommitSHA: mergeSHA, Inputs: []string{}}
	for _, o := range outcomes {
		if o.Provenance == ProvenanceVerified || o.Provenance == ProvenanceRebased {
			st.Inputs = append(st.Inputs, o.Digest)
		} else {
			st.Unverified++
		}
	}
	st.Inputs = sortedSet(st.Inputs)
	out := CommitOutcome{SHA: mergeSHA, Provenance: ProvenanceUnknown, Reason: ReasonSquashNone}
	if len(st.Inputs) > 0 {
		out.Provenance, out.Reason = ProvenanceDerived, ReasonSquash
	}
	return st, out
}

// RotationPeriod is the key lifetime (plan 7.10: rotation every 90 days).
const RotationPeriod = 90 * 24 * time.Hour

// KeyState is what the rotation schedule decides on.
type KeyState struct {
	// Exists: the node holds a key.
	Exists    bool
	CreatedAt time.Time
	// Enrolment is the enrolment the key was made under ("" for an
	// individual node); CurrentEnrolment is the node's enrolment now.
	Enrolment        string
	CurrentEnrolment string
	// Retired: the key was retired by hand (rotate-key) and not replaced.
	Retired bool
}

// Rotation is a schedule decision.
type Rotation string

// The Rotation values.
const (
	RotationKeep        Rotation = "keep"
	RotationGenerate    Rotation = "generate"
	RotationAge         Rotation = "rotate_age"
	RotationReEnrolment Rotation = "rotate_re_enrolment"
)

type rotationRule struct {
	when func(k KeyState, now time.Time) bool
	out  Rotation
}

// rotationRules is the ordered rotation table.
var rotationRules = []rotationRule{
	{func(k KeyState, _ time.Time) bool { return !k.Exists || k.Retired }, RotationGenerate},
	{func(k KeyState, _ time.Time) bool { return k.Enrolment != k.CurrentEnrolment }, RotationReEnrolment},
	{func(k KeyState, now time.Time) bool { return !now.Before(k.CreatedAt.Add(RotationPeriod)) }, RotationAge},
	{func(KeyState, time.Time) bool { return true }, RotationKeep},
}

// RotationDue is the schedule's decision for the node's key at now.
func RotationDue(k KeyState, now time.Time) Rotation {
	for _, r := range rotationRules {
		if r.when(k, now) {
			return r.out
		}
	}
	return RotationKeep
}

// FloorAction is what a missing or unverified record does in CI.
type FloorAction string

// The FloorAction values: a review label by default, a failure only
// under an org (or policy) floor.
const (
	FloorLabel FloorAction = "label"
	FloorFail  FloorAction = "fail"
)
