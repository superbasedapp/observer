package projectmatch

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// MappingFile is the node's copy of the signed mapping, as the org client
// accepted it: the mapping, the composed bundle version it came with, and
// when the org last confirmed it (an accept, or a 304 on the poll). Past
// AcceptedAt + the mapping's MaxAgeSeconds the project layer is unknown.
type MappingFile struct {
	Mapping       orgcontract.ProjectMapping `json:"mapping"`
	BundleVersion int64                      `json:"bundle_version"`
	AcceptedAt    time.Time                  `json:"accepted_at"`
}

// Expired reports whether the mapping is past its offline lifetime at now.
func (f MappingFile) Expired(now time.Time) bool {
	age := time.Duration(f.Mapping.MaxAgeSeconds) * time.Second
	if age <= 0 || f.AcceptedAt.IsZero() {
		return true
	}
	return now.After(f.AcceptedAt.Add(age))
}

// DecodeMappingFile reads a MappingFile.
func DecodeMappingFile(raw []byte) (MappingFile, error) {
	var f MappingFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return MappingFile{}, fmt.Errorf("projectmatch.DecodeMappingFile: %w", err)
	}
	return f, nil
}

// MatchFile is the daemon's match record for one project root: the org
// projects its identity matched in the mapping, under which epoch and mapping
// digest. A record whose epoch or digest differs from the mapping in force is
// stale and treated as absent.
type MatchFile struct {
	ProjectRootHash string    `json:"project_root_hash"`
	OrgProjectIDs   []string  `json:"org_project_ids"`
	Epoch           int64     `json:"epoch"`
	MappingDigest   string    `json:"mapping_digest"`
	MatchedAt       time.Time `json:"matched_at"`
	// ValidUntil is the mapping's offline lifetime as the matcher saw it
	// (MappingFile.AcceptedAt plus MaxAgeSeconds). Until then a current
	// record answers without the hook reading the mapping at all; after it
	// the hook reads the mapping, whose lifetime a 304 may have extended.
	// A resolve record's ValidUntil is the earlier of that and the
	// answer's expiry.
	ValidUntil time.Time `json:"valid_until"`
	// Source says where the answer came from: SourceMapping (the signed
	// mapping or its index; "" in a record written before lane sec-p2a) or
	// SourceResolve (the signed answer of the resolve call).
	Source string `json:"source,omitempty"`
	// BundleVersion is the composed bundle version a resolve record was
	// answered under. Its envelopes carry that version, so the record is
	// current only while that version is in force.
	BundleVersion int64 `json:"bundle_version,omitempty"`
	// Unknown records that the matcher could not decide (the mapping is
	// truncated, nothing in it matched and the resolve call failed): the
	// project layer is unknown here and the org's project_unknown decision
	// applies (security plan section 3 PR14). OrgProjectIDs is empty.
	Unknown bool `json:"unknown,omitempty"`
	// Reason says why Unknown is set, for `observer guard status`.
	Reason string `json:"reason,omitempty"`
}

// Match record sources.
const (
	// SourceMapping: matched against the signed mapping (or its index).
	SourceMapping = "mapping"
	// SourceResolve: answered by the signed resolve call.
	SourceResolve = "resolve"
)

// CurrentFor reports whether the record belongs to the delivery in force:
// the same epoch and mapping digest, and, for a resolve record, the same
// composed bundle version.
func (f MatchFile) CurrentFor(pb *orgcontract.ProjectBinding, version int64) bool {
	if pb == nil || f.Epoch != pb.Epoch || f.MappingDigest != pb.MappingDigest {
		return false
	}
	return f.Source != SourceResolve || f.BundleVersion == version
}

// ValidUntil is the mapping's offline lifetime end.
func (f MappingFile) ValidUntil() time.Time {
	return f.AcceptedAt.Add(time.Duration(f.Mapping.MaxAgeSeconds) * time.Second)
}

// DecodeMatchFile reads a MatchFile.
func DecodeMatchFile(raw []byte) (MatchFile, error) {
	var f MatchFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return MatchFile{}, fmt.Errorf("projectmatch.DecodeMatchFile: %w", err)
	}
	return f, nil
}

// Signals are a directory's own identity hashes, the same unsalted SHA-256
// values the node ships (agent migration 102).
type Signals struct {
	RemoteHash         string
	UpstreamRemoteHash string
	// RemoteFormHashes are the hashes of every match form of the remote
	// and the upstream remote (orgcontract.ProjectRemoteForms: the exact
	// form, the lowercased path on a case-insensitive host, the canonical
	// Azure DevOps form), deduplicated. They include RemoteHash and
	// UpstreamRemoteHash.
	RemoteFormHashes []string
	RootCommitHash   string
	IsGit            bool
	// Root is the identity root (the main repository for a linked
	// worktree), the key the store's root-commit cache is read under.
	Root string
}

// Hash is the store's sha256Hex: empty in, empty out.
func Hash(s string) string {
	if s == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// SignalsFor computes dir's identity hashes with file reads only
// (git.ResolveIdentity with no root-commit exec and no content scan). A linked
// worktree resolves to its main repository's identity (F0-14), so it matches
// the main project; the checkout root is never the key. cachedRootCommit is a
// root commit the caller already holds for that identity root ("" when none).
func SignalsFor(dir, cachedRootCommit string) (Signals, error) {
	id, err := git.ResolveIdentity(dir, git.IdentityOptions{SkipContentFingerprint: true})
	if err != nil {
		return Signals{}, err
	}
	s := Signals{IsGit: id.IsGit, Root: id.Root}
	if id.IsGit {
		s.RemoteHash = Hash(id.Remote)
		s.UpstreamRemoteHash = Hash(id.UpstreamRemote)
		s.RemoteFormHashes = FormHashes(id.Remote, id.UpstreamRemote)
		s.RootCommitHash = Hash(cachedRootCommit)
	}
	return s, nil
}

// FormHashes returns the hashes of every match form of the given normalized
// remotes (orgcontract.ProjectRemoteForms), exact forms first, deduplicated.
// The exact form's hash is the value nodes already ship (Hash of the
// normalized remote); git.NormalizeRemote itself is never changed.
func FormHashes(normalizedRemotes ...string) []string {
	var out []string
	seen := map[string]bool{}
	for _, r := range normalizedRemotes {
		for _, f := range orgcontract.ProjectRemoteForms(r) {
			h := Hash(f)
			if !seen[h] {
				seen[h] = true
				out = append(out, h)
			}
		}
	}
	return out
}

// remoteLookupHashes is every remote-kind hash a directory is looked up by:
// its form hashes, or, for Signals built by hand with no forms, the exact
// remote and upstream remote hashes.
func (s Signals) remoteLookupHashes() []string {
	if len(s.RemoteFormHashes) > 0 {
		return s.RemoteFormHashes
	}
	return []string{s.RemoteHash, s.UpstreamRemoteHash}
}

// RemoteLookupHashes is remoteLookupHashes for callers outside the package
// (the daemon's index lookup and the resolve request).
func (s Signals) RemoteLookupHashes() []string { return s.remoteLookupHashes() }

// HasIdentity reports whether s carries any hash a mapping or the resolve
// call could match.
func (s Signals) HasIdentity() bool {
	for _, h := range s.remoteLookupHashes() {
		if h != "" {
			return true
		}
	}
	return s.RootCommitHash != ""
}

// Index is the lookup structure over one mapping: remote-kind hashes (remote
// and upstream remote) and root commit hashes, each to the projects carrying
// them.
type Index struct {
	remote map[string][]string
	root   map[string][]string
}

// BuildIndex inverts a mapping.
func BuildIndex(m orgcontract.ProjectMapping) Index {
	ix := Index{remote: map[string][]string{}, root: map[string][]string{}}
	add := func(into map[string][]string, h, id string) {
		if h == "" {
			return
		}
		for _, have := range into[h] {
			if have == id {
				return
			}
		}
		into[h] = append(into[h], id)
	}
	for _, e := range m.Projects {
		for _, r := range e.Repos {
			add(ix.remote, r.RemoteHash, e.OrgProjectID)
			add(ix.remote, r.UpstreamRemoteHash, e.OrgProjectID)
			add(ix.root, r.RootCommitHash, e.OrgProjectID)
		}
	}
	return ix
}

// Match returns, sorted, every project the signals map to. A directory's
// remote and upstream remote are looked up among the mapping's remote-kind
// hashes and its root commit among the root commit hashes. Over-matching
// (a fork matching both its own project and the upstream's) only ever adds
// sections, and several matches take the strictest of all.
func (ix Index) Match(s Signals) []string {
	set := map[string]bool{}
	for _, h := range s.remoteLookupHashes() {
		if h == "" {
			continue
		}
		for _, id := range ix.remote[h] {
			set[id] = true
		}
	}
	if s.RootCommitHash != "" {
		for _, id := range ix.root[s.RootCommitHash] {
			set[id] = true
		}
	}
	out := make([]string, 0, len(set))
	for id := range set {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// Layer states for one directory (Decide).
const (
	// StateNone: no project audience on this node (no v3 delivery held).
	StateNone = "none"
	// StateMatched: the directory matched at least one project.
	StateMatched = "matched"
	// StateUnmatched: the mapping is current and nothing matched; the org,
	// team and member layers apply.
	StateUnmatched = "unmatched"
	// StateUnknown: the node holds a v3 delivery but its mapping is missing,
	// unreadable, of another delivery, or past its offline lifetime; the
	// project layer is unknown (security plan section 7.11 "Offline launch").
	StateUnknown = "unknown"
)

// DecideInput is everything Decide reads for one directory.
type DecideInput struct {
	// Composed is the project binding of the composed bundle in force (nil
	// when the node holds no v3 delivery).
	Composed *orgcontract.ProjectBinding
	// ComposedVersion is that bundle's version.
	ComposedVersion int64
	// Mapping is the cached mapping file (nil when absent or unreadable).
	Mapping *MappingFile
	// LoadMapping, when Mapping is nil, reads it on demand: a current daemon
	// record inside its lifetime never calls it.
	LoadMapping func() *MappingFile
	// Record is the daemon's match record for the directory (nil when none).
	Record *MatchFile
	// Signals computes the directory's own hashes; called only when no
	// current record exists (the hook then matches from the mapping).
	Signals func() (Signals, error)
	Now     time.Time
}

// Decision is Decide's answer.
type Decision struct {
	State string
	IDs   []string
	// FromRecord reports that a current daemon record answered (the hook
	// read no mapping index).
	FromRecord bool
	// Reason says why State is unknown, when the matcher knows.
	Reason string
}

// Decide resolves which projects' envelopes apply to one directory. Walked
// top-down: no v3 delivery is none; a daemon record of this delivery still
// inside the mapping's lifetime answers (the hook reads no mapping); a
// missing, foreign or expired mapping is unknown; a record of this delivery
// answers once the mapping proves its lifetime was extended; else the
// directory's own signals are matched against the mapping.
func Decide(in DecideInput) Decision {
	if in.Composed == nil {
		return Decision{State: StateNone}
	}
	r := in.Record
	current := r != nil && r.CurrentFor(in.Composed, in.ComposedVersion)
	if current && !r.ValidUntil.IsZero() && in.Now.Before(r.ValidUntil) {
		if r.Unknown {
			return Decision{State: StateUnknown, FromRecord: true, Reason: r.Reason}
		}
		return decisionFor(append([]string(nil), r.OrgProjectIDs...), true)
	}
	m := in.Mapping
	if in.LoadMapping != nil && m == nil {
		m = in.LoadMapping()
	}
	ofDelivery := m != nil && m.BundleVersion == in.ComposedVersion && m.Mapping.Epoch == in.Composed.Epoch &&
		orgcontract.ProjectMappingDigest(m.Mapping) == in.Composed.MappingDigest
	if !ofDelivery || m.Expired(in.Now) {
		// The project layer is unknown only where a project bundle could
		// apply (lane sec-p2a audit finding 2): the last signed mapping of
		// this delivery listing no project for the member, complete (not
		// truncated), means none reaches them, and a directory with no
		// identity (not a git repository) can match no project. Expiry alone
		// never makes every directory unknown for such a member.
		if ofDelivery && len(m.Mapping.Projects) == 0 && !m.Mapping.Truncated {
			return Decision{State: StateUnmatched}
		}
		if noIdentity(in) {
			return Decision{State: StateUnmatched}
		}
		return Decision{State: StateUnknown}
	}
	// A resolve record past its own expiry is not reused: the mapping
	// below answers, and a truncated mapping reads unknown until the
	// matcher asks again. A mapping record (its lifetime is the mapping's,
	// which the check above just proved extended) still answers.
	if current && r.Source != SourceResolve {
		if r.Unknown {
			return Decision{State: StateUnknown, FromRecord: true, Reason: r.Reason}
		}
		return decisionFor(append([]string(nil), r.OrgProjectIDs...), true)
	}
	if in.Signals == nil {
		return Decision{State: StateUnknown}
	}
	s, err := in.Signals()
	if err != nil {
		return Decision{State: StateUnknown}
	}
	d := decisionFor(BuildIndex(m.Mapping).Match(s), false)
	if d.State == StateUnmatched && m.Mapping.Truncated && s.identified() {
		// Above the cap the mapping does not list every project that
		// reaches this member, so "nothing matched" is not an answer:
		// only the resolve call (launch and session start, never here)
		// can say. Unknown never relaxes (PR14).
		return Decision{State: StateUnknown, Reason: ReasonTruncated}
	}
	return d
}

// noIdentity reports whether the directory has no identity hash because it is
// not a git repository, so it matches no project (plan 7.11 "remote-less: not
// matched"). A directory whose identity cannot be read is not known to have
// none.
func noIdentity(in DecideInput) bool {
	if in.Signals == nil {
		return false
	}
	s, err := in.Signals()
	return err == nil && !s.identified()
}

// identified reports whether s is a git repository or carries an identity
// hash (Signals built by hand name hashes without IsGit).
func (s Signals) identified() bool {
	return s.IsGit || s.HasIdentity()
}

// Unknown reasons.
const (
	// ReasonTruncated: the mapping is above the cap and nothing in it
	// matched; no resolve answer is held.
	ReasonTruncated = "mapping_truncated"
	// ReasonResolveFailed: the mapping is above the cap, nothing in it
	// matched, and the resolve call failed or was refused.
	ReasonResolveFailed = "resolve_failed"
)

func decisionFor(ids []string, fromRecord bool) Decision {
	sort.Strings(ids)
	if len(ids) == 0 {
		return Decision{State: StateUnmatched, FromRecord: fromRecord}
	}
	return Decision{State: StateMatched, IDs: ids, FromRecord: fromRecord}
}
