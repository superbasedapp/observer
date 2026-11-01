package secchange

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"time"
)

// Version is the record's shape version.
const Version = 1

// Domain is the domain string every v1 payload carries (security plan
// 7.10 "Domain separation and canonical bytes").
const Domain = "sbo-change-record-v1"

// Label is the fixed label every record carries: node-reported
// attribution, never proof of authorship.
const Label = "node_reported_attribution"

// PayloadType is the DSSE payload type of a v1 record.
const PayloadType = "application/vnd.superbased.change-record.v1+json"

// The attestation levels a record's key can carry (plan 7.10 "Key
// enrolment"). An individual node self-certifies; an org-certified key is
// one an org certificate in the verifier's TrustSet vouches for (lane
// SEC-F2B issues those).
const (
	AttestationSelf = "self_attested"
	AttestationOrg  = "org_certified"
)

// The key storage classes: the OS keychain, or the 0600 file fallback of
// internal/keystore, reported as file_key.
const (
	StorageKeychain = "keychain"
	StorageFileKey  = "file_key"
)

// The human capture states, LOC's own vocabulary (docs/loc-tracking.md):
// none means unmeasured, never zero.
const (
	HumanCaptureNone   = "none"
	HumanCaptureVSCode = "vscode"
)

// Limits on a record, so a hostile or broken builder cannot make one
// unbounded.
const (
	MaxListItems   = 256
	MaxFiles       = 1024
	MaxItemBytes   = 160
	MaxPayloadSize = 256 << 10
)

// Record is the v1 change record payload. Every list is sorted and
// de-duplicated by Normalize; every count is non-negative.
type Record struct {
	Domain      string   `json:"domain"`
	Version     int      `json:"version"`
	Label       string   `json:"label"`
	Binding     Binding  `json:"binding"`
	Key         KeyRef   `json:"key"`
	CommittedAt string   `json:"committed_at"`
	RecordedAt  string   `json:"recorded_at"`
	Lines       Lines    `json:"lines"`
	Files       []File   `json:"files"`
	Sessions    []string `json:"sessions"`
	Agents      []string `json:"agents"`
	Models      []string `json:"models"`
	// ToolVersions are "agent@version" pairs.
	ToolVersions []string `json:"tool_versions"`
	// PromptIDs are opaque prompt identifiers (action ids), never text.
	PromptIDs []string `json:"prompt_ids"`
	Guard     Guard    `json:"guard"`
	// TaintAtWrite counts the commit's AI edits written while the session
	// was tainted.
	TaintAtWrite int64    `json:"taint_at_write"`
	Scanners     []string `json:"scanners"`
	PackVersions []string `json:"pack_versions"`
	Findings     Findings `json:"findings"`
	Exceptions   []string `json:"exceptions"`
	// Evidence references a sandbox run's execution evidence envelope
	// (roadmap F0-13) when one is involved; nil keeps the record complete
	// and valid without the sandbox module.
	Evidence *Evidence `json:"evidence,omitempty"`
}

// Binding ties a record to one commit and one enrolment.
type Binding struct {
	CommitSHA string `json:"commit_sha"`
	TreeSHA   string `json:"tree_sha"`
	// PatchFP is the commit's `git patch-id --stable` fingerprint, "" when
	// PatchFPState is not "ok" (a binary-only, empty or too-large patch).
	PatchFP      string `json:"patch_fp"`
	PatchFPState string `json:"patch_fp_state"`
	OrgID        string `json:"org_id"`
	OrgProjectID string `json:"org_project_id"`
	// MachineIdentity is the node's machine identity ("" on an individual
	// node that has none).
	MachineIdentity string `json:"machine_identity"`
	// ProjectHash is the project identity hash (the root hash the security
	// tables key on).
	ProjectHash   string `json:"project_hash"`
	PolicyVersion string `json:"policy_version"`
}

// KeyRef names the signing key and how far it can be trusted.
type KeyRef struct {
	ID          string `json:"id"`
	Attestation string `json:"attestation"`
	Storage     string `json:"storage"`
}

// Lines is the commit's line split.
type Lines struct {
	AI           int64  `json:"ai"`
	Human        int64  `json:"human"`
	Unknown      int64  `json:"unknown"`
	HumanCapture string `json:"human_capture"`
}

// File is one changed file's line split, by path hash (internal/loc.
// PathHash), never by path.
type File struct {
	PathHash string `json:"path_hash"`
	AI       int64  `json:"ai"`
	Human    int64  `json:"human"`
	Unknown  int64  `json:"unknown"`
}

// Guard counts the guard verdicts on the record's sessions.
type Guard struct {
	Events       int64 `json:"events"`
	Denies       int64 `json:"denies"`
	Asks         int64 `json:"asks"`
	ApprovedAsks int64 `json:"approved_asks"`
}

// Findings summarizes the security findings in the change.
type Findings struct {
	Open     int64 `json:"open"`
	Blocking int64 `json:"blocking"`
}

// Evidence is the reference to a sandbox run's evidence envelope.
type Evidence struct {
	RunID          string `json:"run_id"`
	Digest         string `json:"digest"`
	IsolationClass string `json:"isolation_class"`
	CaptureLevel   string `json:"capture_level"`
	KeyCustody     string `json:"key_custody"`
	Verification   string `json:"verification"`
}

var (
	shaRE   = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)
	hexRE   = regexp.MustCompile(`^[0-9a-f]{8,128}$`)
	keyIDRE = regexp.MustCompile(`^[0-9a-f]{32}$`)
	itemRE  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$`)
)

// fpStates is the closed set of patch fingerprint states, the same strings
// as internal/commitlog.FingerprintState.
var fpStates = map[string]bool{"ok": true, "too_large": true, "binary_only": true, "empty": true, "": true}

var attestations = map[string]bool{AttestationSelf: true, AttestationOrg: true}

var storages = map[string]bool{StorageKeychain: true, StorageFileKey: true}

var humanCaptures = map[string]bool{HumanCaptureNone: true, HumanCaptureVSCode: true}

// ErrInvalid is wrapped by every Validate failure.
var ErrInvalid = errors.New("secchange: invalid record")

// Normalize fills the fixed fields and sorts and de-duplicates every list,
// so two builders that saw the same facts produce the same bytes.
func (r Record) Normalize() Record {
	r.Domain, r.Version, r.Label = Domain, Version, Label
	for _, l := range []*[]string{&r.Sessions, &r.Agents, &r.Models, &r.ToolVersions, &r.PromptIDs, &r.Scanners, &r.PackVersions, &r.Exceptions} {
		*l = sortedSet(*l)
	}
	sort.Slice(r.Files, func(i, j int) bool { return r.Files[i].PathHash < r.Files[j].PathHash })
	if r.Files == nil {
		r.Files = []File{}
	}
	if r.Lines.HumanCapture == "" {
		r.Lines.HumanCapture = HumanCaptureNone
	}
	return r
}

func sortedSet(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// Validate checks every field against its shape or closed vocabulary.
func (r Record) Validate() error {
	for _, c := range r.fieldChecks() {
		if !c.ok {
			return fmt.Errorf("%w: %s", ErrInvalid, c.what)
		}
	}
	for _, check := range []func() string{r.filesProblem, r.listsProblem, r.evidenceProblem} {
		if what := check(); what != "" {
			return fmt.Errorf("%w: %s", ErrInvalid, what)
		}
	}
	return nil
}

type fieldCheck struct {
	what string
	ok   bool
}

// fieldChecks is the table of the record's scalar fields.
func (r Record) fieldChecks() []fieldCheck {
	b := r.Binding
	return []fieldCheck{
		{"domain", r.Domain == Domain},
		{"version", r.Version == Version},
		{"label", r.Label == Label},
		{"commit sha", shaRE.MatchString(b.CommitSHA)},
		{"tree sha", shaRE.MatchString(b.TreeSHA)},
		{"patch fingerprint state", fpStates[b.PatchFPState]},
		{"patch fingerprint", (b.PatchFPState == "ok") == (b.PatchFP != "") && (b.PatchFP == "" || shaRE.MatchString(b.PatchFP))},
		{"project hash", b.ProjectHash == "" || hexRE.MatchString(b.ProjectHash)},
		{"org id", optionalItem(b.OrgID)},
		{"org project id", optionalItem(b.OrgProjectID)},
		{"machine identity", optionalItem(b.MachineIdentity)},
		{"policy version", optionalItem(b.PolicyVersion)},
		{"key id", keyIDRE.MatchString(r.Key.ID)},
		{"key attestation", attestations[r.Key.Attestation]},
		{"key storage", storages[r.Key.Storage]},
		{"committed at", validTime(r.CommittedAt)},
		{"recorded at", validTime(r.RecordedAt)},
		{"human capture", humanCaptures[r.Lines.HumanCapture]},
		{"line counts", nonNegative(r.Lines.AI, r.Lines.Human, r.Lines.Unknown)},
		{"guard counts", nonNegative(r.Guard.Events, r.Guard.Denies, r.Guard.Asks, r.Guard.ApprovedAsks)},
		{"finding counts", nonNegative(r.Findings.Open, r.Findings.Blocking, r.TaintAtWrite)},
		{"file count", len(r.Files) <= MaxFiles},
	}
}

func optionalItem(s string) bool { return s == "" || itemShape(s) }

func nonNegative(ns ...int64) bool {
	for _, n := range ns {
		if n < 0 {
			return false
		}
	}
	return true
}

func (r Record) filesProblem() string {
	for i, f := range r.Files {
		if !hexRE.MatchString(f.PathHash) || !nonNegative(f.AI, f.Human, f.Unknown) {
			return "file " + fmt.Sprint(i)
		}
		if i > 0 && r.Files[i-1].PathHash >= f.PathHash {
			return "files not sorted and unique"
		}
	}
	return ""
}

func (r Record) listsProblem() string {
	lists := []struct {
		what string
		l    []string
	}{
		{"sessions", r.Sessions},
		{"agents", r.Agents},
		{"models", r.Models},
		{"tool versions", r.ToolVersions},
		{"prompt ids", r.PromptIDs},
		{"scanners", r.Scanners},
		{"pack versions", r.PackVersions},
		{"exceptions", r.Exceptions},
	}
	for _, l := range lists {
		if len(l.l) > MaxListItems {
			return l.what + " over the cap"
		}
		for i, s := range l.l {
			if !itemShape(s) || (i > 0 && l.l[i-1] >= s) {
				return l.what
			}
		}
	}
	return ""
}

func (r Record) evidenceProblem() string {
	e := r.Evidence
	if e == nil {
		return ""
	}
	if !itemShape(e.RunID) || !hexRE.MatchString(e.Digest) {
		return "evidence"
	}
	for _, v := range []string{e.IsolationClass, e.CaptureLevel, e.KeyCustody, e.Verification} {
		if !optionalItem(v) {
			return "evidence"
		}
	}
	return ""
}

func itemShape(s string) bool { return len(s) <= MaxItemBytes && itemRE.MatchString(s) }

func validTime(s string) bool {
	t, err := time.Parse(time.RFC3339, s)
	return err == nil && t.UTC().Format(time.RFC3339) == s
}

// FormatTime is the one time spelling a record uses: RFC 3339, UTC,
// second precision.
func FormatTime(t time.Time) string { return t.UTC().Truncate(time.Second).Format(time.RFC3339) }

// Canonical returns the canonical JSON of v: object keys sorted, no
// insignificant whitespace, no HTML escaping, numbers as written.
func Canonical(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("secchange.Canonical: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var generic any
	if err := dec.Decode(&generic); err != nil {
		return nil, fmt.Errorf("secchange.Canonical: %w", err)
	}
	var buf bytes.Buffer
	if err := writeCanonical(&buf, generic); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeCanonical(buf *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeString(buf, k); err != nil {
				return err
			}
			buf.WriteByte(':')
			if err := writeCanonical(buf, t[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	case []any:
		buf.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(buf, e); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case string:
		return writeString(buf, t)
	case json.Number:
		buf.WriteString(t.String())
	case bool:
		if t {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case nil:
		buf.WriteString("null")
	default:
		return fmt.Errorf("secchange.Canonical: unexpected %T", v)
	}
	return nil
}

func writeString(buf *bytes.Buffer, s string) error {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		return err
	}
	buf.Write(bytes.TrimSuffix(b.Bytes(), []byte("\n")))
	return nil
}

// Payload returns the record's canonical bytes after Normalize and
// Validate.
func (r Record) Payload() ([]byte, error) {
	n := r.Normalize()
	if err := n.Validate(); err != nil {
		return nil, err
	}
	b, err := Canonical(n)
	if err != nil {
		return nil, err
	}
	if len(b) > MaxPayloadSize {
		return nil, fmt.Errorf("%w: payload over %d bytes", ErrInvalid, MaxPayloadSize)
	}
	return b, nil
}

// ParsePayload decodes a v1 payload strictly: unknown fields refused, the
// record valid, and the bytes equal to their own canonical form (one
// encoding per record).
func ParsePayload(b []byte) (Record, error) {
	var r Record
	if len(b) > MaxPayloadSize {
		return r, fmt.Errorf("%w: payload over %d bytes", ErrInvalid, MaxPayloadSize)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return Record{}, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	if dec.More() {
		return Record{}, fmt.Errorf("%w: trailing data", ErrInvalid)
	}
	if err := r.Validate(); err != nil {
		return Record{}, err
	}
	canon, err := Canonical(r)
	if err != nil {
		return Record{}, err
	}
	if !bytes.Equal(canon, b) {
		return Record{}, fmt.Errorf("%w: payload is not in canonical form", ErrInvalid)
	}
	return r, nil
}
