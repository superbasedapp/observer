package secverify

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/secchange"
)

// PolicySource says where the policy came from. It is printed in the
// summary and in the SARIF run properties so a reader can tell a binding
// setup from an advisory one.
type PolicySource string

// The closed policy source vocabulary.
const (
	// SourceProtected: a file the caller named outside the repository under
	// test, the required workflow's own protected checkout (security plan
	// 7.9: "the policy is read from the required workflow's own protected
	// repository").
	SourceProtected PolicySource = "protected_file"
	// SourceBaseCommit: read from the PR's BASE commit. A fallback for a
	// repository-local, advisory setup only, and labelled so.
	SourceBaseCommit PolicySource = "base_commit_advisory"
	// SourceBuiltin: no policy named; the built-in defaults.
	SourceBuiltin PolicySource = "builtin_defaults"
	// SourceOrg: the org's signed CI policy (org.security.ci, lane
	// SEC-F2B), checked against the org key the protected workflow pins.
	SourceOrg PolicySource = orgcontract.CIPolicySourceOrg
)

// Mode is the policy mode.
type Mode string

// The closed mode vocabulary.
const (
	// ModeEnforce: a finding whose action is deny fails the check.
	ModeEnforce Mode = "enforce"
	// ModeObserve: findings are reported and never fail the check; an
	// unknown verdict still does (fail closed on errors).
	ModeObserve Mode = "observe"
)

// PolicyVersion is the only policy file version this build reads.
const PolicyVersion = 1

// MaxPolicyBytes caps the policy file.
const MaxPolicyBytes = 64 << 10

// Policy is the verify policy.
type Policy struct {
	Version int  `toml:"version"`
	Mode    Mode `toml:"mode"`
	// Detectors overrides a detector's default action: deny, flag or off.
	Detectors map[string]Action `toml:"detectors"`
	// Require lists the detectors that must finish for a pass; one that is
	// not in this build, is off, or did not finish makes the verdict
	// unknown.
	Require []string `toml:"require"`
	// FixturePaths are globs ("**" crosses segments) whose secret findings
	// are lowered from deny to flag (test data and fixtures, security plan
	// 5.3).
	FixturePaths []string `toml:"fixture_paths"`
	// MaxFileAddedBytes overrides the per-file added-text cap.
	MaxFileAddedBytes int `toml:"max_file_added_bytes"`
	// MaxFiles overrides the changed-file cap.
	MaxFiles int `toml:"max_files"`
	// Provenance is the floor for a commit with no verified AI change
	// record (security plan 7.10 "Missing record"): "label" (the default)
	// reports unknown_provenance as a review label, "fail" fails the check
	// in enforce mode. It applies only when verify was given a keys file.
	Provenance secchange.FloorAction `toml:"provenance"`

	// Source is set by the loader, never by the file.
	Source PolicySource `toml:"-"`
	// OrgVersion is the version of the org's signed CI policy this policy
	// came from (Source org; 0 otherwise), set by ParseOrgPolicy and written
	// into the SARIF so the result upload reports the policy the run used.
	OrgVersion int64 `toml:"-"`
}

// DefaultPolicy is the built-in policy: enforce, every built detector at
// its default action and required.
func DefaultPolicy() Policy {
	return Policy{
		Version:      PolicyVersion,
		Mode:         ModeEnforce,
		Detectors:    map[string]Action{},
		Require:      builtDetectorIDs(),
		FixturePaths: []string{"**/testdata/**", "**/fixtures/**", "**/__fixtures__/**", "**/test-fixtures/**"},
		Source:       SourceBuiltin,
	}
}

// ErrPolicy wraps every policy refusal.
var ErrPolicy = errors.New("secverify: policy refused")

// ParsePolicy reads a policy file. Unknown keys, an unknown version, mode,
// action or detector id, and a required detector that is switched off are
// refused: a typo must not quietly weaken the check. Absent fields take the
// built-in defaults.
func ParsePolicy(b []byte, src PolicySource) (Policy, error) {
	if len(b) > MaxPolicyBytes {
		return Policy{}, fmt.Errorf("%w: over %d bytes", ErrPolicy, MaxPolicyBytes)
	}
	var raw Policy
	md, err := toml.NewDecoder(bytes.NewReader(b)).Decode(&raw)
	if err != nil {
		return Policy{}, fmt.Errorf("%w: %w", ErrPolicy, err)
	}
	if und := md.Undecoded(); len(und) > 0 {
		keys := make([]string, 0, len(und))
		for _, k := range und {
			keys = append(keys, k.String())
		}
		sort.Strings(keys)
		return Policy{}, fmt.Errorf("%w: unknown keys %s", ErrPolicy, clipSafe(strings.Join(keys, ", "), 200))
	}
	p := DefaultPolicy()
	if raw.Version != PolicyVersion {
		return Policy{}, fmt.Errorf("%w: version %d, this build reads version %d", ErrPolicy, raw.Version, PolicyVersion)
	}
	if raw.Mode != "" {
		p.Mode = raw.Mode
	}
	if md.IsDefined("require") {
		p.Require = raw.Require
	}
	if md.IsDefined("fixture_paths") {
		p.FixturePaths = raw.FixturePaths
	}
	for id, a := range raw.Detectors {
		p.Detectors[id] = a
	}
	if raw.MaxFileAddedBytes != 0 {
		p.MaxFileAddedBytes = raw.MaxFileAddedBytes
	}
	if raw.MaxFiles != 0 {
		p.MaxFiles = raw.MaxFiles
	}
	if raw.Provenance != "" {
		p.Provenance = raw.Provenance
	}
	p.Source = src
	if err := p.Validate(); err != nil {
		return Policy{}, err
	}
	return p, nil
}

// Validate checks a policy against the closed vocabularies.
func (p Policy) Validate() error {
	if p.Mode != ModeEnforce && p.Mode != ModeObserve {
		return fmt.Errorf("%w: mode %q", ErrPolicy, clipSafe(string(p.Mode), 16))
	}
	if !validFloor(p.Provenance) {
		return fmt.Errorf("%w: provenance %q (want label or fail)", ErrPolicy, clipSafe(string(p.Provenance), 16))
	}
	known := map[string]bool{}
	for _, d := range Detectors() {
		known[d.ID] = true
	}
	ids := make([]string, 0, len(p.Detectors))
	for id := range p.Detectors {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if !known[id] {
			return fmt.Errorf("%w: unknown detector %q", ErrPolicy, clipSafe(id, 32))
		}
		switch p.Detectors[id] {
		case ActionDeny, ActionFlag, ActionOff:
		default:
			return fmt.Errorf("%w: detector %s: action %q (want deny, flag or off)", ErrPolicy, id, clipSafe(string(p.Detectors[id]), 16))
		}
	}
	for _, id := range p.Require {
		if !known[id] {
			return fmt.Errorf("%w: require names unknown detector %q", ErrPolicy, clipSafe(id, 32))
		}
		if p.Detectors[id] == ActionOff {
			return fmt.Errorf("%w: detector %s is both required and off", ErrPolicy, id)
		}
	}
	for _, g := range p.FixturePaths {
		if g == "" || len(g) > MaxPathBytes || strings.HasPrefix(g, "/") || strings.ContainsRune(g, '\\') {
			return fmt.Errorf("%w: fixture path %q", ErrPolicy, clipSafe(g, 64))
		}
	}
	if p.MaxFileAddedBytes < 0 || p.MaxFiles < 0 {
		return fmt.Errorf("%w: negative cap", ErrPolicy)
	}
	return nil
}

// limits applies the policy's caps over the defaults.
func (p Policy) limits() Limits {
	lim := DefaultLimits()
	if p.MaxFileAddedBytes > 0 {
		lim.MaxFileAddedBytes = p.MaxFileAddedBytes
	}
	if p.MaxFiles > 0 {
		lim.MaxFiles = p.MaxFiles
	}
	return lim
}

// Limits returns the parser caps this policy sets.
func (p Policy) Limits() Limits { return p.limits() }

// isFixture reports whether rel matches a fixture glob.
func (p Policy) isFixture(rel string) bool {
	for _, g := range p.FixturePaths {
		if matchGlob(g, rel) {
			return true
		}
	}
	return false
}
