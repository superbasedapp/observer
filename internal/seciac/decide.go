package seciac

import (
	"slices"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/secengine"
)

// Status is a decision's outcome (the secengine vocabulary).
type Status = secengine.Status

// The Status values, re-used from secengine so the cards and the posture
// read one vocabulary.
const (
	StatusVerified           = secengine.StatusVerified
	StatusUnverifiedLabelled = secengine.StatusUnverifiedLabelled
	StatusRefused            = secengine.StatusRefused
)

// ReasonUnverified is the coverage reason of a refused or labelled engine.
const ReasonUnverified = secengine.ReasonUnverified

// The decision's detail codes, one per row.
const (
	DetailRevoked          = secengine.DetailRevoked
	DetailPinOwed          = secengine.DetailPinOwed
	DetailTooOld           = secengine.DetailTooOld
	DetailManifest         = secengine.DetailManifest
	DetailCompiled         = secengine.DetailCompiled
	DetailNoMatch          = secengine.DetailNoMatch
	DetailTreeChanged      = secengine.DetailTreeChanged
	DetailTreeUnreadable   = secengine.DetailTreeUnreadable
	DetailRecordUnreadable = secengine.DetailRecordUnreadable
	// DetailInstalled: the binary is the one the guided install extracted
	// from a verified archive whose pin is still in force.
	DetailInstalled = "guided_install_pin"
	// DetailChangedSinceFirstUse: an unpinned binary whose digest is not
	// the one recorded the first time it ran on this node.
	DetailChangedSinceFirstUse = "digest_changed_since_first_use"
	// DetailUnpinnedNotAllowed: an unpinned binary on an individual node
	// whose owner has not set the engine's allow_unpinned key (orchestrator
	// ruling P-143, audit finding F4): refused by default.
	DetailUnpinnedNotAllowed = "unpinned_not_allowed"
)

// InstallRecord is the guided install's record of what it extracted: the
// binary digest bound to the verified archive digest it came from. The
// caller verifies the record's MAC and sets Verified; an unverified record
// vouches for nothing.
type InstallRecord struct {
	ArchiveSHA256 string
	BinarySHA256  string
	Version       string
	Verified      bool
}

// Input is one decision's facts.
type Input struct {
	Engine       EngineID
	GOOS, GOARCH string
	// Digest is the binary's sha256 as the runner computed it.
	Digest string
	// Version is what the binary reported; "" when not asked yet (it is
	// asked only after the binary is cleared).
	Version string
	// Managed: a managed node refuses what an individual node labels.
	Managed bool
	// AllowUnpinned is the individual node owner's explicit local key
	// ([security.scan.<engine>].allow_unpinned): only with it does a binary
	// no pin vouches for run, labelled unverified. A managed node refuses
	// such a binary whatever the key says (ruling P-143).
	AllowUnpinned bool
	// Manifest is the verified engine manifest, nil when none.
	Manifest *ManifestPins
	// Compiled overrides the compiled pin table (tests); nil reads it.
	Compiled []Pin
	// Installed is the guided install's record, nil when none.
	Installed *InstallRecord
	// FirstUse is the digest recorded the first time an unpinned binary
	// ran on this individual node ("" when none).
	FirstUse string
	// Revoked are digests remembered as revoked whatever the manifest says.
	Revoked []string
	// Tree is the queries tree's state (secengine.TreeNone for an engine
	// without one).
	Tree secengine.TreeState
}

// Decision is Decide's answer.
type Decision struct {
	Status Status
	Reason string
	Detail string
	// Untested: a verified binary whose version is above the minimum but
	// not the tested one; it runs, every result labelled untested.
	Untested bool
	// DigestOnly: the pin rests on a digest alone (no upstream signature).
	DigestOnly bool
	// Unpinned: no pin vouches for the binary (it ran, if at all, only
	// under the allow_unpinned key).
	Unpinned bool
	Pin      Pin
}

// Run reports whether the engine may start.
func (d Decision) Run() bool { return d.Status != StatusRefused }

type facts struct {
	in        Input
	engine    Engine
	digest    string
	revoked   bool
	platform  []Pin // manifest rows for the platform
	compiled  Pin
	compOK    bool
	vouch     Pin
	vouchHow  string
	vouchedOK bool
}

func lower(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

func derive(in Input) facts {
	f := facts{in: in, digest: lower(in.Digest)}
	f.engine, _ = Lookup(in.Engine)
	pins := in.Compiled
	if pins == nil {
		pins = CompiledPins(in.Engine)
	}
	f.compiled, f.compOK = pinFor(pins, in.GOOS, in.GOARCH)
	revoked := append([]string(nil), in.Revoked...)
	if in.Manifest != nil {
		revoked = append(revoked, in.Manifest.Revoked...)
		for _, p := range in.Manifest.Pins {
			if p.OS == in.GOOS && p.Arch == in.GOARCH {
				f.platform = append(f.platform, p)
			}
		}
	}
	isRevoked := func(d string) bool {
		return d != "" && slices.ContainsFunc(revoked, func(r string) bool { return lower(r) == lower(d) })
	}
	f.revoked = isRevoked(f.digest)
	if r := in.Installed; r != nil && r.Verified && isRevoked(r.ArchiveSHA256) && lower(r.BinarySHA256) == f.digest {
		f.revoked = true
	}
	// What vouches for the digest: a manifest pin superseding the compiled
	// table for its platform; the compiled pin's binary digest; or the
	// guided install's record bound to an archive still pinned.
	for _, p := range f.platform {
		if r := in.Installed; r != nil && r.Verified && lower(r.ArchiveSHA256) == p.AssetSHA256 && lower(r.BinarySHA256) == f.digest {
			f.vouch, f.vouchHow, f.vouchedOK = p, DetailInstalled, true
			return f
		}
	}
	if len(f.platform) == 0 && f.compOK && f.compiled.Status == PinPinned {
		switch {
		case f.compiled.BinarySHA256 != "" && lower(f.compiled.BinarySHA256) == f.digest:
			f.vouch, f.vouchHow, f.vouchedOK = f.compiled, DetailCompiled, true
		case in.Installed != nil && in.Installed.Verified && lower(in.Installed.ArchiveSHA256) == lower(f.compiled.AssetSHA256) && lower(in.Installed.BinarySHA256) == f.digest:
			f.vouch, f.vouchHow, f.vouchedOK = f.compiled, DetailInstalled, true
		}
	}
	return f
}

// pinOwed: no pin anywhere for the platform.
func (f facts) pinOwed() bool {
	return len(f.platform) == 0 && (!f.compOK || f.compiled.Status != PinPinned)
}

// unverified is the tenancy rule: refused on a managed node, labelled on
// an individual one.
func unverified(f facts, detail string) Decision {
	d := Decision{Status: StatusUnverifiedLabelled, Reason: ReasonUnverified, Detail: detail, Pin: f.compiled}
	if f.in.Managed {
		d.Status = StatusRefused
	}
	return d
}

// unpinned is the rule for a binary no pin vouches for (ruling P-143,
// audit finding F4): refused on a managed node; refused on an individual
// node unless its owner set allow_unpinned; then labelled unverified.
func unpinned(f facts, detail string) Decision {
	d := unverified(f, detail)
	d.Unpinned = true
	if !f.in.Managed && !f.in.AllowUnpinned {
		d.Status, d.Detail = StatusRefused, DetailUnpinnedNotAllowed
	}
	return d
}

// rules is the decision table, walked top-down (CLAUDE.md module rule 5).
var rules = []struct {
	name   string
	when   func(f facts) bool
	decide func(f facts) Decision
}{
	{"a revoked digest never runs", func(f facts) bool { return f.revoked }, func(facts) Decision {
		return Decision{Status: StatusRefused, Reason: ReasonUnverified, Detail: DetailRevoked}
	}},
	{"a version below the minimum is refused", func(f facts) bool {
		return f.in.Version != "" && secengine.CompareVersions(f.in.Version, f.engine.MinVersion) < 0
	}, func(facts) Decision {
		return Decision{Status: StatusRefused, Reason: ReasonUnverified, Detail: DetailTooOld}
	}},
	{"a pinned binary whose queries tree changed is unverified", func(f facts) bool {
		return f.vouchedOK && f.in.Tree == secengine.TreeChanged
	}, func(f facts) Decision { return unverified(f, DetailTreeChanged) }},
	{"a pinned binary whose queries tree cannot be read is unverified", func(f facts) bool {
		return f.vouchedOK && f.in.Tree == secengine.TreeUnreadable
	}, func(f facts) Decision { return unverified(f, DetailTreeUnreadable) }},
	{"a pinned binary whose engine record cannot be read is unverified", func(f facts) bool {
		return f.vouchedOK && f.in.Tree == secengine.TreeRecordUnreadable
	}, func(f facts) Decision { return unverified(f, DetailRecordUnreadable) }},
	{"a pinned binary runs", func(f facts) bool { return f.vouchedOK }, func(f facts) Decision {
		return Decision{
			Status: StatusVerified, Detail: f.vouchHow, Pin: f.vouch, DigestOnly: f.vouch.DigestOnly,
			Untested: f.in.Version != "" && !f.engine.Tested(f.in.Version),
		}
	}},
	{"a platform with no pin anywhere is unpinned (pin owed)", func(f facts) bool { return f.pinOwed() }, func(f facts) Decision {
		return unpinned(f, DetailPinOwed)
	}},
	{"an unpinned binary changed since its first use is unpinned", func(f facts) bool {
		return f.in.FirstUse != "" && lower(f.in.FirstUse) != f.digest
	}, func(f facts) Decision { return unpinned(f, DetailChangedSinceFirstUse) }},
	{"anything else is unpinned", func(facts) bool { return true }, func(f facts) Decision {
		return unpinned(f, DetailNoMatch)
	}},
}

// Decide walks the decision table.
func Decide(in Input) Decision {
	f := derive(in)
	if f.engine.ID == "" {
		return Decision{Status: StatusRefused, Reason: ReasonUnverified}
	}
	for _, r := range rules {
		if r.when(f) {
			return r.decide(f)
		}
	}
	return Decision{Status: StatusRefused, Reason: ReasonUnverified}
}

// RuleNames lists the decision table's rows in order (the docs and the
// one-test-per-row check read it).
func RuleNames() []string {
	out := make([]string, 0, len(rules))
	for _, r := range rules {
		out = append(out, r.name)
	}
	return out
}
