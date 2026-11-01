package secengine

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// ManifestPins is what a verified security.engine manifest says about
// Opengrep: its pins per platform and the digests it revokes.
type ManifestPins struct {
	Pins    []Pin
	Revoked []string
	// Version is the manifest's publish counter.
	Version int64
}

// FromManifest reads a verified engine manifest. Only entries whose
// upstream check is cosign_keyless_online with Opengrep's branch-form
// identity for their own version and the GitHub Actions issuer count; any
// other entry is refused, so a manifest cannot pin a digest it did not
// verify the way JSP-8 requires (section 8.1).
func FromManifest(m content.Manifest) (ManifestPins, error) {
	if m.Kind != content.Engine {
		return ManifestPins{}, fmt.Errorf("secengine.FromManifest: kind %q", m.Kind)
	}
	out := ManifestPins{Version: m.ManifestVersion}
	for _, e := range m.Entries {
		if !strings.HasPrefix(e.Name, "opengrep") {
			continue // another engine's entry in a shared manifest
		}
		if ParseVersion(e.Version) == nil || e.OS == "" || e.Arch == "" {
			return ManifestPins{}, fmt.Errorf("secengine.FromManifest: entry %q needs a version, an OS and an arch", e.Name)
		}
		u := e.Upstream
		if u.Method != content.UpstreamCosignKeylessOnline || u.Identity != Identity(e.Version) || u.Issuer != Issuer {
			return ManifestPins{}, fmt.Errorf("secengine.FromManifest: entry %q was not verified keyless online under %s", e.Name, Identity(e.Version))
		}
		out.Pins = append(out.Pins, Pin{Version: e.Version, OS: e.OS, Arch: e.Arch, Asset: e.Name, SHA256: strings.ToLower(e.SHA256), Status: PinPinned, Source: "manifest", SizeBytes: e.SizeBytes, ApproxBytes: e.SizeBytes})
	}
	out.Revoked = RevocationsOf(m)
	return out, nil
}

// RevocationsOf returns the digests a manifest revokes, lowercased, whatever
// its freshness and its entries: a revocation only ever refuses, so the list
// of a manifest past its age floor, or one whose entries FromManifest
// refuses, still applies (lane SEC-G1 audit finding 5).
func RevocationsOf(m content.Manifest) []string {
	var out []string
	for _, r := range m.Revoked {
		if d := strings.ToLower(strings.TrimSpace(r.SHA256)); d != "" {
			out = append(out, d)
		}
	}
	return out
}

// Status is a decision's outcome.
type Status string

// The Status values.
const (
	// StatusVerified: the binary matches a pin; it runs unlabelled.
	StatusVerified Status = "verified"
	// StatusUnverifiedLabelled: no pin matches, on an individual node; it
	// runs, every result labelled unverified (section 8.1: trusted at
	// first use and labelled so).
	StatusUnverifiedLabelled Status = "unverified_labelled"
	// StatusRefused: nothing runs; the result is driver_unverified.
	StatusRefused Status = "refused"
)

// ReasonUnverified is the coverage reason of a refused engine.
const ReasonUnverified = "driver_unverified"

// The decision's detail codes, one per row.
const (
	DetailRevoked        = "revoked"
	DetailPinOwed        = "pin_owed"
	DetailTooOld         = "below_min_version"
	DetailManifest       = "manifest_pin"
	DetailCompiled       = "compiled_pin"
	DetailNoMatch        = "digest_not_pinned"
	DetailTreeChanged    = "companion_tree_changed"
	DetailTreeUnreadable = "companion_tree_unreadable"
	// DetailRecordUnreadable: the driver's record of the tree did not load.
	DetailRecordUnreadable = "engine_record_unreadable"
)

// Input is one decision's facts.
type Input struct {
	GOOS, GOARCH string
	// Digest is the binary's sha256 as the runner computed it.
	Digest string
	// Version is what the binary reported; "" when it was not asked yet
	// (the version is asked only after the binary is cleared).
	Version string
	// Managed: a managed node refuses what an individual node labels.
	Managed bool
	// Manifest is the verified engine manifest, nil when none.
	Manifest *ManifestPins
	// Tree is the companion tree's state.
	Tree TreeState
}

// Decision is Decide's answer.
type Decision struct {
	Status Status
	// Reason is ReasonUnverified unless the binary is verified.
	Reason string
	Detail string
	// Pin is the pin the digest matched, or the platform's pin row.
	Pin Pin
}

// Run reports whether the engine may start.
func (d Decision) Run() bool { return d.Status != StatusRefused }

// facts are the derived facts the rule table reads.
type facts struct {
	in            Input
	revoked       bool
	manifestRows  []Pin
	manifestMatch *Pin
	compiled      Pin
	compiledOK    bool
}

func derive(in Input) facts {
	f := facts{in: in}
	d := strings.ToLower(in.Digest)
	f.compiled, f.compiledOK = CompiledPin(in.GOOS, in.GOARCH)
	if in.Manifest != nil {
		f.revoked = slices.ContainsFunc(in.Manifest.Revoked, func(r string) bool { return strings.EqualFold(strings.TrimSpace(r), d) })
		for i, p := range in.Manifest.Pins {
			if p.OS != in.GOOS || p.Arch != in.GOARCH {
				continue
			}
			f.manifestRows = append(f.manifestRows, p)
			if p.SHA256 == d && f.manifestMatch == nil {
				f.manifestMatch = &in.Manifest.Pins[i]
			}
		}
	}
	return f
}

// verifiedHere reports whether a pin vouches for the digest: a manifest
// entry, or the compiled pin of a platform the manifest does not list (a
// manifest supersedes the compiled pins for the platforms it lists).
func (f facts) verifiedHere() (Pin, string, bool) {
	if f.manifestMatch != nil {
		return *f.manifestMatch, DetailManifest, true
	}
	if len(f.manifestRows) == 0 && f.compiledOK && f.compiled.Status == PinPinned && f.compiled.SHA256 == strings.ToLower(f.in.Digest) {
		return f.compiled, DetailCompiled, true
	}
	return Pin{}, "", false
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

// rules is the decision table, walked top-down; the first row whose test
// holds decides (CLAUDE.md module rule 5).
var rules = []struct {
	name   string
	when   func(f facts) bool
	decide func(f facts) Decision
}{
	{
		"a revoked digest never runs", func(f facts) bool { return f.revoked },
		func(f facts) Decision {
			return Decision{Status: StatusRefused, Reason: ReasonUnverified, Detail: DetailRevoked}
		},
	},
	{"a platform with no pin anywhere is refused (pin owed)", func(f facts) bool {
		return len(f.manifestRows) == 0 && (!f.compiledOK || f.compiled.Status != PinPinned)
	}, func(f facts) Decision {
		return Decision{Status: StatusRefused, Reason: ReasonUnverified, Detail: DetailPinOwed, Pin: f.compiled}
	}},
	{"a version below the minimum is refused", func(f facts) bool {
		return f.in.Version != "" && CompareVersions(f.in.Version, MinVersion) < 0
	}, func(f facts) Decision {
		return Decision{Status: StatusRefused, Reason: ReasonUnverified, Detail: DetailTooOld}
	}},
	{"a pinned binary whose companion tree changed is unverified", func(f facts) bool {
		_, _, ok := f.verifiedHere()
		return ok && f.in.Tree == TreeChanged
	}, func(f facts) Decision { return unverified(f, DetailTreeChanged) }},
	{"a pinned binary whose companion tree cannot be read is unverified", func(f facts) bool {
		_, _, ok := f.verifiedHere()
		return ok && f.in.Tree == TreeUnreadable
	}, func(f facts) Decision { return unverified(f, DetailTreeUnreadable) }},
	{"a pinned binary whose engine record cannot be read is unverified", func(f facts) bool {
		_, _, ok := f.verifiedHere()
		return ok && f.in.Tree == TreeRecordUnreadable
	}, func(f facts) Decision { return unverified(f, DetailRecordUnreadable) }},
	{
		"a pinned binary runs", func(f facts) bool { _, _, ok := f.verifiedHere(); return ok },
		func(f facts) Decision {
			p, detail, _ := f.verifiedHere()
			return Decision{Status: StatusVerified, Detail: detail, Pin: p}
		},
	},
	{
		"anything else is unverified", func(facts) bool { return true },
		func(f facts) Decision { return unverified(f, DetailNoMatch) },
	},
}

// Decide walks the decision table.
func Decide(in Input) Decision {
	f := derive(in)
	for _, r := range rules {
		if r.when(f) {
			return r.decide(f)
		}
	}
	return Decision{Status: StatusRefused, Reason: ReasonUnverified}
}

// ParseVersion reads MAJOR.MINOR.PATCH (an optional leading v), nil when
// it is anything else.
func ParseVersion(v string) []int {
	parts := strings.Split(strings.TrimPrefix(strings.TrimSpace(v), "v"), ".")
	if len(parts) != 3 {
		return nil
	}
	out := make([]int, 3)
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil
		}
		out[i] = n
	}
	return out
}

// CompareVersions compares two versions; an unreadable one sorts lowest.
func CompareVersions(a, b string) int {
	pa, pb := ParseVersion(a), ParseVersion(b)
	switch {
	case pa == nil && pb == nil:
		return 0
	case pa == nil:
		return -1
	case pb == nil:
		return 1
	}
	return slices.Compare(pa, pb)
}

// Tested reports whether a version is the tested one; another readable
// version at or above the minimum runs labelled "untested".
func Tested(v string) bool { return CompareVersions(v, TestedVersion) == 0 }
