package update

import (
	"strings"

	updatespec "github.com/marmutapp/superbased-observer/internal/updatespec"
)

// distro.go is the update rail's view of the prebuilt node distros
// (modular packaging plan 5.2 and 5.6). The vocabulary is DUPLICATED as
// literals rather than imported from internal/components, so this package
// stays stdlib-only (see doc.go); distro_test.go asserts the two lists
// agree, so a distro added on one side fails loudly.

// The prebuilt node distros an update artifact may hold.
const (
	DistroMinimal   = "minimal"
	DistroDeveloper = "developer"
	DistroManaged   = "managed"
	DistroFull      = "full"
)

// knownDistros is the closed set, in catalog order.
var knownDistros = []string{DistroMinimal, DistroDeveloper, DistroManaged, DistroFull}

// KnownDistros returns the prebuilt node distro names, in catalog order.
func KnownDistros() []string { return append([]string(nil), knownDistros...) }

// KnownDistro reports whether d (after NormalizeDistro) is a prebuilt
// node distro. The empty string is full, the meaning every v1 artifact
// and every pre-modular binary has.
func KnownDistro(d string) bool {
	n := NormalizeDistro(d)
	for _, k := range knownDistros {
		if k == n {
			return true
		}
	}
	return false
}

// CustomDistroPrefix starts a custom distro id (modular packaging plan 5.3,
// lane MP-CUST): `custom-<manifest digest>`, the FULL hex SHA-256 of the
// component manifest (components.ManifestDigest), never a prefix of it, so
// two manifests can never share an id. Duplicated from internal/components
// like the prebuilt names; distro_test.go asserts the two agree.
const CustomDistroPrefix = "custom-"

// CustomDistro returns the custom distro id of a manifest digest.
func CustomDistro(manifestDigest string) string {
	return CustomDistroPrefix + strings.ToLower(strings.TrimSpace(manifestDigest))
}

// IsCustomDistro reports whether d (after NormalizeDistro) is a custom
// distro id: the prefix and exactly 64 lowercase hex characters.
func IsCustomDistro(d string) bool {
	n := NormalizeDistro(d)
	if !strings.HasPrefix(n, CustomDistroPrefix) {
		return false
	}
	return updatespec.IsHexSHA256(strings.TrimPrefix(n, CustomDistroPrefix))
}

// ArtifactDistro reports whether d may label an update artifact: a prebuilt
// distro or a custom distro id. A custom artifact is selected only by a node
// running that exact custom distro (SelectArtifactFor matches the whole
// id), so a custom build updates only from a matching custom build or
// refuses (verify.go rule 9), and no other node ever selects one.
func ArtifactDistro(d string) bool { return KnownDistro(d) || IsCustomDistro(d) }

// NormalizeDistro folds a distro spelling onto its catalog name. Empty
// is full: a v1 manifest names no distro and always means the full build
// (plan 5.6), and an unstamped binary is the full build.
func NormalizeDistro(d string) string {
	l := strings.ToLower(strings.TrimSpace(d))
	if l == "" {
		return DistroFull
	}
	return l
}

// Reasons the distro rules produce. They live in internal/updatespec with
// the rest of the closed vocabulary; these aliases keep this package's
// spelling (update.ReasonX) for its callers.
const (
	ReasonServerLacksDistroUpdates = updatespec.ReasonServerLacksDistroUpdates
	ReasonCeilingInvalid           = updatespec.ReasonCeilingInvalid
	ReasonDistroNotAllowed         = updatespec.ReasonDistroNotAllowed
	ReasonDistroEpochStale         = updatespec.ReasonDistroEpochStale
	ReasonReleaseIndex             = updatespec.ReasonReleaseIndex
)

// DistroContext is what a distro-aware node knows about itself when it
// verifies a manifest. The ZERO VALUE (Aware false) is the pre-modular
// behaviour exactly: no distro rule runs and the full artifact is
// selected, so every caller written before this file is unchanged.
//
// Every boolean is fail-closed when Aware is true: a caller that forgets
// to set UpdatesAllowed refuses every update, one that forgets
// LegacyFullAllowed refuses the v1 fallback, and one that forgets
// TargetAllowed refuses every distro change.
type DistroContext struct {
	// Aware marks a distro-aware node. Only such a node runs rules 10-12.
	Aware bool
	// Current is the distro the running binary was built as ("" = full).
	Current string
	// Target is the distro this node should run: the one its component
	// policy names, else Current. A Target different from Current is a
	// distro transition.
	Target string
	// TargetAllowed reports that the node's effective component policy
	// and local ceiling allow Target. Read only for a transition.
	TargetAllowed bool
	// Epoch is the distro_epoch this node last applied on the channel
	// being verified (zero when none).
	Epoch int64
	// UpdatesAllowed is the local ceiling's verdict
	// (managedconfig.Result.UpdatesAllowed): false while the ceiling's
	// source exists but failed a check.
	UpdatesAllowed bool
	// LegacyFullAllowed answers the new-node / old-server cell
	// (nodecomponents.LegacyFullFallbackAllowed): the node runs full and
	// its ceiling, when pinned, permits every full component.
	LegacyFullAllowed bool
}

// target returns the normalized distro the node should run.
func (d DistroContext) target() string {
	if strings.TrimSpace(d.Target) == "" {
		return NormalizeDistro(d.Current)
	}
	return NormalizeDistro(d.Target)
}

// IsTransition reports whether the context asks for a distro change.
func (d DistroContext) IsTransition() bool {
	return d.Aware && d.target() != NormalizeDistro(d.Current)
}
