package intervention

import (
	"context"
	"errors"
	"sort"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

var (
	// ErrBindingUnsupported reports that installed-process binding is not
	// implemented on the current operating system.
	ErrBindingUnsupported = errors.New("intervention: installed process binding unsupported")
	// ErrInvalidCandidate reports malformed or contradictory installed-path
	// input supplied by the caller.
	ErrInvalidCandidate = errors.New("intervention: invalid installed candidate")
	// ErrBindingMismatch reports that fresh process evidence no longer matches
	// the requested manifest surface and stable identity.
	ErrBindingMismatch = errors.New("intervention: process binding mismatch")
	// ErrBindingAmbiguous reports that fresh evidence matches more than one
	// declared surface. No target may be selected from an ambiguous result.
	ErrBindingAmbiguous = errors.New("intervention: process binding ambiguous")
)

// BindingState is the install-time result for one declared surface.
type BindingState string

const (
	// BindingNotInstalled means the caller supplied no installed candidate for
	// this surface. It is inventory absence, not verified control.
	BindingNotInstalled BindingState = "not_installed"
	// BindingReady means every supplied candidate produced at least one exact
	// installed process target and none was unresolved.
	BindingReady BindingState = "ready"
	// BindingPartial means at least one exact target exists but another supplied
	// launch form could not be bound.
	BindingPartial BindingState = "partial"
	// BindingUnsupported means the surface class or installed launch form has no
	// identity-safe process binding.
	BindingUnsupported BindingState = "unsupported"
	// BindingInvalid means installed input was malformed or contradicted the
	// registry declaration.
	BindingInvalid BindingState = "invalid"
)

// BindingReason is a stable, path-free explanation for a surface state.
type BindingReason string

const (
	ReasonSharedHost              BindingReason = "shared_host"
	ReasonRemoteExecution         BindingReason = "remote_execution"
	ReasonUnclassifiedSurface     BindingReason = "unclassified_surface"
	ReasonNoBinaryCapability      BindingReason = "no_binary_capability"
	ReasonNoInstalledCandidate    BindingReason = "no_installed_candidate"
	ReasonCandidateSurfaceUnknown BindingReason = "candidate_surface_unknown"
	ReasonCandidatePathInvalid    BindingReason = "candidate_path_invalid"
	ReasonCandidateNotExecutable  BindingReason = "candidate_not_executable"
	ReasonGenericProcessHost      BindingReason = "generic_or_shared_process_host"
	ReasonNativeNotDeclared       BindingReason = "native_not_declared"
	ReasonInvocationUnknown       BindingReason = "invocation_not_declared"
	ReasonInterpreterNotDeclared  BindingReason = "interpreter_not_declared"
	ReasonInterpreterUnresolved   BindingReason = "interpreter_unresolved"
	ReasonShellLauncher           BindingReason = "shell_launcher"
	ReasonLauncherFormUnknown     BindingReason = "launcher_form_unknown"
	ReasonWorkerNotFound          BindingReason = "declared_worker_not_found"
	ReasonWorkerInvalid           BindingReason = "declared_worker_invalid"
)

// InstalledInterpreter supplies an exact interpreter path for an env-style
// shebang. BuildInstallManifest never searches PATH or executes an interpreter.
type InstalledInterpreter struct {
	Kind integration.InterpreterKind
	Path string
}

// InstalledCandidate is one launcher path already selected by the caller's
// normal BinaryResolveSpec resolution. SurfaceID may be omitted only when the
// tool has exactly one dedicated-process surface. Interpreters contains only
// exact known paths and never environment values. This is local discovery
// evidence; it does not attest the vendor signature or package provenance,
// which remains the installer/controller's responsibility.
type InstalledCandidate struct {
	Tool         string
	SurfaceID    string
	LauncherPath string
	Interpreters []InstalledInterpreter
}

// InstalledFile is a canonical path and its immutable filesystem identity at
// manifest-build time. Identity is device/inode; replacing a file requires a
// manifest refresh before the replacement can match.
type InstalledFile struct {
	Path     string
	Identity ExecutableIdentity
}

// TargetKind identifies the exact process shape represented by a manifest
// target.
type TargetKind string

const (
	// TargetNativeExecutable matches the process executable device/inode.
	TargetNativeExecutable TargetKind = "native_executable"
	// TargetInterpretedEntrypoint matches both an interpreter executable and an
	// exact script entrypoint. The script proof is a point-in-time /proc argv
	// observation and does not claim immutable argv provenance.
	TargetInterpretedEntrypoint TargetKind = "interpreted_entrypoint"
)

// InstallTarget is one exact installed process identity. Entrypoint is set
// only for TargetInterpretedEntrypoint. A target represents one process and
// never implies descendant containment.
type InstallTarget struct {
	Kind       TargetKind
	Executable InstalledFile
	Entrypoint *InstalledFile
	// BoundProcess limits a retained native target to one previously verified
	// process lifetime after its installed executable is replaced or removed.
	// It must never authorize a later process through a stale inode.
	BoundProcess *Identity
}

// SurfaceManifest is the binding result for one registry surface. Reasons are
// stable and contain no host paths or arguments.
type SurfaceManifest struct {
	Spec    integration.InterventionSurfaceSpec
	State   BindingState
	Reasons []BindingReason
	Targets []InstallTarget
}

// InstallManifest is the complete registry-derived surface inventory for one
// build. It includes uninstalled and unsupported rows so readiness cannot
// interpret omission as control.
type InstallManifest struct {
	Surfaces []SurfaceManifest
}

// Surface returns the manifest row for id.
func (m InstallManifest) Surface(id string) (SurfaceManifest, bool) {
	for _, surface := range m.Surfaces {
		if surface.Spec.ID == id {
			return surface, true
		}
	}
	return SurfaceManifest{}, false
}

// EntrypointEvidence is a canonicalized, current filesystem observation of a
// process's direct script argument. It intentionally carries no other argv.
type EntrypointEvidence struct {
	Path     string
	Identity ExecutableIdentity
}

// ProcessEvidence contains only the process fields required by the pure
// matcher. Identity is the stable process identity returned by Inspect.
type ProcessEvidence struct {
	Identity    Identity
	Entrypoint  *EntrypointEvidence
	Invocations []InvocationEvidence
}

// InvocationClass is a path-free classification of one process's current argv
// shape against one registry surface declaration and target kind.
type InvocationClass string

const (
	// InvocationCLI is an explicitly declared dedicated CLI form.
	InvocationCLI InvocationClass = "cli"
	// InvocationNonCLI is an explicitly declared shared/service form.
	InvocationNonCLI InvocationClass = "non_cli"
	// InvocationUnclassified is the fail-closed value for every other
	// invocation. It never authorizes process control.
	InvocationUnclassified InvocationClass = "unclassified"
)

// InvocationEvidence retains only a surface ID, target kind, and closed class.
// Raw argv is read transiently and is never returned, logged, audited, or
// stored.
type InvocationEvidence struct {
	SurfaceID string
	Target    TargetKind
	Class     InvocationClass
}

// MatchState is the result of matching one process against a manifest.
type MatchState string

const (
	// MatchNone means the process matched no exact installed target.
	MatchNone MatchState = "no_match"
	// MatchBound means exactly one dedicated surface target matched.
	MatchBound MatchState = "bound"
	// MatchRefused means policy-safe scalar checks rejected the process.
	MatchRefused MatchState = "refused"
	// MatchAmbiguous means more than one surface target matched; callers must
	// not select one or signal the process.
	MatchAmbiguous MatchState = "ambiguous"
)

// MatchReason is a stable matcher outcome.
type MatchReason string

const (
	MatchReasonNone              MatchReason = "none"
	MatchReasonInvalidIdentity   MatchReason = "invalid_identity"
	MatchReasonWrongUID          MatchReason = "wrong_uid"
	MatchReasonForbiddenPID      MatchReason = "self_or_ancestor"
	MatchReasonNoTarget          MatchReason = "no_exact_target"
	MatchReasonAmbiguous         MatchReason = "ambiguous_exact_target"
	MatchReasonNonCLI            MatchReason = "declared_non_cli_invocation"
	MatchReasonInvocationUnknown MatchReason = "invocation_unclassified"
)

// MatchOptions defines the local principal and process IDs the matcher must
// refuse. ForbiddenPIDs is normally the controller plus all of its ancestors.
type MatchOptions struct {
	TargetUID     int
	ForbiddenPIDs []int
}

// ScanOptions identifies the governed operating-system user and controller.
// ControllerPID defaults to the current process when zero; it and every
// ancestor are excluded from matches.
type ScanOptions struct {
	TargetUID     int
	ControllerPID int
	// InspectProtected is an optional authenticated, privileged identity reader
	// for a same-user process whose executable cannot be inspected locally.
	// The supplied birth fields and returned identity are revalidated locally.
	// This supplements inventory only: full binding and signal-time inspection
	// still use the ordinary process-control implementation.
	InspectProtected func(context.Context, int, int64, string) (Identity, error)
}

// ScanResult is one process-table reconciliation. Matches contains only
// exact, unambiguous dedicated-process bindings. Ambiguous and Refused retain
// stable identities for local diagnostics without paths or arguments.
//
// Complete reports whether the process table itself was fully reconciled. An
// invocation the registry could not classify is NOT a node-wide reconciliation
// failure: it names its own surface in UnclassifiedSurfaces so one abstaining
// process degrades that surface's coverage only.
type ScanResult struct {
	Complete  bool
	Matches   []ProcessMatch
	Ambiguous []Identity
	Refused   []Identity
	// UnclassifiedSurfaces lists the dedicated surface IDs that abstained on at
	// least one observed process because its leading argument was neither a
	// declared CLI nor a declared non-billable form. It is sorted, deduplicated,
	// and carries no paths, arguments, or identities.
	UnclassifiedSurfaces []string
	Failures             []ProcessScanFailure
	TransientGone        int
}

// ProcessScanFailureReason is a path-free reason that a possibly relevant
// process could not be reconciled.
type ProcessScanFailureReason string

const (
	ScanFailureInspectionUnavailable ProcessScanFailureReason = "inspection_unavailable"
	ScanFailureEntrypointUnavailable ProcessScanFailureReason = "entrypoint_unavailable"
	ScanFailureMountNamespace        ProcessScanFailureReason = "different_mount_namespace"
)

// ProcessScanFailure identifies one unreconciled PID without retaining its
// argv, cwd, executable path, or other host-sensitive strings.
type ProcessScanFailure struct {
	PID    int
	Reason ProcessScanFailureReason
}

// ProcessMatch is one exact dedicated-process binding. Identity is copied from
// the evidence and remains the value callers must pass to Acquire.
type ProcessMatch struct {
	Tool      string
	SurfaceID string
	Identity  Identity
	Target    InstallTarget
}

// MatchResult is the complete pure result for one process.
type MatchResult struct {
	State   MatchState
	Reason  MatchReason
	Matches []ProcessMatch
	// UnclassifiedSurfaces names the dedicated surfaces whose declaration could
	// not classify this process's leading argument. It is set only with
	// MatchReasonInvocationUnknown and scopes that abstention to those surfaces
	// instead of the whole scan.
	UnclassifiedSurfaces []string
}

// MatchInstalledProcess matches evidence against exact manifest identities.
// It does not inspect the OS, infer descendants, use basenames/cwd as adapter
// evidence, or choose among ambiguous surfaces.
func MatchInstalledProcess(manifest InstallManifest, evidence ProcessEvidence, opts MatchOptions) MatchResult {
	if !validIdentity(evidence.Identity) {
		return MatchResult{State: MatchRefused, Reason: MatchReasonInvalidIdentity}
	}
	if opts.TargetUID < 0 || evidence.Identity.UID != opts.TargetUID {
		return MatchResult{State: MatchRefused, Reason: MatchReasonWrongUID}
	}
	for _, pid := range opts.ForbiddenPIDs {
		if evidence.Identity.PID == pid {
			return MatchResult{State: MatchRefused, Reason: MatchReasonForbiddenPID}
		}
	}

	var matches []ProcessMatch
	var unclassified []string
	invocationClass := InvocationClass("")
	for _, surface := range manifest.Surfaces {
		if surface.Spec.Class != integration.SurfaceDedicatedProcess ||
			(surface.State != BindingReady && surface.State != BindingPartial) {
			continue
		}
		for _, target := range surface.Targets {
			if targetIdentityMatches(target, evidence) {
				class := invocationFor(evidence.Invocations, surface.Spec.ID, target.Kind)
				if class == InvocationNonCLI {
					invocationClass = InvocationNonCLI
				} else if class == InvocationUnclassified {
					if invocationClass == "" {
						invocationClass = InvocationUnclassified
					}
					unclassified = appendUniqueSurface(unclassified, surface.Spec.ID)
				}
			}
			if !targetMatches(surface.Spec.ID, target, evidence) {
				continue
			}
			matches = append(matches, ProcessMatch{
				Tool:      surface.Spec.Tool,
				SurfaceID: surface.Spec.ID,
				Identity:  evidence.Identity,
				Target:    target,
			})
		}
	}
	if len(matches) == 0 {
		if invocationClass == InvocationNonCLI {
			return MatchResult{State: MatchRefused, Reason: MatchReasonNonCLI}
		}
		if invocationClass == InvocationUnclassified {
			return MatchResult{
				State:                MatchRefused,
				Reason:               MatchReasonInvocationUnknown,
				UnclassifiedSurfaces: unclassified,
			}
		}
		return MatchResult{State: MatchNone, Reason: MatchReasonNoTarget}
	}
	matches = uniqueMatches(matches)
	if len(matches) != 1 {
		return MatchResult{State: MatchAmbiguous, Reason: MatchReasonAmbiguous, Matches: matches}
	}
	return MatchResult{State: MatchBound, Reason: MatchReasonNone, Matches: matches}
}

func targetMatches(surfaceID string, target InstallTarget, evidence ProcessEvidence) bool {
	return targetIdentityMatches(target, evidence) &&
		invocationFor(evidence.Invocations, surfaceID, target.Kind) == InvocationCLI
}

func targetIdentityMatches(target InstallTarget, evidence ProcessEvidence) bool {
	if !nativeExecutableMatches(target, evidence.Identity) {
		return false
	}
	if target.Kind == TargetNativeExecutable {
		return target.Entrypoint == nil
	}
	if target.Kind != TargetInterpretedEntrypoint || target.Entrypoint == nil || evidence.Entrypoint == nil {
		return false
	}
	return target.Entrypoint.Path == evidence.Entrypoint.Path &&
		target.Entrypoint.Identity == evidence.Entrypoint.Identity
}

func nativeExecutableMatches(target InstallTarget, identity Identity) bool {
	return (target.BoundProcess == nil || sameIdentity(*target.BoundProcess, identity)) &&
		target.Executable.Identity == identity.Executable
}

func invocationFor(evidence []InvocationEvidence, surfaceID string, target TargetKind) InvocationClass {
	for _, item := range evidence {
		if item.SurfaceID == surfaceID && item.Target == target {
			return item.Class
		}
	}
	return InvocationUnclassified
}

func recordScanMatch(result *ScanResult, evidence ProcessEvidence, match MatchResult) {
	if result == nil {
		return
	}
	switch match.State {
	case MatchBound:
		result.Matches = append(result.Matches, match.Matches[0])
	case MatchAmbiguous:
		result.Complete = false
		result.Ambiguous = append(result.Ambiguous, evidence.Identity)
	case MatchRefused:
		result.Refused = append(result.Refused, evidence.Identity)
		// An invocation the registry cannot classify is a per-surface coverage
		// gap, never a node-wide reconciliation failure: the process table was
		// still read completely, and one abstaining process must not degrade
		// every other governed surface.
		for _, surface := range match.UnclassifiedSurfaces {
			result.UnclassifiedSurfaces = appendUniqueSurface(result.UnclassifiedSurfaces, surface)
		}
	}
}

// appendUniqueSurface keeps a surface-ID list sorted and deduplicated so the
// reported coverage gap is stable across scans.
func appendUniqueSurface(list []string, id string) []string {
	if id == "" {
		return list
	}
	index := sort.SearchStrings(list, id)
	if index < len(list) && list[index] == id {
		return list
	}
	list = append(list, "")
	copy(list[index+1:], list[index:])
	list[index] = id
	return list
}

func uniqueMatches(in []ProcessMatch) []ProcessMatch {
	type key struct {
		surface string
		kind    TargetKind
		exe     ExecutableIdentity
		entry   ExecutableIdentity
	}
	seen := make(map[key]bool, len(in))
	out := make([]ProcessMatch, 0, len(in))
	for _, match := range in {
		var entry ExecutableIdentity
		if match.Target.Entrypoint != nil {
			entry = match.Target.Entrypoint.Identity
		}
		k := key{surface: match.SurfaceID, kind: match.Target.Kind, exe: match.Target.Executable.Identity, entry: entry}
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, match)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SurfaceID < out[j].SurfaceID })
	return out
}
