package sandboxadopt

import (
	"fmt"
	"strconv"
	"strings"
)

// CodeCheckpointUnsupported is the one refusal code of a checkpoint or
// restore that cannot run here; its reason names why.
const CodeCheckpointUnsupported Code = "checkpoint_unsupported"

// MinCRIU is the lowest CRIU Podman's checkpoint accepts (3.11).
const MinCRIU = "3.11"

// DefaultExportCapBytes caps a checkpoint export (2 GiB); a larger export
// is removed and refused.
const DefaultExportCapBytes int64 = 2 << 30

// ExportSuffix names a run's checkpoint export in its state dir.
const ExportSuffix = ".checkpoint.tar"

// CheckpointFacts are what the caller read before a checkpoint.
type CheckpointFacts struct {
	// UserAction: the checkpoint was asked for by the user (the CLI verb or
	// the dashboard button), never by a timer, a sweep or an update.
	UserAction bool
	Engine     EngineFacts
	// Runtime is the container's OCI runtime (runc, crun, runsc).
	Runtime string
	// CRIUVersion is `criu --version`'s version ("" when criu is absent).
	CRIUVersion string
	// Running: the container is running.
	Running bool
	// StateDirPerm is the run's state dir permission bits; StateDirOwned
	// that it is this user's, not a link.
	StateDirPerm  uint32
	StateDirOwned bool
	// CapBytes is the export cap (0: the default).
	CapBytes int64
}

// CheckpointPlan is what the caller sends to libpod.
type CheckpointPlan struct {
	// ExportName is the export's file name in the run's state dir.
	ExportName string
	// CapBytes is the cap the caller enforces while writing.
	CapBytes int64
}

// Refusal is a refused checkpoint or restore.
type Refusal struct {
	Code   Code
	Reason string
}

// Error renders the refusal.
func (r Refusal) Error() string { return string(r.Code) + ": " + r.Reason }

// cpRule is one row of the checkpoint table: when refuse holds, the
// checkpoint is refused with why.
type cpRule struct {
	refuse func(CheckpointFacts) bool
	why    func(CheckpointFacts) string
}

// checkpointRules are walked top-down; the first that matches refuses
// (decision 2 of lane GATES-SBX: rootful Podman with CRIU only, and only
// on a user action).
var checkpointRules = []cpRule{
	{func(f CheckpointFacts) bool { return !f.UserAction }, func(CheckpointFacts) string {
		return "a checkpoint runs only when you ask for it (observer sandbox checkpoint, or the dashboard button), never automatically"
	}},
	{func(f CheckpointFacts) bool { return f.Engine.Engine == EngineDocker }, func(CheckpointFacts) string {
		return "Docker's checkpoint is an experimental feature with no export; only rootful Podman is supported"
	}},
	{func(f CheckpointFacts) bool { return f.Engine.Engine != EnginePodman }, func(CheckpointFacts) string {
		return "the engine is not Podman"
	}},
	{func(f CheckpointFacts) bool { return f.Engine.Mode != ModeRootful }, func(CheckpointFacts) string {
		return "rootless Podman cannot checkpoint (CRIU needs root); use a rootful Podman socket"
	}},
	{func(f CheckpointFacts) bool { return strings.TrimSpace(f.Runtime) == "runsc" }, func(CheckpointFacts) string {
		return "the oci-runsc row runs gVisor, whose checkpoint is its own (runsc checkpoint), not CRIU's"
	}},
	{func(f CheckpointFacts) bool { return strings.TrimSpace(f.CRIUVersion) == "" }, func(CheckpointFacts) string {
		return "criu is not installed on this machine"
	}},
	{func(f CheckpointFacts) bool { return !versionAtLeast(f.CRIUVersion, MinCRIU) }, func(f CheckpointFacts) string {
		return fmt.Sprintf("criu %s is older than %s, the lowest Podman accepts", strings.TrimSpace(f.CRIUVersion), MinCRIU)
	}},
	{func(f CheckpointFacts) bool { return !f.Running }, func(CheckpointFacts) string {
		return "the container is not running"
	}},
	{func(f CheckpointFacts) bool { return !f.StateDirOwned || f.StateDirPerm&0o077 != 0 }, func(CheckpointFacts) string {
		return "the run's state dir is not an owner-only (0700) directory of this user"
	}},
}

// PlanCheckpoint decides whether a checkpoint of runID may run and where
// its export goes.
func PlanCheckpoint(runID string, f CheckpointFacts) (CheckpointPlan, *Refusal) {
	for _, r := range checkpointRules {
		if r.refuse(f) {
			return CheckpointPlan{}, &Refusal{Code: CodeCheckpointUnsupported, Reason: r.why(f)}
		}
	}
	capb := f.CapBytes
	if capb <= 0 {
		capb = DefaultExportCapBytes
	}
	return CheckpointPlan{ExportName: runID + ExportSuffix, CapBytes: capb}, nil
}

// ExportVerdict judges a written export: refused (and to be removed) when
// it is over the cap or empty.
func ExportVerdict(size, capBytes int64) *Refusal {
	if capBytes <= 0 {
		capBytes = DefaultExportCapBytes
	}
	switch {
	case size <= 0:
		return &Refusal{Code: CodeCheckpointUnsupported, Reason: "the engine wrote an empty export"}
	case size > capBytes:
		return &Refusal{Code: CodeCheckpointUnsupported, Reason: fmt.Sprintf("the export is over the %d byte cap; it was removed", capBytes)}
	}
	return nil
}

// RestoreFacts are what the caller read after the engine restored a run
// from its export, before anything is attached.
type RestoreFacts struct {
	// Checkpoint is the same table's facts (a restore needs what a
	// checkpoint needs).
	Checkpoint CheckpointFacts
	// ExportOwned: the export is an owner-only regular file of this user.
	ExportOwned bool
	// SocketDirIntact: the run's per-run socket dir (the relay's home in
	// the container) survived and is the run's own.
	SocketDirIntact bool
	// ReadBackOK: the restored container matches the kept plan.
	ReadBackOK     bool
	ReadBackReason string
}

// PlanRestore decides whether a restore may start, from the facts before
// the import.
func PlanRestore(f RestoreFacts) *Refusal {
	cp := f.Checkpoint
	cp.Running = true // a restore starts from no container
	if _, r := PlanCheckpoint("restore", cp); r != nil {
		return r
	}
	if !f.ExportOwned {
		return &Refusal{Code: CodeCheckpointUnsupported, Reason: "the export is not an owner-only file of this user"}
	}
	return nil
}

// RestoredVerdict judges a restored container: one whose relay socket dir
// or plan did not survive is refused, and the caller removes it, never
// running it without capture.
func RestoredVerdict(f RestoreFacts) *Refusal {
	if !f.SocketDirIntact {
		return &Refusal{Code: CodeRestoreLostCapture, Reason: "the run's relay socket dir did not survive the restore, so the box would run without capture; the container was removed"}
	}
	if !f.ReadBackOK {
		return &Refusal{Code: CodeBuiltBelowPlan, Reason: "the restored container does not match its plan: " + f.ReadBackReason + "; it was removed"}
	}
	return nil
}

// versionAtLeast compares dotted numeric versions ("3.17.1" >= "3.11").
// A version that does not parse is not at least anything.
func versionAtLeast(have, want string) bool {
	h, ok1 := parseVersion(have)
	w, ok2 := parseVersion(want)
	if !ok1 || !ok2 {
		return false
	}
	for i := 0; i < len(w); i++ {
		var hv int
		if i < len(h) {
			hv = h[i]
		}
		if hv != w[i] {
			return hv > w[i]
		}
	}
	return true
}

func parseVersion(s string) ([]int, bool) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	if s == "" {
		return nil, false
	}
	var out []int
	for _, p := range strings.Split(s, ".") {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil, false
		}
		out = append(out, n)
	}
	return out, true
}

// ParseCRIUVersion reads the version from `criu --version` output
// ("Version: 3.17.1" on its first line); "" when absent.
func ParseCRIUVersion(out string) string {
	for _, line := range strings.Split(out, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "Version:"); ok {
			v = strings.TrimSpace(v)
			if _, ok := parseVersion(v); ok {
				return v
			}
		}
	}
	return ""
}
