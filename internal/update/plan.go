package update

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Installed describes the binary currently running on this node.
type Installed struct {
	// Version is main.version ("v1.32.0", or "dev" on an unstamped
	// build).
	Version string
	// SchemaVersion is the agent DB's current schema high-water mark
	// (internal/db.Version). It is recorded BEFORE the swap because
	// migrations run inside db.Open, which makes the pre-apply value
	// unrecoverable afterwards (§3.7 step 5).
	SchemaVersion int
	// ExecPath is the resolved path of the running executable.
	ExecPath string
	// Detection is the install-method verdict for ExecPath.
	Detection Detection
}

// PlanInput is everything BuildApplyPlan needs. Nothing here is read
// from the environment by this package: the caller resolves the
// executable, the clock and the state directory and passes them in.
type PlanInput struct {
	// Installed is the running binary.
	Installed Installed
	// Manifest is the VERIFIED manifest (Verify has already run).
	Manifest Manifest
	// Artifact is the row Verify selected for this platform.
	Artifact Artifact
	// TargetSchemaVersion is the agent schema version the TARGET
	// binary carries, when it is known (a manifest field a later wave
	// may add, or a probe of the staged binary). Zero means unknown,
	// which is treated as "may advance the schema" — the conservative
	// direction, because the cost of an unnecessary snapshot is disk
	// and the cost of a missing one is a brick (§3.7 step 5).
	TargetSchemaVersion int
	// StateDir is [update].state_dir (default ~/.observer/updates).
	StateDir string
	// Now is the clock for the maintenance-window gate.
	Now time.Time
	// Window is the node's [update].window. The zero value permits any
	// time.
	Window Window
	// Force is `observer update apply --force`: it ignores the
	// maintenance window (and, in W3, permits an apply with a live
	// dashboard PTY after warning its owners). It never shortens the
	// drain and never skips verification.
	Force bool
}

// ApplyPlan is the fully-resolved, effect-free description of one
// apply: every path, every expected hash, and whether a DB snapshot is
// required. cmd/observer/update_apply.go executes it; `observer update
// apply --dry-run` prints it.
type ApplyPlan struct {
	// TargetVersion is the version this apply reaches.
	TargetVersion string
	// ArchiveType is "tar.gz" or "zip".
	ArchiveType string
	// DownloadPath is the final archive path; PartialPath is the
	// O_EXCL .part file it is streamed into first.
	DownloadPath string
	PartialPath  string
	// StagedBinaryPath is where the extracted member lands before the
	// swap.
	StagedBinaryPath string
	// RollbackBinaryPath is where the CURRENT executable is preserved.
	RollbackBinaryPath string
	// DBBackupPath is the VACUUM INTO snapshot path, empty when no
	// snapshot is required.
	DBBackupPath string
	// ExpectedArchiveSHA256 / ExpectedMemberSHA256 come from the SIGNED
	// manifest, never from a mirror response.
	ExpectedArchiveSHA256 string
	ExpectedMemberSHA256  string
	// MaxBytes is the download ceiling (the artifact's declared size).
	MaxBytes int64
	// AdvancesSchema reports whether the target's migration set is (or
	// may be) ahead of the installed one.
	AdvancesSchema bool
	// NeedsDBSnapshot is AdvancesSchema — named separately because it
	// is what the executor branches on, and because a later wave may
	// add reasons to snapshot that are not schema advances.
	NeedsDBSnapshot bool
	// Blocked reports that this node must not proceed. State and
	// Reason say why. A blocked plan is a DEFER, not an error: the
	// caller reports it and carries on serving (§3.7 gate 0).
	Blocked bool
	// State is the state the node should report for this plan.
	State State
	// Reason qualifies State when Blocked.
	Reason Reason
	// Advice is what to tell the operator when this node cannot
	// self-apply (the install-method table's command).
	Advice string
	// Steps is the human-readable plan for --dry-run, in execution
	// order.
	Steps []string
}

// BuildApplyPlan turns a verified manifest + artifact into the plan an
// apply executes, or into an honest block.
//
// It performs NO I/O: every path is composed, never created or
// stat'ed. That is what makes the "does this need a DB snapshot"
// decision — the one whose omission turns a failed migrating apply into
// an unrecoverable brick — a unit-testable rule rather than a comment
// in an effectful function.
func BuildApplyPlan(in PlanInput) (ApplyPlan, error) {
	if in.Artifact.Filename == "" {
		return ApplyPlan{}, fmt.Errorf("update.BuildApplyPlan: no artifact selected")
	}
	if _, ok := SelectArtifact(in.Manifest, in.Artifact.Kind, in.Artifact.OS, in.Artifact.Arch); !ok {
		return ApplyPlan{}, fmt.Errorf("update.BuildApplyPlan: artifact %s is not part of manifest %d",
			in.Artifact.Filename, in.Manifest.ManifestVersion)
	}
	if strings.TrimSpace(in.StateDir) == "" {
		return ApplyPlan{}, fmt.Errorf("update.BuildApplyPlan: state_dir is required")
	}

	version := in.Manifest.Version
	verDir := filepath.Join(in.StateDir, version)
	advances := in.TargetSchemaVersion == 0 || in.TargetSchemaVersion > in.Installed.SchemaVersion

	p := ApplyPlan{
		TargetVersion:         version,
		ArchiveType:           in.Artifact.ArchiveType,
		DownloadPath:          filepath.Join(verDir, in.Artifact.Filename),
		PartialPath:           filepath.Join(verDir, in.Artifact.Filename+".part"),
		StagedBinaryPath:      stagedBinaryPath(in.Installed.ExecPath, verDir, in.Artifact.OS, version),
		RollbackBinaryPath:    filepath.Join(in.StateDir, "rollback", "observer-"+versionSlug(in.Installed.Version)),
		ExpectedArchiveSHA256: in.Artifact.SHA256,
		ExpectedMemberSHA256:  in.Artifact.MemberSHA256,
		MaxBytes:              in.Artifact.SizeBytes,
		AdvancesSchema:        advances,
		NeedsDBSnapshot:       advances,
		State:                 StateAvailable,
	}
	if advances {
		p.DBBackupPath = filepath.Join(in.StateDir, "preupgrade-"+versionSlug(in.Installed.Version)+".db")
	}

	// Gate 0, in order. Each gate DEFERS (Blocked + a state + a
	// reason); none of them is an error, because "this node cannot
	// self-apply" is a fleet fact the admin must see, not a fault the
	// operator must clear.
	switch {
	case !in.Installed.Detection.SelfApply:
		p.Blocked = true
		p.State = StateBlocked
		p.Reason = ReasonInstallMethod
		if in.Installed.Detection.Method == MethodBinaryReadOnly {
			p.Reason = ReasonNotWritable
		}
		p.Advice = AdviceFor(in.Installed.Detection, version)
	case !in.Force && !in.Window.Permits(in.Now):
		p.Blocked = true
		p.State = StateAvailable
		p.Reason = ReasonWindow
		p.Advice = fmt.Sprintf("outside the maintenance window %s; next open %s",
			in.Window.String(), in.Window.NextOpen(in.Now).Format(time.RFC3339))
	}

	p.Steps = planSteps(in, p)
	return p, nil
}

// planSteps renders the execution order for --dry-run. It is built from
// the plan itself so a printed step cannot claim something the executor
// will not do.
func planSteps(in PlanInput, p ApplyPlan) []string {
	if p.Blocked {
		return []string{fmt.Sprintf("blocked: %s (%s)", p.Reason, p.Advice)}
	}
	steps := []string{
		fmt.Sprintf("download %s (%d bytes max) from the org mirror to %s", in.Artifact.Filename, p.MaxBytes, p.PartialPath),
		fmt.Sprintf("verify archive sha256 %s", short(p.ExpectedArchiveSHA256)),
		fmt.Sprintf("verify vendor %s signature over the archive bytes", in.Artifact.UpstreamSigType),
		fmt.Sprintf("extract member %q from the %s archive (skipping %s), verify sha256 %s, probe --version == %s",
			in.Artifact.Member, p.ArchiveType, aliasList(in.Artifact.AliasMembers), short(p.ExpectedMemberSHA256), p.TargetVersion),
		"drain: stop admitting proxied requests, wait for in-flight to reach zero",
		fmt.Sprintf("stage rollback: copy %s to %s, record schema version %d",
			in.Installed.ExecPath, p.RollbackBinaryPath, in.Installed.SchemaVersion),
	}
	if p.NeedsDBSnapshot {
		steps = append(steps, fmt.Sprintf("snapshot the database to %s (the target advances the schema)", p.DBBackupPath))
	} else {
		steps = append(steps, "no database snapshot (the target does not advance the schema)")
	}
	steps = append(steps,
		fmt.Sprintf("atomic swap %s -> %s", p.StagedBinaryPath, in.Installed.ExecPath),
		"fork-exec the new binary and wait for its self-check (handshake)",
		"on success: exit; on failure: kill the child, restore the previous binary"+snapshotClause(p),
	)
	return steps
}

// snapshotClause names the DB restore in the rollback step only when a
// snapshot exists to restore.
func snapshotClause(p ApplyPlan) string {
	if p.NeedsDBSnapshot {
		return " and the database snapshot, discarding rows ingested since it was taken"
	}
	return ""
}

// aliasList renders alias members for the dry-run text.
func aliasList(aliases []string) string {
	if len(aliases) == 0 {
		return "no aliases"
	}
	return strings.Join(aliases, ", ")
}

// short truncates a hex digest for display.
func short(h string) string {
	if len(h) <= 12 {
		return h
	}
	return h[:12] + "…"
}

// stagedBinaryPath decides WHERE the extracted binary waits for the swap.
//
// It is a SIBLING of the installed executable, not a file under
// state_dir/<version>/, because §3.7 step 6's atomic swap is
// os.Rename(staged, exePath) and rename cannot cross a filesystem. A
// binary in /usr/local/bin, /opt, a Docker volume or a Windows mount
// with $HOME (and therefore state_dir) on another device would get
// EXDEV on every apply — a deterministic, silent-until-you-look failure
// that pathIsReplaceable cannot see, because it probes writability, not
// device identity. Staging beside the target removes the question
// instead of detecting it.
//
// The name is dotted and version-stamped so an abandoned apply leaves an
// obviously-ours, obviously-stale file rather than something that looks
// like a second installed binary; the executor removes it on every
// non-applying exit.
//
// The state_dir fallback is kept for the one caller that has no
// executable path (a plan built for display).
func stagedBinaryPath(execPath, verDir, goos, version string) string {
	dir := filepath.Dir(strings.TrimSpace(execPath))
	if strings.TrimSpace(execPath) == "" || dir == "" || dir == "." {
		return filepath.Join(verDir, BinaryName(goos))
	}
	name := ".observer-staged-" + versionSlug(version)
	if goos == "windows" {
		name += ".exe"
	}
	return filepath.Join(dir, name)
}

// versionSlug makes a version safe for a filename.
func versionSlug(v string) string {
	if strings.TrimSpace(v) == "" {
		return "unknown"
	}
	repl := strings.NewReplacer("/", "-", `\`, "-", ":", "-", " ", "-")
	return repl.Replace(v)
}

// RollbackInput is the state a rollback decision is made from. It is
// read from update_state by the OLD daemon, which is still alive
// precisely so this decision has an actor (§3.7 step 8).
type RollbackInput struct {
	// State is the node's current state (StateApplying on the failure
	// path this decision exists for).
	State State
	// HasPreviousBinary reports that previous_binary_path exists.
	HasPreviousBinary bool
	// PreviousSchemaVersion is the schema version recorded before the
	// swap; CurrentSchemaVersion is what the DB is at now.
	PreviousSchemaVersion int
	CurrentSchemaVersion  int
	// HasDBBackup reports that previous_db_backup_path exists.
	HasDBBackup bool
}

// RollbackDecision is what the parent does after a failed handshake.
type RollbackDecision struct {
	// RestoreBinary / RestoreDB are the two effects.
	RestoreBinary bool
	RestoreDB     bool
	// Refuse means no safe restore exists, so the node stops in
	// StateFailed for an operator rather than guessing.
	Refuse bool
	// State is the state to report.
	State State
	// ErrorClass is the class to report alongside it.
	ErrorClass ErrorClass
	// DiscardsDataWindow reports that restoring the snapshot will
	// discard rows ingested since it was taken. It is surfaced in the
	// CLI and the ledger rather than left for an operator to discover
	// (ruling R15).
	DiscardsDataWindow bool
	// Reason is the human-readable explanation.
	Reason string
}

// rollbackRule is one row of the rollback decision table.
type rollbackRule struct {
	name    string
	matches func(RollbackInput) bool
	decide  func(RollbackInput) RollbackDecision
}

// rollbackRules is the §3.7 step 8 decision as DATA, walked top-down.
// Order matters: the refusals come first, because a decision to restore
// must never be reached on inputs where a restore is unsafe.
var rollbackRules = []rollbackRule{
	{
		name:    "no-previous-binary",
		matches: func(in RollbackInput) bool { return !in.HasPreviousBinary },
		decide: func(RollbackInput) RollbackDecision {
			return RollbackDecision{
				Refuse: true, State: StateFailed, ErrorClass: ErrorSwap,
				Reason: "no previous binary was staged; nothing to restore",
			}
		},
	},
	{
		name: "schema-advanced-no-snapshot",
		matches: func(in RollbackInput) bool {
			return in.CurrentSchemaVersion > in.PreviousSchemaVersion && !in.HasDBBackup
		},
		decide: func(in RollbackInput) RollbackDecision {
			return RollbackDecision{
				Refuse: true, State: StateFailed, ErrorClass: ErrorHealthcheck,
				Reason: fmt.Sprintf(
					"the schema advanced (%d -> %d) and no snapshot exists; restoring an older binary against a newer schema is a corruption risk",
					in.PreviousSchemaVersion, in.CurrentSchemaVersion),
			}
		},
	},
	{
		name: "schema-advanced-with-snapshot",
		matches: func(in RollbackInput) bool {
			return in.CurrentSchemaVersion > in.PreviousSchemaVersion && in.HasDBBackup
		},
		decide: func(in RollbackInput) RollbackDecision {
			return RollbackDecision{
				RestoreBinary: true, RestoreDB: true, DiscardsDataWindow: true,
				State: StateRolledBack, ErrorClass: ErrorHealthcheck,
				Reason: fmt.Sprintf(
					"restoring the previous binary and the pre-apply snapshot (schema %d -> %d); rows ingested since the snapshot are discarded",
					in.PreviousSchemaVersion, in.CurrentSchemaVersion),
			}
		},
	},
	{
		name:    "same-schema",
		matches: func(RollbackInput) bool { return true },
		decide: func(RollbackInput) RollbackDecision {
			return RollbackDecision{
				RestoreBinary: true, State: StateRolledBack, ErrorClass: ErrorHealthcheck,
				Reason: "restoring the previous binary; the schema did not advance, so the database is untouched",
			}
		},
	},
}

// DecideRollback answers what to do after a failed apply.
//
// The refusal branch ("should be unreachable" — a snapshot that fails
// to write aborts the apply at step 5) is implemented anyway, because
// "should be unreachable" is not a recovery plan.
func DecideRollback(in RollbackInput) RollbackDecision {
	for _, r := range rollbackRules {
		if r.matches(in) {
			return r.decide(in)
		}
	}
	// Unreachable: the last rule matches everything. Returning a
	// refusal rather than a zero value keeps the fail-safe direction.
	return RollbackDecision{Refuse: true, State: StateFailed, Reason: "no rollback rule matched"}
}

// Window is a local maintenance window, e.g. "02:00-05:00" in the
// machine's own timezone. The zero value is "any time", which is what
// an empty [update].window means.
//
// A window that wraps midnight ("22:00-02:00") is normal on a fleet
// spread across timezones and is handled explicitly rather than by
// accident.
type Window struct {
	// startMin and endMin are minutes since local midnight.
	startMin, endMin int
	// set distinguishes a configured window from the zero value.
	set bool
	// raw is the text the window was parsed from, for display.
	raw string
}

// ParseWindow parses "HH:MM-HH:MM". An empty string yields the zero
// window (always permitted), which is the documented meaning of an
// empty [update].window.
func ParseWindow(s string) (Window, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Window{}, nil
	}
	parts := strings.Split(s, "-")
	if len(parts) != 2 {
		return Window{}, fmt.Errorf("update.ParseWindow: %q is not HH:MM-HH:MM", s)
	}
	start, err := parseClock(parts[0])
	if err != nil {
		return Window{}, fmt.Errorf("update.ParseWindow: %q: %w", s, err)
	}
	end, err := parseClock(parts[1])
	if err != nil {
		return Window{}, fmt.Errorf("update.ParseWindow: %q: %w", s, err)
	}
	if start == end {
		return Window{}, fmt.Errorf("update.ParseWindow: %q is a zero-length window", s)
	}
	return Window{startMin: start, endMin: end, set: true, raw: s}, nil
}

// parseClock parses "HH:MM" into minutes since midnight.
func parseClock(s string) (int, error) {
	s = strings.TrimSpace(s)
	hm := strings.Split(s, ":")
	if len(hm) != 2 {
		return 0, fmt.Errorf("%q is not HH:MM", s)
	}
	h, err := strconv.Atoi(hm[0])
	if err != nil || h < 0 || h > 23 {
		return 0, fmt.Errorf("%q has an out-of-range hour", s)
	}
	m, err := strconv.Atoi(hm[1])
	if err != nil || m < 0 || m > 59 {
		return 0, fmt.Errorf("%q has an out-of-range minute", s)
	}
	return h*60 + m, nil
}

// IsSet reports whether a window was configured.
func (w Window) IsSet() bool { return w.set }

// String renders the window as configured, or "any time".
func (w Window) String() string {
	if !w.set {
		return "any time"
	}
	return w.raw
}

// Permits reports whether t (in its own location) falls inside the
// window. The zero window permits everything.
func (w Window) Permits(t time.Time) bool {
	if !w.set {
		return true
	}
	if t.IsZero() {
		return false
	}
	mins := t.Hour()*60 + t.Minute()
	if w.startMin < w.endMin {
		return mins >= w.startMin && mins < w.endMin
	}
	// Wraps midnight.
	return mins >= w.startMin || mins < w.endMin
}

// NextOpen returns the next instant the window is open at or after t.
// When the window is open at t, t is returned unchanged, so a caller
// can print "next open" without special-casing "now".
func (w Window) NextOpen(t time.Time) time.Time {
	if !w.set || w.Permits(t) {
		return t
	}
	start := time.Date(t.Year(), t.Month(), t.Day(), w.startMin/60, w.startMin%60, 0, 0, t.Location())
	if !start.After(t) {
		start = start.AddDate(0, 0, 1)
	}
	return start
}
