package secposture

import (
	"time"

	"github.com/marmutapp/superbased-observer/internal/guardposture"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// ModuleSignal is what the signed guard posture says about the security
// module (section 4.3: the module's inactive state is signed into the
// guard posture the hook already reads, so a deleted security file reads
// as absent only when the module really is off).
type ModuleSignal int

const (
	// ModuleNoDaemon: no guard posture and no key exist; no daemon has
	// published on this node. The hook has nothing the module could have
	// written, so the state is absent (the guard posture's own fallback).
	ModuleNoDaemon ModuleSignal = iota
	// ModuleActive: the guard posture verifies and says the module is
	// active.
	ModuleActive
	// ModuleInactive: the guard posture verifies and says the module is
	// inactive.
	ModuleInactive
	// ModuleUnverified: a guard posture or its key exists but the pair
	// does not verify. Stricter, never looser: unknown.
	ModuleUnverified
)

// ReadOutcome is how reading the project's posture file went.
type ReadOutcome int

const (
	// ReadOK: the file decoded and verified under the key.
	ReadOK ReadOutcome = iota
	// ReadMissing: no file for the project.
	ReadMissing
	// ReadTooLarge: over MaxFileBytes.
	ReadTooLarge
	// ReadUnverified: no key, a malformed file or key, a foreign schema, a
	// MAC that does not verify, or a file naming another project.
	ReadUnverified
)

// Versions are the policy and bundle versions the hook loaded. Check off
// skips the comparison (no version is known yet).
type Versions struct {
	Check  bool
	Policy string
	Bundle string
}

// Input is everything the state function reads. It is built by Load (or by
// the daemon path from its in-memory posture) and is pure data.
type Input struct {
	Module ModuleSignal
	Read   ReadOutcome
	// File is set when Read is ReadOK.
	File *File
	Now  time.Time
	// Seen is the seen mark; SeenOK false means it could not be read.
	Seen   uint64
	SeenOK bool
	Want   Versions
	// Dirty is the dirty counter; DirtyOK false means it could not be read.
	Dirty   uint64
	DirtyOK bool
}

// Reason is a closed reason code for a derived state.
type Reason string

// The Reason values, one per row of the state table.
const (
	ReasonModuleInactive  Reason = "module_inactive"
	ReasonNoDaemon        Reason = "no_daemon"
	ReasonGuardUnverified Reason = "guard_posture_unverified"
	ReasonMissing         Reason = "posture_missing"
	ReasonTooLarge        Reason = "posture_over_cap"
	ReasonUnverified      Reason = "posture_unverified"
	ReasonNoActivePack    Reason = "no_active_pack"
	ReasonExpired         Reason = "posture_expired"
	ReasonFromFuture      Reason = "posture_issued_in_future"
	ReasonSeenUnreadable  Reason = "seen_unreadable"
	ReasonRollback        Reason = "posture_rolled_back"
	ReasonVersionMismatch Reason = "version_mismatch"
	ReasonOverflow        Reason = "posture_overflow"
	ReasonScanStale       Reason = "scan_stale"
	ReasonDirtyUnreadable Reason = "dirty_unreadable"
	ReasonDirty           Reason = "unscanned_activity"
	ReasonBlocking        Reason = "blocking_findings"
	ReasonClean           Reason = "clean"
	ReasonNoProjectRoot   Reason = "no_project_root"
)

// MaxClockSkew is how far in the future an IssuedAt may be before the file
// reads as unknown.
const MaxClockSkew = time.Minute

// State is a derived project state.
type State struct {
	Posture policy.SecurityPosture
	// Blocking is n of blocking(n).
	Blocking int
	// HistoryOnly is how many of them an unpushed commit alone holds open
	// (File.HistoryOnly).
	HistoryOnly int
	// HistoryCapped is how many of the HistoryOnly ones are held only past
	// a reflog cap (File.HistoryCapped).
	HistoryCapped int
	// HistoryOnlyOn counts, per remote, the HistoryOnly findings that
	// remote already has (File.HistoryOnlyOn, each at most HistoryOnly);
	// empty when the held list was capped (no remote can be read as having
	// them all). Held are the held commits (File.Held).
	HistoryOnlyOn map[string]int
	Held          []HeldCommit
	// DefaultPushRemote is File.DefaultPushRemote while there is a
	// history-only hold.
	DefaultPushRemote string
	Reason            Reason
}

// stateRow is one row of the state table, walked top to bottom: the first
// row whose when matches decides (CLAUDE.md module rule 5).
type stateRow struct {
	when    func(in Input) bool
	posture policy.SecurityPosture
	reason  Reason
}

func fileOK(in Input) bool { return in.Read == ReadOK && in.File != nil }

// stateTable is the section 4.8 state table. Order is load-bearing: the
// module signal first, then every way the file cannot be trusted (each
// unknown, PR14), then dirty before blocking (the plan's blocking(n)
// requires "not dirty"), then clean.
var stateTable = []stateRow{
	{func(in Input) bool { return in.Module == ModuleInactive }, policy.SecurityPostureAbsent, ReasonModuleInactive},
	{func(in Input) bool { return in.Module == ModuleNoDaemon }, policy.SecurityPostureAbsent, ReasonNoDaemon},
	{func(in Input) bool { return in.Module != ModuleActive }, policy.SecurityPostureUnknown, ReasonGuardUnverified},
	{func(in Input) bool { return in.Read == ReadMissing }, policy.SecurityPostureUnknown, ReasonMissing},
	{func(in Input) bool { return in.Read == ReadTooLarge }, policy.SecurityPostureUnknown, ReasonTooLarge},
	{func(in Input) bool { return !fileOK(in) }, policy.SecurityPostureUnknown, ReasonUnverified},
	{func(in Input) bool { return len(in.File.Packs) == 0 }, policy.SecurityPostureAbsent, ReasonNoActivePack},
	{func(in Input) bool { return !in.Now.Before(in.File.ExpiresAt) }, policy.SecurityPostureUnknown, ReasonExpired},
	{func(in Input) bool { return in.File.IssuedAt.After(in.Now.Add(MaxClockSkew)) }, policy.SecurityPostureUnknown, ReasonFromFuture},
	{func(in Input) bool { return !in.SeenOK }, policy.SecurityPostureUnknown, ReasonSeenUnreadable},
	{func(in Input) bool { return in.File.Sequence < in.Seen }, policy.SecurityPostureUnknown, ReasonRollback},
	{func(in Input) bool {
		return in.Want.Check && (in.File.PolicyVersion != in.Want.Policy || in.File.BundleVersion != in.Want.Bundle)
	}, policy.SecurityPostureUnknown, ReasonVersionMismatch},
	{func(in Input) bool { return in.File.Overflow }, policy.SecurityPostureUnknown, ReasonOverflow},
	// The oldest scan the gate trusts ([security.scanning]
	// max_scan_staleness_min, lane LEFT-SEC): a project whose newest scan
	// is older, or that was never scanned, reads as unknown. Off (0) by
	// default, so the row matches nothing on a file that does not set it.
	{scanStale, policy.SecurityPostureUnknown, ReasonScanStale},
	{func(in Input) bool { return !in.DirtyOK }, policy.SecurityPostureDirty, ReasonDirtyUnreadable},
	{func(in Input) bool { return in.Dirty > in.File.DirtyCleanEpoch }, policy.SecurityPostureDirty, ReasonDirty},
	{func(in Input) bool { return len(in.File.Blocking) > 0 }, policy.SecurityPostureBlocking, ReasonBlocking},
	{func(Input) bool { return true }, policy.SecurityPostureClean, ReasonClean},
}

// scanStale reports a file whose scan is older than its signed staleness.
func scanStale(in Input) bool {
	m := in.File.MaxScanStalenessMin
	return m > 0 && in.Now.Sub(in.File.ScannedAt) > time.Duration(m)*time.Minute
}

// Derive is the one pure function that turns what the hook (or the
// daemon) read into the project's state (section 4.8).
func Derive(in Input) State {
	for _, r := range stateTable {
		if r.when(in) {
			st := State{Posture: r.posture, Reason: r.reason}
			if r.posture == policy.SecurityPostureBlocking {
				st.Blocking = len(in.File.Blocking)
				st.HistoryOnly = historyOnlyIn(in.File)
				st.HistoryCapped = historyCappedIn(in.File)
				st.HistoryOnlyOn, st.Held = heldIn(in.File, st.HistoryOnly)
				if st.HistoryOnly > 0 {
					st.DefaultPushRemote = in.File.DefaultPushRemote
				}
			}
			return st
		}
	}
	return State{Posture: policy.SecurityPostureUnknown, Reason: ReasonUnverified}
}

// historyOnlyIn counts the distinct HistoryOnly keys that are in Blocking
// (a file built in memory is not normalized yet).
func historyOnlyIn(f *File) int {
	in := make(map[string]bool, len(f.Blocking))
	for _, k := range f.Blocking {
		in[k] = true
	}
	n := 0
	for _, k := range f.HistoryOnly {
		if in[k] {
			n++
			in[k] = false
		}
	}
	return n
}

// historyCappedIn counts the distinct HistoryCapped keys that are
// history-only blocking keys.
func historyCappedIn(f *File) int {
	if len(f.HistoryCapped) == 0 {
		return 0
	}
	in := make(map[string]bool, len(f.Blocking))
	for _, k := range f.Blocking {
		in[k] = true
	}
	only := make(map[string]bool, len(f.HistoryOnly))
	for _, k := range f.HistoryOnly {
		if in[k] {
			only[k] = true
		}
	}
	n := 0
	for _, k := range f.HistoryCapped {
		if only[k] {
			n++
			only[k] = false
		}
	}
	return n
}

// heldIn copies the per-remote counts (capped at n, the history-only
// count) and the held commits off a file. A capped held list keeps the
// commits for the wording but no per-remote count: a key past the cap
// could hold a commit no remote has.
func heldIn(f *File, n int) (map[string]int, []HeldCommit) {
	if n == 0 {
		return nil, nil
	}
	held := append([]HeldCommit(nil), f.Held...)
	if f.HeldOverflow || len(f.HistoryOnlyOn) == 0 {
		return nil, held
	}
	on := make(map[string]int, len(f.HistoryOnlyOn))
	for r, k := range f.HistoryOnlyOn {
		if k > 0 {
			on[r] = min(k, n)
		}
	}
	return on, held
}

// ModuleSignalFrom reads the module signal off a guard posture load
// result: its state (absent, valid or tampered) and, when valid, the two
// MAC-covered security fields. A posture from a daemon that does not
// record the module reads as inactive: that daemon never ran it.
func ModuleSignalFrom(state guardposture.State, p *guardposture.Posture) ModuleSignal {
	switch {
	case state == guardposture.StateAbsent:
		return ModuleNoDaemon
	case state != guardposture.StateValid || p == nil:
		return ModuleUnverified
	case p.SecurityRecorded && p.SecurityActive:
		return ModuleActive
	default:
		return ModuleInactive
	}
}
