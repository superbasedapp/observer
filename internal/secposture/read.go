package secposture

import (
	"errors"
	"io"
	"os"
	"slices"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// Reading is one project's posture read on the hook path: what was read,
// the derived state, and the verified file when there is one.
type Reading struct {
	Input Input
	State State
	// File is the verified posture file; nil unless Input.Read is ReadOK.
	File *File
}

// Load reads one project's posture (key, file, seen mark, dirty counter)
// and derives its state. module is what the signed guard posture says; it
// is read by the caller because the hook already holds that read. Load
// never writes; Accept raises the seen mark after a state was used.
func Load(l Layout, projectRoot string, module ModuleSignal, now time.Time, want Versions) Reading {
	in := Input{Module: module, Now: now, Want: want, SeenOK: true, DirtyOK: true}
	hash := ProjectRootHash(projectRoot)
	if module != ModuleActive || l.Dir == "" || hash == "" {
		if module == ModuleActive {
			// Active, but the hook cannot name the project or the
			// directory: honestly unknown.
			in.Read = ReadMissing
			st := State{Posture: policy.SecurityPostureUnknown, Reason: ReasonNoProjectRoot}
			return Reading{Input: in, State: st}
		}
		return Reading{Input: in, State: Derive(in)}
	}
	in.Read, in.File = readFile(l, hash)
	in.Seen, in.SeenOK = readSeen(l, hash)
	if d, err := ReadDirty(l, hash); err != nil {
		in.DirtyOK = false
	} else {
		in.Dirty = d
	}
	r := Reading{Input: in, State: Derive(in)}
	if in.Read == ReadOK {
		r.File = in.File
	}
	return r
}

func readSeen(l Layout, hash string) (uint64, bool) {
	n, err := ReadSeen(l, hash)
	return n, err == nil
}

// readFile reads, size-caps, decodes and verifies one posture file. A file
// naming another project than its file name is unverified.
func readFile(l Layout, hash string) (ReadOutcome, *File) {
	key, err := ReadKey(l.KeyPath())
	if err != nil || key == nil {
		if _, statErr := os.Stat(l.PosturePath(hash)); errors.Is(statErr, os.ErrNotExist) && err == nil {
			return ReadMissing, nil
		}
		return ReadUnverified, nil
	}
	f, err := os.Open(l.PosturePath(hash))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ReadMissing, nil
		}
		return ReadUnverified, nil
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, MaxFileBytes+1))
	if err != nil {
		return ReadUnverified, nil
	}
	if len(data) > MaxFileBytes {
		return ReadTooLarge, nil
	}
	pf, err := Decode(data)
	if err != nil || !Verify(pf, key) {
		return ReadUnverified, nil
	}
	if pf.ProjectRootHash != hash {
		return ReadUnverified, nil
	}
	return ReadOK, pf
}

// Accept raises the project's seen mark to the verified file's sequence,
// so an older file put back in place later reads as a rollback. The hook
// calls it after a Load that used a verified file.
func Accept(l Layout, projectRoot string, r Reading) error {
	if r.File == nil || r.State.Reason == ReasonRollback {
		return nil
	}
	return RaiseSeen(l, ProjectRootHash(projectRoot), r.File.Sequence)
}

// Facts turns a reading into the Event.Security facts it carries (section
// 4.7 item 2): the posture state, n, the active pack set and the trust
// verdict. The in-hook detector hits, the quick scan and the install
// verdict are added by their own steps.
//
// The pack set, the trust verdict and the project match are copied from
// the file only when the state says the file is current (factRows): a
// validly signed but expired, rolled back, future or mismatched file must
// not put its old "trust clean" on the event. Otherwise Trust is unknown
// and, for an unknown state, the pack set is the module root alone: the
// root's commit gate rows are what answer an unknown state (they ask), and
// no child's membership can be read from a file that is not current.
func Facts(r Reading) policy.Security {
	sec := policy.Security{Posture: r.State.Posture, Blocking: r.State.Blocking, BlockingHistoryOnly: r.State.HistoryOnly, BlockingHistoryCapped: r.State.HistoryCapped, DefaultPushRemote: r.State.DefaultPushRemote}
	if len(r.State.HistoryOnlyOn) > 0 {
		sec.BlockingHistoryOnlyOn = make(map[string]int, len(r.State.HistoryOnlyOn))
		for k, n := range r.State.HistoryOnlyOn {
			sec.BlockingHistoryOnlyOn[k] = n
		}
	}
	for _, h := range r.State.Held {
		sec.HeldCommits = append(sec.HeldCommits, policy.HeldCommit{Commit: h.Commit, Remotes: append([]string(nil), h.Remotes...)})
	}
	if r.File != nil {
		sec.Overflow = r.File.Overflow
		// The floor only ever makes a decision stricter, so it is copied
		// from any file the reading has, also one that is past its expiry
		// or below the seen mark: an unknown state in a floored project
		// takes the floor's cell (deny), never the looser ask (PR14).
		sec.CommitGateFloor = r.File.CommitGateFloor
	}
	if r.File == nil || !factRows[r.State.Reason] {
		sec.Trust = policy.TrustUnknown
		if r.State.Posture == policy.SecurityPostureUnknown {
			sec.Packs = []string{RootPack}
		}
		return sec
	}
	sec.Packs = append([]string(nil), r.File.Packs...)
	sec.Trust = r.File.Trust
	sec.TrustReasons = append([]string(nil), r.File.TrustReasons...)
	if len(r.File.OrgProjectIDs) > 0 {
		sec.Project = policy.ProjectMatch{
			OrgProjectIDs: append([]string(nil), r.File.OrgProjectIDs...),
			Epoch:         r.File.AssignmentEpoch,
		}
	}
	return sec
}

// HeldOf returns the held commits a current verified file lists (lane
// sec-gate4 milestone 1d, for the opt-in pre-push hook): the unpushed
// commits that alone hold blocking findings open, whatever the dirty
// state. ok is false when there is no current file; a capped list is
// returned as it is.
func HeldOf(r Reading) ([]HeldCommit, bool) {
	if r.File == nil || !factRows[r.State.Reason] {
		return nil, false
	}
	if len(r.File.HistoryOnly) == 0 {
		return nil, true
	}
	return append([]HeldCommit(nil), r.File.Held...), true
}

// HeldOverflowOf reports whether a current verified file's held list was
// capped (File.HeldOverflow with a history-only hold): commits past the
// cap are held too, and nothing in the file names them (lane sec-gate4
// audit finding 8).
func HeldOverflowOf(r Reading) bool {
	if r.File == nil || !factRows[r.State.Reason] {
		return false
	}
	return len(r.File.HistoryOnly) > 0 && r.File.HeldOverflow
}

// FactsUnder is Facts for a hook whose signed guard posture says the
// module is active and carries the node's active pack set (signed, the
// guard posture's SecurityPacks). Whenever the project's own file cannot
// be used (missing, unverified, over the cap, expired, rolled back, from
// the future, a version mismatch, an overflow, no project root), the event
// still carries that signed set, so the commit gate (the root's rows) and
// the content-only rows (S-721) keep firing on the unknown state instead of
// going silent (lane SEC-GATEFIX, P-014 item 1). A reading whose file is
// current keeps the file's own set.
func FactsUnder(r Reading, signed []string) policy.Security {
	sec := Facts(r)
	if r.State.Posture == policy.SecurityPostureUnknown && (r.File == nil || !factRows[r.State.Reason]) {
		sec.Packs = UnknownPacks(signed)
	}
	return sec
}

// UnknownPacks is the pack set an unknown state carries under the signed
// set: the set with the module root added (the root's rows answer an
// unknown state), sorted and deduplicated. An empty signed set (a daemon
// that does not record it) yields the root alone.
func UnknownPacks(signed []string) []string {
	out := []string{RootPack}
	for _, id := range signed {
		if id != "" && !slices.Contains(out, id) {
			out = append(out, id)
		}
	}
	slices.Sort(out)
	return out
}

// RootPack is the module root's component id. Its rows (the commit gate)
// answer an unknown state, so an unknown reading carries it alone.
const RootPack = "security"

// factRows are the state reasons under which the verified file is current
// and its facts may be copied: every check on the file passed and the
// state came from its contents (clean, dirty, blocking) or from its empty
// pack set (no_active_pack). dirty_unreadable is one of them: the file
// passed every check, only the local dirty counter could not be read.
var factRows = map[Reason]bool{
	ReasonClean:           true,
	ReasonDirty:           true,
	ReasonDirtyUnreadable: true,
	ReasonBlocking:        true,
	ReasonNoActivePack:    true,
}
