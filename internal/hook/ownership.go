package hook

import (
	"fmt"
	"os"
	"time"

	"github.com/marmutapp/superbased-observer/internal/fsatomic"
	"github.com/marmutapp/superbased-observer/internal/hookdigest"
)

// ownership.go - T-872: what a registration does when the place it writes is
// occupied by something that does not read as Observer's.
//
// Every writer recognises its own artifact by CONTENT (an observer `hook`
// command, a marker line). Some writers also own the artifact by NAME: the
// file is one Observer names in a plugin or hooks directory
// (superbased-observer.ts, observer-guard.ts, ~/.grok/hooks/
// superbased-observer.json), or the entry is one Observer names inside a
// shared file (the antigravity hook name, the vibe [[hooks]] name, the
// Poolside and Crush entry names). Before T-872 both kinds refused when the
// content no longer read as Observer's, so overwriting Observer's own plugin
// with an empty module, or stubbing the command under Observer's own hook
// name, left the tool ungated until someone ran `observer init --force` (the
// 2026-10-17 re-test, E1).
//
// conflictRules decides it, top-down, from four facts and never from a tool
// name: --force overwrites; a managed node's repair pass rewrites an artifact
// Observer owns by name AND has installed before (hook_checksums.json records
// a successful install at that path); everything else is refused, so a
// genuinely foreign hook, and every artifact that is Observer's only by
// content (an entry in the vendor's own event list, a hook file named after
// the vendor's event), keeps the refusal and stays a reported risk.

// artifactIdentity is how a writer's mechanism recognises its artifact
// independently of what the artifact holds now.
type artifactIdentity int

const (
	// identityContent: the artifact sits in a vendor-named slot (an event
	// list in the vendor's settings file, a hook file named after the event)
	// and is Observer's only while its content says so. Content that no
	// longer says so cannot be told apart from the developer's own hook.
	identityContent artifactIdentity = iota
	// identityOwnedName: the artifact carries a name only Observer uses (a
	// file Observer names, or an entry Observer names inside a shared file).
	identityOwnedName
)

// conflictAction is what a writer does with an occupied slot.
type conflictAction int

const (
	// conflictRefuse leaves the artifact alone and fails the registration
	// (the "pass --force" error); the integrity probe keeps reporting it.
	conflictRefuse conflictAction = iota
	// conflictRepair rewrites a neutralised Observer artifact and reports
	// the write as a repair (Rewrite rule ownedRepairRule).
	conflictRepair
	// conflictOverwrite is the operator's --force takeover.
	conflictOverwrite
)

// conflictFacts are the inputs of the decision.
type conflictFacts struct {
	// force is Options.Force.
	force bool
	// repairOwned is Options.RepairOwnedArtifacts (a managed node's repair
	// pass).
	repairOwned bool
	// identity is the writer's artifactIdentity for the occupied slot.
	identity artifactIdentity
	// installedByObserver is true when hook_checksums.json records a
	// successful Observer install at the artifact's path.
	installedByObserver bool
}

// conflictRule is one row of conflictRules.
type conflictRule struct {
	name   string
	when   func(conflictFacts) bool
	action conflictAction
}

// conflictRules is walked top-down; the first row whose when holds decides.
// The last row always holds.
var conflictRules = []conflictRule{
	{
		name:   "force",
		when:   func(f conflictFacts) bool { return f.force },
		action: conflictOverwrite,
	},
	{
		name: ownedRepairRule,
		when: func(f conflictFacts) bool {
			return f.repairOwned && f.identity == identityOwnedName && f.installedByObserver
		},
		action: conflictRepair,
	},
	{
		name:   "foreign",
		when:   func(conflictFacts) bool { return true },
		action: conflictRefuse,
	},
}

// decideConflict walks conflictRules and returns the deciding row's action
// and name.
func decideConflict(f conflictFacts) (conflictAction, string) {
	for _, row := range conflictRules {
		if row.when(f) {
			return row.action, row.name
		}
	}
	return conflictRefuse, "foreign"
}

// ownedRepairRule names the conflictRules row (and the Rewrite rule) of a
// managed repair of a neutralised Observer artifact.
const ownedRepairRule = "owned-neutralised"

// ownedRepairReason is the Rewrite reason the repair reports.
const ownedRepairReason = "Observer's own artifact (named by Observer, installed by Observer) no longer held Observer's hook; the managed repair pass rewrote it"

// resolveConflict decides what this registration does with an occupied slot
// at path whose content does not read as Observer's. The registry is read
// only when the answer depends on it.
func (r *Registry) resolveConflict(path string, id artifactIdentity) conflictAction {
	f := conflictFacts{force: r.opts.Force, repairOwned: r.opts.RepairOwnedArtifacts, identity: id}
	if f.repairOwned && !f.force && id == identityOwnedName {
		f.installedByObserver = r.observerInstalled(path)
	}
	action, _ := decideConflict(f)
	return action
}

// refuses reports whether resolveConflict refuses the slot: the one test the
// writers whose artifacts are Observer's only by content make before they
// fail with the --force error.
func (r *Registry) refuses(path string, id artifactIdentity) bool {
	return r.resolveConflict(path, id) == conflictRefuse
}

// observerInstalled reports whether hook_checksums.json records a successful
// Observer install at path: a checksum (whole-file or hooks-subtree) or the
// events a successful registration recorded. An entry that only records a
// failed attempt (last_result "error") is not evidence.
func (r *Registry) observerInstalled(path string) bool {
	entry := r.checksumEntries()[path]
	if entry == nil {
		return false
	}
	if s, _ := entry["sha256"].(string); s != "" {
		return true
	}
	if s, _ := entry[hookdigest.KeyDigest].(string); s != "" {
		return true
	}
	return len(entryEvents(entry)) > 0
}

// noteOwnedRepair records the managed repair of a neutralised artifact on res
// for every event the repair wrote back, so the caller's log names the rule.
// The events are already in res.HooksAdded, which is what Reconcile reports
// as hook_repaired. res.RepairCopy, when the repair kept one, is named too.
func noteOwnedRepair(res *RegistrationResult, path string, events []string) {
	from := "neutralised " + path
	if res.RepairCopy != "" {
		from += " (previous bytes kept at " + res.RepairCopy + ")"
	}
	for _, e := range events {
		res.Rewrites = append(res.Rewrites, Rewrite{
			Event:  e,
			Rule:   ownedRepairRule,
			Reason: ownedRepairReason,
			From:   from,
			To:     "observer's canonical entry",
		})
	}
}

// RepairCopiesKept is how many copies of one artifact's pre-repair bytes a
// managed node keeps (T-884). Each repair adds a new copy and removes the
// oldest beyond this many, so a repeatedly neutralised artifact cannot fill
// the disk while the recent history stays recoverable.
const RepairCopiesKept = 3

// keepRepairCopy keeps the pre-repair bytes of a non-credential artifact
// recoverable next to it before a managed repair rewrites it (T-884): a NEW
// file named fsatomic.DisplacedName(path, now) (the org bundle cache's
// ".displaced-<UTC>" convention), mode 0600, never an existing file, so a
// user's own path+".bak" is never touched. Only Observer's own displaced
// copies of path are pruned, to RepairCopiesKept. It records the copy on res
// (RepairCopy), which Reconcile persists and the integrity probe reports with
// hook_repaired. Empty data needs no copy.
func keepRepairCopy(res *RegistrationResult, path string, data []byte) error {
	if len(data) == 0 {
		return nil
	}
	aside, err := fsatomic.KeepDisplacedCopy(path, data, time.Now(), RepairCopiesKept)
	if err != nil {
		return fmt.Errorf("keep pre-repair copy of %s: %w", path, err)
	}
	res.RepairCopy = aside
	return nil
}

// keepRepairCopyOf is keepRepairCopy over the bytes at path now. A missing
// file needs no copy.
func keepRepairCopyOf(res *RegistrationResult, path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("keep pre-repair copy of %s: %w", path, err)
	}
	return keepRepairCopy(res, path, raw)
}

// keepReplacedBytes keeps the bytes a registration is about to replace in an
// occupied slot: a managed repair keeps a displaced copy (keepRepairCopy);
// the operator's --force takeover keeps the single path+".bak" it has always
// written (backupForeignCommandCodeMod).
func keepReplacedBytes(res *RegistrationResult, path string, data []byte, repair bool) error {
	if repair {
		return keepRepairCopy(res, path, data)
	}
	return backupForeignCommandCodeMod(path, data)
}

// occupiedOwnedFile is the foreign-file guard of a writer that writes a whole
// file Observer owns by name (a plugin shim, a Command Code mod, a plugin
// manifest): the file at path already holds existing, ours says whether it
// reads as Observer's, and hooks are the Observer-shaped entries found in it.
// A file that is Observer's and runs an Observer binary is no conflict. Any
// other file is resolved by resolveConflict(path, identityOwnedName): a
// refusal is returned as err (the FU-192 reason when an entry runs another
// binary, else "doesn't look like an observer-managed file", FU-207) and
// nothing may be written; repair is a managed repair of a neutralised file;
// foreign without repair is the operator's --force takeover. Either way the
// caller keeps the replaced bytes (keepReplacedBytes) before it writes.
func (r *Registry) occupiedOwnedFile(prefix, path string, ours bool, hooks []shapedHook) (foreign, repair bool, err error) {
	return r.occupiedOwnedFileIn(prefix, path, path, ours, hooks)
}

// occupiedOwnedFileIn is occupiedOwnedFile for a file that is one part of an
// artifact Observer installs as a whole (a plugin directory's manifest):
// owner is the path whose install record (hook_checksums.json) decides a
// managed repair.
func (r *Registry) occupiedOwnedFileIn(prefix, path, owner string, ours bool, hooks []shapedHook) (foreign, repair bool, err error) {
	_, foreignBin := r.foreignShapedHook(hooks)
	if ours && !foreignBin {
		return false, false, nil
	}
	switch r.resolveConflict(owner, identityOwnedName) {
	case conflictRefuse:
		if foreignBin {
			return true, false, foreignBinaryError(prefix, "", path)
		}
		return true, false, foreignFileError(prefix, path)
	case conflictRepair:
		return true, true, nil
	}
	return true, false, nil
}

// foreignFileError is the refusal of a whole file at a path Observer writes
// that does not read as Observer's.
func foreignFileError(prefix, path string) error {
	return fmt.Errorf("%s: %s already exists and doesn't look like an observer-managed file; pass --force to overwrite", prefix, path)
}
