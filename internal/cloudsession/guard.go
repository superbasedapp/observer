package cloudsession

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// guard.go is the self-modification guard. Live grounding (CA-A2) found that
// an edit to a repository's .claude/settings.json hooks takes effect on the
// very next tool call with no review prompt, so the agent can rewrite the
// hooks that capture it (drop the capture entries, change the flush
// destination) in the middle of the session it is being observed in.
//
// The guard ties a session's capture to the hook block the developer
// committed: the first flush of a session reads the owned block (every entry
// carrying OwnerTag, with its event and matcher) from the repository's HEAD
// commit and records its digest as the session's baseline; every flush then
// compares the working tree's owned block with the baseline and holds the
// delivery when they differ. It is a tamper EVIDENCE check against an agent
// editing its own configuration, not a boundary against an agent that runs
// as root in the same VM (docs/security.md CLOUDSESS-5).

// HookBlock is the owned hook block of one hook file.
type HookBlock struct {
	// Present reports that the file holds at least one owned entry.
	Present bool
	// Entries is the number of owned entries.
	Entries int
	// Digest is "sha256:<hex>" over the canonical owned entries; empty
	// when none is present.
	Digest string
}

// HookFile returns the repository file holding the agent's hook entries.
func HookFile(a Agent) (RepoFile, bool) {
	for _, f := range a.Files {
		r, err := rendererFor(f.Format)
		if err == nil && r.block != nil {
			return f, true
		}
	}
	return RepoFile{}, false
}

// OwnedHookBlock returns the owned hook block of the agent's hook file
// content. A missing file (exists=false) has no block. A file that does not
// parse has no owned block either: the agent's own entries cannot be
// trusted out of a file the vendor could not read.
func OwnedHookBlock(a Agent, content string, exists bool) (HookBlock, error) {
	f, ok := HookFile(a)
	if !ok {
		return HookBlock{}, fmt.Errorf("cloudsession: agent %q has no hook file", a.ID)
	}
	if !exists {
		return HookBlock{}, nil
	}
	r, err := rendererFor(f.Format)
	if err != nil {
		return HookBlock{}, err
	}
	lines := r.block(content)
	if len(lines) == 0 {
		return HookBlock{}, nil
	}
	// The block is a set: where the team's own event keys put Observer's
	// entries (and the vendor runs one event's hooks in parallel anyway)
	// does not change what runs.
	sort.Strings(lines)
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return HookBlock{Present: true, Entries: len(lines), Digest: "sha256:" + hex.EncodeToString(sum[:])}, nil
}

// ownedBlockLines returns one canonical line per owned entry of a hooks map
// (event, matcher, and the entry in the normalized two-space layout, so a
// whitespace-only reformat or a reordering does not change the digest while
// any change to an owned entry, its event or its matcher does). grouped is the Claude Code
// {matcher, hooks:[...]} shape; otherwise the entries sit in the arrays.
func ownedBlockLines(content string, grouped bool, commandKey string) []string {
	root, err := parseJSON(content)
	if err != nil || root.kind != jObject {
		return nil
	}
	hooks := root.get("hooks")
	if hooks == nil || hooks.kind != jObject {
		return nil
	}
	var lines []string
	add := func(event, matcher string, entry *jnode) {
		if entry.kind == jObject && ownedEntry(entry, commandKey) {
			lines = append(lines, jString(event).raw+"\t"+jString(matcher).raw+"\t"+strings.Join(strings.Fields(entry.encode()), " "))
		}
	}
	for i, event := range hooks.keys {
		arr := hooks.vals[i]
		if arr == nil || arr.kind != jArray {
			continue
		}
		for _, it := range arr.items {
			if !grouped {
				add(event, "", it)
				continue
			}
			if it.kind != jObject {
				continue
			}
			matcher, _ := it.get("matcher").stringValue()
			if inner := it.get("hooks"); inner != nil && inner.kind == jArray {
				for _, e := range inner.items {
					add(event, matcher, e)
				}
			}
		}
	}
	return lines
}

// BaselineSource says where a session's hook-block baseline was read from.
type BaselineSource string

// The baseline sources.
const (
	// BaselineHead: the hook file as committed at the repository's HEAD
	// when the session's first flush ran.
	BaselineHead BaselineSource = "head"
	// BaselineWorktree: the working-tree file, accepted only when the flush
	// was told to trust uncommitted hooks (a manual test before commit).
	BaselineWorktree BaselineSource = "worktree"
)

// HookBaseline is the recorded baseline of one agent's session.
type HookBaseline struct {
	Agent     string         `json:"agent"`
	VendorRef string         `json:"vendor_ref,omitempty"`
	Source    BaselineSource `json:"source"`
	Present   bool           `json:"present"`
	Digest    string         `json:"digest,omitempty"`
}

// NeedsBaseline reports whether this flush records a new baseline: none is
// recorded, it belongs to another vendor session (a VM reused across
// sessions), or the agent has no vendor session reference and this is the
// session's first hook.
func NeedsBaseline(prev *HookBaseline, agent, vendorRef string, spec TriggerSpec) bool {
	switch {
	case prev == nil || prev.Agent != agent:
		return true
	case prev.VendorRef != vendorRef:
		return true
	case vendorRef == "" && spec.StartsSession:
		return true
	}
	return false
}

// PlanBaseline picks the baseline for a new session: the block committed at
// HEAD, or, when HEAD has none and trustUncommitted is set, the working
// tree's block.
func PlanBaseline(agent, vendorRef string, head, worktree HookBlock, trustUncommitted bool) HookBaseline {
	b := HookBaseline{Agent: agent, VendorRef: vendorRef, Source: BaselineHead, Present: head.Present, Digest: head.Digest}
	if !head.Present && trustUncommitted {
		b.Source, b.Present, b.Digest = BaselineWorktree, worktree.Present, worktree.Digest
	}
	return b
}

// GuardVerdict is the guard's answer for one flush.
type GuardVerdict string

// The guard verdicts.
const (
	GuardVerified    GuardVerdict = "verified"
	GuardChanged     GuardVerdict = "changed"
	GuardUncommitted GuardVerdict = "uncommitted"
)

// guardRule is one row of the guard table.
type guardRule struct {
	verdict GuardVerdict
	reason  CoverageReason
	when    func(b HookBaseline, current HookBlock) bool
}

// guardRules is THE guard table, walked top-down.
var guardRules = []guardRule{
	{GuardUncommitted, ReasonHookBlockUncommitted, func(b HookBaseline, _ HookBlock) bool { return !b.Present }},
	{GuardChanged, ReasonHookBlockChanged, func(b HookBaseline, c HookBlock) bool { return !c.Present || c.Digest != b.Digest }},
	{GuardVerified, "", func(HookBaseline, HookBlock) bool { return true }},
}

// CheckHookBlock compares the working tree's owned block with the session's
// baseline. reason is the coverage reason to record when the verdict holds
// the delivery ("" for verified).
func CheckHookBlock(b HookBaseline, current HookBlock) (GuardVerdict, CoverageReason) {
	for _, r := range guardRules {
		if r.when(b, current) {
			return r.verdict, r.reason
		}
	}
	return GuardVerified, ""
}
