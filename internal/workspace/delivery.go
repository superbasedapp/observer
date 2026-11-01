package workspace

import "fmt"

// delivery.go maps a workspace source onto how the prepared tree reaches a
// box (sandbox plan v2 section 6, "Delivery"), from the backend row's
// filesystem modes. One table, one test per row; the first matching row
// wins.

// Delivery is how a prepared tree reaches the box.
type Delivery string

// The Delivery values (section 6).
const (
	DeliveryBindSamePath Delivery = "bind_same_path"
	DeliveryVirtiofs     Delivery = "virtiofs"
	DeliveryNinep        Delivery = "ninep"
	DeliveryDiskImage    Delivery = "disk_image"
	DeliverySync         Delivery = "sync"
	DeliveryRemoteClone  Delivery = "remote_clone"
)

// deliveryRule is one mapping row: the source it applies to, the
// deliveries it may use in preference order, and the refusal when the
// backend offers none of them.
type deliveryRule struct {
	source Source
	prefer []Delivery
	refuse string
}

// deliveryRules is the section 6 table. A live workspace is the host's own
// tree, so only a share keeps it live (a disk image or a copy would not); a
// clone works with any delivery; a worktree is a live share of a linked
// worktree (off by default, allow_worktree_source) and needs the host's own
// mounts, because the read-only parts of the main repository's .git folder
// are host-side binds a guest cannot be held to.
var deliveryRules = []deliveryRule{
	{SourceLive, []Delivery{DeliveryBindSamePath, DeliveryVirtiofs}, "the live source needs a shared tree (bind_same_path or virtiofs); this backend offers neither (source_unsupported)"},
	{SourceWorktree, []Delivery{DeliveryBindSamePath}, "the worktree source needs bind_same_path (the read-only parts of the main repository's .git folder are host-side binds)"},
	{SourceCloneLocal, []Delivery{DeliveryBindSamePath, DeliveryVirtiofs, DeliveryDiskImage, DeliverySync, DeliveryNinep}, "this backend offers no delivery for a local clone"},
	{SourceCloneRemote, []Delivery{DeliveryBindSamePath, DeliveryVirtiofs, DeliveryRemoteClone, DeliveryDiskImage, DeliverySync, DeliveryNinep}, "this backend offers no delivery for a remote clone"},
}

// DeliveryFor picks the delivery of src on a backend offering modes.
func DeliveryFor(src Source, modes []Delivery) (Delivery, error) {
	have := map[Delivery]bool{}
	for _, m := range modes {
		have[m] = true
	}
	for _, r := range deliveryRules {
		if r.source != src {
			continue
		}
		for _, d := range r.prefer {
			if have[d] {
				return d, nil
			}
		}
		return "", fmt.Errorf("workspace.DeliveryFor: %s", r.refuse)
	}
	return "", fmt.Errorf("workspace.DeliveryFor: unknown source %q", src)
}

// ReturnsWork reports whether a run of src leaves its work in a copy that
// the return step must bring back: every source but a live share (live,
// worktree).
func ReturnsWork(src Source) bool { return src != SourceLive && src != SourceWorktree }
