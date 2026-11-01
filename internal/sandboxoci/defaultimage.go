package sandboxoci

import (
	"fmt"
	"sort"
	"strings"
)

// defaultimage.go is Observer's default image on this machine (sandbox
// plan v2 section 12.3, ledger SBX-IMG-1, lane SBX-P3C): the pull by digest
// once a signed sandbox.image manifest resolves, and the removal of an image
// the manifest later revokes. Pure: the cmd layer reads the manifest, the
// engine and the host's record of the images it pulled, and runs the calls.
//
// What the prune may ever remove is narrow by construction: only an image
// Observer itself pulled (a reference in the host's own pull record) that
// still carries the default image's own label (ObserverImageLabel, set by
// deploy/sandbox-image's recipe) and whose digest or image id the manifest
// revokes. A user's image, a .devcontainer image and an image re-tagged or
// rebuilt under the same name are never in that set; an image a container
// still uses is refused by name.

// ObserverImageLabel is the label Observer's default image recipe sets
// (deploy/sandbox-image/Dockerfile); an image without it is never pruned.
const ObserverImageLabel = "app.superbased.observer.sandbox.agent-cli"

// PulledImage is one image the host's own record says Observer pulled.
type PulledImage struct {
	// Ref is the reference pulled (repository@sha256:<64 hex>).
	Ref string `json:"ref"`
	// Digest is the reference's digest (sha256:<64 hex>).
	Digest string `json:"digest"`
	// ID is the image id the read-back saw after the pull.
	ID string `json:"id"`
}

// PulledImageState is what the engine says about one pulled image now.
type PulledImageState struct {
	Present bool
	ID      string
	Labels  map[string]string
	// UsedBy are the containers (running or not) made from it.
	UsedBy []string
}

// PruneAction is what the prune does with one pulled image.
type PruneAction string

// The PruneAction values.
const (
	// PruneKeep: not revoked.
	PruneKeep PruneAction = "keep"
	// PruneForget: no longer in the engine; the record goes.
	PruneForget PruneAction = "forget"
	// PruneRefuse: revoked but not removed; Reason says why.
	PruneRefuse PruneAction = "refuse"
	// PruneRemove: revoked, Observer's own and unused: removed.
	PruneRemove PruneAction = "remove"
)

// PruneVerdict is one pulled image's answer.
type PruneVerdict struct {
	Image  PulledImage
	Action PruneAction
	Reason string
}

// pruneRule is one row of the prune table, walked top-down; the first
// matching row decides.
type pruneRule struct {
	name   string
	match  func(img PulledImage, st PulledImageState, revoked bool) bool
	action PruneAction
	reason func(img PulledImage, st PulledImageState) string
}

var pruneRules = []pruneRule{
	{name: "not revoked", match: func(_ PulledImage, _ PulledImageState, revoked bool) bool { return !revoked }, action: PruneKeep},
	{name: "gone", match: func(_ PulledImage, st PulledImageState, _ bool) bool { return !st.Present }, action: PruneForget},
	{
		name: "not Observer's image",
		match: func(_ PulledImage, st PulledImageState, _ bool) bool {
			_, ok := st.Labels[ObserverImageLabel]
			return !ok
		},
		action: PruneRefuse,
		reason: func(img PulledImage, _ PulledImageState) string {
			return img.Ref + " no longer carries Observer's image label (re-tagged or rebuilt under the name); left alone, remove it yourself if it is yours"
		},
	},
	{
		name: "another id",
		match: func(img PulledImage, st PulledImageState, _ bool) bool {
			return img.ID != "" && !strings.EqualFold(img.ID, st.ID)
		},
		action: PruneRefuse,
		reason: func(img PulledImage, st PulledImageState) string {
			return fmt.Sprintf("%s is now image %s, not the %s Observer pulled; left alone", img.Ref, st.ID, img.ID)
		},
	},
	{
		name:   "in use",
		match:  func(_ PulledImage, st PulledImageState, _ bool) bool { return len(st.UsedBy) > 0 },
		action: PruneRefuse,
		reason: func(img PulledImage, st PulledImageState) string {
			used := append([]string(nil), st.UsedBy...)
			sort.Strings(used)
			return fmt.Sprintf("%s is revoked but still used by container %s; stop and remove it, then prune again", img.Ref, strings.Join(used, ", "))
		},
	},
	{name: "remove", match: func(PulledImage, PulledImageState, bool) bool { return true }, action: PruneRemove},
}

// PlanPrune judges every pulled image: revoked reports whether a sha256 hex
// (a digest or an image id, without "sha256:") is revoked by the manifest;
// state is the engine's answer for an image.
func PlanPrune(pulled []PulledImage, state func(PulledImage) PulledImageState, revoked func(hex string) bool) []PruneVerdict {
	out := make([]PruneVerdict, 0, len(pulled))
	for _, img := range pulled {
		st := state(img)
		rv := revoked != nil && (revoked(strings.TrimPrefix(img.Digest, "sha256:")) || (img.ID != "" && revoked(strings.TrimPrefix(img.ID, "sha256:"))))
		for _, r := range pruneRules {
			if !r.match(img, st, rv) {
				continue
			}
			v := PruneVerdict{Image: img, Action: r.action}
			if r.reason != nil {
				v.Reason = r.reason(img, st)
			}
			out = append(out, v)
			break
		}
	}
	return out
}

// RevokedCaches picks, from this install's cache volumes, the ones keyed by
// a revoked image digest (their LabelCacheImage), sorted.
func RevokedCaches(vols []CacheVolumeFact, installID string, revoked func(hex string) bool) []string {
	var out []string
	for _, v := range vols {
		if v.Labels[LabelRole] != RoleToolCache || v.Labels[LabelInstall] != installID {
			continue
		}
		if d := strings.TrimPrefix(v.Labels[LabelCacheImage], "sha256:"); d != "" && revoked != nil && revoked(d) {
			out = append(out, v.Name)
		}
	}
	sort.Strings(out)
	return out
}

// PullTracker sums a pull's progress stream: the layers seen and their
// sizes, the digest the engine reports, and the lines worth showing (one per
// layer when it completes, so a terminal is not flooded).
type PullTracker struct {
	totals map[string]int64
	done   map[string]bool
	digest string
}

// Add takes one progress event and returns the line worth showing for it
// ("" for none).
func (t *PullTracker) Add(status, id string, total int64, errMsg string) string {
	if t.totals == nil {
		t.totals, t.done = map[string]int64{}, map[string]bool{}
	}
	if errMsg != "" {
		return "the engine reported: " + errMsg
	}
	if d, ok := strings.CutPrefix(status, "Digest: "); ok {
		t.digest = strings.TrimSpace(d)
		return ""
	}
	if id != "" && total > t.totals[id] {
		t.totals[id] = total
	}
	if id != "" && (status == "Pull complete" || status == "Already exists") && !t.done[id] {
		t.done[id] = true
		if total := t.totals[id]; total > 0 {
			return fmt.Sprintf("layer %s: %s", shortLayer(id), HumanBytes(total))
		}
		return fmt.Sprintf("layer %s: %s", shortLayer(id), strings.ToLower(status))
	}
	return ""
}

// Digest is the digest the engine reported ("" when it named none).
func (t *PullTracker) Digest() string { return t.digest }

// Bytes is the sum of the layer sizes the stream reported.
func (t *PullTracker) Bytes() int64 {
	var n int64
	for _, v := range t.totals {
		n += v
	}
	return n
}

// DefaultPullByteBound stops a pull of an image whose manifest declares no
// size once its layers pass this many bytes.
const DefaultPullByteBound = 8 << 30

// PullByteBound is how many bytes of layers a pull may report before it is
// stopped (lane SBX-P3C audit finding 5): the declared size plus a tenth and
// 8 MB of slack, or DefaultPullByteBound when none is declared.
func PullByteBound(declared int64) int64 {
	if declared <= 0 {
		return DefaultPullByteBound
	}
	return declared + declared/10 + 8<<20
}

// PullAnnouncement is the line said before a pull starts: what, from where,
// how large (as the signed manifest declares it, or that it does not), and
// the bounds the pull is stopped at.
func PullAnnouncement(ref, version, repository string, declared int64, timeout string) string {
	size := "size not declared by the signed manifest"
	if declared > 0 {
		size = HumanBytes(declared) + " as the signed manifest declares"
	}
	return fmt.Sprintf("pulling Observer's default image %s (version %s, %s) from %s; the engine fetches it, and the pull is stopped past %s or %s",
		ref, version, size, repository, HumanBytes(PullByteBound(declared)), timeout)
}

// CheckPulledDigest refuses a pull whose engine reported another digest
// than the one asked for (a pull by digest must land that digest).
func CheckPulledDigest(want, reported string) error {
	if reported == "" || strings.EqualFold(want, reported) {
		return nil
	}
	return fmt.Errorf("the engine reported digest %s for a pull of %s; refused", reported, want)
}

func shortLayer(id string) string {
	id = strings.TrimPrefix(id, "sha256:")
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// HumanBytes is n as a short size (KB, MB, GB, base 1000, one decimal).
func HumanBytes(n int64) string {
	switch {
	case n >= 1_000_000_000:
		return fmt.Sprintf("%.1f GB", float64(n)/1e9)
	case n >= 1_000_000:
		return fmt.Sprintf("%.1f MB", float64(n)/1e6)
	case n >= 1_000:
		return fmt.Sprintf("%.1f KB", float64(n)/1e3)
	}
	return fmt.Sprintf("%d B", n)
}
