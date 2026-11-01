//go:build !sbo_omit_terminals_sandbox_oci && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxengine"
	"github.com/marmutapp/superbased-observer/internal/sandboximage"
	"github.com/marmutapp/superbased-observer/internal/sandboxoci"
)

// terminal_sandbox_oci_pull.go is Observer's default image on this machine
// (sandbox plan v2 section 12.3, ledger SBX-IMG-1, lane SBX-P3C): the pull
// by digest and the removal of a revoked image. Both act only once a signed
// sandbox.image manifest is installed (none is published yet, so nothing
// changes until the operator's release signing step), and only on a
// user-launched oci launch or an explicit `observer sandbox oci image ...`
// verb, never in the background.
//
//   - Pull: only after the manifest resolves (signed, and fresh: an expired
//     manifest leaves only an image already present usable, as
//     last-known-good), only repository@digest from the signed descriptor;
//     the engine fetches it, the progress names each layer's size, a
//     reported digest other than the one asked for is refused, and the image
//     is read back (id, platform) through the same check every launch runs
//     before it is used. An image that fails the read-back is removed again.
//     The pull is recorded under the observer directory (pulled-images.json).
//   - Prune: at the next launch and in `observer sandbox oci image prune`,
//     an image in that record whose digest or id the manifest revokes is
//     removed from the engine, unless it no longer carries Observer's label
//     or a container still uses it (refused by name); the tool cache volumes
//     keyed by a revoked digest go too. A user's or a .devcontainer image is
//     never in the record.

// ociDefaultPullTimeout bounds one pull of the default image.
var ociDefaultPullTimeout = 10 * time.Minute

// ociPulledFile is the host's record of the images Observer pulled.
func ociPulledFile(observerDir string) string {
	return filepath.Join(ociStateDir(observerDir), "pulled-images.json")
}

// ociPulledImages reads the record (empty when none or unreadable).
func ociPulledImages(observerDir string) []sandboxoci.PulledImage {
	b, err := readOwnedNoFollow(ociPulledFile(observerDir), 1<<20)
	if err != nil {
		return nil
	}
	var list []sandboxoci.PulledImage
	if json.Unmarshal(b, &list) != nil {
		return nil
	}
	return list
}

// setOCIPulled records img (keep true) or forgets its reference.
func setOCIPulled(observerDir string, img sandboxoci.PulledImage, keep bool) error {
	var out []sandboxoci.PulledImage
	for _, p := range ociPulledImages(observerDir) {
		if p.Ref != img.Ref {
			out = append(out, p)
		}
	}
	if keep {
		out = append(out, img)
	}
	if out == nil {
		out = []sandboxoci.PulledImage{}
	}
	return writeOCIStateFile(ociPulledFile(observerDir), out)
}

// ociPullDefault pulls the trusted default image by digest, reads it back
// and records it. say receives the lines to show (the source and each
// layer's size). It returns what was pulled and its size in bytes.
func ociPullDefault(ctx context.Context, c *sandboxengine.Client, trust ociImageTrust, observerDir string, say func(string)) (sandboxoci.PulledImage, int64, error) {
	switch {
	case trust.refusal != "":
		return sandboxoci.PulledImage{}, 0, fmt.Errorf("%s: %s; nothing was pulled", sandboxoci.VerdictArtifactUnverified, trust.refusal)
	case trust.desc == nil:
		return sandboxoci.PulledImage{}, 0, fmt.Errorf("%s: no signed sandbox.image manifest is installed, so Observer's default image is not known (it is not published yet); nothing was pulled", sandboxoci.VerdictArtifactUnverified)
	case trust.stale:
		return sandboxoci.PulledImage{}, 0, fmt.Errorf("%s (%s): the default image's manifest has expired, and a pull needs a fresh one (only an image already present runs as last-known-good); nothing was pulled", sandboxoci.VerdictArtifactUnverified, sandboximage.ReasonNeedsFresh)
	}
	d := *trust.desc
	ref := d.Ref()
	// Said before the download starts (audit finding 5): the source, the
	// declared size and the bounds; the pull is stopped past either bound.
	say(sandboxoci.PullAnnouncement(ref, d.Version, d.Repository, d.SizeBytes, ociDefaultPullTimeout.String()))
	bound := sandboxoci.PullByteBound(d.SizeBytes)
	var tr sandboxoci.PullTracker
	pctx, cancel := context.WithTimeout(ctx, ociDefaultPullTimeout)
	defer cancel()
	over := false
	err := c.ImagePullStream(pctx, ref, func(ev sandboxengine.PullEvent) {
		if l := tr.Add(ev.Status, ev.ID, ev.Total, ev.Error); l != "" {
			say(l)
		}
		if !over && tr.Bytes() > bound {
			over = true
			cancel()
		}
	})
	if over {
		_ = c.ImageRemove(context.Background(), ref)
		return sandboxoci.PulledImage{}, 0, fmt.Errorf("pull %s: stopped: its layers passed %s, the bound for this image; nothing was used", ref, sandboxoci.HumanBytes(bound))
	}
	if err != nil {
		v := sandboxoci.PullFailure(ociHost(), "", err.Error())
		return sandboxoci.PulledImage{}, 0, fmt.Errorf("pull %s: %s", ref, v.Error())
	}
	if err := sandboxoci.CheckPulledDigest(d.Digest, tr.Digest()); err != nil {
		_ = c.ImageRemove(context.Background(), ref)
		return sandboxoci.PulledImage{}, 0, fmt.Errorf("%s: %w", sandboxoci.VerdictArtifactUnverified, err)
	}
	ictx, icancel := context.WithTimeout(ctx, 30*time.Second)
	id, err := c.ImageIdentity(ictx, ref)
	icancel()
	if err != nil {
		return sandboxoci.PulledImage{}, 0, fmt.Errorf("%s: the engine did not answer about the pulled image: %w", sandboxoci.VerdictArtifactUnverified, err)
	}
	if r := ociCheckDefaultImage(trust, id); !r.OK {
		_ = c.ImageRemove(context.Background(), ref)
		return sandboxoci.PulledImage{}, 0, fmt.Errorf("the pulled image failed its read-back and was removed: %s", r.Error())
	}
	img := sandboxoci.PulledImage{Ref: ref, Digest: d.Digest, ID: id.ID}
	if err := setOCIPulled(observerDir, img, true); err != nil {
		return img, tr.Bytes(), fmt.Errorf("record the pulled image: %w", err)
	}
	say(fmt.Sprintf("pulled %s (%s), read back as image %s for %s/%s", ref, sandboxoci.HumanBytes(tr.Bytes()), id.ID, id.OS, id.Architecture))
	return img, tr.Bytes(), nil
}

// ociPruneResult is one prune's outcome.
type ociPruneResult struct {
	Removed []string
	Refused []string
	Caches  []string
}

// ociPruneRevoked removes the revoked images Observer pulled and the cache
// volumes keyed by a revoked digest (revoked: the manifest's predicate; nil
// does nothing).
func ociPruneRevoked(ctx context.Context, c *sandboxengine.Client, observerDir, installID string, revoked func(string) bool) (ociPruneResult, error) {
	var res ociPruneResult
	if revoked == nil {
		return res, nil
	}
	var errs []error
	pulled := ociPulledImages(observerDir)
	verdicts := sandboxoci.PlanPrune(pulled, func(img sandboxoci.PulledImage) sandboxoci.PulledImageState {
		sctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		id, err := c.ImageIdentity(sctx, img.Ref)
		if err != nil {
			// Unknown: the image is treated as present, unlabelled, so the
			// prune refuses rather than guesses.
			return sandboxoci.PulledImageState{Present: true, ID: "?"}
		}
		st := sandboxoci.PulledImageState{Present: id.Present, ID: id.ID, Labels: id.Labels}
		if id.Present {
			st.UsedBy, _ = c.ContainersUsing(sctx, img.Ref)
		}
		return st
	}, revoked)
	for _, v := range verdicts {
		switch v.Action {
		case sandboxoci.PruneForget:
			if err := setOCIPulled(observerDir, v.Image, false); err != nil {
				errs = append(errs, err)
			}
		case sandboxoci.PruneRefuse:
			res.Refused = append(res.Refused, v.Reason)
		case sandboxoci.PruneRemove:
			rctx, cancel := context.WithTimeout(ctx, 60*time.Second)
			err := c.ImageRemove(rctx, v.Image.Ref)
			cancel()
			if err != nil {
				res.Refused = append(res.Refused, fmt.Sprintf("%s is revoked but the engine did not remove it: %v", v.Image.Ref, err))
				continue
			}
			res.Removed = append(res.Removed, v.Image.Ref)
			if err := setOCIPulled(observerDir, v.Image, false); err != nil {
				errs = append(errs, err)
			}
		}
	}
	lctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	vols, err := c.VolumeList(lctx, sandboxoci.CacheFilter(installID, "", ""))
	cancel()
	if err != nil {
		errs = append(errs, fmt.Errorf("list the tool caches: %w", err))
		return res, errors.Join(errs...)
	}
	facts := make([]sandboxoci.CacheVolumeFact, 0, len(vols))
	for _, v := range vols {
		facts = append(facts, sandboxoci.CacheVolumeFact{Name: v.Name, Labels: v.Labels})
	}
	for _, name := range sandboxoci.RevokedCaches(facts, installID, revoked) {
		rctx, rcancel := context.WithTimeout(ctx, 30*time.Second)
		err := c.VolumeRemove(rctx, name)
		rcancel()
		if err != nil {
			res.Refused = append(res.Refused, fmt.Sprintf("the cache %s of a revoked image was kept: %v", name, err))
			continue
		}
		_ = setOCICacheRecord(observerDir, name, nil)
		_ = ociRemoveCacheDir(observerDir, name)
		res.Caches = append(res.Caches, name)
	}
	return res, errors.Join(errs...)
}
