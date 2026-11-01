package orgclient

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/fsatomic"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/projectmatch"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// The project audience on the guard bundle rail, node accept side (security
// plan section 7.11, spike JSP-10, lane sec-p). A v3 delivery (the server
// answers binding-v3 only once the org published a project-scoped bundle) is
// gated by projectmatch.AcceptDelivery after the composed bundle's own
// signature and key pin verified, and on success the org client is the ONE
// writer of:
//
//   - the signed mapping and one file per project envelope, beside the org
//     bundle cache (projectmatch.Layout), which the guard reads;
//   - the node-local mapping index (store.ReplaceOrgProjectMappingIndex), which
//     the daemon's matcher reads;
//   - a guard_policy_state row (#project-audience) recording the epoch, the
//     downgrade fence that survives a deleted cache file.
//
// The composed bundle is cached WITHOUT its projects field, so the hook's org
// layer reads the same small file as before.

// ProjectAudienceStateSuffix tags the guard_policy_state row that records the
// last accepted project audience: Path = <org-server-url> + this suffix,
// Version = the epoch, ContentHash = the mapping digest.
const ProjectAudienceStateSuffix = store.ProjectAudienceFenceSuffix

// policyBundleMaxBody bounds a policy-bundle response. A v3 delivery carries
// up to orgcontract.MaxProjectMappingProjects envelopes and the mapping, so
// it is larger than the 1 MiB a bundle alone ever needed.
const policyBundleMaxBody = 8 << 20

// heldProjectAudience is what the node remembers: a v3 delivery was held
// (the cached bundle carries a project binding, or a state row exists) and
// the highest epoch accepted.
func (c *Client) heldProjectAudience(ctx context.Context, cachePath, orgURL string) (projectmatch.Held, error) {
	var held projectmatch.Held
	if pb := cachedProjectBinding(cachePath); pb != nil {
		held = projectmatch.Held{HadV3: true, Epoch: pb.Epoch}
	}
	states, err := c.store.LatestGuardPolicyStates(ctx)
	if err != nil {
		return held, err
	}
	for _, st := range states {
		if st.Layer == "org" && st.Path == orgURL+ProjectAudienceStateSuffix {
			held.HadV3 = true
			if e, perr := strconv.ParseInt(st.Version, 10, 64); perr == nil && e > held.Epoch {
				held.Epoch = e
			}
		}
	}
	return held, nil
}

// cachedProjectBinding reads the project binding of the bundle cached at path
// (nil when absent, unreadable or not v3).
func cachedProjectBinding(path string) *orgcontract.ProjectBinding {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var held struct {
		ProjectBinding *orgcontract.ProjectBinding `json:"project_binding"`
	}
	if json.Unmarshal(raw, &held) != nil {
		return nil
	}
	return held.ProjectBinding
}

// projectGate runs the v3 accept gate for b. It returns a rejection (true)
// with its detail, or false when b may be accepted.
func (c *Client) projectGate(ctx context.Context, b orgcontract.PolicyBundle, enr *store.Enrolment, cachePath string, key ed25519.PublicKey) (PolicyResult, bool, error) {
	held, err := c.heldProjectAudience(ctx, cachePath, enr.OrgServerURL)
	if err != nil {
		return PolicyResult{}, false, fmt.Errorf("orgclient.FetchPolicyBundle: read project audience state: %w: %w", errPolicyLocalPreResponse, err)
	}
	if _, err := projectmatch.AcceptDelivery(held, b, projectmatch.Identity{OrgID: enr.OrgID, Subject: enr.UserID}, key); err != nil {
		code := RejectSigInvalid
		if errors.Is(err, projectmatch.ErrEpochLower) {
			code = RejectVersionDowngrade
		}
		return PolicyResult{
			Status: PolicyRejected, Version: b.Version, RejectCode: code,
			Detail: "project audience: " + err.Error(),
		}, true, nil
	}
	return PolicyResult{}, false, nil
}

// writeProjectAudience writes an ACCEPTED v3 delivery's project half: every
// envelope, then the mapping, then the index and the state row; envelope files
// of projects no longer listed are removed. The composed bundle itself is
// written by the caller AFTER this returns, so a guard that reads the new
// composed bundle always finds its files (a guard reading the old one in the
// window finds a newer mapping, reads it as of another delivery, and treats
// the project layer as unknown until the bundle lands; the org, team and
// member layers apply throughout).
func (c *Client) writeProjectAudience(ctx context.Context, b orgcontract.PolicyBundle, cachePath, orgURL string, now time.Time) error {
	if b.ProjectBinding == nil || b.Projects == nil {
		return nil
	}
	l := projectmatch.LayoutFor(cachePath)
	keep := map[string]bool{}
	for _, env := range b.Projects.Envelopes {
		raw, err := json.Marshal(env)
		if err != nil {
			return fmt.Errorf("orgclient.writeProjectAudience: marshal envelope: %w", err)
		}
		path := l.EnvelopePath(env.ProjectBinding.OrgProjectID)
		if err := writeProjectFile(path, raw); err != nil {
			return err
		}
		keep[filepath.Base(path)] = true
	}
	mf := projectmatch.MappingFile{Mapping: b.Projects.Mapping, BundleVersion: b.Version, AcceptedAt: now.UTC()}
	raw, err := json.Marshal(mf)
	if err != nil {
		return fmt.Errorf("orgclient.writeProjectAudience: marshal mapping: %w", err)
	}
	if err := writeProjectFile(l.MappingPath(), raw); err != nil {
		return err
	}
	// Envelopes the resolve call returned are bound to the previous
	// delivery's version: drop them, and the matcher asks again for the
	// roots whose records named them (lane sec-p2a).
	_ = os.RemoveAll(l.ResolvedDir())
	if entries, err := os.ReadDir(l.EnvelopesDir()); err == nil {
		for _, e := range entries {
			if !keep[e.Name()] && strings.HasSuffix(e.Name(), ".json") {
				_ = os.Remove(filepath.Join(l.EnvelopesDir(), e.Name()))
			}
		}
	}
	if err := c.store.ReplaceOrgProjectMappingIndex(ctx, b.ProjectBinding.Epoch, b.ProjectBinding.MappingDigest, indexRows(b.Projects.Mapping)); err != nil {
		return err
	}
	if _, err := c.store.RecordGuardPolicyState(ctx, store.GuardPolicyStateRow{
		Layer:       "org",
		Path:        orgURL + ProjectAudienceStateSuffix,
		Version:     strconv.FormatInt(b.ProjectBinding.Epoch, 10),
		ContentHash: b.ProjectBinding.MappingDigest,
		LoadedAt:    now.UTC(),
	}); err != nil {
		return fmt.Errorf("orgclient.writeProjectAudience: record state: %w", err)
	}
	return nil
}

// indexRows flattens a mapping into the node-local index's rows.
func indexRows(m orgcontract.ProjectMapping) []store.OrgProjectMappingRow {
	var out []store.OrgProjectMappingRow
	for _, e := range m.Projects {
		for _, r := range e.Repos {
			for _, h := range []string{r.RemoteHash, r.UpstreamRemoteHash} {
				if h != "" {
					out = append(out, store.OrgProjectMappingRow{Hash: h, Kind: store.OrgProjectHashRemote, OrgProjectID: e.OrgProjectID})
				}
			}
			if r.RootCommitHash != "" {
				out = append(out, store.OrgProjectMappingRow{Hash: r.RootCommitHash, Kind: store.OrgProjectHashRoot, OrgProjectID: e.OrgProjectID})
			}
		}
	}
	return out
}

// confirmProjectMapping records that the org just confirmed (a 304) the
// mapping the node holds, which restarts its offline lifetime. A node with no
// mapping file does nothing.
func confirmProjectMapping(cachePath string, now time.Time) {
	l := projectmatch.LayoutFor(cachePath)
	raw, err := os.ReadFile(l.MappingPath())
	if err != nil {
		return
	}
	mf, err := projectmatch.DecodeMappingFile(raw)
	if err != nil {
		return
	}
	mf.AcceptedAt = now.UTC()
	if out, err := json.Marshal(mf); err == nil {
		_ = writeProjectFile(l.MappingPath(), out)
	}
}

// projectFilesPresent reports whether the project half the cached bundle
// names is on disk: true for a bundle with no project binding; for a v3
// bundle, a mapping file of the same version must exist. A conditional
// request is sent only when it holds, so a deleted mapping is re-downloaded.
func projectFilesPresent(cachePath string) bool {
	pb := cachedProjectBinding(cachePath)
	if pb == nil {
		return true
	}
	l := projectmatch.LayoutFor(cachePath)
	raw, err := os.ReadFile(l.MappingPath())
	if err != nil {
		return false
	}
	mf, err := projectmatch.DecodeMappingFile(raw)
	if err != nil || orgcontract.ProjectMappingDigest(mf.Mapping) != pb.MappingDigest {
		return false
	}
	// A mapped project whose envelope file is gone (deleted, or never
	// written because the server could not compose it) is fetched again in
	// full rather than kept by a 304 (audit finding 4).
	for _, e := range mf.Mapping.Projects {
		if _, err := os.Stat(l.EnvelopePath(e.OrgProjectID)); err != nil {
			return false
		}
	}
	return true
}

// writeProjectFile is the atomic, owner-only write every project file uses.
func writeProjectFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("orgclient.writeProjectFile: %w", err)
	}
	if err := fsatomic.WriteFile(path, data, fsatomic.Options{TempPattern: ".org-project-*.tmp"}); err != nil {
		return fmt.Errorf("orgclient.writeProjectFile: %w", err)
	}
	return nil
}
