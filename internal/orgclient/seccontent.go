package orgclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/contentchan"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// seccontent.go is the managed node's fetch of the org mirror's security
// content (security plan 8.3 and 8.5, the mirror side; lane SEC-E4): the
// vendor-signed envelope and the artifacts of each security content kind,
// from GET orgcontract.AgentSecurityContentPath on the enrolled org server
// only, over the existing org.client lane (its bearer, TLS and key pin),
// installed through internal/contentchan with the content channel's
// signature, rollback, epoch and expiry rules unchanged. The org server
// cannot sign content: every envelope is verified against the vendor keys
// the caller passes, exactly as one from the public feed would be.
//
// A failed fetch (the server down, the relay not configured, the kind not
// mirrored) changes nothing on disk: the last-known-good stays in use and
// its freshness (fresh, stale, unknown) is what every surface shows; it is
// never reported clean.

// SecurityContentKind is one row of the kind table.
type SecurityContentKind struct {
	Kind content.Kind
	// Consumer names what reads the kind on the node.
	Consumer string
}

// SecurityContentKinds is THE kind table of the mirror fetch: every
// security kind of the content channel, so the later lanes (rule packs and
// engines, SEC-G2) add a consumer, not a fetch path.
var SecurityContentKinds = []SecurityContentKind{
	{content.MaliciousPackages, "the install gate's index (security.deps)"},
	{content.PopularNames, "the install gate's index (security.deps)"},
	{content.OSVExport, "the dependency scanners' databases (security.scan.scalibr, security.scan.osv)"},
	{content.OSVOSExport, "the image OS-package scanner's per-release databases (security.scan.os)"},
	{content.OSVShards, "the remote lookup's shard set descriptors (security.deps match = remote, lane RM-2; the shard objects are mirrored by RM-3)"},
	{content.KEV, "the exploit-likelihood labels and ranking of dependency findings (security.deps, CISA KEV)"},
	{content.EPSS, "the exploit-likelihood labels and ranking of dependency findings (security.deps, FIRST EPSS)"},
	{content.AgentCVETable, "the agent CVE table (not consumed yet)"},
	{content.RulePack, "the code rules' rule pack (SEC-G2)"},
	{content.Engine, "the code rules' engine pins (SEC-G2)"},
}

// LookupSecurityContentKind returns the row for kind.
func LookupSecurityContentKind(kind content.Kind) (SecurityContentKind, bool) {
	for _, k := range SecurityContentKinds {
		if k.Kind == kind {
			return k, true
		}
	}
	return SecurityContentKind{}, false
}

// SandboxContentKind is one row of the sandbox kind table.
type SandboxContentKind struct {
	Kind content.Kind
	// Consumer names what reads the kind on the node.
	Consumer string
	// Component is the sandbox driver component whose activity gates the
	// fetch: the node fetches the kind only while that driver is active
	// (cmd/observer reads it; this package does not act on it).
	Component string
}

// SandboxContentKinds is the sandbox kind table beside
// SecurityContentKinds (sandbox plan 12.3, lane SBX-P3D): the same fetch
// path (InstallSecurityContent) and the same mirror route, one consumer per
// row. sandbox.rootfs and sandbox.guest_binary joined with P4 (lane
// SBX-P4): their bulk bytes arrive only through `observer sandbox content
// import <dir>` in this lane (no org mirror row; the mirror keeps both off
// under its small-kind cap), so a mirror or feed fetch of them answers that
// the source does not publish them.
var SandboxContentKinds = []SandboxContentKind{
	{content.SandboxImage, "the container driver's default image (Observer's signed descriptor and SBOM)", "terminals.sandbox.oci"},
	{content.SandboxNative, "the Windows driver's signed MXC file manifest (the compiled pins stay the floor)", "terminals.sandbox.mxc"},
	{content.SandboxRootfs, "the microVM driver's guest image set (descriptor, SBOM, kernel, initramfs, read-only rootfs and its verity tree)", "terminals.sandbox.vm"},
	{content.SandboxGuest, "the microVM driver's guest observer, one per architecture, the host agent's version", "terminals.sandbox.vm"},
}

// LookupSandboxContentKind returns the row for kind.
func LookupSandboxContentKind(kind content.Kind) (SandboxContentKind, bool) {
	for _, k := range SandboxContentKinds {
		if k.Kind == kind {
			return k, true
		}
	}
	return SandboxContentKind{}, false
}

// mirrorFetchKind reports whether the mirror fetch serves kind: a row of
// either table.
func mirrorFetchKind(kind content.Kind) bool {
	_, sec := LookupSecurityContentKind(kind)
	_, sbx := LookupSandboxContentKind(kind)
	return sec || sbx
}

// The mirror fetch's typed outcomes.
var (
	// ErrSecurityContentNotSupported: the org server serves no mirror (it
	// predates the relay, it is not configured, or its mode is off).
	ErrSecurityContentNotSupported = errors.New("orgclient: the org server mirrors no security content")
	// ErrSecurityContentNotMirrored: the server has no copy of this kind
	// or artifact.
	ErrSecurityContentNotMirrored = errors.New("orgclient: this security content is not in the org mirror")
	// ErrSecurityContentManagedOnly: the server serves the mirror to managed
	// enrolments only (403 managed_only) and this enrolment is not one.
	ErrSecurityContentManagedOnly = errors.New("orgclient: the org server mirrors security content for managed enrolments only")
	// errSecurityContentNotModified is a 304.
	errSecurityContentNotModified = errors.New("orgclient: not modified")
)

// sandboxFeedFallbacks are the mirror refusals after which a sandbox kind
// may come from the public signed feed instead (SBX-P3D audit finding 2,
// the orchestrator's default): the server says it runs no mirror for this
// node (404 not_supported: the relay mode is off, no mirror is configured,
// or the server predates the route) or serves managed enrolments only (403
// managed_only). Nothing else falls back: a network error, a 5xx, an auth
// failure or a kind the org's own mirror does not hold (not_mirrored) keeps
// the node on its org, so an org that runs a mirror is never bypassed.
var sandboxFeedFallbacks = []error{ErrSecurityContentNotSupported, ErrSecurityContentManagedOnly}

// SandboxContentFeedFallback reports whether err, from InstallSecurityContent
// for a sandbox kind, lets the node fetch that kind from the public signed
// feed instead (sandboxFeedFallbacks). The feed's content is vendor-signed
// and verified exactly as the mirror's would be.
func SandboxContentFeedFallback(err error) bool {
	for _, f := range sandboxFeedFallbacks {
		if errors.Is(err, f) {
			return true
		}
	}
	return false
}

// EnrolmentManaged reports whether this node is managed: a managed
// enrolment, or one whose org switched it to enterprise (NodeManaged,
// P-204); not enrolled reports false.
func (c *Client) EnrolmentManaged(ctx context.Context) (bool, error) {
	managed, err := NodeManaged(ctx, c.store)
	if err != nil {
		return false, fmt.Errorf("orgclient: %w", err)
	}
	return managed, nil
}

// fetchSecurityContent GETs one file of kind into w (at most limit bytes)
// with an optional If-None-Match, returning the response's ETag.
func (c *Client) fetchSecurityContent(ctx context.Context, kind content.Kind, file, etag string, platform bool, w io.Writer, limit int64) (string, error) {
	enr, err := c.store.LoadEnrolment(ctx)
	if err != nil {
		return "", fmt.Errorf("orgclient: load enrolment: %w", err)
	}
	if enr == nil {
		return "", ErrNotEnrolled
	}
	bearer, err := c.bearers.LoadBearer()
	if err != nil {
		return "", fmt.Errorf("orgclient: load bearer: %w", err)
	}
	u := strings.TrimRight(enr.OrgServerURL, "/") + orgcontract.AgentSecurityContentPath + url.PathEscape(string(kind)) + "/" + url.PathEscape(file)
	if platform {
		u += "?os=" + url.QueryEscape(runtime.GOOS) + "&arch=" + url.QueryEscape(runtime.GOARCH)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("orgclient: security content: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotModified:
		return etag, errSecurityContentNotModified
	case http.StatusNotFound:
		var e struct {
			Error string `json:"error"`
			Code  string `json:"code"`
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		_ = json.Unmarshal(b, &e)
		if strings.Contains(e.Error+e.Code, "not_mirrored") {
			return "", ErrSecurityContentNotMirrored
		}
		return "", ErrSecurityContentNotSupported
	case http.StatusMethodNotAllowed:
		return "", ErrSecurityContentNotSupported
	case http.StatusForbidden:
		var e struct {
			Error string `json:"error"`
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if json.Unmarshal(b, &e) == nil && e.Error == managedOnlyCode {
			return "", ErrSecurityContentManagedOnly
		}
		return "", ErrAuthFailed
	case http.StatusUnauthorized:
		return "", ErrAuthFailed
	default:
		return "", fmt.Errorf("orgclient: security content: server returned %d", resp.StatusCode)
	}
	n, err := io.Copy(w, io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return "", fmt.Errorf("orgclient: security content: %w", err)
	}
	if n > limit {
		return "", errors.New("orgclient: security content over its cap")
	}
	return resp.Header.Get("ETag"), nil
}

// SecurityContentResult is one kind's fetch.
type SecurityContentResult struct {
	Kind content.Kind
	// Unchanged: the server's envelope is the accepted one (or a 304).
	Unchanged bool
	State     content.State
	// Reused counts the artifacts taken from the installed copy (same name,
	// platform, size and sha256) instead of being fetched again.
	Reused int
}

// stageInstalledArtifact stages the installed artifact src under a fresh
// ".incoming-*" name in root, as a downloaded artifact is staged: a hard
// link (no second copy of an export of hundreds of megabytes), or a copy
// where the filesystem refuses the link. The caller removes the staged name.
func stageInstalledArtifact(root, src string) (string, error) {
	f, err := os.CreateTemp(root, ".incoming-*")
	if err != nil {
		return "", err
	}
	name := f.Name()
	if err := f.Close(); err != nil {
		_ = os.Remove(name)
		return "", err
	}
	if err := os.Remove(name); err != nil {
		return "", err
	}
	if err := os.Link(src, name); err == nil {
		return name, nil
	}
	in, err := os.Open(src) //nolint:gosec // G304: a file of the content channel's own kind directory
	if err != nil {
		return "", err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", err
	}
	_, err = io.Copy(out, in)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(name)
		return "", err
	}
	return name, nil
}

// securityContentETagFile keeps the mirror envelopes' ETags beside the
// content root, per kind.
const securityContentETagFile = "org-mirror-etag.json"

func readSecurityContentETags(st contentchan.Store) map[string]string {
	out := map[string]string{}
	b, err := os.ReadFile(filepath.Join(filepath.Dir(st.Root), securityContentETagFile))
	if err == nil && len(b) < 8192 {
		_ = json.Unmarshal(b, &out)
	}
	return out
}

func writeSecurityContentETag(st contentchan.Store, kind content.Kind, tag string) {
	tags := readSecurityContentETags(st)
	if len(tag) > 256 || tags[string(kind)] == tag {
		return
	}
	tags[string(kind)] = tag
	if b, err := json.Marshal(tags); err == nil {
		p := filepath.Join(filepath.Dir(st.Root), securityContentETagFile)
		_ = os.MkdirAll(filepath.Dir(p), 0o700)
		_ = os.WriteFile(p+".tmp", b, 0o600)
		_ = os.Rename(p+".tmp", p)
	}
}

// InstallSecurityContent fetches kind (a row of SecurityContentKinds or
// SandboxContentKinds) from the org mirror and installs it
// into st under tr (the vendor keys; the org server's own key is never a
// trust root for content). The envelope is revalidated with its ETag; each
// artifact for this platform is streamed to a file under st's root (or,
// when the same bytes are already installed, staged from the installed
// copy: contentchan.Store.InstalledArtifact) and handed to
// contentchan.InstallFiles, which checks every size and digest
// before anything is installed. On any failure nothing changes and the
// last-known-good stays.
func (c *Client) InstallSecurityContent(ctx context.Context, st contentchan.Store, kind content.Kind, tr contentchan.Trust) (SecurityContentResult, error) {
	res := SecurityContentResult{Kind: kind}
	if !mirrorFetchKind(kind) {
		return res, fmt.Errorf("orgclient: %q is not a mirrored content kind", kind)
	}
	prev, err := st.State(kind)
	if err != nil {
		return res, err
	}
	res.State = prev
	etag := ""
	if prev.Accepted != nil {
		etag = readSecurityContentETags(st)[string(kind)]
	}
	var env strings.Builder
	newTag, err := c.fetchSecurityContent(ctx, kind, orgcontract.SecurityContentManifestFile, etag, false, &env, content.MaxEnvelopeBytes)
	if errors.Is(err, errSecurityContentNotModified) {
		res.Unchanged = true
		return res, nil
	}
	if err != nil {
		return res, err
	}
	envelope := []byte(env.String())
	// Read the entry list from a verified envelope (the same checks run
	// again inside InstallFiles, against the accepted high-water mark).
	v, err := content.Verify(content.VerifyInput{
		Envelope: envelope, Kind: kind, VendorKeys: tr.VendorKeys, FeedKeys: tr.FeedKeys, RequireOrg: tr.RequireOrg, OrgKey: tr.OrgKey,
		Accepted: prev.Accepted, Now: time.Now(),
	})
	if err != nil {
		res.State, _ = st.InstallFiles(kind, envelope, nil, tr) // records the refusal; keeps last-known-good
		return res, err
	}
	if prev.Accepted != nil && v.Hash == prev.Accepted.ManifestHash {
		writeSecurityContentETag(st, kind, newTag)
		res.Unchanged = true
		return res, nil
	}
	if err := os.MkdirAll(st.Root, 0o700); err != nil {
		return res, err
	}
	files := map[string]string{}
	defer func() {
		for _, p := range files {
			_ = os.Remove(p)
		}
	}()
	for _, e := range v.Manifest.Entries {
		if (e.OS != "" && e.OS != runtime.GOOS) || (e.Arch != "" && e.Arch != runtime.GOARCH) || content.IsRevoked(v.Manifest, e.SHA256) {
			continue
		}
		// The same bytes are already installed (same name and platform,
		// size and sha256): stage them instead of downloading them again,
		// so a manifest that changes one OSV export fetches that export
		// only (static feed mirroring plan, B2). InstallFiles checks the
		// staged file like a downloaded one.
		if src, ok := st.InstalledArtifact(kind, e); ok {
			if p, err := stageInstalledArtifact(st.Root, src); err == nil {
				files[e.Name] = p
				res.Reused++
				continue
			}
		}
		f, err := os.CreateTemp(st.Root, ".incoming-*")
		if err != nil {
			return res, err
		}
		files[e.Name] = f.Name()
		_, ferr := c.fetchSecurityContent(ctx, kind, e.Name, "", e.OS != "" || e.Arch != "", f, e.SizeBytes)
		if cerr := f.Close(); ferr == nil {
			ferr = cerr
		}
		if ferr != nil {
			return res, fmt.Errorf("artifact %s: %w", e.Name, ferr)
		}
	}
	next, err := st.InstallFiles(kind, envelope, files, tr)
	res.State = next
	if err != nil {
		return res, err
	}
	writeSecurityContentETag(st, kind, newTag)
	return res, nil
}
